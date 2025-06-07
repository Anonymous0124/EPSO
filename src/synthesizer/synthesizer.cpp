#include "synthesizer.h"

#include "src/validator/validator.h"
#include "src/verifier/verifier.h"
#include "src/peepholeOptimizer/peepholeOptimizer.h"



#include <pqxx/pqxx>

using namespace std;
using namespace superbpf;

namespace superbpf {

    string WinSynthesizer::cur_example_name;

    bool cmp(pair<u8, double> a, pair<u8, double> b) {
        return a.second < b.second;
    }

    vector<u8> sort_opcodes(vector<u8> opcodes) {
        vector<pair<u8, double>> vec;
        for (auto opcode:opcodes) {
            pair<u8,double> pair={opcode,insn_runtime[opcode]};
            vec.emplace_back(pair);
        }
        std::sort(vec.begin(), vec.end(), cmp);
        vector<u8> res;
        for(auto [opcode,time]:vec){
            res.emplace_back(opcode);
        }
        return res;
    }

    void Synthesizer::set_opt_sorted_opcodes_imms() {
        sorted_optional_opcodes_.clear();
        optional_imms_.clear();
        optional_imm2s_.clear();
        vector<Insn> &origin_insns = origin_->insns();
        bool has_load=false,has_store=false;
        bool has_add=false,has_or=false,has_and=false,has_xor=false;
        bool ld_32=false,st_32=false;
        for (int i = 0; i < origin_insns.size(); i++) {
            Insn &insn = origin_insns[i];
            u8 insn_opcode = insn._opcode;
            if (insn._opcode == 0) {
                optional_imm2s_.insert(insn._imm);
            } else {
                set<u8> opcodes = insn.get_related_opcodes();
                // prune: decide whether to add BPF_ST to optional opcodes (TODO: may be deleted)
                bool add_bpf_st = true;
                if (BPF_CLASS(insn._opcode) == BPF_STX) {
                    has_store=true;
                    for (int j = i - 1; j >= 0; j--) {
                        Insn &def_insn = origin_insns[j];
                        if (def_insn._dst_reg == insn._src_reg) {
                            if (def_insn.getType() == OP_LD)
                                add_bpf_st = false;
                            break;
                        }
                    }
                    if(BPF_SIZE(insn._opcode)==BPF_W){
                        st_32=true;
                    }
                }
                else if(BPF_CLASS(insn._opcode)==BPF_ALU||BPF_CLASS(insn._opcode)==BPF_ALU64){
                    auto op=BPF_OP(insn._opcode);
                    switch(op){
                        case BPF_ADD:
                            atomic_imms_.insert(BPF_ADD);has_add=true;break;
                        case BPF_OR:
                            atomic_imms_.insert(BPF_OR);has_or=true;break;
                        case BPF_AND:
                            atomic_imms_.insert(BPF_AND);has_and=true;break;
                        case BPF_XOR:
                            atomic_imms_.insert(BPF_XOR);has_xor=true;break;
                    }
                }
                else if(BPF_CLASS(insn._opcode)==BPF_LDX){
                    has_load=true;
                    if(BPF_SIZE(insn._opcode)==BPF_W){
                        ld_32=true;
                    }
                }
                if (!add_bpf_st) {
                    for (auto it = opcodes.begin(); it != opcodes.end();) {
                        if (BPF_CLASS(*it) == BPF_ST)
                            it = opcodes.erase(it);
                        else
                            it++;
                    }
                }
                for (u8 opcode: opcodes) {
                    sorted_optional_opcodes_.emplace_back(opcode);
                }
                if (insn_opcode == ATOMIC32 || insn_opcode == ATOMIC64)
                    atomic_imms_.insert(insn._imm);
                else
                    optional_imms_.insert(insn._imm);
            }
        }
        if(has_load&&has_store&&(has_add||has_or||has_and||has_xor)){
            sorted_optional_opcodes_.emplace_back(MOV64XC);
            if(has_add) {
                if(ld_32&&st_32)
                    sorted_optional_opcodes_.emplace_back(XADD32);
                else
                    sorted_optional_opcodes_.emplace_back(XADD64);
            }
        }
        sorted_optional_opcodes_=sort_opcodes(sorted_optional_opcodes_);
    }

    void Synthesizer::set_ld_bytes() {
        ld_bytes_ = 0;
        vector<Insn> insns = origin_->insns();
        for (Insn &insn: insns) {
            if (insn.getType() == OP_LD)
                ld_bytes_ += opcode2byte_num.at(insn._opcode);
        }
    }

    set<u8> Synthesizer::get_optional_dst_regs(u8 code, State *last_state, bool is_used, bool is_defed) {
        set<u8> res;
        for (u8 i = 0; i < MAX_BPF_REG; i++) {
            res.insert(i);
        }
        if (is_used) {
            res = last_state->get_valid_reg_ids();
        }
        if (is_defed) {
            if (res.count(10))
                res.erase(10);
            u8 left_reg = 10;
            set<int> live_regs = origin_->regs_live_out();
            // prune: merge similar regs
            for (auto it = res.begin(); it != res.end();) {
                u8 reg = *it;
                if (!last_state->is_regi_valid(reg) && !live_regs.count(reg)) {
                    if (left_reg == 10) {
                        left_reg = reg;
                        it++;
                    } else {
                        it = res.erase(it);
                    }
                } else {
                    it++;
                }
            }
        }
        return res;
    }

    set<u8> Synthesizer::get_optional_src_regs(u8 code, State *last_state, bool is_used) {
        set<u8> res;
        if (code == LDDW) {
            for (int i = 0; i <= 6; i++)
                res.insert(i);
        } else {
            if (is_used) {
                return last_state->get_valid_reg_ids();
            } else {
                res.insert(0);
            }
        }
        return res;
    }

    set<s16> Synthesizer::get_optional_offs_helper(vector<State *> states, u8 reg_id, int byte_num, bool is_st) {
        set<s16> res;
        for (int i = 0; i < testcases_.size(); i++) {
            s64 reg_val = states[i]->get_regi_val(reg_id);
            map<u64, int> mem_areas;
            if (is_st)
                mem_areas = testcases_[i]->get_st_mem_areas();
            else
                mem_areas = testcases_[i]->get_ld_mem_areas();
//            cout<<"mem addrs at off selection part\n";
//            for(auto [base_addr,size]:mem_areas)
//                cout<<base_addr<<' '<<size<<endl;
            set<s16> temp_res;
            for (auto &mem_area: mem_areas) {
                u64 base = mem_area.first;
                int size = mem_area.second;
                if (size < byte_num)
                    continue;
                if (i == 0) {
                    for (u64 addr = base; addr <= (base + size - byte_num); addr++) {
                        s16 off = addr - reg_val;
                        if ((u64) (reg_val + off) == addr) {
//                            if (byte_num != 1 && off % byte_num != 0) //TODO: verifier's memory access alignment
//                                continue;
                            res.insert(off);
                        }
                    }
                } else {
                    for (u64 addr = base; addr <= (base + size - byte_num); addr++) {
                        s16 off = addr - reg_val;
                        if ((u64) (reg_val + off) == addr) {
                            if (!((byte_num != 1) && (off % 2 != 0)))
                                temp_res.insert(off);
                        }
                    }
                }
            }
            if (i != 0) {
                set<s16> new_res;
                set_intersection(res.begin(), res.end(), temp_res.begin(), temp_res.end(),
                                 inserter(new_res, new_res.begin()));
                res = new_res;
            }
        }
//        if(!res.empty()){
//            cout<<"final_res:"<<endl;
//            for(auto it:res)
//                cout<<it<<' ';
//            cout<<endl;
//        }

        return res;
    }

    set<s16> Synthesizer::get_optional_offs(vector<State *> states, u8 opcode, u8 dst_reg, u8 src_reg) {
        set<s16> res;
        // st: addr = dst + off; ldx: addr = src + off
        u8 bpf_class = BPF_CLASS(opcode);
        if ((bpf_class == BPF_STX) || (bpf_class == BPF_ST)) {
            res = get_optional_offs_helper(states, dst_reg, opcode2byte_num.at(opcode), true);
        } else if (bpf_class == BPF_LDX) {
            res = get_optional_offs_helper(states, src_reg, opcode2byte_num.at(opcode), false);
        } else {
            res.insert(0);
        }
        return res;
    }

    set<s32> Synthesizer::get_optional_imms(u8 opcode) {
        set<s32> res;
        u8 bpf_class = BPF_CLASS(opcode), bpf_op = BPF_OP(opcode), bpf_src = BPF_SRC(opcode), bpf_mode = BPF_MODE(
                opcode);
        if (opcode == 0) {
            res = optional_imm2s_;
        } else if (((bpf_class == BPF_ALU64 || bpf_class == BPF_ALU) && (bpf_src == BPF_K) && (bpf_op != BPF_END)
                    && !(bpf_op == BPF_LSH || bpf_op == BPF_RSH || bpf_op == BPF_ARSH))
                   || (bpf_class == BPF_ST)
                   || (bpf_class == BPF_LD)) {
            res = optional_imms_;
        } else if ((bpf_class == BPF_ALU64 || bpf_class == BPF_ALU) && (bpf_op == BPF_END)) {
            for (s32 imm: optional_imms_) {
                if (imm == 16 || imm == 32 || imm == 64)
                    res.insert(imm);
            }
        } else if ((bpf_class == BPF_ALU64 || bpf_class == BPF_ALU) &&
                   (bpf_op == BPF_LSH || bpf_op == BPF_RSH || bpf_op == BPF_ARSH)) {
            for (s32 imm: optional_imms_) {
                if (imm >= 0 && imm <= 64)
                    res.insert(imm);
            }
        } else if (bpf_class == BPF_STX && bpf_mode == BPF_ATOMIC) {
            res = atomic_imms_;
        } else {
            res.insert(0);
        }
        // if div or mod, imm not allowed to be 0
        Insn insn;
        insn._opcode = opcode;
        if (insn.isDivModK() && res.count(0))
            res.erase(0);
        return res;
    }

    unsigned Synthesizer::get_bytes_num(u8 opcode){
        unsigned res;
        u8 size=BPF_SIZE(opcode);
        switch(size){
            case BPF_B:res=1;break;
            case BPF_H:res=2;break;
            case BPF_W:res=4;break;
            case BPF_DW:res=8;break;
            default:assert(0);
        }
        return res;
    }

    double Synthesizer::score_insns(vector<Insn> &insns) {
        double res = 0;
        for (Insn insn: insns) {
            if (insn._opcode == CALL)
                res -= call_runtime[insn._imm];
            else if (insn._opcode == BE)
                res -= be_runtime[insn._imm];
            else if (insn._opcode == LE)
                res -= le_runtime[insn._imm];
            else
                res -= insn_runtime[insn._opcode];
        }
        return res;
    }

    Node* Synthesizer::synthesize_using_patterns(Node* origin){
        Node* rewrite=new Node(*origin);
        auto insns=origin->insns();
        /*
            r_a = *(u8/16/32 *) (r_b + off)
            r_a <<= 8/16/32
            r_b = *(u8/16/32 *) (r_b + off - 1/2/3)
            r_a |= r_b
        */
        int ld_count=0,lsh_count=0,or_count=0;
        int or_dst_reg=-1,ld_src_reg=-1;
        vector<int> bytes_num;
        vector<s16> offsets;
        for(auto insn:insns){
            if(insn.is_ldx()) {
                ld_count++;
                bytes_num.emplace_back(get_bytes_num(insn._opcode));
                offsets.emplace_back(insn._off);
                if(ld_src_reg==-1)
                    ld_src_reg=insn._src_reg;
                else if(ld_src_reg!=insn._src_reg)
                    return rewrite;
            }
            else if(insn._opcode == LSH32XC || insn._opcode == LSH64XC){
                bytes_num.emplace_back(insn._imm/8);
            }
            else if(insn._opcode == OR32XY || insn._opcode == OR64XY) {
                or_count++;
                or_dst_reg=insn._dst_reg;
            }
        }
        if(ld_count==2&&lsh_count==1&&or_count==1){  // TODO: expand to more than 4 insns
            bool bytes_num_equal=true,interval_equal=true;
            for(int i=1;i<bytes_num.size();i++){
                if(bytes_num[i]!=bytes_num[0]){
                    bytes_num_equal=false;
                    break;
                }
            }
            if(bytes_num_equal){
                sort(offsets.begin(),offsets.end());
                for(int i=1;i<offsets.size();i++){
                    if(abs(offsets[i]-offsets[i-1])!=bytes_num[0]){
                        interval_equal=false;
                        break;
                    }
                }
            }
            if(bytes_num_equal&&interval_equal){
                if(bytes_num[0]==8)
                    return rewrite;
                Insn insn;
                switch(bytes_num[0]){
                    case 1:insn._opcode=LDXH;break;
                    case 2:insn._opcode=LDXW;break;
                    case 4:insn._opcode=LDXDW;
                }
                insn._dst_reg=or_dst_reg;
                insn._src_reg=ld_src_reg;
                insn._off=offsets[0];
            }
        }
        return rewrite;
    }

    void Synthesizer::print_last_synthesis_time() {
        cout << "Synthesis time: ";
        if (last_synthesis_time_ / 3600 != 0) {
            int hour = last_synthesis_time_ / 3600;
            cout << hour << " h, ";
            last_synthesis_time_ = last_synthesis_time_ - 3600 * hour;
        }
        if (last_synthesis_time_ / 60 != 0) {
            int min = last_synthesis_time_ / 60;
            cout << min << " min, ";
            last_synthesis_time_ = last_synthesis_time_ - 60 * min;
        }
        cout << last_synthesis_time_ << " s." << endl;
    }

    void Synthesizer::add_testcase(Testcase *testcase) {
        testcases_.emplace_back(testcase);
    }

    Node* WinSynthesizer::match_pattern(Node* origin){
        bool optimized=false;
        Node* rewrite= nullptr;
        PeepholeOptimizer peepholeOptimizer(win_size_);
        vector<Node> rewrites=peepholeOptimizer.match_pattern(origin);
        if(!rewrites.empty()) {
            sort(rewrites.begin(),rewrites.end());
            for(int i=0;i<rewrites.size();i++){
                vector<Node> specific_rewrites= peepholeOptimizer.get_specific_insns(rewrites[i]);
                int j=0;
                for(j=0;j<specific_rewrites.size();j++){
                    auto specific_rewrite=specific_rewrites[j];
                    Validator validator(origin,&specific_rewrite);
                    cout<<"Validation started."<<endl;
                    if(validator.verify()) {
                        optimized=true;
                        rewrite=new Node(origin->idx(),specific_rewrite.insns());
                        break;
                    }
                }
                if(j<specific_rewrites.size())
                    break;
            }
        }
        return rewrite;
    }

    Node *WinSynthesizer::synthesize_with_context() {
//        origin_->print_insns();
//        testcases_.back()->print_testcase();
        assert(win_size_ != 0);
//        for (Testcase *testcase: testcases_)
//            testcase->print_testcase();
        Verifier::refresh_hit_times();
        if (origin_->size() <= win_size_) {
            // using pattern matching
            auto matched_rewrite= match_pattern(origin_);
            if(matched_rewrite) {
                matched_rewrite->set_prog_attach_type(origin_->prog_type(),origin_->attach_type());
                printf("\033[32mHit one optimization pattern.\n\n\033[0m");
                return matched_rewrite;
            }

            synthesizer_->set_prog(origin_);
            for (Testcase *testcase: testcases_)
                synthesizer_->add_testcase(testcase);
            Node *rewrite_node = synthesizer_->synthesize();
            assert(rewrite_node!= nullptr);
            Validator validator(origin_,rewrite_node);
            if(validator.verify()){
                if(rewrite_node->size()<origin_->size()) // TODO
                    store_opt_pattern(origin_,rewrite_node);
            }
            else{
                cout<<"Node's validation failed."<<endl;
                origin_->print_insns();
                rewrite_node->print_insns();
            }
            rewrite_node->set_prog_attach_type(origin_->prog_type(),origin_->attach_type());
            synthesizer_->print_last_synthesis_time();
            return rewrite_node;
        }
        // window decomposition
        int start = 0;
        for (int i = 0; i < testcases_last_state_.size(); i++) {
            testcases_last_state_[i] = testcases_[i]->init_state();
        }
        Node* origin_copy=new Node(*origin_);
        vector<Insn> rewrite_insns;
        while (start < origin_copy->size()) {
            int end = min(start + win_size_,origin_copy->size());
            Node *origin_sub_node = origin_copy->get_sub_node(start, end);
            synthesizer_->set_prog_with_inited_testcases(origin_sub_node, testcases_last_state_);
            // using pattern matching
            Node* rewrite_sub_node=match_pattern(origin_sub_node);
            if(!rewrite_sub_node)
                rewrite_sub_node = synthesizer_->synthesize();
            else
                printf("\033[32mHit one optimization pattern.\n\n\033[0m");

//            origin_sub_node->print_insns();
//            origin_sub_node->print_insns();
//            cout << "origin sub node:" << endl;
//            origin_sub_node->print_insns();
//            origin_sub_node->print_live_regs();
//            Node* rewrite_sub_node=synthesizer_->synthesize(); // without using pattern matching
            cout<<"Validation started."<<endl;
            origin_sub_node->print_insns();
            origin_sub_node->print_live_regs();
            rewrite_sub_node->print_insns();
            Validator validator(origin_sub_node,rewrite_sub_node);
            if(validator.verify()){
                if(rewrite_sub_node->size()<origin_sub_node->size()) // TODO
                    store_opt_pattern(origin_sub_node,rewrite_sub_node);
            }
            else{
                cout<<"Sub node's validation failed."<<endl;
                validator.get_counterexample()->print_testcase();
//                origin_sub_node->print_insns();
//                rewrite_sub_node->print_insns();
//                delete rewrite_sub_node;
//                rewrite_sub_node=new Node(*origin_sub_node); // TODO
            }
//            rewrite_sub_node->print_insns();
            cout<<"Sub block "<<rewrite_sub_node->idx()<<" ";
            synthesizer_->print_last_synthesis_time();
//            if (rewrite_sub_node == nullptr) {
//                for (Testcase *testcase: synthesizer_->get_testcases()) {
//                    testcase->print_testcase();
//                }
//            }
            // TODO
            assert(rewrite_sub_node!= nullptr);
            if (rewrite_sub_node == nullptr) {
                rewrite_sub_node = origin_sub_node;
            }
            bool same_with_origin = rewrite_sub_node->same_with_node(origin_sub_node);
            if (!same_with_origin) {
                // if (origin_sub_node->get_score() + 1e-6 < rewrite_sub_node->get_score()) {
                if (origin_sub_node->get_insns_num() > rewrite_sub_node->get_insns_num()) {  // TODO: '>' or '>=' ?
                    // test whether current optimization works
                    for (int i = 0; i < testcases_.size(); i++) {
                        State *cur_state = testcases_last_state_[i], *next_state = new State(cur_state->version() + 1);
                        for (int j = 0; j < rewrite_sub_node->insns().size(); j++) {
                            insn_simulator_.run(rewrite_sub_node->insns()[j], cur_state, next_state);
                            cur_state = next_state;
                            next_state = new State(cur_state->version() + 1);
                        }
                        State *new_cur_state = cur_state;
                        for (int j = end; j < origin_copy->size(); j++) {
                            insn_simulator_.run(origin_copy->insns()[j], new_cur_state, next_state);
                            new_cur_state = next_state;
                            next_state = new State(new_cur_state->version() + 1);
                        }
                        if (!new_cur_state->check_equivalence(testcases_[i]->final_state(),
                                                              origin_->regs_live_out(),origin_->mem_live_out(),
                                                              origin_->init_static_info())) {
//                            testcases_[i]->final_state()->print_state();
//                            new_cur_state->print_state();
                            delete rewrite_sub_node;
                            rewrite_sub_node = origin_sub_node;
                            same_with_origin = true;
                            break;
                        } else {
//                        delete testcases_last_state_[i];
//                            testcases_last_state_[i] = cur_state;
                        }
                    }
                } else {
                    delete rewrite_sub_node;
                    rewrite_sub_node = origin_sub_node;
                    same_with_origin = true;
                };
            }
            if (same_with_origin) {
                for (int i = 0; i < testcases_.size(); i++) {
                    State *cur_state = testcases_[i]->init_state(), *next_state = new State(0);
                    for (int j = 0; j <= start; j++) {
                        insn_simulator_.run(origin_copy->insns()[j], cur_state, next_state);
//                delete testcases_last_state_[i];
//                        delete cur_state;
                        cur_state = next_state;
                        next_state = new State(0);
                    }
                    testcases_last_state_[i] = cur_state;
//                    testcases_last_state_[i]->print_state();
                }
                rewrite_insns.emplace_back(origin_copy->insns()[start]);
                start++;
//                if (start + win_size_ > origin_copy->size()) {
//                    rewrite_insns.insert(rewrite_insns.end(), origin_copy->insns().begin() + start, origin_copy->insns().end());
//                    break;
//                }
            } else {
                origin_copy->edit_insns(start,end,rewrite_sub_node->insns());
                origin_copy->compute_final_static_info();
            }
        }
        Node *rewrite = new Node(origin_->idx(), rewrite_insns);
//        Node *rewrite_using_patterns=synthesizer_->synthesize_using_patterns(rewrite);
        rewrite->set_prog_attach_type(origin_->prog_type(),origin_->attach_type());
        return rewrite;
    }

    void WinSynthesizer::store_opt_pattern(const Node* origin,const Node* rewrite){
        unordered_map<int,int> reg_id_map; // <real reg id, serialized reg id>
        unordered_map<int,int> reg_off_map; // <real reg id, the first visited offset>
        unordered_map<int,int> imm_map; // <real imm, serialized imm>
        auto origin_used_regs=origin->get_used_regs(),rewrite_used_regs=rewrite->get_used_regs();
        set<int> diff_regs;
        set_difference(rewrite_used_regs.begin(),rewrite_used_regs.end(),origin_used_regs.begin(),origin_used_regs.end(),
                       inserter(diff_regs,diff_regs.begin()));
        string origin_insns_str= origin->get_serialized_insns_str(reg_id_map,reg_off_map,imm_map,set<int>());
        string rewrite_insns_str= rewrite->get_serialized_insns_str(reg_id_map,reg_off_map,imm_map,diff_regs);
        // check if the optimization pattern already exits
        try {
            // Connect to the PostgreSQL database
            pqxx::connection conn("dbname=xxdb user=xx password=xx host=localhost port=5432");
            string sql="SELECT origin, rewrite FROM rewrite_rules WHERE origin = "+origin_insns_str+" and rewrite = "+rewrite_insns_str;
            if (conn.is_open()) {
                // Create a transactional object
                pqxx::work txn(conn);
                // Execute a SELECT query
                pqxx::result res = txn.exec(sql);
                // Process the result
                if(!res.empty()){
                    cout<<"Target optimization pattern already existed."<<endl;
                    conn.disconnect();
                    return;
                }
                // Commit the transaction (optional for SELECT queries)
                txn.commit();
            } else {
                std::cerr << "Failed to connect to the database!" << std::endl;
            }
            // Close the connection
            conn.disconnect();
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
        // store optimization pattern
        try {
            // Connect to the PostgreSQL database
            pqxx::connection conn("dbname=xxdb user=xx password=xx host=localhost port=5432");
            string live_regs_str;
            if(origin->regs_live_out().empty()){
                live_regs_str="ARRAY[]::INTEGER[]";
            }
            else{
                live_regs_str="ARRAY[";
                for(auto reg_id:origin->regs_live_out()){
                    if(reg_id_map.count(reg_id))
                        live_regs_str+=(to_string(reg_id_map.at(reg_id))+",");
                }
                if(live_regs_str.back()==',')
                    live_regs_str.pop_back();
                live_regs_str+="]::integer[]";
            };
            string sql="INSERT INTO rewrite_rules (sample_name, origin, rewrite, live_regs) VALUES ('"
                       +cur_example_name+"',"+origin_insns_str+","+rewrite_insns_str+","+live_regs_str+");";
            cout<<sql<<endl;
            if (conn.is_open()) {
                // Create a transactional object
                pqxx::work txn(conn);
                // Execute a SELECT query
                txn.exec(sql);
                txn.commit();
                printf("\033[32mOne new optimization pattern added.\n\n\033[0m");
            } else {
                std::cerr << "Failed to connect to the database!" << std::endl;
            }
            // Close the connection
            conn.disconnect();
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }

    void WinSynthesizer::add_testcase(Testcase *testcase) {
        testcases_.emplace_back(testcase);
        testcases_last_state_.emplace_back(new State(testcase->init_state()));
    }

    Testcase *Synthesizer::get_testcasei(int i) {
        return testcases_[i];
    }

    vector<Testcase *> Synthesizer::get_testcases() {
        return testcases_;
    }

    bool DfsSynthesizer::dfs(int depth) {
        time_t cur_time=clock();
        if(double(cur_time-begin_time_)/CLOCKS_PER_SEC>30){
            return false;
        }
//        if(depth==4){
//            for (int j = 0; j < depth; j++) {
//                cur_rewrite_insns_[j].print_insn();
//            }
//            cout<<endl;
//        }

        int failed_testcase_no = 0;
        int same_idx=0;
        for (same_idx = 0; same_idx < cur_rewrite_insns_.size(); same_idx++) {
            if (origin_->insns()[same_idx] != cur_rewrite_insns_[same_idx])
                break;
        }

//        if (depth==1&&cur_rewrite_insns_[0]._opcode==LDXDW&&cur_rewrite_insns_[0]._src_reg==1
//        &&cur_rewrite_insns_[0]._dst_reg==1) {
//            for (int j = 0; j < 1; j++) {
//                cur_rewrite_insns_[j].print_insn();
//            }
//            cout<<endl;
//        }



        bool success = true;
        // If for all testcases, current state reaches expected final state, current insns_ is the final solution.
        bool extend = true;
        for (int i = 0; i < states_.size(); i++) {
//            states_[i][depth]->print_state();
//            testcases_[i]->final_state()->print_state();

            if (!states_[i][depth]->check_equivalence(testcases_[i]->final_state(),
                                                      origin_->regs_live_out(),origin_->mem_live_out(),
                                                      origin_->init_static_info())) {
//                states_[i][depth]->print_state();
//                testcases_[i]->final_state()->print_state();
                failed_testcase_no = i;
                success = false;
            }
            // Prune: if left insn space is not enough to reach final state, return false directly.
            StateDistance dis = states_[i][depth]->compute_dis(testcases_[i]->final_state(), origin_->regs_live_out(),origin_->mem_live_out());
            int left_space = origin_->size() - depth;
            if (dis.total_dis() > left_space) {
                failed_testcase_no = i;
                extend = false;
                success = false;
                break;
            }
//            // Prune: if current insns already score lower than origin, return false directly.
//            if ((score_insns(cur_rewrite_insns_)) < origin_score_ - 1e-6) {
//                failed_testcase_no = i;
//                extend = false;
//                success = false;
//                break;
//            }
//            if (success) {
//                for (int j = 0; j < cur_rewrite_insns_.size(); j++) {
//                    if (Verifier::do_check(states_[i][j], cur_rewrite_insns_[j]) != 0) {
////                        for(auto insn:cur_rewrite_insns_)
////                            insn.print_insn();
//                        success = false;
//                    }
//                }
//            }
        }

        if (success) {
//            origin_->print_insns();
//            for(int i=0;i<testcases_.size();i++) {
//                cout<<i<<' ';
//                testcases_[i]->print_testcase();
//            }
//            for(int i=0;i<states_.size();i++){
//                cout<<i<<endl;
//                states_[i][0]->print_state();
//                for(int j=0;j<cur_rewrite_insns_.size();j++) {
//                    cur_rewrite_insns_[j].print_insn();
//                    states_[i][j+1]->print_state();
//                }
//            }
            return true;
        }
        // reach rewrite insns' max length
        if (depth == cur_max_depth_) {
            extend = false;
        }

        if (extend) {
            // prune failed explored
            for (int i = 0; i < states_.size(); i++) {
                State *cur_state = states_[i][depth];
                auto it = testcases_explored_states_.find(cur_state);
                if (it != testcases_explored_states_.end()) {
                    if (it->second <= depth) {
                        extend = false;
                        break;
                    }
                }
            }
        }

        if (extend) {
            for (auto opcode: sorted_optional_opcodes_) {
                if (depth == origin_->size() - 1 && opcode != 0 && BPF_CLASS(opcode) == BPF_LD)
                    continue;
                Insn insn;
                insn._opcode = opcode;
//                insn.print_insn();
                vector<int> temp = insn.getRegUses();
                set<u8> use_regs(temp.begin(), temp.end());
                // dst_reg
                bool is_dst_used = (use_regs.find(-1) != use_regs.end());
                bool is_dst_defed = (insn.getRegDef() == -1);
                // assuming all testcases' valid regs are always the same
                set<u8> dst_regs = get_optional_dst_regs(opcode, states_[0][depth], is_dst_used, is_dst_defed);
//                if(dst_regs.count(1)&&dst_regs.count(8))
//                    dst_regs={1,8,10};
//                else if(dst_regs.count(8))
//                    dst_regs={8,10};
//                else
//                    dst_regs={10};
                for (u8 dst_reg: dst_regs) {
                    insn._dst_reg = dst_reg;
                    bool is_src_used = (use_regs.find(-2) != use_regs.end());
                    set<u8> src_regs = get_optional_src_regs(opcode, states_[0][depth], is_src_used);
//                    if(!src_regs.count(1))
//                        src_regs={7};
//                    else
//                        src_regs={1,7};
                    for (u8 src_reg: src_regs) {
                        // prune: avoid defining the same reg without using
                        bool catch_def = false;
                        if (is_dst_defed && !is_dst_used && (!is_src_used || src_reg != dst_reg)) {
                            for (int i = cur_rewrite_insns_.size() - 1; i >= 0; i--) {
                                vector<int> reg_used = cur_rewrite_insns_[i].getRegUses();
                                set<int> reg_used_set(reg_used.begin(), reg_used.end());
                                if (reg_used_set.count(dst_reg))
                                    break;
                                if (cur_rewrite_insns_[i].getRegDef() == dst_reg) {
                                    catch_def = true;
                                    break;
                                }
                            }
                        }
                        if (catch_def)
                            continue;
                        insn._src_reg = src_reg;
                        vector<State *> last_states;
                        for (int i = 0; i < states_.size(); i++) {
                            last_states.emplace_back(states_[i][depth]);
                        }
                        set<s16> offs = get_optional_offs(last_states, opcode, dst_reg, src_reg);
//                        if(src_reg==7&&offs.count(4))
//                            offs={4};
//                        else if(dst_reg==8&&src_reg==1&&offs.count(0))
//                            offs={0};
//                        else if(dst_reg==10&&offs.count(static_cast<short>(0xffe8)))
//                            offs={static_cast<short>(0xffe8)};
                        for (s16 off: offs) {
                            insn._off = off;
                            set<s32> imms = get_optional_imms(opcode);
                            for (s32 imm: imms) {
                                insn._imm = imm;
                                while (depth < cur_rewrite_insns_.size()) {
                                    cur_rewrite_insns_.pop_back();
                                }
                                if (BPF_CLASS(opcode) == BPF_LD) {
                                    set<s32> imm2s = get_optional_imms(0);
                                    for (s32 imm2: imm2s) {
                                        cur_rewrite_insns_.emplace_back(insn);
                                        cur_rewrite_insns_.emplace_back(
                                                Insn(0, 0, 0, 0, imm2)
                                        );
                                        for (int i = 0; i < states_.size(); i++) {
                                            insn_simulator_.run(opcode, dst_reg, src_reg, off, imm,
                                                                states_[i][depth], states_[i][depth + 1], imm2);
                                            states_[i][depth + 2]->copy_from_state(states_[i][depth + 1]);
                                        }
                                        if (dfs(depth + 2)) {
                                            return true;
                                        }
                                    }
                                } else {
                                    cur_rewrite_insns_.emplace_back(insn);
                                    for (int i = 0; i < states_.size(); i++) {
                                        insn_simulator_.run(opcode, dst_reg, src_reg, off, imm,
                                                            states_[i][depth], states_[i][depth + 1]);
                                        if(states_[i][depth]==states_[i][depth+1]){
                                            extend=false;
                                        }
                                    }
                                    cur_time=clock();
                                    if(double(cur_time-begin_time_)/CLOCKS_PER_SEC>30){
                                        return false;
                                    }
                                    if (extend&&dfs(depth + 1)) {
                                        return true;
                                    }
                                    cur_rewrite_insns_.pop_back();
                                }
                            }
                        }
                    }
                }
            }
        }

        if (depth <= 2) {
            State *cur_state = states_[failed_testcase_no][depth];
            auto it = testcases_explored_states_.find(cur_state);
            if (it != testcases_explored_states_.end()) {
                if (it->second > depth) {
                    it->second = depth;
                }
            } else {
                State *new_state = new State(depth);
                new_state->copy_from_state(cur_state);
                new_state->set_testcase_no(failed_testcase_no);
                testcases_explored_states_.insert({new_state, depth});
            }
        }


        return false;
    }

    bool DfsSynthesizer::dfs_without_pruning2(int depth) {
        int failed_testcase_no = 0;
        bool success = true;
        // If for all testcases, current state reaches expected final state, current insns_ is the final solution.
        bool extend = true;
        for (int i = 0; i < states_.size(); i++) {
            if (!states_[i][depth]->check_equivalence(testcases_[i]->final_state(),
                                                      origin_->regs_live_out(),origin_->mem_live_out(),
                                                      origin_->init_static_info())) {
                failed_testcase_no = i;
                success = false;
            }
//            // Prune: if left insn space is not enough to reach final state, return false directly.
//            StateDistance dis = states_[i][depth]->compute_dis(testcases_[i]->final_state(), origin_->regs_live_out(),origin_->mem_live_out());
//            int left_space = origin_->size() - depth;
//            if (dis.total_dis() > left_space) {
//                failed_testcase_no = i;
//                extend = false;
//                success = false;
//                break;
//            }
//            if (success) {
//                for (int j = 0; j < cur_rewrite_insns_.size(); j++) {
//                    if (Verifier::do_check(states_[i][j], cur_rewrite_insns_[j]) != 0) {
//                        success = false;
//                    }
//                }
//            }
        }

        if (success) {
            return true;
        }
        // reach rewrite insns' max length
        if (depth == cur_max_depth_) {
            extend = false;
        }

        if (extend) {
            // prune failed explored
            for (int i = 0; i < states_.size(); i++) {
                State *cur_state = states_[i][depth];
                auto it = testcases_explored_states_.find(cur_state);
                if (it != testcases_explored_states_.end()) {
                    if (it->second <= depth) {
                        extend = false;
                        break;
                    }
                }
            }
        }

        if (extend) {
            for (auto opcode: sorted_optional_opcodes_) {
                if (depth == origin_->size() - 1 && opcode != 0 && BPF_CLASS(opcode) == BPF_LD)
                    continue;
                Insn insn;
                insn._opcode = opcode;
                vector<int> temp = insn.getRegUses();
                set<u8> use_regs(temp.begin(), temp.end());
                // dst_reg
                bool is_dst_used = (use_regs.find(-1) != use_regs.end());
                bool is_dst_defed = (insn.getRegDef() == -1);
                // assuming all testcases' valid regs are always the same
                set<u8> dst_regs = get_optional_dst_regs(opcode, states_[0][depth], is_dst_used, is_dst_defed);
                for (u8 dst_reg: dst_regs) {
                    insn._dst_reg = dst_reg;
                    bool is_src_used = (use_regs.find(-2) != use_regs.end());
                    set<u8> src_regs = get_optional_src_regs(opcode, states_[0][depth], is_src_used);
                    for (u8 src_reg: src_regs) {
                        // prune: avoid defining the same reg without using
                        bool catch_def = false;
                        if (is_dst_defed && !is_dst_used && (!is_src_used || src_reg != dst_reg)) {
                            for (int i = cur_rewrite_insns_.size() - 1; i >= 0; i--) {
                                vector<int> reg_used = cur_rewrite_insns_[i].getRegUses();
                                set<int> reg_used_set(reg_used.begin(), reg_used.end());
                                if (reg_used_set.count(dst_reg))
                                    break;
                                if (cur_rewrite_insns_[i].getRegDef() == dst_reg) {
                                    catch_def = true;
                                    break;
                                }
                            }
                        }
                        if (catch_def)
                            continue;
                        insn._src_reg = src_reg;
                        vector<State *> last_states;
                        for (int i = 0; i < states_.size(); i++) {
                            last_states.emplace_back(states_[i][depth]);
                        }
                        set<s16> offs = get_optional_offs(last_states, opcode, dst_reg, src_reg);
                        for (s16 off: offs) {
                            insn._off = off;
                            set<s32> imms = get_optional_imms(opcode);
                            for (s32 imm: imms) {
                                insn._imm = imm;
                                while (depth < cur_rewrite_insns_.size()) {
                                    cur_rewrite_insns_.pop_back();
                                }
                                if (BPF_CLASS(opcode) == BPF_LD) {
                                    set<s32> imm2s = get_optional_imms(0);
                                    for (s32 imm2: imm2s) {
                                        cur_rewrite_insns_.emplace_back(insn);
                                        cur_rewrite_insns_.emplace_back(
                                                Insn(0, 0, 0, 0, imm2)
                                        );
                                        for (int i = 0; i < states_.size(); i++) {
                                            insn_simulator_.run(opcode, dst_reg, src_reg, off, imm,
                                                                states_[i][depth], states_[i][depth + 1], imm2);
                                            states_[i][depth + 2]->copy_from_state(states_[i][depth + 1]);
                                        }
                                        if (dfs(depth + 2)) {
                                            return true;
                                        }
                                    }
                                } else {
                                    cur_rewrite_insns_.emplace_back(insn);
                                    for (int i = 0; i < states_.size(); i++) {
                                        insn_simulator_.run(opcode, dst_reg, src_reg, off, imm,
                                                            states_[i][depth], states_[i][depth + 1]);
                                        if(states_[i][depth]==states_[i][depth+1]){
                                            extend=false;
                                        }
                                    }
                                    if (extend&&dfs(depth + 1)) {
                                        return true;
                                    }
                                    cur_rewrite_insns_.pop_back();
                                }
                            }
                        }
                    }
                }
            }
        }

        if (depth <= 2) {
            State *cur_state = states_[failed_testcase_no][depth];
            auto it = testcases_explored_states_.find(cur_state);
            if (it != testcases_explored_states_.end()) {
                if (it->second > depth) {
                    it->second = depth;
                }
            } else {
                State *new_state = new State(depth);
                new_state->copy_from_state(cur_state);
                new_state->set_testcase_no(failed_testcase_no);
                testcases_explored_states_.insert({new_state, depth});
            }
        }
        return false;
    }

    bool DfsSynthesizer::dfs_without_pruning3(int depth) {
        int failed_testcase_no = 0;
        bool success = true;
        // If for all testcases, current state reaches expected final state, current insns_ is the final solution.
        bool extend = true;
        for (int i = 0; i < states_.size(); i++) {
            if (!states_[i][depth]->check_equivalence(testcases_[i]->final_state(),
                                                      origin_->regs_live_out(),origin_->mem_live_out(),
                                                      origin_->init_static_info())) {
                failed_testcase_no = i;
                success = false;
            }
            // Prune: if left insn space is not enough to reach final state, return false directly.
            StateDistance dis = states_[i][depth]->compute_dis(testcases_[i]->final_state(), origin_->regs_live_out(),origin_->mem_live_out());
            int left_space = origin_->size() - depth;
            if (dis.total_dis() > left_space) {
                failed_testcase_no = i;
                extend = false;
                success = false;
                break;
            }
//            if (success) {
//                for (int j = 0; j < cur_rewrite_insns_.size(); j++) {
//                    if (Verifier::do_check(states_[i][j], cur_rewrite_insns_[j]) != 0) {
//                        success = false;
//                    }
//                }
//            }
        }

        if (success) {
            return true;
        }
        // reach rewrite insns' max length
        if (depth == cur_max_depth_) {
            extend = false;
        }

//        if (extend) {
//            // prune failed explored
//            for (int i = 0; i < states_.size(); i++) {
//                State *cur_state = states_[i][depth];
//                auto it = testcases_explored_states_.find(cur_state);
//                if (it != testcases_explored_states_.end()) {
//                    if (it->second <= depth) {
//                        extend = false;
//                    }
//                }
//            }
//        }

        if (extend) {
            for (auto opcode: sorted_optional_opcodes_) {
                if (depth == origin_->size() - 1 && opcode != 0 && BPF_CLASS(opcode) == BPF_LD)
                    continue;
                Insn insn;
                insn._opcode = opcode;
                vector<int> temp = insn.getRegUses();
                set<u8> use_regs(temp.begin(), temp.end());
                // dst_reg
                bool is_dst_used = (use_regs.find(-1) != use_regs.end());
                bool is_dst_defed = (insn.getRegDef() == -1);
                // assuming all testcases' valid regs are always the same
                set<u8> dst_regs = get_optional_dst_regs(opcode, states_[0][depth], is_dst_used, is_dst_defed);
                for (u8 dst_reg: dst_regs) {
                    insn._dst_reg = dst_reg;
                    bool is_src_used = (use_regs.find(-2) != use_regs.end());
                    set<u8> src_regs = get_optional_src_regs(opcode, states_[0][depth], is_src_used);
                    for (u8 src_reg: src_regs) {
                        // prune: avoid defining the same reg without using
                        bool catch_def = false;
                        if (is_dst_defed && !is_dst_used && (!is_src_used || src_reg != dst_reg)) {
                            for (int i = cur_rewrite_insns_.size() - 1; i >= 0; i--) {
                                vector<int> reg_used = cur_rewrite_insns_[i].getRegUses();
                                set<int> reg_used_set(reg_used.begin(), reg_used.end());
                                if (reg_used_set.count(dst_reg))
                                    break;
                                if (cur_rewrite_insns_[i].getRegDef() == dst_reg) {
                                    catch_def = true;
                                    break;
                                }
                            }
                        }
                        if (catch_def)
                            continue;
                        insn._src_reg = src_reg;
                        vector<State *> last_states;
                        for (int i = 0; i < states_.size(); i++) {
                            last_states.emplace_back(states_[i][depth]);
                        }
                        set<s16> offs = get_optional_offs(last_states, opcode, dst_reg, src_reg);
                        for (s16 off: offs) {
                            insn._off = off;
                            set<s32> imms = get_optional_imms(opcode);
                            for (s32 imm: imms) {
                                insn._imm = imm;
                                while (depth < cur_rewrite_insns_.size()) {
                                    cur_rewrite_insns_.pop_back();
                                }
                                if (BPF_CLASS(opcode) == BPF_LD) {
                                    set<s32> imm2s = get_optional_imms(0);
                                    for (s32 imm2: imm2s) {
                                        cur_rewrite_insns_.emplace_back(insn);
                                        cur_rewrite_insns_.emplace_back(
                                                Insn(0, 0, 0, 0, imm2)
                                        );
                                        for (int i = 0; i < states_.size(); i++) {
                                            insn_simulator_.run(opcode, dst_reg, src_reg, off, imm,
                                                                states_[i][depth], states_[i][depth + 1], imm2);
                                            states_[i][depth + 2]->copy_from_state(states_[i][depth + 1]);
                                        }
                                        if (dfs(depth + 2)) {
                                            return true;
                                        }
                                    }
                                } else {
                                    cur_rewrite_insns_.emplace_back(insn);
                                    for (int i = 0; i < states_.size(); i++) {
                                        insn_simulator_.run(opcode, dst_reg, src_reg, off, imm,
                                                            states_[i][depth], states_[i][depth + 1]);
                                        if(states_[i][depth]==states_[i][depth+1]){
                                            extend=false;
                                        }
                                    }
                                    if (extend&&dfs(depth + 1)) {
                                        return true;
                                    }
                                    cur_rewrite_insns_.pop_back();
                                }
                            }
                        }
                    }
                }
            }
        }

        return false;
    }

    bool DfsSynthesizer::dfs_without_pruning4(int depth) {
        int failed_testcase_no = 0;
        bool success = true;
        // If for all testcases, current state reaches expected final state, current insns_ is the final solution.
        bool extend = true;
        for (int i = 0; i < states_.size(); i++) {
            if (!states_[i][depth]->check_equivalence(testcases_[i]->final_state(),
                                                      origin_->regs_live_out(),origin_->mem_live_out(),
                                                      origin_->init_static_info())) {
                failed_testcase_no = i;
                success = false;
            }
            // Prune: if left insn space is not enough to reach final state, return false directly.
            StateDistance dis = states_[i][depth]->compute_dis(testcases_[i]->final_state(), origin_->regs_live_out(),origin_->mem_live_out());
            int left_space = origin_->size() - depth;
            if (dis.total_dis() > left_space) {
                failed_testcase_no = i;
                extend = false;
                success = false;
                break;
            }
//            if (success) {
//                for (int j = 0; j < cur_rewrite_insns_.size(); j++) {
//                    if (Verifier::do_check(states_[i][j], cur_rewrite_insns_[j]) != 0) {
//                        success = false;
//                    }
//                }
//            }
        }

        if (success) {
            return true;
        }
        // reach rewrite insns' max length
        if (depth == cur_max_depth_) {
            extend = false;
        }

        if (extend) {
            // prune failed explored
            for (int i = 0; i < states_.size(); i++) {
                State *cur_state = states_[i][depth];
                auto it = testcases_explored_states_.find(cur_state);
                if (it != testcases_explored_states_.end()) {
                    if (it->second <= depth) {
                        extend = false;
                        break;
                    }
                }
            }
        }

        if (extend) {
            for (auto opcode: sorted_optional_opcodes_) {
                if (depth == origin_->size() - 1 && opcode != 0 && BPF_CLASS(opcode) == BPF_LD)
                    continue;
                Insn insn;
                insn._opcode = opcode;
                vector<int> temp = insn.getRegUses();
                set<u8> use_regs(temp.begin(), temp.end());
                // dst_reg
                bool is_dst_used = (use_regs.find(-1) != use_regs.end());
                bool is_dst_defed = (insn.getRegDef() == -1);
                // assuming all testcases' valid regs are always the same
                set<u8> dst_regs = get_optional_dst_regs(opcode, states_[0][depth], is_dst_used, is_dst_defed);
                for (u8 dst_reg: dst_regs) {
                    insn._dst_reg = dst_reg;
                    bool is_src_used = (use_regs.find(-2) != use_regs.end());
                    set<u8> src_regs = get_optional_src_regs(opcode, states_[0][depth], is_src_used);
                    for (u8 src_reg: src_regs) {
                        // prune: avoid defining the same reg without using
//                        bool catch_def = false;
//                        if (is_dst_defed && !is_dst_used && (!is_src_used || src_reg != dst_reg)) {
//                            for (int i = cur_rewrite_insns_.size() - 1; i >= 0; i--) {
//                                vector<int> reg_used = cur_rewrite_insns_[i].getRegUses();
//                                set<int> reg_used_set(reg_used.begin(), reg_used.end());
//                                if (reg_used_set.count(dst_reg))
//                                    break;
//                                if (cur_rewrite_insns_[i].getRegDef() == dst_reg) {
//                                    catch_def = true;
//                                    break;
//                                }
//                            }
//                        }
//                        if (catch_def)
//                            continue;
                        insn._src_reg = src_reg;
                        vector<State *> last_states;
                        for (int i = 0; i < states_.size(); i++) {
                            last_states.emplace_back(states_[i][depth]);
                        }
                        set<s16> offs = {0x4,0x0,static_cast<short>(0xffe8)};//get_optional_offs(last_states, opcode, dst_reg, src_reg);
                        for (s16 off: offs) {
                            insn._off = off;
                            set<s32> imms = get_optional_imms(opcode);
                            for (s32 imm: imms) {
                                insn._imm = imm;
                                while (depth < cur_rewrite_insns_.size()) {
                                    cur_rewrite_insns_.pop_back();
                                }
                                if (BPF_CLASS(opcode) == BPF_LD) {
                                    set<s32> imm2s = get_optional_imms(0);
                                    for (s32 imm2: imm2s) {
                                        cur_rewrite_insns_.emplace_back(insn);
                                        cur_rewrite_insns_.emplace_back(
                                                Insn(0, 0, 0, 0, imm2)
                                        );
                                        for (int i = 0; i < states_.size(); i++) {
                                            insn_simulator_.run(opcode, dst_reg, src_reg, off, imm,
                                                                states_[i][depth], states_[i][depth + 1], imm2);
                                            states_[i][depth + 2]->copy_from_state(states_[i][depth + 1]);
                                        }
                                        if (dfs(depth + 2)) {
                                            return true;
                                        }
                                    }
                                } else {
                                    cur_rewrite_insns_.emplace_back(insn);
                                    for (int i = 0; i < states_.size(); i++) {
                                        insn_simulator_.run(opcode, dst_reg, src_reg, off, imm,
                                                            states_[i][depth], states_[i][depth + 1]);
                                        if(states_[i][depth]==states_[i][depth+1]){
                                            extend=false;
                                        }
                                    }
                                    if (extend&&dfs(depth + 1)) {
                                        return true;
                                    }
                                    cur_rewrite_insns_.pop_back();
                                }
                            }
                        }
                    }
                }
            }
        }

        if (depth <= 2) {
            State *cur_state = states_[failed_testcase_no][depth];
            auto it = testcases_explored_states_.find(cur_state);
            if (it != testcases_explored_states_.end()) {
                if (it->second > depth) {
                    it->second = depth;
                }
            } else {
                State *new_state = new State(depth);
                new_state->copy_from_state(cur_state);
                new_state->set_testcase_no(failed_testcase_no);
                testcases_explored_states_.insert({new_state, depth});
            }
        }
        return false;
    }

    bool DfsSynthesizer::dfs_no_pruning(int depth) {
        int failed_testcase_no = 0;
        bool success = true;
        // If for all testcases, current state reaches expected final state, current insns_ is the final solution.
        bool extend = true;
        for (int i = 0; i < states_.size(); i++) {
            if (!states_[i][depth]->check_equivalence(testcases_[i]->final_state(),
                                                      origin_->regs_live_out(),origin_->mem_live_out(),
                                                      origin_->init_static_info())) {
                failed_testcase_no = i;
                success = false;
            }
            // Prune: if left insn space is not enough to reach final state, return false directly.
            StateDistance dis = states_[i][depth]->compute_dis(testcases_[i]->final_state(), origin_->regs_live_out(),origin_->mem_live_out());
            int left_space = origin_->size() - depth;
            if (dis.total_dis() > left_space) {
                failed_testcase_no = i;
                extend = false;
                success = false;
                break;
            }
//            if (success) {
//                for (int j = 0; j < cur_rewrite_insns_.size(); j++) {
//                    if (Verifier::do_check(states_[i][j], cur_rewrite_insns_[j]) != 0) {
//                        success = false;
//                    }
//                }
//            }
        }

        if (success) {
            return true;
        }
        // reach rewrite insns' max length
        if (depth == cur_max_depth_) {
            extend = false;
        }

        if (extend) {
            // prune failed explored
            for (int i = 0; i < states_.size(); i++) {
                State *cur_state = states_[i][depth];
                auto it = testcases_explored_states_.find(cur_state);
                if (it != testcases_explored_states_.end()) {
                    if (it->second <= depth) {
                        extend = false;
                        break;
                    }
                }
            }
        }

        if (extend) {
            for (auto opcode: sorted_optional_opcodes_) {
                if (depth == origin_->size() - 1 && opcode != 0 && BPF_CLASS(opcode) == BPF_LD)
                    continue;
                Insn insn;
                insn._opcode = opcode;
                vector<int> temp = insn.getRegUses();
                set<u8> use_regs(temp.begin(), temp.end());
                // dst_reg
                bool is_dst_used = (use_regs.find(-1) != use_regs.end());
                bool is_dst_defed = (insn.getRegDef() == -1);
                // assuming all testcases' valid regs are always the same
                set<u8> dst_regs = get_optional_dst_regs(opcode, states_[0][depth], is_dst_used, is_dst_defed);
                for (u8 dst_reg: dst_regs) {
                    insn._dst_reg = dst_reg;
                    bool is_src_used = (use_regs.find(-2) != use_regs.end());
                    set<u8> src_regs = get_optional_src_regs(opcode, states_[0][depth], is_src_used);
                    for (u8 src_reg: src_regs) {
                        // prune: avoid defining the same reg without using
                        bool catch_def = false;
                        if (is_dst_defed && !is_dst_used && (!is_src_used || src_reg != dst_reg)) {
                            for (int i = cur_rewrite_insns_.size() - 1; i >= 0; i--) {
                                vector<int> reg_used = cur_rewrite_insns_[i].getRegUses();
                                set<int> reg_used_set(reg_used.begin(), reg_used.end());
                                if (reg_used_set.count(dst_reg))
                                    break;
                                if (cur_rewrite_insns_[i].getRegDef() == dst_reg) {
                                    catch_def = true;
                                    break;
                                }
                            }
                        }
                        if (catch_def)
                            continue;
                        insn._src_reg = src_reg;
                        vector<State *> last_states;
                        for (int i = 0; i < states_.size(); i++) {
                            last_states.emplace_back(states_[i][depth]);
                        }
                        set<s16> offs = get_optional_offs(last_states, opcode, dst_reg, src_reg);
                        for (s16 off: offs) {
                            insn._off = off;
                            set<s32> imms = get_optional_imms(opcode);
                            for (s32 imm: imms) {
                                insn._imm = imm;
                                while (depth < cur_rewrite_insns_.size()) {
                                    cur_rewrite_insns_.pop_back();
                                }
                                if (BPF_CLASS(opcode) == BPF_LD) {
                                    set<s32> imm2s = get_optional_imms(0);
                                    for (s32 imm2: imm2s) {
                                        cur_rewrite_insns_.emplace_back(insn);
                                        cur_rewrite_insns_.emplace_back(
                                                Insn(0, 0, 0, 0, imm2)
                                        );
                                        for (int i = 0; i < states_.size(); i++) {
                                            insn_simulator_.run(opcode, dst_reg, src_reg, off, imm,
                                                                states_[i][depth], states_[i][depth + 1], imm2);
                                            states_[i][depth + 2]->copy_from_state(states_[i][depth + 1]);
                                        }
                                        if (dfs(depth + 2)) {
                                            return true;
                                        }
                                    }
                                } else {
                                    cur_rewrite_insns_.emplace_back(insn);
                                    for (int i = 0; i < states_.size(); i++) {
                                        insn_simulator_.run(opcode, dst_reg, src_reg, off, imm,
                                                            states_[i][depth], states_[i][depth + 1]);
                                        if(states_[i][depth]==states_[i][depth+1]){
                                            extend=false;
                                        }
                                    }
                                    if (extend&&dfs(depth + 1)) {
                                        return true;
                                    }
                                    cur_rewrite_insns_.pop_back();
                                }
                            }
                        }
                    }
                }
            }
        }
        if (depth <= 2) {
            State *cur_state = states_[failed_testcase_no][depth];
            auto it = testcases_explored_states_.find(cur_state);
            if (it != testcases_explored_states_.end()) {
                if (it->second > depth) {
                    it->second = depth;
                }
            } else {
                State *new_state = new State(depth);
                new_state->copy_from_state(cur_state);
                new_state->set_testcase_no(failed_testcase_no);
                testcases_explored_states_.insert({new_state, depth});
            }
        }
        return false;
    }

    void DfsSynthesizer::add_testcase(Testcase *testcase) {
        testcases_.emplace_back(new Testcase(testcase));
        // init 'states_[...][0]'
        vector<State *> new_states;
        for (int i = 0; i <= origin_->size(); i++) {
            new_states.emplace_back(new State(i));
        }
        new_states[0]->copy_from_state(testcase->init_state());
        states_.emplace_back(new_states);
    }

    Node *DfsSynthesizer::synthesize() {
        time_t begin, end;
        begin_time_=begin = clock();
        Node *rewrite = nullptr;
//        origin_->print_insns();
//        origin_->print_static_info();
//        cout << "cur testcases:" << endl;
//        for (Testcase *testcase: testcases_)
//            testcase->print_testcase();
        for (int i = 0; i <= origin_->size(); i++) {
            end=clock();
            // set time-out as 2 min
            if(double(end-begin)/CLOCKS_PER_SEC>30){
                last_synthesis_time_=double(end-begin)/CLOCKS_PER_SEC;
                return new Node(*origin_);
            }
            cur_max_depth_ = i;
            cout<<cur_max_depth_<<endl;
            for (auto it: testcases_explored_states_)
                delete it.first;
            testcases_explored_states_.clear();
            bool (DfsSynthesizer::*dfs_func_ptr)(int depth);
            switch(pruning_type){
                case ALL:
                    dfs_func_ptr=&DfsSynthesizer::dfs;break;
                case OFF2:
                    dfs_func_ptr=&DfsSynthesizer::dfs_without_pruning2;break;
                case OFF3:
                    dfs_func_ptr=&DfsSynthesizer::dfs_without_pruning3;break;
                case OFF4:
                    dfs_func_ptr=&DfsSynthesizer::dfs_without_pruning4;break;
                case NONE:
                    dfs_func_ptr=&DfsSynthesizer::dfs_no_pruning;break;
            }
            if ((this->*dfs_func_ptr)(0)) {
                rewrite = new Node(origin_->idx(), cur_rewrite_insns_);
//                cout<<"rewrite"<<endl;
//                rewrite->print_insns();
                rewrite->add_regs_live_out(origin_->regs_live_out());
                rewrite->set_split_insns(origin_->get_split_insns());
                break;
            }
        }

        end = clock();
        last_synthesis_time_ = double(end - begin) / CLOCKS_PER_SEC;
        if(rewrite== nullptr)
            rewrite=new Node(*origin_);
        return rewrite;
    }

    void DfsSynthesizer::clear() {
        for (Testcase *testcase: testcases_)
            delete testcase;
        testcases_.clear();
        for (int i = 0; i < states_.size(); i++)
            for (int j = 0; j < states_[0].size(); j++)
                delete states_[i][j];
        states_.clear();
        cur_rewrite_insns_.clear();
        for (auto it: testcases_explored_states_)
            delete it.first;
        testcases_explored_states_.clear();
    }

    void DfsSynthesizer::set_prog(Node *origin) {
        clear();
        origin_ = origin;
        origin_score_ = score_insns(origin_->insns());
        set_opt_sorted_opcodes_imms();
        set_ld_bytes();
    }

    void DfsSynthesizer::set_prog_with_random_testcase(Node *origin) {
        clear();
        origin_ = origin;
        origin_score_ = score_insns(origin_->insns());
        set_opt_sorted_opcodes_imms();
        set_ld_bytes();
        testcase_gen->set_prog(origin_->insns());
        add_testcase(testcase_gen->gen_random_testcase());
    }

    void DfsSynthesizer::set_prog_with_inited_testcases(Node *origin, vector<State *> init_states) {
        clear();
        origin_ = origin;
        origin_score_ = score_insns(origin_->insns());
        set_opt_sorted_opcodes_imms();
        set_ld_bytes();
        testcase_gen->set_prog(origin_->insns());
//        origin->print_insns();
//        for(auto state:init_states)
//            state->print_state();
        for (State *init_state: init_states) {
            add_testcase(testcase_gen->gen_testcase_with_redundant_init_state(init_state));
        }
    }

    void BfsSynthesizer::add_testcase(Testcase *testcase) {
        testcases_.emplace_back(testcase);
    }

    Node *BfsSynthesizer::synthesize() {
        time_t begin, end;
        begin = clock();

        queue<BfsNode *> q;
        // construct init node with init state, push into queue
        vector<State *> init_states;
        for (Testcase *testcase: testcases_) {
            init_states.emplace_back(testcase->init_state());
        }
        BfsNode *init_node = new BfsNode(init_states, ld_bytes_);
        q.push(init_node);
        BfsNode *cur_node = nullptr;
        int last_insn_num = 0;
        while (!q.empty()) {
//        cout << q.size() << endl;
            cur_node = q.front();
            q.pop();
            vector<Insn> cur_insns = cur_node->get_insns();
//        for (Insn insn: cur_insns) {
//            insn.print_insn();
//        }
//        cout << endl;
            if (cur_insns.size() != last_insn_num) {
                last_insn_num = cur_insns.size();
                cout << last_insn_num << endl;
            }
            vector<State *> cur_states = cur_node->get_states();
            // If current node reaches expected final states, optimal solution is found.
            bool reach_final = true;
            for (int i = 0; i < cur_states.size(); i++) {
                if (!cur_states[i]->check_equivalence(testcases_[i]->final_state(),
                                                      origin_->regs_live_out(),origin_->mem_live_out(),
                                                      origin_->init_static_info())) {
                    reach_final = false;
                    break;
                }
            }
            if (reach_final) {
                break;
            }
            // If left insn space is not enough to reach final state, prune.
            bool worth_continue = true;
            for (int i = 0; i < cur_states.size(); i++) {
                StateDistance dis = cur_states[i]->compute_dis(testcases_[i]->final_state(), origin_->regs_live_out(),origin_->mem_live_out());
                int left_space = origin_->size() - cur_node->get_insns().size();
                if ((dis.diff_reg_num + dis.least_st_insns) > left_space) {
                    worth_continue = false;
                    break;
                }
            }
            // If current candidate insns score lower than origin, prune.
            if (score_insns(origin_->insns()) < score_insns(cur_insns) - 1e-6) {
                worth_continue = false;
            }
            if (worth_continue) {
                int cur_size = cur_node->get_insns().size();
                for (auto opcode: sorted_optional_opcodes_) {
                    Insn insn;
                    insn._opcode = opcode;
                    vector<int> temp = insn.getRegUses();
                    set<u8> use_regs(temp.begin(), temp.end());
                    // dst_reg
                    bool is_dst_used = (use_regs.find(-1) != use_regs.end());
                    bool is_dst_defed = (insn.getRegDef() == -1);
                    // assuming all testcases' valid regs are always the same
                    set<u8> dst_regs = {1,8,10};//get_optional_dst_regs(opcode, cur_states[0], is_dst_used, is_dst_defed);
                    for (u8 dst_reg: dst_regs) {
                        // prune: avoid defining the same reg without using
                        bool catch_def = false;
                        if (is_dst_defed && !is_dst_used) {
                            for (int i = cur_size - 1; i >= 0; i--) {
                                vector<int> reg_used = cur_insns[i].getRegUses();
                                set<int> reg_used_set(reg_used.begin(), reg_used.end());
                                if (reg_used_set.count(dst_reg))
                                    break;
                                if (cur_insns[i].getRegDef() == dst_reg) {
                                    catch_def = true;
                                    break;
                                }
                            }
                        }
                        if (catch_def)
                            continue;
                        insn._dst_reg = dst_reg;
                        bool is_src_used = (use_regs.find(-2) != use_regs.end());
                        set<u8> src_regs = {1,7};//get_optional_src_regs(opcode, cur_states[0], is_src_used);
                        for (u8 src_reg: src_regs) {
                            insn._src_reg = src_reg;
                            set<s16> offs = get_optional_offs(cur_states, opcode, dst_reg, src_reg);
                            for (s16 off: offs) {
                                insn._off = off;
                                set<s32> imms = get_optional_imms(opcode);
                                for (s32 imm: imms) {
                                    insn._imm = imm;
                                    vector<Insn> new_insns(cur_insns);
                                    new_insns.emplace_back(insn);
                                    vector<State *> new_last_states;
                                    set<u64> new_ld_addrs = cur_node->ld_addrs();
                                    bool add_to_queue = true;
//                                // prune useless load operations
//                                short left_ld_bytes = cur_node->left_ld_bytes();
//                                if (insn.getType() == OP_LD) {
//                                    left_ld_bytes -= opcode2byte_num.at(opcode);
//                                }
//                                if (left_ld_bytes < 0)
//                                    add_to_queue = false;
                                    // compute new states
                                    if (add_to_queue) {
                                        for (int i = 0; i < cur_states.size(); i++) {
                                            State *new_last_state = new State(cur_size + 1);
                                            insn_simulator_.run(opcode, dst_reg, src_reg, off, imm,
                                                                cur_states[i], new_last_state);
                                            new_last_states.emplace_back(new_last_state);
                                            // prune useless store operations
                                            if (insn.getType() == OP_ST) {
                                                int cur_mem_similar = new_last_state->compute_mem_similarity(
                                                        testcases_[i]->final_state(),origin_->mem_live_out());
                                                int last_mem_similar = cur_states[i]->compute_mem_similarity(
                                                        testcases_[i]->final_state(),origin_->mem_live_out());
                                                if (cur_mem_similar <= last_mem_similar) {
                                                    add_to_queue = false;
                                                    break;
                                                }
                                            }
                                            // prune: load the same addr at most once
                                            if (i == 0 && insn.getType() == OP_LD) {
                                                set<u64> &insn_ld_addrs = insn_simulator_.last_ld_addrs();
                                                for (u64 addr: insn_ld_addrs) {
                                                    if (new_ld_addrs.count(addr)) {
                                                        add_to_queue = false;
                                                        break;
                                                    }
                                                }
                                                if (add_to_queue) {
                                                    new_ld_addrs.insert(insn_ld_addrs.begin(), insn_ld_addrs.end());
                                                }
                                            }
                                        }
                                    }
                                    if (add_to_queue) {
                                        BfsNode *new_node = new BfsNode(new_insns, new_last_states, new_ld_addrs);
                                        q.push(new_node);
                                    } else {
                                        for (State *state: new_last_states)
                                            delete state;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            delete cur_node;
            cur_node = nullptr;
        }
        Node *rewrite = nullptr;
        if (cur_node != nullptr) {  // find solution
            rewrite = new Node(origin_->idx(), cur_node->get_insns());
            rewrite->add_regs_live_out(origin_->regs_live_out());
            rewrite->set_split_insns(origin_->get_split_insns());
            delete cur_node;
        }

        end = clock();
        last_synthesis_time_ = double(end - begin) / CLOCKS_PER_SEC;
        return rewrite;
    }
}
