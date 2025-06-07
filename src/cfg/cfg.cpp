#include "cfg.h"

#include <iomanip>
#include <set>

#include "ebpf/ctx.h"
#include "instruction/insn_simulator.h"

using namespace std;
using namespace superbpf;

namespace superbpf {



    int Node::idx() {
        return idx_;
    }

    int Node::size() {
        return insns_.size();
    }

    std::vector<Insn> &Node::insns() {
        return insns_;
    }

    int Node::getHeadIdx() {
        return idx_;
    }

    int Node::getTailIdx() {
        return idx_ + insns_.size();
    }

    StaticInfo Node::init_static_info() {
        return static_info_[0];
    }

    StaticInfo Node::final_static_info() {
        return static_info_[static_info_.size() - 1];
    }

    std::set<int> Node::regs_live_in() const{
        return regs_live_in_;
    }

    std::set<int> Node::regs_live_out() const{
        return regs_live_out_;
    }

    std::map<u8, std::set<int>> Node::mem_live_in() {
        return mem_live_in_;
    }

    std::map<u8, std::set<int>> Node::mem_live_out() {
        return mem_live_out_;
    }

    StaticInfo Node::branch_final_static_info() {
        return branch_final_static_info_;
    }

    std::set<int> Node::used_imms() {
        return used_imms_;
    }

    std::vector<Insn> &Node::get_split_insns() {
        return split_insns_;
    }

    set<int> Node::get_used_regs() const{
        // Regs used but already defined in this block do not count.
        set<int> res;
        for (int i = 0; i < insns_.size(); i++) {
            vector<int> used_regs = insns_[i].getRegUses();
            for (auto it = used_regs.begin(); it != used_regs.end();) {
                int j;
                for (j = i - 1; j >= 0; j--) {
                    if (insns_[j].getRegDef() == *it) {
                        it = used_regs.erase(it);
                        break;
                    }
                }
                if (j == -1)
                    it++;
            }
            res.insert(used_regs.begin(), used_regs.end());
        }
        return res;
    }

    set<int> Node::get_defined_regs() const{
        set<int> res;
        for (auto insn: insns_) {
            int def_reg = insn.getRegDef();
            if (def_reg != -1)
                res.insert(def_reg);
        }
        return res;
    }

    std::map<u8, std::set<int>> Node::get_used_mems() {
        return ld_mem_addrs_;
    }

    std::map<u8, std::set<int>> Node::get_used_mems(int insn_i) {
        map<u8, set<int>> res;
        auto insn = insns_[insn_i];
        if (BPF_CLASS(insn._opcode) == BPF_LDX) {
            auto type = static_info_[insn_i].get_regi_type(insn._src_reg);
            auto type_off = static_info_[insn_i].get_regi_off(insn._src_reg);
            int bytes_num = bpf_size_to_bytes(BPF_SIZE(insn._opcode));
            for (int i = 0; i < bytes_num; i++) {
                res[type].insert(type_off + insn._off + i);
            }
        }
        return res;
    }

    std::map<u8, std::set<int>> Node::get_defined_mems() {
        return st_mem_addrs_;
    }

    std::map<u8, std::set<int>> Node::get_defined_mems(int insn_i) {
        map<u8, set<int>> res;
        auto insn = insns_[insn_i];
        if (BPF_CLASS(insn._opcode) == BPF_STX || BPF_CLASS(insn._opcode) == BPF_ST) {
            auto type = static_info_[insn_i].get_regi_type(insn._dst_reg);
            auto type_off = static_info_[insn_i].get_regi_off(insn._dst_reg);
            int bytes_num = bpf_size_to_bytes(BPF_SIZE(insn._opcode));
            for (int i = 0; i < bytes_num; i++) {
                res[type].insert(type_off + insn._off + i);
            }
        }
        return res;
    }

    vector<Insn> Node::get_complete_insns(int empty_num) {
        vector<Insn> res(insns_);
        for (int i = 0; i < empty_num; i++) {
            res.emplace_back(
                    Insn(0x05, 0, 0, 0, 0)
            );
        }
        for (int i = split_insns_.size() - 1; i >= 0; i--) {
            res.emplace_back(split_insns_[i]);
        }
        return res;
    }

    double Node::get_score() {
        double res = 0;
        double default_insn_runtime = 1;
        for (Insn insn: insns_) {
//            insn.print_insn();
//            cout<<insn.get_runtime()<<endl;
            res -= insn.get_runtime();
        }
        return res;
    }

    int Node::get_insns_num() {
        int res = 0;
        for (Insn insn: insns_) {
            if(insn._opcode!=0)
                res++;
        }
        return res;
    }

    /* Get node composed by insns between insns_[start, end). */
    Node *Node::get_sub_node(int start, int end) {
        assert(start >= 0 && end <= insns_.size());
        vector<Insn> sub_insns(insns_.begin() + start, insns_.begin() + end);
        Node *sub_node = new Node(idx_ + start, sub_insns);
        sub_node->set_prog_attach_type(prog_type_, attach_type_);
        // set static info
        sub_node->set_init_static_info(static_info_[start]);
        sub_node->compute_final_static_info();
        // set liveliness
        set<int> regs_live_out = regs_live_out_;
        for (int i = insns_.size() - 1; i >= end; i--) {
            // edit live out regs
            int def_reg = insns_[i].getRegDef();
            if (regs_live_out.count(def_reg))
                regs_live_out.erase(def_reg);
            vector<int> regs = insns_[i].getRegUses();
            regs_live_out.insert(regs.begin(), regs.end());
        }
        sub_node->add_regs_live_out(regs_live_out);
        map<u8, set<int>> mem_live_out = mem_live_out_;
        for (int i = insns_.size() - 1; i >= end; i--) {
            // edit live out regs
            auto def_mems = get_defined_mems(i);
            for (auto [type, addrs]: def_mems) {
                if (mem_live_out.count(type)) {
                    for (auto addr: addrs) {
                        if (mem_live_out.at(type).count(addr))
                            mem_live_out.at(type).erase(addr);
                    }
                }
            }
            auto use_mems = get_used_mems(i);
            for (auto [type, addrs]: def_mems) {
                mem_live_out[type].insert(addrs.begin(), addrs.end());
            }
        }
        sub_node->add_mem_live_out(mem_live_out);
        return sub_node;
    }

    /* Get node composed by selected insns. */
    Node Node::get_sub_node_by_selected_insns(vector<int> insn_idxes) {
        vector<Insn> sub_insns;
        for(auto i:insn_idxes){
            sub_insns.emplace_back(insns_[i]);
        }
        Node sub_node(idx_+insn_idxes[0], sub_insns);
        sub_node.set_prog_attach_type(prog_type_, attach_type_);
        // set static info
        sub_node.set_init_static_info(static_info_[insn_idxes[0]]);
        sub_node.compute_final_static_info();
        // set liveliness
        set<int> regs_live_out = regs_live_out_;
        for (int i = insns_.size() - 1; i > insn_idxes.back(); i--) {
            // edit live out regs
            int def_reg = insns_[i].getRegDef();
            if (regs_live_out.count(def_reg))
                regs_live_out.erase(def_reg);
        }
        sub_node.add_regs_live_out(regs_live_out);
        map<u8, set<int>> mem_live_out = mem_live_out_;
        for (int i = insns_.size() - 1; i >insn_idxes.back(); i--) {
            // edit live out regs
            auto def_mems = get_defined_mems(i);
            for (auto [type, addrs]: def_mems) {
                if (mem_live_out.count(type)) {
                    for (auto addr: addrs) {
                        if (mem_live_out.at(type).count(addr))
                            mem_live_out.at(type).erase(addr);
                    }
                }
            }
        }
        sub_node.add_mem_live_out(mem_live_out);
        return sub_node;
    }

    void Node::split_insns() {
        set<int> regs_live_out;
        int end = insns_.size() - 1;
        while (end >= 0 && insns_[end].isSplit()) {
            // edit live out regs
            int def_reg = insns_[end].getRegDef();
            if (regs_live_out_.count(def_reg))
                regs_live_out_.erase(def_reg);
            vector<int> regs = insns_[end].getRegUses();
            regs_live_out.insert(regs.begin(), regs.end());
            // add jmp insns
            split_insns_.emplace_back(insns_[end]);
            insns_.pop_back();
            end--;
        }
        add_regs_live_out(regs_live_out);
    }

    void Node::set_prog_attach_type(bpf_prog_type prog_type, bpf_attach_type attach_type) {
        prog_type_ = prog_type;
        attach_type_ = attach_type;
    }

    void Node::set_regs_live_in(std::set<int> regs) {
        regs_live_in_ = regs;
    }


    void Node::add_regs_live_out(std::set<int> regs) {
        regs_live_out_.insert(regs.begin(), regs.end());
    }

    void Node::set_mem_live_in(map<u8, set<int>> mems) {
        mem_live_in_ = mems;
    }

    void Node::add_mem_live_out(std::map<u8, std::set<int>> mems) {
        for (auto [mem_type, mem_areas]: mems) {
            if (mem_live_out_.find(mem_type) != mem_live_out_.end()) {
                mem_live_out_.at(mem_type).insert(mem_areas.begin(), mem_areas.end());
            } else {
                mem_live_out_.insert({mem_type, mem_areas});
            }
        }
    }

    void Node::set_init_static_info(const StaticInfo &init_info) {
        static_info_[0].copy(init_info);
    }

    void Node::set_final_static_info(const StaticInfo &init_info) {
        static_info_[static_info_.size() - 1].copy(init_info);
    }

    void Node::edit_insns(int start,int end,const vector<Insn>& rewrite_insns){
        assert(start+rewrite_insns.size()<=insns_.size());
        for(int i=0;i<rewrite_insns.size();i++){
            insns_[start+i]=rewrite_insns[i];
        }
        auto it=insns_.begin()+start+(int)rewrite_insns.size();
        for(int i=start+(int)rewrite_insns.size();i<end;i++){
            it=insns_.erase(it);
        }
        while(static_info_.size()>insns_.size()+1)
            static_info_.pop_back();
    }

    void Node::edit_insns(vector<int> insns_idxes,const vector<Insn>& rewrite_insns){
        assert(rewrite_insns.size()<=insns_idxes.size());
        for(int i=0;i<rewrite_insns.size();i++){
            insns_[insns_idxes[i]]=rewrite_insns[i];
        }
        for(int i=rewrite_insns.size();i<insns_idxes.size();i++){
            insns_[insns_idxes[i]]._opcode=0;
        }
    }

    void Node::clear_invalid_insns(){
        vector<Insn> new_insns;
        for(auto insn:insns_){
            if(insn._opcode)
                new_insns.emplace_back(insn);
        }
        insns_=new_insns;
        while(static_info_.size()>insns_.size()+1)
            static_info_.pop_back();
        compute_final_static_info();
    }

    void Node::clear_goto0_insns(){
        vector<Insn> new_insns;
        for(auto insn:insns_){
            if(!insn.isGoto0())
                new_insns.emplace_back(insn);
        }
        insns_=new_insns;
        while(static_info_.size()>insns_.size()+1)
            static_info_.pop_back();
        compute_final_static_info();
    }

    void Node::set_split_insns(std::vector<Insn> insns) {
        split_insns_ = insns;
    }

    void Node::compute_final_static_info() {
        while(static_info_.size()>insns_.size()+1)
            static_info_.pop_back();
        map<u8, set<u8>> same_regs;
        for (int i = 0; i < insns_.size(); i++) {
            auto insn = insns_[i];
            static_info_[i + 1].copy(static_info_[i]);
            u8 code = insn._opcode, dst_reg = insn._dst_reg, src_reg = insn._src_reg;
            if(code==0)
                continue;
            u8 insn_class = BPF_CLASS(code), insn_op = BPF_OP(code), insn_src = BPF_SRC(code), insn_mode = BPF_MODE(
                    code);
            s16 off = insn._off;
            s32 imm = insn._imm;
            int bytes_num = bpf_size_to_bytes(BPF_SIZE(code));
            // clear same regs of 'dst_reg'
            if (insn_class != BPF_STX && insn_class != BPF_ST && insn_class != BPF_JMP && insn_class != BPF_JMP32) {
                if (same_regs.find(dst_reg) != same_regs.end()) {
                    for (auto cur_reg: same_regs.at(dst_reg)) {
                        if (same_regs.find(cur_reg) != same_regs.end()) {
                            auto cur_regs_set = same_regs.at(cur_reg);
                            if (cur_regs_set.find(dst_reg) != cur_regs_set.end())
                                same_regs.at(cur_reg).erase(dst_reg);
                        }
                    }
                    same_regs.at(dst_reg).clear();
                }
            }
            if (insn_class == BPF_ALU || insn_class == BPF_ALU64) {
                if (code == MOV64XY) {
                    static_info_[i + 1].set_regi_info(dst_reg, static_info_[i].get_regi_info(src_reg));
                    if (same_regs.find(dst_reg) == same_regs.end())
                        same_regs.insert({dst_reg, {}});
                    if (same_regs.find(src_reg) == same_regs.end())
                        same_regs.insert({src_reg, {}});
                    same_regs[dst_reg].insert(src_reg);
                    same_regs[src_reg].insert(dst_reg);
                } else if (code == MOV64XC || code == MOV32XC) {
                    if (insn._is_reloc == 0 && insn._is_core_reloc == 0)
                        static_info_[i + 1].set_regi_info(dst_reg, RegInfo(imm, SCALAR_VALUE));
                    else {
                        static_info_[i + 1].set_regi_type(dst_reg, SCALAR_VALUE);
                        static_info_[i + 1].set_regi_value_invalid(dst_reg);
                    }
                } else if (insn_src == BPF_X && insn_op != BPF_END && insn_op != BPF_NEG) {
//                    if (static_info_[i].get_regi_type(dst_reg) != SCALAR_VALUE &&
//                        static_info_[i].get_regi_type(src_reg) != SCALAR_VALUE)
//                        final_static_info_.set_regi_info(dst_reg, SCALAR_VALUE);
                    static_info_[i + 1].set_regi_value_invalid(dst_reg);
//                    final_static_info_.set_regi_info(dst_reg, static_info_[i].get_regi_type(dst_reg));
                } else if (insn_src == BPF_K) {
                    static_info_[i + 1].set_regi_type(dst_reg, static_info_[i].get_regi_type(dst_reg));
                    static_info_[i + 1].set_regi_map_id(dst_reg, static_info_[i].get_regi_mapid(dst_reg));
                    // TODO: overflow?
                    if(static_info_[i].is_value_valid(dst_reg)){
                        int64_t new_smin_val = InsnSimulator::compute_val(insn_op,
                                                                          static_info_[i].get_regi_smin_val(dst_reg), imm);
                        int64_t new_smax_val = InsnSimulator::compute_val(insn_op,
                                                                          static_info_[i].get_regi_smax_val(dst_reg), imm);
                        if(new_smax_val<new_smin_val){
                            swap(new_smin_val,new_smax_val);
                        }
                        static_info_[i + 1].set_regi_min_max_val(dst_reg, new_smin_val, new_smax_val);
                    }
                    if (static_info_[i].get_regi_type(dst_reg) != SCALAR_VALUE) {  // a pointer
                        int new_off = (int)InsnSimulator::compute_val(insn_op, static_info_[i].get_regi_off(dst_reg), imm);
                        static_info_[i + 1].set_regi_off(dst_reg, new_off);
                    }
                }
            } else if (insn_class == BPF_LDX) {
                s64 max_val = ((unsigned) 0xffffffffffffffff) >> (8 * (8 - bytes_num));
                static_info_[i + 1].set_regi_min_max_val(dst_reg, 0, max_val);
                RegType src_reg_type = static_info_[i].get_regi_type(src_reg);
                int reg_off = static_info_[i].get_regi_off(src_reg);
                if (src_reg_type == PTR_TO_CTX) {
                    RegType reg_type = SCALAR_VALUE;
                    bool is_valid_access = is_ctx_valid_access(prog_type_, attach_type_, off, bytes_num, BPF_READ,
                                                               reg_type);
                    assert(is_valid_access);
                    static_info_[i + 1].set_regi_type(dst_reg, reg_type);
                    static_info_[i + 1].set_regi_off(dst_reg, 0);
                } else if (src_reg_type == PTR_TO_STACK)
                    static_info_[i + 1].set_regi_type(dst_reg, STACK_VALUE);
                else
                    static_info_[i + 1].set_regi_type(dst_reg, SCALAR_VALUE);
                if (ld_mem_addrs_.find(src_reg_type) == ld_mem_addrs_.end())
                    ld_mem_addrs_.insert({src_reg_type, set<int>()});
                for (int addr_i = reg_off + off; addr_i != reg_off + off + bytes_num; addr_i++) {
                    ld_mem_addrs_.at(src_reg_type).insert(addr_i);
                }
            } else if (insn_class == BPF_LD && code != 0) {
                if (insn_mode == BPF_IMM) {
//                    if (src_reg == 0) {
//                        final_static_info_.set_regi_info(dst_reg, RegInfo(SCALAR_VALUE));
//                    } else if (src_reg == BPF_PSEUDO_BTF_ID) { ;  // TODO
//                    } else if (src_reg == BPF_PSEUDO_MAP_VALUE) {
//                        final_static_info_.set_regi_info(dst_reg, RegInfo(PTR_TO_MAP_VALUE));
//                    } else if (src_reg == BPF_PSEUDO_MAP_FD) {
//                        final_static_info_.set_regi_info(dst_reg, RegInfo(CONST_PTR_TO_MAP));
//                    }
                    static_info_[i + 1].set_regi_info(dst_reg,
                                                      RegInfo(LD_IMM_VALUE));  // TODO: found that all src_reg of 'ld_imm' insns are 0, why?
                } else if (insn_mode == BPF_IND || insn_mode == BPF_ABS) {
                    static_info_[i + 1].set_regi_info(dst_reg, RegInfo(SCALAR_VALUE));
                }
                if (bytes_num != 8) {
                    s64 max_val = ((unsigned) 0xffffffffffffffff) >> (8 * (8 - bytes_num));
                    static_info_[i + 1].set_regi_min_max_val(dst_reg, 0, max_val);
                }
            } else if (insn_class == BPF_STX || insn_class == BPF_ST) {
                auto dst_reg_type = static_info_[i].get_regi_type(dst_reg);
                auto reg_off = static_info_[i].get_regi_off(dst_reg);
                if (st_mem_addrs_.find(dst_reg_type) == st_mem_addrs_.end())
                    st_mem_addrs_.insert({dst_reg_type, set<int>()});
                for (int addr_i = reg_off + off; addr_i != reg_off + off + bytes_num; addr_i++) {
                    st_mem_addrs_.at(dst_reg_type).insert(addr_i);
                }
            } else if (insn_class == BPF_JMP || insn_class == BPF_JMP32) {
                if (code == CALL) {  // refers to 'check_helper_call' in verifier.c
                    // TODO: not all calls call to helper functions?
                    for (int j = 1; j < 5; j++) {
                        static_info_[i + 1].set_regi_info(i, RegInfo(NOT_INIT));
                    }
                    if (helper_funcs_ret_type.find(insn._imm) != helper_funcs_ret_type.end()) {
                        auto type=helper_funcs_ret_type.at(insn._imm);
                        static_info_[i + 1].set_regi_info(0, RegInfo(type));
                        if(type==PTR_TO_MAP_VALUE||type==PTR_TO_MAP_VALUE_OR_NULL)
                            static_info_[i + 1].set_regi_map_id(0, idx_);
                    } else
                        static_info_[i + 1].set_regi_info(0, RegInfo(SCALAR_VALUE));
                    set<int> stack_addrs;
                    for (int addr_i = 0; addr_i > -512; addr_i--)
                        stack_addrs.insert(addr_i);
                    ld_mem_addrs_[PTR_TO_STACK] = stack_addrs;
                } else if (code != EXIT) {  // jeq, jne, ...
                    branch_final_static_info_.copy(static_info_[i]);
                    RegType cur_dst_type = static_info_[i].get_regi_type(dst_reg);
                    int cur_dst_mapid = static_info_[i].get_regi_mapid(dst_reg);
                    if (insn_op == BPF_JEQ && insn_src == BPF_K) {
                        if (imm == 0) {
                            if (reg_type_str.at(cur_dst_type).find("_or_null") != string::npos) {
                                static_info_[i + 1].set_regi_info(dst_reg, RegInfo(type_exclude_null.at(cur_dst_type)));
                                if(cur_dst_type==PTR_TO_MAP_VALUE_OR_NULL||cur_dst_type==PTR_TO_MAP_VALUE)
                                    static_info_[i + 1].set_regi_map_id(dst_reg, cur_dst_mapid);
                                if (same_regs.find(dst_reg) != same_regs.end() && !same_regs.at(dst_reg).empty()) {
                                    for (auto cur_reg: same_regs.at(dst_reg)) {
                                        static_info_[i + 1].set_regi_info(cur_reg,
                                                                          RegInfo(type_exclude_null.at(cur_dst_type)));
                                        if(cur_dst_type==PTR_TO_MAP_VALUE_OR_NULL||cur_dst_type==PTR_TO_MAP_VALUE)
                                            static_info_[i + 1].set_regi_map_id(cur_reg, cur_dst_mapid);
                                    }
                                }
                            }

                        }
                        static_info_[i + 1].set_regi_min_max_val(dst_reg, static_info_[i].get_regi_smin_val(dst_reg),
                                                                 static_info_[i].get_regi_smax_val(dst_reg));
                        branch_final_static_info_.set_regi_info(dst_reg, RegInfo(imm, SCALAR_VALUE));
                        if (same_regs.find(dst_reg) != same_regs.end() && !same_regs.at(dst_reg).empty()) {
                            for (auto cur_reg: same_regs.at(dst_reg)) {
                                branch_final_static_info_.set_regi_info(cur_reg, RegInfo(imm, SCALAR_VALUE));
                            }
                        }
                    } else if (insn_op == BPF_JNE && insn_src == BPF_K) {
                        if (imm == 0) {
                            if (reg_type_str.at(cur_dst_type).find("_or_null") != string::npos) {
                                branch_final_static_info_.set_regi_info(dst_reg,
                                                                        RegInfo(type_exclude_null.at(cur_dst_type)));
                                if(cur_dst_type==PTR_TO_MAP_VALUE_OR_NULL||cur_dst_type==PTR_TO_MAP_VALUE)
                                    static_info_[i + 1].set_regi_map_id(dst_reg, cur_dst_mapid);
                                if (same_regs.find(dst_reg) != same_regs.end() && !same_regs.at(dst_reg).empty()) {
                                    for (auto cur_reg: same_regs.at(dst_reg)) {
                                        branch_final_static_info_.set_regi_info(cur_reg,
                                                                                RegInfo(type_exclude_null.at(
                                                                                        cur_dst_type)));
                                        if(cur_dst_type==PTR_TO_MAP_VALUE_OR_NULL||cur_dst_type==PTR_TO_MAP_VALUE)
                                            static_info_[i + 1].set_regi_map_id(cur_reg, cur_dst_mapid);
                                    }
                                }
                            }
                        }
                        branch_final_static_info_.set_regi_min_max_val(dst_reg, static_info_[i].get_regi_smin_val(dst_reg),
                                                                 static_info_[i].get_regi_smax_val(dst_reg));
                        static_info_[i + 1].set_regi_info(dst_reg, RegInfo(imm, SCALAR_VALUE));
                        if (same_regs.find(dst_reg) != same_regs.end() && !same_regs.at(dst_reg).empty()) {
                            for (auto cur_reg: same_regs.at(dst_reg)) {
                                static_info_[i + 1].set_regi_info(cur_reg,
                                                                  RegInfo(imm, SCALAR_VALUE));
                            }
                        }
                    }
                }
            }
        }
    }

    void Node::record_used_imms() {
        used_imms_.clear();
        for (int i = 0; i < insns_.size(); i++) {
            used_imms_.insert(insns_[i]._imm);
        }
    }

    bool Node::same_with_node(Node *node) {
        if (insns_.size() != node->size())
            return false;
        for (int i = 0; i < insns_.size(); i++) {
            if (insns_[i] != node->insns_[i])
                return false;
        }
        return true;
    }

    int Node::bpf_size_to_bytes(int bpf_size) {
        int bytes = -EINVAL;
        if (bpf_size == BPF_B)
            bytes = sizeof(u8);
        else if (bpf_size == BPF_H)
            bytes = sizeof(u16);
        else if (bpf_size == BPF_W)
            bytes = sizeof(u32);
        else if (bpf_size == BPF_DW)
            bytes = sizeof(u64);
        return bytes;
    }

    void Node::print_insns() const{
        if(insns_.size()==0&&!split_insns_.empty()&&split_insns_[0]._opcode==JA&&split_insns_[0]._off==0)
            return;
        cout << "block " << idx_ << endl;
        cout << "insn[i] : code            dst_reg src_reg off        imm" << endl;
        for (int i = 0; i < insns_.size(); i++) {
            if(insns_[i]._opcode==JA&&insns_[i]._off==0)
                continue;
            cout << right << setw(7) << idx_ + i << " : ";
            insns_[i].print_insn();
        }
        if (!split_insns_.empty())
            cout << endl;
        for (int i = split_insns_.size() - 1; i >= 0; i--) {
            if(split_insns_[i]._opcode==JA&&split_insns_[i]._off==0)
                continue;
            cout << right << setw(7) << (idx_ + insns_.size() + split_insns_.size() - 1 - i) << " : ";
            split_insns_[i].print_insn();
        }
//        for (int i = 0; i < 60; i++)
//            cout << "-";
//        cout << "\n";
    }

    void Node::print_live_regs() {
        cout << "Live-out regs: ";
        if (regs_live_out_.empty())
            cout << "none";
        for (int i: regs_live_out_) {
            cout << (int) i << ' ';
        }
        cout << endl;
    }


    void Node::print_live_mems() {
        map<u8, set<pair<int, int>>> mem_areas_live_in, mem_areas_live_out;
        mem_addrs2areas(mem_live_in_, mem_areas_live_in);
        mem_addrs2areas(mem_live_out_, mem_areas_live_out);
        cout << "Live-in memory areas: ";
        if (mem_live_in_.empty())
            cout << "none";
        for (auto [mem_type, mem_areas]: mem_areas_live_in) {
            cout << reg_type_str[(RegType) mem_type] << ": ";
            for (auto mem_area: mem_areas) {
                cout << "[" << mem_area.first << ", " << mem_area.second << "] ";
            }
            cout << " | ";
        }
        cout << endl;
        cout << "Live-out memory areas: ";
        if (mem_live_out_.empty())
            cout << "none";
        for (auto [mem_type, mem_areas]: mem_areas_live_out) {
            cout << reg_type_str[(RegType) mem_type] << ": ";
            for (auto mem_area: mem_areas) {
                cout << "[" << mem_area.first << ", " << mem_area.second << "] ";
            }
            cout << " | ";
        }
        cout << endl;
    }

    void Node::print_init_static_info() {
        cout << "Initial static information: ";
        init_static_info().print_info();
    }

    void Node::print_static_info() {
        cout << "Initial static information: ";
        init_static_info().print_info();
        cout << "Final static information: ";
        final_static_info().print_info();
        cout << "Final static information for another branch: ";
        branch_final_static_info_.print_info();
        cout << "Used memory areas: ";
        map<u8, set<pair<int, int>>> ld_mem_areas, st_mem_areas;
        mem_addrs2areas(ld_mem_addrs_, ld_mem_areas);
        mem_addrs2areas(st_mem_addrs_, st_mem_areas);
        for (auto [mem_type, mem_areas]: ld_mem_areas) {
            cout << reg_type_str[(RegType) mem_type] << ": ";
            for (auto mem_area: mem_areas) {
                cout << "[" << mem_area.first << ", " << mem_area.second << "] ";
            }
            cout << " | ";
        }
        cout << endl;
        cout << "Defined memory areas: ";
        for (auto [mem_type, mem_areas]: st_mem_areas) {
            cout << reg_type_str[(RegType) mem_type] << ": ";
            for (auto mem_area: mem_areas) {
                cout << "[" << mem_area.first << ", " << mem_area.second << "] ";
            }
            cout << " | ";
        }
        cout << endl;
    }

    void Node::mem_addrs2areas(map<u8, std::set<int>> &mem_addrs, map<u8, std::set<std::pair<int, int>>> &mem_areas) {
        for (auto [type, addrs]: mem_addrs) {
            if (mem_areas.find(type) == mem_areas.end())
                mem_areas.insert({type, set<pair<int, int>>()});
            int last_addr = INT_MIN, start_addr = INT_MIN;
            for (auto addr: addrs) {
                if (last_addr == INT_MIN) {
                    start_addr = last_addr = addr;
                } else if (last_addr + 1 == addr) {
                    last_addr++;
                } else {
                    mem_areas.at(type).insert({start_addr, last_addr});
                    start_addr = last_addr = addr;
                }
            }
            mem_areas.at(type).insert({start_addr, last_addr});
        }
    }

    string Node::get_serialized_insns_str(unordered_map<int,int>& reg_id_map,unordered_map<int,int>& reg_off_map,
                                          unordered_map<int,int>& imm_map,set<int> new_regs) const{
        if(insns_.empty())
            return "ARRAY[]::instruction[]";
        int reg_count=0,imm_count=0;
        string res="ARRAY[";
        unordered_map<int,unordered_map<int,int>> related_regs;
        for(auto insn:insns_){
            if(insn._opcode==MOV32XY||insn._opcode==MOV64XY){
                related_regs[insn._dst_reg].insert({insn._src_reg,0});
                related_regs[insn._src_reg].insert({insn._dst_reg,0});
            }
            else if(insn._opcode==ADD32XC||insn._opcode==ADD64XC){
                for(auto &[reg_id,off]:related_regs[insn._dst_reg]){
                    off+=insn._imm;
                    related_regs[reg_id][insn._dst_reg]-=insn._imm;
                }
            }
            else if(insn._opcode==SUB32XC||insn._opcode==SUB64XC){
                for(auto &[reg_id,off]:related_regs[insn._dst_reg]){
                    off-=insn._imm;
                    related_regs[reg_id][insn._dst_reg]+=insn._imm;
                }
            }
            // serialize dst_reg and src_reg
            int serialized_dst_reg=0,serialized_src_reg=0;
            if(reg_id_map.count(insn._dst_reg)){
                serialized_dst_reg=reg_id_map.at(insn._dst_reg);
            }
            else{
                serialized_dst_reg=reg_count;
                reg_count++;
                reg_id_map[insn._dst_reg]=serialized_dst_reg;
            }
            if(insn.is_src_reg_used()) {
                if(new_regs.count(insn._src_reg)){
                    serialized_src_reg=-1;
                }
                else{
                    if(reg_id_map.count(insn._src_reg)){
                        serialized_src_reg=reg_id_map.at(insn._src_reg);
                    }
                    else{
                        serialized_src_reg=reg_count;
                        reg_count++;
                        reg_id_map[insn._src_reg]=serialized_src_reg;
                    }
                }
            }
            // serialize off and imm
            int serialized_off=0,serialized_imm=0;
            if(insn.is_st()||insn.is_ldx()){
                int base_reg=(insn.is_st())?insn._dst_reg:insn._src_reg;
                if(reg_off_map.count(base_reg)){
                    serialized_off=insn._off-reg_off_map.at(base_reg);
                }
                else{
                    // Attention: the action below is used to prevent rewrites' reg_off information from being lost
                    // in situations where rewrite's base register is different from origins (usually because of
                    // some registers have same values).
                    bool found=false;
                    for(auto [reg_id,off]:related_regs[base_reg]){
                        if(reg_off_map.count(reg_id)){
                            found=true;
                            if(insn.is_st())
                                serialized_dst_reg=reg_id_map[reg_id];
                            else
                                serialized_src_reg=reg_id_map[reg_id];
                            serialized_off=insn._off-reg_off_map.at(reg_id)+off;
//                            cout<<base_reg<<' '<<reg_id<<' '<<insn._off<<' '<<reg_off_map.at(reg_id)<<' '<<off<<endl;
                            break;
                        }
                    }
                    if(!found) {
                        serialized_off = 0;
                        reg_off_map[base_reg] = insn._off;
                    }
//                    serialized_off = 0;
//                    reg_off_map[base_reg] = insn._off;
                }
            }
            if(insn.is_imm_used()){
                serialized_imm=insn._imm; // TODO: temporary solution
//                if(insn.isShift()){ // special scenarios in which 'imm' values are important
//                    serialized_imm=insn._imm;
//                }
//                if(insn.is_atomic()){
//                    serialized_imm=insn._imm;
//                }
//                else{
//                    if(imm_map.count(insn._imm)){
//                        serialized_imm=imm_map.at(insn._imm);
//                    }
//                    else{
//                        serialized_imm=imm_count;
//                        imm_count++;
//                        imm_map[insn._imm]=serialized_imm;
//                    }
//                }
            }
            res+=("("+ to_string(insn._opcode)+ ","+to_string(serialized_dst_reg)+ ","+to_string(serialized_src_reg)+","
                    + to_string(serialized_off)+","+ to_string(serialized_imm)+")::instruction,");
        }
        res.pop_back();
        res+="]";
//        print_insns();
//        cout<<res<<endl;
        return res;
    }

/*
 * All insns not planned to be optimized are used to split blocks.
 */
    CFG::CFG(bpf_prog_type prog_type, const std::vector<Insn> &insns) {
        prog_type_ = prog_type;
        build_cfg(insns);
    }

    CFG::CFG(bpf_prog_type prog_type, bpf_attach_type attach_type, const std::vector<Insn> &insns) {
        prog_type_ = prog_type;
        attach_type_ = attach_type;
        build_cfg(insns);
    }

    void CFG::build_cfg(const std::vector<Insn> &insns) {
        // 将指令序列构造为CFG，拓扑排序在getDAG中完成
        unordered_map<int, vector<int>> edges;  // 收集跳转边
        set<int> blockHead, blockTail;  // 构造代码块的头尾划分
        // 跳转语句本身是block结束点
        // 跳转地址是block开始点
        // block开始点之前是结束点
        //          OP
        // tail->   JMP   ---
        // head->   OP      |
        //          ...     |
        // tail->   OP      |
        // head->   OP  <----
        blockHead.insert(0);
        blockTail.insert(insns.size() - 1);
        for (int i = 0; i < insns.size(); i++) {
            auto &insn = insns[i];
            if (!insn.isSplit()) {
                continue;
            }
            if (!insn.is_length_2()) {
                blockTail.insert(i);
                blockHead.insert(i + 1);
            } else {
                blockTail.insert(i + 1);
                blockHead.insert(i + 2);
            }
            if (insn.isJump()) {
                int dst = i + insn.getJumpDst() + 1;
                blockTail.insert(dst - 1);
                blockHead.insert(dst);
                edges[i].push_back(dst);
                if (insn.getType() == OP_COND_JMP) {
                    edges[i].push_back(i + 1);
                }
            }
        }

        // 构造代码块
        int head;
        for (int i = 0; i < insns.size(); i++) {
            if (blockHead.find(i) != blockHead.end()) {
                head = i;
            }
            if (blockTail.find(i) != blockTail.end()) {
                addNode(insns, head, i, edges[i]);
            }
        }

        // 如果某个block没有出边，此时它需要补 fall 边
        for (auto &[idx, node]: getAllNodes()) {
            if (node->insns()[node->size() - 1].getType() == OP_RET)
                continue;
            auto &children = getNodeChildren(idx);
            auto tailIdx = node->getTailIdx();
            if (children.empty() && tailIdx != insns.size()) {
                auto &parent = getNodeParent(tailIdx);
                children.push_back(tailIdx);
                parent.push_back(idx);
            }
        }
    }

    void CFG::addNode(const vector<Insn> &prog, int begin, int end, const vector<int> &children) {
        auto node = new Node(begin, prog, begin, end);
        node->set_prog_attach_type(prog_type_, attach_type_);
        nodes_.insert({begin, node});
        node_chidren_[begin] = children;
        for (int c: children) {
            node_parent_[c].push_back(begin);
        }
    }

    set<int> CFG::merge_regs_live_in(vector<int> successors) {
        set<int> res;
        // If no successors, must be the last block.
        if (successors.size() == 0)
            res.insert(0);
        for (int i: successors) {
            if(!nodes_.count(i))
                continue;
            set<int> regs_live_in = nodes_.at(i)->regs_live_in();
            res.insert(regs_live_in.begin(), regs_live_in.end());
        }
        return res;
    }

    map<u8, set<int>> CFG::merge_mem_live_in(vector<int> successors) {
        std::map<u8, std::set<int>> res;
        if (successors.empty()) {
            set<int> ctx_mem_addrs;
            for (int i = 0; i < ctx_size.at(prog_type_); i++)
                ctx_mem_addrs.insert(i);
            res.insert({PTR_TO_CTX, ctx_mem_addrs});
            if (pkt_size.find(prog_type_) != pkt_size.end()) {
                set<int> pkt_mem_addrs;
                for (int i = 0; i < pkt_size.at(prog_type_); i++)
                    pkt_mem_addrs.insert(i);
                res.insert({PTR_TO_PACKET, pkt_mem_addrs});
            }
        }
        for (auto i: successors) {
            auto mem_live_in = nodes_.at(i)->mem_live_in();
            for (auto [mem_type, mem_addrs]: mem_live_in) {
                if (res.find(mem_type) != res.end()) {
                    res.at(mem_type).insert(mem_addrs.begin(), mem_addrs.end());
                } else {
                    res.insert({mem_type, mem_addrs});
                }
            }
        }
        return res;
    }

    StaticInfo CFG::merge_final_static_info(int node_id, vector<int> predecessors) {
        StaticInfo res;
        if (predecessors.empty())
            return res;
        else {
            if (nodes_.at(predecessors[0])->getTailIdx() == node_id)
                res = nodes_.at(predecessors[0])->final_static_info();
            else
                res = nodes_.at(predecessors[0])->branch_final_static_info();
        }
        for (int i = 1; i < predecessors.size(); i++) {
            if (nodes_.at(predecessors[i])->getTailIdx() == node_id) {
                res.merge(nodes_.at(predecessors[i])->final_static_info());
            } else
                res.merge(nodes_.at(predecessors[i])->branch_final_static_info());
        }
        return res;
    }

    void CFG::analyze_regs_live_out() {
        queue<int> q;
        for (auto it: nodes_)
            q.push(it.first);
        while (!q.empty()) {
            int node_id = q.front();
            q.pop();
            Node *node = nodes_.at(node_id);
            set<int> origin_regs_live_in = node->regs_live_in();
            set<int> regs_live_out = merge_regs_live_in(node_chidren_.at(node_id));
            node->add_regs_live_out(regs_live_out);
            // set live-in regs (use U (out - def))
            set<int> regs_live_in;
            set<int> used_regs = node->get_used_regs();
            set<int> def_regs = node->get_defined_regs();
            set_difference(regs_live_out.begin(), regs_live_out.end(), def_regs.begin(), def_regs.end(),
                           inserter(regs_live_in, regs_live_in.begin()));
            regs_live_in.insert(used_regs.begin(), used_regs.end());
            if (regs_live_in != origin_regs_live_in && node_parent_.find(node_id) != node_parent_.end()) {
                for (auto cur_pre: node_parent_.at(node_id)) {
                    q.push(cur_pre);
                }
            }
            node->set_regs_live_in(regs_live_in);
        }
    }

    void CFG::analyze_mem_liveness() {
        queue<int> q;
        for (auto it: nodes_)
            q.push(it.first);
        while (!q.empty()) {
            int node_id = q.front();
            q.pop();
            Node *node = nodes_.at(node_id);
            auto origin_mem_live_in = node->mem_live_in();
            auto mem_live_out = merge_mem_live_in(node_chidren_.at(node_id));
            node->add_mem_live_out(mem_live_out);
            // set live-in regs (use U (out - def))
            map<u8, set<int>> mem_live_in;
            auto used_mem = node->get_used_mems(), def_mem = node->get_defined_mems();
            for (auto [mem_type, mem_addrs]: mem_live_out) {
                if (mem_live_in.find(mem_type) == mem_live_in.end())
                    mem_live_in.insert({mem_type, set<int>()});
                if (def_mem.find(mem_type) != def_mem.end())
                    set_difference(mem_live_out.at(mem_type).begin(), mem_live_out.at(mem_type).end(),
                                   def_mem.at(mem_type).begin(), def_mem.at(mem_type).end(),
                                   inserter(mem_live_in.at(mem_type), mem_live_in.at(mem_type).begin()));
                else
                    mem_live_in.at(mem_type) = mem_addrs;
            }
            for (auto [mem_type, mem_areas]: used_mem) {
                if (mem_live_in.find(mem_type) == mem_live_in.end())
                    mem_live_in.insert({mem_type, set<int>()});
                mem_live_in.at(mem_type).insert(used_mem.at(mem_type).begin(), used_mem.at(mem_type).end());
            }
            if (mem_live_in != origin_mem_live_in && node_parent_.find(node_id) != node_parent_.end()) {
                for (auto cur_pre: node_parent_.at(node_id)) {
                    q.push(cur_pre);
                }
            }
            node->set_mem_live_in(mem_live_in);
        }
    }

    void CFG::analyze_init_static_info() {
        queue<int> q;
        if (prog_type_ != BPF_PROG_TYPE_EXT) {
            StaticInfo init_info;
            // r[1][0].type =  PTR_TO_CTX, r[10][0].type = PTR_TO_STACK
            init_info.set_regi_type(1, PTR_TO_CTX);  // refer to verifier.c: do_check_common(...)
            init_info.set_regi_type(10, PTR_TO_STACK);  // refer to verifier.c: init_reg_state(...)
            nodes_.at(0)->set_init_static_info(init_info);
            nodes_.at(0)->compute_final_static_info();
            for (auto node_idx: node_chidren_.at(0))
                q.push(node_idx);
        }
        unordered_map<int,int> visit_times;
        while (!q.empty()) {
            int node_id = q.front();
            q.pop();
            Node *cur_node = nodes_.at(node_id);
            StaticInfo origin_final_static_info = cur_node->final_static_info();
            cur_node->set_init_static_info(merge_final_static_info(node_id, getNodeParent(node_id)));
            cur_node->compute_final_static_info();
            if (origin_final_static_info != cur_node->final_static_info()) {
//                cout<<cur_node->idx()<<endl;
//                origin_final_static_info.print_info();
//                cur_node->final_static_info().print_info();
//                cout<<endl;
                visit_times[cur_node->idx()]++;
                if(visit_times[cur_node->idx()]>=500)
                    continue;
                for (auto cur_block_id: node_chidren_.at(node_id)) {
                    if(nodes_.count(cur_block_id))
                        q.push(cur_block_id);
                    else
                        cout<<node_id<<endl;
                }
            }
        }
    }

    void CFG::record_used_imms() {
        for (auto it = nodes_.begin(); it != nodes_.end(); it++) {
            nodes_.at(it->first)->record_used_imms();
        }
    }

    Node *CFG::getNode(int node_idx) {
        return nodes_.at(node_idx);
    }

    std::map<int, Node *> CFG::getAllNodes() {
        return nodes_;
    }

    std::vector<int> &CFG::getNodeChildren(int begin) {
        return node_chidren_[begin];
    }

    std::vector<int> &CFG::getNodeParent(int begin) {
        return node_parent_[begin];
    }

    void CFG::static_analysis() {
        analyze_regs_live_out();
        analyze_init_static_info();
        analyze_mem_liveness();
        record_used_imms();
    }

    void CFG::print_bbi(int idx) {
        nodes_.at(idx)->print_insns();
    }

    void CFG::print_prog() {
        for (auto &[idx, node]: nodes_) {
            cout << "Node " << idx << " from " << node->getHeadIdx() << " to " << node->getTailIdx() << ", to:";
            for (auto &succ: getNodeChildren(idx)) {
                cout << succ << ",";
            }
            cout << " | from: ";
            for (auto &pre: getNodeParent(idx)) {
                cout << pre << ",";
            }
            cout << "\n";
            node->print_insns();
            node->print_live_regs();
            node->print_live_mems();
            node->print_static_info();
            cout << endl;
        }
    }

    void CFG::print_live_regs() {
        cout << "Live-out info:" << endl;
        for (auto it = nodes_.begin(); it != nodes_.end(); it++) {
            cout << endl << "Block " << it->first << ": " << endl;
            it->second->print_live_regs();
        }
    }

}

