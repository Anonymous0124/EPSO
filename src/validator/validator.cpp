#include "validator/validator.h"

#include "src/instruction/insn_simulator.h"
#include "src/instruction/insn_sym_simulator.h"

using namespace superbpf;
using namespace z3;
using namespace  std;

namespace superbpf {
    Validator::Validator(Node *target, Node *rewrite)
            : target_regs_(c_, "target", target->init_static_info()),
              target_mem_(c_, "target"),
              rewrite_regs_(c_, "rewrite", target->init_static_info()),
              rewrite_mem_(c_, "rewrite") {
        target_ = target;
        rewrite_ = rewrite;
        counterexample_ = NULL;
    }

    void Validator::print_states(vector<Insn> &insns, SymRegsValidation &regs, SymMemoryValidation &mem, model &m) {
        InsnSimulator insn_simulator;
        vector<State *> states;
//        set<u64> target_ld_mem_addrs;
//        set<u64> target_st_mem_addrs;
//        set<u64> target_mem_addrs;

        for (int i = 0; i <= insns.size(); i++) {
            states.emplace_back(new State(i));
        }
        vector<int> reg_idx(11, 0);
        map<RegType, int> mem_idx = {{PTR_TO_CTX,    0},
                                     {PTR_TO_STACK,  0},
                                     {PTR_TO_PACKET, 0}};
        for (int i = 0; i < insns.size(); i++) {
            Insn &insn = insns[i];
            vector<int> use_regs = insn.getRegUses();
            State *cur_state = states[i], *next_state = states[i + 1];
            // If regs going to be used by this insn are not valid yet, give them random values.
            for (int reg_i: use_regs) {
                if (!cur_state->is_regi_valid(reg_i)) {
                    auto reg_type = regs.get_reg_type(reg_i, reg_idx[reg_i]);
                    auto type_off = regs.get_reg_off(reg_i, reg_idx[reg_i]);
                    s64 reg_val = (int64_t) m.eval(regs.get_reg_value(reg_i, reg_idx[reg_i])).get_numeral_int64();
                    states[i]->set_regi(reg_i, reg_val, reg_type, type_off);
                }
            }
            if (BPF_CLASS(insn._opcode) != BPF_STX && BPF_CLASS(insn._opcode) != BPF_ST) {
                auto reg_type = regs.get_reg_type(insn._dst_reg, reg_idx[insn._dst_reg]);
                auto type_off = regs.get_reg_off(insn._dst_reg, reg_idx[insn._dst_reg]);
                s64 reg_val = (int64_t) m.eval(
                        regs.get_reg_value(insn._dst_reg, reg_idx[insn._dst_reg])).get_numeral_int64();
                states[i]->set_regi(insn._dst_reg, reg_val, reg_type, type_off);
                reg_idx[insn._dst_reg]++;
                auto dst_reg_type = regs.get_reg_type(insn._dst_reg, reg_idx[insn._dst_reg]);
                auto dst_type_off = regs.get_reg_off(insn._dst_reg, reg_idx[insn._dst_reg]);
                s64 dst_reg_val = (int64_t) m.eval(
                        regs.get_reg_value(insn._dst_reg, reg_idx[insn._dst_reg])).get_numeral_int64();
                next_state->set_regi(insn._dst_reg, dst_reg_val, dst_reg_type, dst_type_off);
            }
            // If memory units going to be accessed by this insn are not valid yet, give them random values.
            if (insn.is_ldx()) {
                auto type = cur_state->get_regi_type(insn._src_reg);
                auto type_off = cur_state->get_regi_off(insn._src_reg);
                u64 addr = (u64) (cur_state->get_regi_val(insn._src_reg) + insn._off);
                int size = bpfsize2byte(BPF_SIZE(insn._opcode));
                vector<z3::expr> mem_units = mem.get_mem_units(mem_idx[type], c_.bv_val(addr, 64), size);
                for (u64 off = 0; off < size; off++) {
                    if (!states[i]->is_memi_valid(addr + off, 1))
                        states[i]->set_memi(addr + off, (int8_t) m.eval(mem_units[off]).get_numeral_uint(), type,
                                            type_off + insn._off + off);
                }
            } else if (insn.is_st()) {
                u64 addr = (u64) (cur_state->get_regi_val(insn._dst_reg) + insn._off);
                auto type = cur_state->get_regi_type(insn._dst_reg);
                auto type_off = cur_state->get_regi_off(insn._dst_reg);
                int size = bpfsize2byte(BPF_SIZE(insn._opcode));
                for (u64 off = 0; off < size; off++) {
                    states[i]->add_mem_unit(addr + off, type, type_off + insn._off + off);
                }
                vector<z3::expr> cur_mem_units = mem.get_mem_units(mem_idx[type], c_.bv_val(addr, 64), size);
                for (u64 off = 0; off < size; off++) {
                    cur_state->set_memi(addr + off, (int8_t) m.eval(cur_mem_units[off]).get_numeral_uint(), type,
                                        type_off + insn._off + off);
                }
                mem_idx[type]++;
                vector<z3::expr> mem_units = mem.get_mem_units(mem_idx[type], c_.bv_val(addr, 64), size);
                for (u64 off = 0; off < size; off++) {
                    next_state->set_memi(addr + off, (int8_t) m.eval(mem_units[off]).get_numeral_uint(), type,
                                         type_off + insn._off + off);
                }
            }
//            insn_simulator.run(insn._opcode, insn._dst_reg, insn._src_reg, insn._off, insn._imm,
//                               cur_state, next_state);
        }
        for (int i=0;i<insns.size();i++){
            states[i]->print_state();
            insns[i].print_insn();

        }
        states.back()->print_state();
    }

    bool Validator::verify() {
        bool res = false;
        solver s = solver(c_);
        z3::expr_vector target_semantics = symbolic_execution(target_, target_regs_, target_mem_);
        z3::expr_vector rewrite_semantics = symbolic_execution(rewrite_, rewrite_regs_, rewrite_mem_);
        z3::expr input_equal_semantics = input_equal();
        z3::expr output_inequal_semantics = output_inequal();
        // cout << target_semantics << endl << endl;
        // cout << rewrite_semantics << endl << endl;
        // cout << input_equal_semantics << endl << endl;
        // cout << output_inequal_semantics << endl << endl;
        s.add(target_semantics);
        s.add(rewrite_semantics);
        s.add(input_equal_semantics);
        s.add(output_inequal_semantics);
        if (s.check() == unsat) {
            printf("Validation passed!\n");
            res = true;
        } else {
            // generate counterexample
            printf("Validation failed.\n");
            model m = s.get_model();
//        cout << m << endl;
            gen_counterexample(m);
//            gen_counterexample_debug(m);
//            std::cout<<"target_states:\n";
//            print_states(target_->insns(),target_regs_,target_mem_,m);
//            std::cout<<"rewrite_states:\n";
//            print_states(rewrite_->insns(),rewrite_regs_,rewrite_mem_,m);
            res = false;
        }
        return res;
    }

    Testcase *Validator::get_counterexample() {
        return counterexample_;
    }

    z3::expr_vector Validator::symbolic_execution(Node *node, SymRegsValidation &regs, SymMemoryValidation &mem) {
        z3::expr_vector res(c_);
        vector<Insn> insns = node->insns();
        if(insns.empty()) {
            Insn nop(0,0,0,0,0);
            insns.emplace_back(nop);
        }
        for (auto insn: insns) {
            std::function<void(z3::context &, u8, u8, u8, s16, s32, SymRegsValidation &,
                               SymMemoryValidation &)> exec_func;
            if (insn._opcode == 0) {
                exec_func = &InsnSymSimulator::nop;
            }
            else{
                switch (BPF_CLASS(insn._opcode)) {
                    case BPF_ALU64:
                    case BPF_ALU:
                        exec_func = &InsnSymSimulator::bpf_alu_func;
                        break;
                    case BPF_STX:
                        switch (BPF_MODE(insn._opcode)) {
                            case BPF_MEM:
                                exec_func = &InsnSymSimulator::bpf_store;
                                break;
                            case BPF_ATOMIC:
                                exec_func = &InsnSymSimulator::bpf_atomic;
                                break;
                            default:
                                assert(0);
                        }
                        break;
                    case BPF_ST:
                        switch (BPF_MODE(insn._opcode)) {
                            case BPF_MEM:
                                exec_func = &InsnSymSimulator::bpf_store;
                                break;
                            default:
                                assert(0);
                        }
                        break;
                    case BPF_LDX:
                        switch (BPF_MODE(insn._opcode)) {
                            case BPF_MEM:
                                exec_func = &InsnSymSimulator::bpf_load;
                                break;
                            default:
                                assert(0);
                        }
                        break;
                    case BPF_LD:
                        // TODO:
                        assert(0);
                    case BPF_JMP:
                        // TODO:
                        assert(0);
                    case BPF_JMP32:
                        // TODO:
                        assert(0);
                    default:
                        assert(0);
                }
            }

            exec_func(c_, insn._opcode, insn._dst_reg, insn._src_reg, insn._off, insn._imm, regs, mem);
        }
        for (auto cons: regs.constraints()) {
            res.push_back(cons);
        }
        for (auto cons: mem.constraints()) {
            res.push_back(cons);
        }

//        res.push_back(regs.get_reg_value(1, 0) == c_.bv_val(1024, 64));
        return res;
    }

    z3::expr Validator::input_equal() {
        z3::expr_vector cons_vec(c_);
        auto regs_live_in = target_->regs_live_in();
        auto static_info = target_->init_static_info();
        for (int reg_no = 0; reg_no < MAX_BPF_REG; reg_no++) {
            expr reg_val = target_regs_.get_reg_init_value(reg_no);
            z3::expr cons = (target_regs_.get_reg_init_value(reg_no) == rewrite_regs_.get_reg_init_value(reg_no));
            // Apply range analysis in validation part.
            if (static_info.get_regi_info(reg_no).is_value_valid_) {
                int64_t smin_val = static_info.get_regi_info(reg_no).smin_value_,
                        smax_val = static_info.get_regi_info(reg_no).smax_value_;
//                assert(smin_val<=smax_val);
                if(smin_val<=smax_val){
                    z3::expr min_val_cons = (reg_val >= c_.bv_val(smin_val, 64));
                    z3::expr max_val_cons = (reg_val <= c_.bv_val(smax_val, 64));
                    cons_vec.push_back(min_val_cons);
                    cons_vec.push_back(max_val_cons);
                }

            }
//            if(static_info.get_regi_info(reg_no).is_type_valid_){
//                RegType type=static_info.get_regi_type(reg_no);
//                if(type != SCALAR_VALUE && type != NOT_INIT && type != LD_IMM_VALUE && type != STACK_VALUE &&
//                   type != CTX_VALUE && type != MIXED_TYPE){
//                    z3::expr ptr_cons=(((reg_val<<3)>>3)==reg_val);
//                    cons_vec.push_back(ptr_cons);
//                }
//            }
            cons_vec.push_back(cons);
        }
        cons_vec.push_back(target_mem_.get_mem_init_sym() == rewrite_mem_.get_mem_init_sym());
        // maps
//        auto target_init_maps=target_mem_.get_maps_init_sym();
//        auto rewrite_init_maps=rewrite_mem_.get_maps_init_sym();
//        for(auto [map_id,map]:target_init_maps){
//            cons_vec.push_back(map==rewrite_init_maps.at(map_id));
//        }
        assert(!cons_vec.empty());
        return z3::mk_and(cons_vec);
    }

    z3::expr Validator::output_inequal() {
        z3::expr_vector cons_vec(c_);
        auto regs_live_out = target_->regs_live_out();
        for (auto reg_no: regs_live_out) {
            z3::expr cons = (target_regs_.get_reg_value(reg_no) != rewrite_regs_.get_reg_value(reg_no));
            cons_vec.push_back(cons);
        }
        for (auto [mem_type, type_ptrs]: target_mem_.type_off2smt_mem()) {
            if(mem_type==PTR_TO_STACK)
                continue;
            for (auto [off,target_mem_val]: type_ptrs.ptrs()) {
                z3::expr rewrite_mem_val(c_);
                bool rewrite_res=rewrite_mem_.type_off2smt_var((RegType)mem_type, off, rewrite_mem_val);
                if(rewrite_res) {
                    cons_vec.push_back(target_mem_val != rewrite_mem_val);
                }
                else{
                    return c_.bool_val(true);
                }
            }
        }
        if(target_->mem_live_out().count(PTR_TO_STACK)){
            auto stack_offs=target_->mem_live_out().at(PTR_TO_STACK);
            for (auto off: stack_offs) {
                z3::expr target_mem_val(c_),rewrite_mem_val(c_);
                bool target_res=target_mem_.type_off2smt_var(PTR_TO_STACK, off, target_mem_val);
                bool rewrite_res=rewrite_mem_.type_off2smt_var(PTR_TO_STACK, off, rewrite_mem_val);
                if(target_res&&rewrite_res) {
                    cons_vec.push_back(target_mem_val != rewrite_mem_val);
                }
                else if(target_res) {
                    return c_.bool_val(true);
                }
            }
        }

//        auto target_final_maps=target_mem_.get_maps_final_sym();
//        auto rewrite_final_maps=rewrite_mem_.get_maps_final_sym();
//        for(auto [map_id,map]:target_final_maps){
//            cons_vec.push_back(map!=rewrite_final_maps.at(map_id));
//        }
//        assert(!cons_vec.empty());
        if(cons_vec.empty())
            return c_.bool_val(false);
        return z3::mk_or(cons_vec);
    }

    int Validator::bpfsize2byte(int bpf_size) {
        switch (bpf_size) {
            case BPF_B:
                return 1;
            case BPF_H:
                return 2;
            case BPF_W:
                return 4;
            case BPF_DW:
                return 8;
        }
    }

    map<u64, int> Validator::compute_mem_areas(set<u64> mem_addrs) {
        map<u64, int> mem_areas;
        u64 last_addr = UINT64_MAX, start_addr = 0;
        for (auto it = mem_addrs.begin(); it != mem_addrs.end(); it++) {
            u64 cur_addr = *it;
            if ((last_addr == UINT64_MAX) || (last_addr + 1 != cur_addr)) {  // new memory area
                mem_areas.insert({cur_addr, 1});
                start_addr = cur_addr;
            } else {
                mem_areas.at(start_addr) += 1;
            }
            last_addr = cur_addr;
        }
        return mem_areas;
    }

    void Validator::gen_counterexample(model &m) {
        Testcase *testcase;
        InsnSimulator insn_simulator;
        vector<Insn> target_insns = target_->insns();
        vector<State *> states;
        set<u64> ld_mem_addrs;
        set<u64> st_mem_addrs;
        set<u64> mem_addrs;
        for (int i = 0; i <= target_insns.size(); i++) {
            states.emplace_back(new State(i));
        }
        for(int i=0;i<MAX_BPF_REG;i++){
            auto reg_info=target_->init_static_info().get_regi_info(i);
            if(reg_info.is_value_valid_&&reg_info.smin_value_==reg_info.smax_value_) {
                states[0]->set_regi_type(i,SCALAR_VALUE);
                states[0]->set_regi_val(i, reg_info.smin_value_);
            }
        }
        assert(!target_insns.empty());
        for (int i = 0; i < target_insns.size(); i++) {
            Insn &insn = target_insns[i];
            vector<int> use_regs = insn.getRegUses();
            State *cur_state = states[i], *next_state = states[i + 1];
            // If regs going to be used by this insn are not valid yet, give them random values.
            for (int reg_i: use_regs) {
                if (!cur_state->is_regi_valid(reg_i)) {
                    RegType reg_type = SCALAR_VALUE;
                    int type_off = 0;
                    RegInfo reg_info = target_->init_static_info().get_regi_info(reg_i);
                    if (reg_info.is_type_valid_ && reg_info.type_ != NOT_INIT) {
                        reg_type = reg_info.type_;
                        type_off = reg_info.off_;
                    }
                    s64 reg_val = (int64_t) m.eval(target_regs_.get_reg_init_value(reg_i)).get_numeral_uint64();
                    s64 reg_val2 = (int64_t) m.eval(rewrite_regs_.get_reg_init_value(reg_i)).get_numeral_uint64();
                    assert(reg_val == reg_val2);
                    for (int j = 0; j <= i; j++) {
                        states[j]->set_regi(reg_i, reg_val, reg_type, type_off);
                    }
                }
            }
            // If memory units going to be accessed by this insn are not valid yet, give them random values.
            if (insn.is_ldx()) {
                auto type = cur_state->get_regi_type(insn._src_reg);
                auto type_off = cur_state->get_regi_off(insn._src_reg);
                u64 addr = (u64) (cur_state->get_regi_val(insn._src_reg) + insn._off);
                int size = bpfsize2byte(BPF_SIZE(insn._opcode));
                vector<z3::expr> mem_units = target_mem_.get_mem_init_mem_units(c_.bv_val(addr, 64), size);
                for (int j = 0; j <= i; j++) {
                    for (u64 off = 0; off < size; off++) {
                        if (!states[j]->is_memi_valid(addr + off, 1))
                            states[j]->set_memi(addr + off, (int8_t) m.eval(mem_units[off]).get_numeral_uint(), type,
                                                type_off + insn._off + off);
                        if (j == 0) {
                            ld_mem_addrs.insert(addr + off);
                            mem_addrs.insert(addr + off);
                        }
                    }
                }
            } else if (insn.is_st()) {
                u64 addr = (u64) (cur_state->get_regi_val(insn._dst_reg) + insn._off);
                auto type = cur_state->get_regi_type(insn._dst_reg);
                auto type_off = cur_state->get_regi_off(insn._dst_reg);
                int size = bpfsize2byte(BPF_SIZE(insn._opcode));
                for (int j = 0; j <= i; j++) {
                    for (u64 off = 0; off < size; off++) {
                        states[j]->add_mem_unit(addr + off, type, type_off + insn._off + off);
                        if (j == 0) {
                            st_mem_addrs.insert(addr + off);
                            mem_addrs.insert(addr + off);
                            vector<z3::expr> mem_units = target_mem_.get_mem_init_mem_units(c_.bv_val(addr, 64), size);
                            states[j]->set_memi(addr + off, (int8_t) m.eval(mem_units[off]).get_numeral_uint(), type,
                                                type_off + insn._off + off);
                        }
                    }
                }
            }
            if (insn._opcode != 0 && BPF_CLASS(insn._opcode) == BPF_LD) {
                assert(i < target_insns.size() - 1); // ensure ld is not the last insn
                Insn next_insn = target_insns[i + 1];
                assert(next_insn._opcode == 0 && next_insn._dst_reg == 0
                       && next_insn._src_reg == 0 && next_insn._off == 0);
                insn_simulator.run(insn._opcode, insn._dst_reg, insn._src_reg, insn._off, insn._imm,
                                   cur_state, next_state, next_insn._imm);
            } else
                insn_simulator.run(insn._opcode, insn._dst_reg, insn._src_reg, insn._off, insn._imm,
                                   cur_state, next_state);
        }
        State *init_state = new State(states[0]), *final_state = new State(states[states.size() - 1]);
        u64 stack_start_addr=init_state->expand_mem_areas();
        u64 stack_start_addr2=final_state->expand_mem_areas();
        assert(stack_start_addr==stack_start_addr2);
//        final_state->expand_mem_areas();
        map<u64, int> ld_mem_areas = compute_mem_areas(ld_mem_addrs), st_mem_areas = compute_mem_areas(st_mem_addrs),
                mem_areas = compute_mem_areas(mem_addrs);
        if(stack_start_addr!=0){
            ld_mem_areas[stack_start_addr]+=3;
            st_mem_areas[stack_start_addr]+=3;
            mem_areas[stack_start_addr]+=3;
        }
        testcase = new Testcase(init_state, final_state, ld_mem_areas, st_mem_areas, mem_areas);
//        std::cout<<"counterexample:"<<std::endl;
//        testcase->print_testcase();
        counterexample_ = testcase;
    }

    void Validator::gen_counterexample_debug(model &m) {
        Testcase *testcase;
        InsnSimulator insn_simulator;
        vector<Insn> target_insns = rewrite_->insns();
        vector<State *> states;
        set<u64> ld_mem_addrs;
        set<u64> st_mem_addrs;
        set<u64> mem_addrs;
        for (int i = 0; i <= target_insns.size(); i++) {
            states.emplace_back(new State(i));
        }
        assert(!target_insns.empty());
        for (int i = 0; i < target_insns.size(); i++) {
            Insn &insn = target_insns[i];
            vector<int> use_regs = insn.getRegUses();
            State *cur_state = states[i], *next_state = states[i + 1];
            // If regs going to be used by this insn are not valid yet, give them random values.
            for (int reg_i: use_regs) {
                if (!cur_state->is_regi_valid(reg_i)) {
                    RegType reg_type = SCALAR_VALUE;
                    int type_off = 0;
                    RegInfo reg_info = target_->init_static_info().get_regi_info(reg_i);
                    if (reg_info.is_type_valid_ && reg_info.type_ != NOT_INIT) {
                        reg_type = reg_info.type_;
                        type_off = reg_info.off_;
                    }
                    s64 reg_val = (int64_t) m.eval(target_regs_.get_reg_init_value(reg_i)).get_numeral_uint64();
                    s64 reg_val2 = (int64_t) m.eval(rewrite_regs_.get_reg_init_value(reg_i)).get_numeral_uint64();
                    assert(reg_val == reg_val2);
                    for (int j = 0; j <= i; j++) {
                        states[j]->set_regi(reg_i, reg_val, reg_type, type_off);
                    }
                }
            }
            // If memory units going to be accessed by this insn are not valid yet, give them random values.
            if (insn.is_ldx()) {
                auto type = cur_state->get_regi_type(insn._src_reg);
                auto type_off = cur_state->get_regi_off(insn._src_reg);
                u64 addr = (u64) (cur_state->get_regi_val(insn._src_reg) + insn._off);
                int size = bpfsize2byte(BPF_SIZE(insn._opcode));
                vector<z3::expr> mem_units = target_mem_.get_mem_init_mem_units(c_.bv_val(addr, 64), size);
                for (int j = 0; j <= i; j++) {
                    for (u64 off = 0; off < size; off++) {
                        if (!states[j]->is_memi_valid(addr + off, 1))
                            states[j]->set_memi(addr + off, (int8_t) m.eval(mem_units[off]).get_numeral_uint(), type,
                                                type_off + insn._off + off);
                        if (j == 0) {
                            ld_mem_addrs.insert(addr + off);
                            mem_addrs.insert(addr + off);
                        }
                    }
                }
            } else if (insn.is_st()) {
                u64 addr = (u64) (cur_state->get_regi_val(insn._dst_reg) + insn._off);
                auto type = cur_state->get_regi_type(insn._dst_reg);
                auto type_off = cur_state->get_regi_off(insn._dst_reg);
                int size = bpfsize2byte(BPF_SIZE(insn._opcode));
                for (int j = 0; j <= i; j++) {
                    for (u64 off = 0; off < size; off++) {
                        states[j]->add_mem_unit(addr + off, type, type_off + insn._off + off);
                        if (j == 0) {
                            st_mem_addrs.insert(addr + off);
                            mem_addrs.insert(addr + off);
                            vector<z3::expr> mem_units = target_mem_.get_mem_init_mem_units(c_.bv_val(addr, 64), size);
                            states[j]->set_memi(addr + off, (int8_t) m.eval(mem_units[off]).get_numeral_uint(), type,
                                                type_off + insn._off + off);
                        }
                    }
                }
            }
            if (insn._opcode != 0 && BPF_CLASS(insn._opcode) == BPF_LD) {
                assert(i < target_insns.size() - 1); // ensure ld is not the last insn
                Insn next_insn = target_insns[i + 1];
                assert(next_insn._opcode == 0 && next_insn._dst_reg == 0
                       && next_insn._src_reg == 0 && next_insn._off == 0);
                insn_simulator.run(insn._opcode, insn._dst_reg, insn._src_reg, insn._off, insn._imm,
                                   cur_state, next_state, next_insn._imm);
            } else
                insn_simulator.run(insn._opcode, insn._dst_reg, insn._src_reg, insn._off, insn._imm,
                                   cur_state, next_state);
        }
        State *init_state = new State(states[0]), *final_state = new State(states[states.size() - 1]);
        u64 stack_start_addr=init_state->expand_mem_areas();
        u64 stack_start_addr2=final_state->expand_mem_areas();
        assert(stack_start_addr==stack_start_addr2);
//        final_state->expand_mem_areas();
        map<u64, int> ld_mem_areas = compute_mem_areas(ld_mem_addrs), st_mem_areas = compute_mem_areas(st_mem_addrs),
                mem_areas = compute_mem_areas(mem_addrs);
        if(stack_start_addr!=0){
            ld_mem_areas[stack_start_addr]+=3;
            st_mem_areas[stack_start_addr]+=3;
            mem_areas[stack_start_addr]+=3;
        }
        testcase = new Testcase(init_state, final_state, ld_mem_areas, st_mem_areas, mem_areas);
//        std::cout<<"synthesized:"<<std::endl;
//        for(int i=0;i<11;i++) {
//            printf("r[%d] = 0x%lx | ", i, m.eval(target_regs_.get_reg_value(i)).get_numeral_int64());
//            printf("r[%d] = 0x%lx | ", i, m.eval(rewrite_regs_.get_reg_value(i)).get_numeral_int64());
//        }
//        std::cout<<std::endl;
        testcase->print_testcase();
    }
}
