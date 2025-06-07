#include "testcase_gen.h"

#include <cstdlib>

using namespace std;
using namespace superbpf;

namespace superbpf {
    void TestcaseGen::set_prog(vector<Insn> &target, const StaticInfo &init_info) {
        prog_ = target;
        insn_simulator = InsnSimulator();
        testcase_init_info_->copy(init_info);
    }

    void TestcaseGen::set_live_out_regs(vector<u8> regs) {
        regs_live_out_ = regs;
    }

//void TestcaseGen::set_init_state(map<u8, int64_t> reg_vals, map<int, vector<u8>> mem_vals) {
//    for (auto it = reg_vals.begin(); it != reg_vals.end(); it++) {
//        states_[0]->set_regi_val(it->first, it->second);
//    }
//}

    void TestcaseGen::insert_mem_addrs(u64 target_addr, int target_size, bool is_ld) {
        if (is_ld) {
            for (u64 addr = target_addr; addr < target_addr + target_size; addr++) {
                ld_mem_addrs_.insert(addr);
            }
        } else {
            for (u64 addr = target_addr; addr < target_addr + target_size; addr++) {
                st_mem_addrs_.insert(addr);
            }
        }
    }

    void TestcaseGen::run() {
        assert(prog_.size() > 0);
        for (int i = 0; i <= prog_.size(); i++) {
            states_.emplace_back(new State(i));
        }
        for (int i = 0; i < MAX_BPF_REG; i++) {
            auto reg_info = testcase_init_info_->get_regi_info(i);
            if (reg_info.is_value_valid_ && reg_info.smin_value_ == reg_info.smax_value_) {
                states_[0]->set_regi_type(i, SCALAR_VALUE);
                states_[0]->set_regi_val(i, reg_info.smin_value_);
            }
        }
        for (int i = 0; i < prog_.size(); i++) {
            Insn &insn = prog_[i];
            u8 mode = BPF_MODE(insn._opcode);
            vector<int> use_regs = insn.getRegUses();
            State *cur_state = states_[i], *next_state = states_[i + 1];
            // If regs going to be used by this insn are not valid yet, give them random values.
            for (int reg_i: use_regs) {
                if (!cur_state->is_regi_valid(reg_i)) {
                    RegType reg_type = SCALAR_VALUE;
                    int type_off = 0;
                    RegInfo reg_info = testcase_init_info_->get_regi_info(reg_i);
                    if (reg_info.is_type_valid_ && reg_info.type_ != NOT_INIT) {
                        reg_type = reg_info.type_;
                        type_off = reg_info.off_;
                    }
                    int64_t reg_val = get_random_s64(reg_type);
                    // Apply range analysis results in testcase generation process.
                    if (reg_info.is_value_valid_)
                        reg_val = get_random_s64(reg_info.smin_value_, reg_info.smax_value_, reg_type);
                    // special cases: shift, div and mod
                    if (insn.isShiftX() && reg_i == insn._src_reg) {
                        if (BPF_CLASS(insn._opcode) == BPF_ALU64)
                            reg_val = get_random_s64(0, 64, reg_type);
                        else
                            reg_val = get_random_s64(0, 32, reg_type);
                    }
                    for (int state_i = i; state_i >= 0; state_i--) {
                        states_[state_i]->set_regi(reg_i, reg_val, reg_type, type_off);
                    }
                }
            }
            // If memory units going to be accessed by this insn are not valid yet, give them random values.
            if (insn.is_ldx()) {
                u64 addr = (u64) (cur_state->get_regi_val(insn._src_reg) + insn._off);
                auto addr_type = cur_state->get_regi_type(insn._src_reg);
                auto type_off = cur_state->get_regi_off(insn._src_reg);
                int size = bpfsize2byte(BPF_SIZE(insn._opcode));
                if (!cur_state->is_memi_valid(addr, size)) {
                    backprop_random_mem_val(i, addr, size, addr_type, type_off + insn._off);
                }
                insert_mem_addrs(addr, size, true);
            } else if (insn.is_st()) {
                u64 addr = (u64) (cur_state->get_regi_val(insn._dst_reg) + insn._off);
                auto addr_type = cur_state->get_regi_type(insn._dst_reg);
                auto type_off = cur_state->get_regi_off(insn._dst_reg);
                int size = bpfsize2byte(BPF_SIZE(insn._opcode));
                if (mode == BPF_MEM)
                    backprop_uninit_mem(i, addr, size, addr_type, type_off + insn._off);
                else if (mode == BPF_ATOMIC)
                    backprop_random_mem_val(i, addr, size, addr_type, type_off + insn._off);
                insert_mem_addrs(addr, size, false);
            }
            if (insn._opcode != 0 && BPF_CLASS(insn._opcode) == BPF_LD) {
                assert(i < prog_.size() - 1); // ensure ld is not the last insn
                Insn next_insn = prog_[i + 1];
                assert(next_insn._opcode == 0 && next_insn._dst_reg == 0
                       && next_insn._src_reg == 0 && next_insn._off == 0);
                insn_simulator.run(insn._opcode, insn._dst_reg, insn._src_reg, insn._off, insn._imm,
                                   cur_state, next_state, next_insn._imm);
            } else
                insn_simulator.run(insn._opcode, insn._dst_reg, insn._src_reg, insn._off, insn._imm,
                                   cur_state, next_state);
        }
//    for(State* state:states_)
//        state->print_state();
        compute_mem_areas(ST);
        compute_mem_areas(LD);
        compute_mem_areas(OVERALL);
    }

    void TestcaseGen::run_with_init_state(State *init_state) {
        assert(prog_.size() > 0);
        for (int i = 0; i <= prog_.size(); i++) {
            states_.emplace_back(new State(i));
        }
        for (int i = 0; i < MAX_BPF_REG; i++) {
            auto reg_info = testcase_init_info_->get_regi_info(i);
            if (reg_info.is_value_valid_ && reg_info.smin_value_ == reg_info.smax_value_) {
                states_[0]->set_regi_type(i, SCALAR_VALUE);
                states_[0]->set_regi_val(i, reg_info.smin_value_);
            }
        }
        states_[0]->copy_from_state(init_state);
        for (int i = 0; i < prog_.size(); i++) {
            Insn &insn = prog_[i];
            vector<int> use_regs = insn.getRegUses();
            State *cur_state = states_[i], *next_state = states_[i + 1];
            if (insn._opcode != 0 && BPF_CLASS(insn._opcode) == BPF_LD) {
                assert(i < prog_.size() - 1); // ensure ld is not the last insn
                Insn next_insn = prog_[i + 1];
                assert(next_insn._opcode == 0 && next_insn._dst_reg == 0
                       && next_insn._src_reg == 0 && next_insn._off == 0);
                insn_simulator.run(insn._opcode, insn._dst_reg, insn._src_reg, insn._off, insn._imm,
                                   cur_state, next_state, next_insn._imm);
            } else
                insn_simulator.run(insn._opcode, insn._dst_reg, insn._src_reg, insn._off, insn._imm,
                                   cur_state, next_state);
        }
        compute_mem_areas(ST);
        compute_mem_areas(LD);
        compute_mem_areas(OVERALL);
    }

    void TestcaseGen::run_with_redundant_init_state(State *init_state) {
        assert(prog_.size() > 0);
        for (int i = 0; i <= prog_.size(); i++) {
            states_.emplace_back(new State(i));
        }
        for (int i = 0; i < MAX_BPF_REG; i++) {
            auto reg_info = testcase_init_info_->get_regi_info(i);
            if (reg_info.is_value_valid_ && reg_info.smin_value_ == reg_info.smax_value_) {
                states_[0]->set_regi_type(i, SCALAR_VALUE);
                states_[0]->set_regi_val(i, reg_info.smin_value_);
            }
        }
        for (int i = 0; i < prog_.size(); i++) {
            Insn &insn = prog_[i];
            u8 mode = BPF_MODE(insn._opcode);
            vector<int> use_regs = insn.getRegUses();
            State *cur_state = states_[i], *next_state = states_[i + 1];
            // If regs going to be used by this insn are not valid yet, give them values.
            for (int reg_i: use_regs) {
                if (!cur_state->is_regi_valid(reg_i)) {
                    int64_t reg_val = init_state->get_regi_val(reg_i);
                    RegType reg_type = init_state->get_regi_type(reg_i);
                    int type_off = init_state->get_regi_off(reg_i);
                    RegInfo reg_info = testcase_init_info_->get_regi_info(reg_i);
                    if (reg_info.is_type_valid_)
                        reg_type = reg_info.type_;
//                    if (reg_info.is_value_valid_ && (reg_val < reg_info.smin_value_ || reg_val > reg_info.smax_value_))
//                        reg_val = get_random_s64(reg_info.smin_value_, reg_info.smax_value_, reg_type);
                    for (int state_i = i; state_i >= 0; state_i--) {
                        states_[state_i]->set_regi(reg_i, reg_val, reg_type, type_off);
                    }
                }
            }
            // If memory units going to be accessed by this insn are not valid yet, give them values.
            if (insn.is_ldx()) {
                u64 addr = (u64) (cur_state->get_regi_val(insn._src_reg) + insn._off);
                auto addr_type = cur_state->get_regi_type(insn._src_reg);
                auto type_off = cur_state->get_regi_off(insn._src_reg);
                int size = bpfsize2byte(BPF_SIZE(insn._opcode));
                vector<u8> mem_vals = init_state->get_mem_vals(addr, size);
                backprop_mem_vals(i, addr, mem_vals, addr_type, type_off + insn._off);
                insert_mem_addrs(addr, size, true);
            } else if (insn.is_st()) {
                u64 addr = (u64) (cur_state->get_regi_val(insn._dst_reg) + insn._off);
                auto addr_type = cur_state->get_regi_type(insn._dst_reg);
                auto type_off = cur_state->get_regi_off(insn._dst_reg);
                int size = bpfsize2byte(BPF_SIZE(insn._opcode));
                if (mode == BPF_MEM)
                    backprop_uninit_mem(i, addr, size, addr_type, type_off + insn._off);
                else if (mode == BPF_ATOMIC) {
                    vector<u8> mem_vals = init_state->get_mem_vals(addr, size);
                    backprop_mem_vals(i, addr, mem_vals, addr_type, type_off + insn._off);
                }
                insert_mem_addrs(addr, size, false);
            }
            if (insn._opcode != 0 && BPF_CLASS(insn._opcode) == BPF_LD) {
                assert(i < prog_.size() - 1); // ensure ld is not the last insn
                Insn next_insn = prog_[i + 1];
                assert(next_insn._opcode == 0 && next_insn._dst_reg == 0
                       && next_insn._src_reg == 0 && next_insn._off == 0);
                insn_simulator.run(insn._opcode, insn._dst_reg, insn._src_reg, insn._off, insn._imm,
                                   cur_state, next_state, next_insn._imm);
            } else
                insn_simulator.run(insn._opcode, insn._dst_reg, insn._src_reg, insn._off, insn._imm,
                                   cur_state, next_state);
        }
        compute_mem_areas(ST);
        compute_mem_areas(LD);
        compute_mem_areas(OVERALL);
    }

    u8 TestcaseGen::get_random_u8() {
        return (rand() >> 3) << 3;
    }

    s64 TestcaseGen::get_random_s64(const RegType &reg_type) {
        // rand() returns 'int'
        s64 num1 = rand();
        s64 num2 = rand();
        s64 res = (num1 << 32) + num2;
        // try not to randomize as zero (src_reg's value not allowed to be 0 in dive and mod)
        while (res == 0)
            res = rand();
//        if(reg_type!=SCALAR_VALUE)
//            res=(res>>3)<<3;
        res = (res >> 3)
                << 3;  // there may be situations like: ptr1 = ptr0 + scalar_value, so set all random values like this.
        return res;
    }

    s64 TestcaseGen::get_random_s64(s64 lower, s64 upper, const RegType &reg_type) {
        // rand() returns 'int'
        // TODO: not completely implemented by now
        s64 lower_h32 = lower >> 32, upper_h32 = upper >> 32,
                lower_l32 = lower, upper_l32 = upper;
        s64 interval_h = upper_h32 - lower_h32, interval_l = upper_l32 - lower_l32;
        s64 res_h = lower_h32, res_l = lower_l32;
        if (interval_h)
            res_h += rand() % interval_h;
        if (interval_l)
            res_l += rand() % interval_l;
        s64 res = (res_h << 32) + res_l;
//        if(reg_type!=SCALAR_VALUE)
//            res=(res>>3)<<3;
        if (res > 7)
            res = (res >> 3)
                    << 3;  // there may be situations like: ptr1 = ptr0 + scalar_value, so set all random values like this.
        return res;
    }

    int TestcaseGen::bpfsize2byte(int bpf_size) {
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

    void TestcaseGen::print_insns() {
        for (int i = 0; i < prog_.size(); i++) {
            cout << prog_[i] << endl;
        }
    }

    void TestcaseGen::print_states() {
        for (int i = 0; i < states_.size(); i++) {
            states_[i]->print_state();
        }
    }

    void TestcaseGen::backprop_reg_val(int start, u8 reg_i, s64 reg_val) {
        for (int i = 0; i <= start; i++) {
            states_[i]->set_regi_val(reg_i, reg_val);
        }
    }

    void TestcaseGen::backprop_random_mem_val(int start, u64 addr, int size, RegType mem_type, int type_off) {
        vector<u8> random_vals;
        for (int i = 0; i < size; i++) {
            random_vals.emplace_back(get_random_u8());
        }
        for (int i = 0; i <= start; i++) {
            for (int off = 0; off < size; off++) {
                if (!states_[i]->is_memi_valid(addr + off, 1))
                    states_[i]->set_memi(addr + off, random_vals[off], mem_type, type_off + off);
            }

        }
    }

    void TestcaseGen::backprop_mem_vals(int start, u64 addr, vector<u8> mem_vals, RegType type, int type_off) {
        for (int i = 0; i <= start; i++) {
            for (u64 off = 0; off < mem_vals.size(); off++) {
                if (!states_[i]->is_memi_valid(addr + off, 1))
                    states_[i]->set_memi(addr + off, mem_vals[off], type, type_off + off);
            }
        }
    }

    void TestcaseGen::backprop_uninit_mem(int start, u64 addr, int size, RegType type, int type_off) {
        for (int i = 0; i <= start; i++) {
            for (int off = 0; off < size; off++) {
                states_[i]->add_mem_unit(addr + off, type, type_off + off);
            }
        }
    }

    Testcase *TestcaseGen::gen_random_testcase() {
        run();
        State *init_state = new State(states_[0]), *final_state = new State(states_[states_.size() - 1]);
        u64 stack_start_addr = init_state->expand_mem_areas();
        u64 stack_start_addr2 = final_state->expand_mem_areas();
        assert(stack_start_addr == stack_start_addr2);
        if (stack_start_addr != 0) {
            ld_mem_areas_[stack_start_addr] += 3;
            st_mem_areas_[stack_start_addr] += 3;
            mem_areas_[stack_start_addr] += 3;
        }
        Testcase *res = new Testcase(init_state, final_state,
                                     ld_mem_areas_, st_mem_areas_, mem_areas_);
        clear();
        return res;
    }

    Testcase *TestcaseGen::gen_testcase_with_init_state(State *init_state) {
        run_with_init_state(init_state);
        State *final_state = new State(states_[states_.size() - 1]);
        Testcase *res = new Testcase(init_state, final_state,
                                     ld_mem_areas_, st_mem_areas_, mem_areas_);
        clear();
        return res;
    }

    void TestcaseGen::compute_mem_areas(MemType mem_type) {
        set<u64> target_mem_addrs;
        map<u64, int> target_mem_areas;
        switch (mem_type) {
            case LD:
                target_mem_addrs = ld_mem_addrs_;
                break;
            case ST:
                target_mem_addrs = st_mem_addrs_;
                break;
            case OVERALL:
                set_union(ld_mem_addrs_.begin(), ld_mem_addrs_.end(), st_mem_addrs_.begin(), st_mem_addrs_.end(),
                          inserter(target_mem_addrs, target_mem_addrs.begin()));
                break;
        }
        u64 last_addr = UINT64_MAX, start_addr = 0;
        for (auto it = target_mem_addrs.begin(); it != target_mem_addrs.end(); it++) {
            u64 cur_addr = *it;
            if ((last_addr == UINT64_MAX) || (last_addr + 1 != cur_addr)) {  // new memory area
                target_mem_areas.insert({cur_addr, 1});
                start_addr = cur_addr;
            } else {
                target_mem_areas.at(start_addr) += 1;
            }
            last_addr = cur_addr;
        }
        switch (mem_type) {
            case LD:
                ld_mem_areas_ = target_mem_areas;
                break;
            case ST:
                st_mem_areas_ = target_mem_areas;
                break;
            case OVERALL:
                mem_areas_ = target_mem_areas;
                break;
        }
    }

    map<u64, int> TestcaseGen::get_ld_mem_areas() {
        return ld_mem_areas_;
    }

    map<u64, int> TestcaseGen::get_st_mem_areas() {
        return st_mem_areas_;
    }

    map<u64, int> TestcaseGen::get_mem_areas() {
        return mem_areas_;
    }

    State *TestcaseGen::get_init_state() {
        return states_[0];
    }

    State *TestcaseGen::get_final_state() {
        return states_[states_.size() - 1];
    }

    void TestcaseGen::print_mem_areas(TestcaseGen::MemType mem_type) {
        map<u64, int> target_mem_areas;
        switch (mem_type) {
            case LD:
                target_mem_areas = ld_mem_areas_;
                printf("ld_mem_areas: ");
                break;
            case ST:
                target_mem_areas = st_mem_areas_;
                printf("st_mem_areas: ");
                break;
            case OVERALL:
                target_mem_areas = mem_areas_;
                printf("mem_areas: ");
                break;
        }
        for (auto it = target_mem_areas.begin(); it != target_mem_areas.end(); it++) {
            printf("[0x%lx: %d bytes], ", it->first, it->second);
        }
        cout << endl;
    }

    void TestcaseGen::print_mem_areas() {
        print_mem_areas(LD);
        print_mem_areas(ST);
        print_mem_areas(OVERALL);
    }

    Testcase *TestcaseGen::gen_testcase_with_half_redundant_init_state(State *init_state) {

    }

    Testcase *TestcaseGen::gen_testcase_with_redundant_init_state(State *init_state) {
        run_with_redundant_init_state(init_state);
        State *new_init_state = new State(states_[0]), *new_final_state = new State(states_[states_.size() - 1]);
        Testcase *res = new Testcase(new_init_state, new_final_state,
                                     ld_mem_areas_, st_mem_areas_, mem_areas_);
//        for (int i = 0; i < states_.size(); i++)
//            states_[i]->print_state();
        clear();
        return res;
    }

    void TestcaseGen::clear() {
        for (State *state: states_)
            delete state;
        states_.clear();
        ld_mem_addrs_.clear();
        ld_mem_areas_.clear();
        st_mem_addrs_.clear();
        st_mem_areas_.clear();
        mem_areas_.clear();
    }
}