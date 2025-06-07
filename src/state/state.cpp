#include "state.h"

using namespace std;
using namespace superbpf;

namespace superbpf {

    int State::version() const {
        return version_;
    }

    bool State::strict_alignment() const {
        return strict_alignment_;
    }

    bool State::is_regi_valid(u8 reg_i) {
        return (*regs_)[reg_i]->is_valid();
    }

    s64 State::get_regi_val(u8 reg_i) {
        return regs_->get_regi_val(reg_i);
    }

    RegType State::get_regi_type(u8 reg_i) {
        return regs_->get_regi_type(reg_i);
    }

    int State::get_regi_off(u8 reg_i) {
        return regs_->get_regi_off(reg_i);
    }

    Reg *State::get_regi(u8 reg_i) {
        return regs_->get_regi(reg_i);
    }

    set <u8> State::get_valid_reg_ids() {
        return regs_->get_valid_reg_ids();
    }

    bool State::is_memi_valid(u64 addr, int size) {
        return memory_->is_valid(addr, size);
    }

    s64 State::get_memi_val(u64 addr, int size) {
        return memory_->get_val(addr, size);
    }

    vector<u8> State::get_mem_vals(u64 addr, int size) {
        return memory_->get_vals(addr, size);
    }

    void State::set_regi_val(u8 reg_i, s64 val) {
        regs_->set_regi_val(reg_i, val);
    }

    void State::set_regi_type(u8 reg_i, RegType type) {
        regs_->set_regi_type(reg_i, type);
    }

    void State::set_regi_off(u8 reg_i, int off) {
        regs_->set_regi_off(reg_i, off);
    }

    void State::set_regi(u8 reg_i, s64 val, RegType type,int type_off) {
        regs_->set_regi(reg_i, val, type,type_off);
    }

    void State::set_memi_val(u64 addr, u8 val) {
        memory_->set_val(addr, val);
    }

    void State::set_memi_val(u64 addr, int size, s64 val) {
        memory_->set_val(addr, size, val);
    }

    void State::set_memi(u64 addr,u8 val,RegType mem_type,int type_off){
        memory_->set_mem_unit(addr,val,mem_type,type_off);
    }

    void State::set_mems(u64 addr,int size,s64 val,RegType mem_type,int type_off){
        memory_->set_mems(addr,size,val,mem_type,type_off);
    }

    void State::add_mem_unit(u64 addr,RegType mem_type,int type_off) {
        memory_->add_mem_unit(addr,mem_type,type_off);
    }

    void State::set_stk_valid(u64 base_addr){
        memory_->set_stk_valid(base_addr);
    }

    void State::set_reg_mem_vals(map<u8, s64> reg_vals, map<u64, vector<u8>> mem_vals, map<u64, int> mem_areas) {
        regs_->set_regs_val(reg_vals);
        memory_->set_mem_vals(mem_vals, mem_areas);
    }

    void State::copy_from_state(State *state) {
        regs_->copy_from_regs(state->regs_);
        memory_->copy_from_memory(state->memory_);
    }

    void State::set_testcase_no(int no) {
        testcase_no_ = no;
    }

    u64 State::expand_mem_areas(){
        return memory_->expand_mem_areas();
    }

    void State::refresh() {
        regs_->refresh();
        memory_->refresh();
    }

    bool State::check_equivalence(State *state, const std::set<int>& live_regs,const std::map<u8,std::set<int>>& live_memory,
                                  const StaticInfo& init_static_info) {
        bool res = true;
        res = res && regs_->check_equivalence(state->regs_, live_regs,init_static_info);
        res = res && memory_->check_equivalence(state->memory_,live_memory);
        return res;
    }

    StateDistance State::compute_dis(State *target, const std::set<int>& live_regs,const std::map<u8,std::set<int>>& live_memory) {
        StateDistance sd;
        sd.diff_reg_num = regs_->compute_dis(target->regs_, live_regs);
        vector<vector<u8>> target_vals = memory_->compute_diff(target->memory_,live_memory);
        sd.least_st_insns = target_vals.size();
        sd.least_ld_insns = sd.least_st_insns;
        for (vector<u8> target_val: target_vals) {
            for (int i = 0; i < regs_->size(); i++) {
                if (regs_->is_regi_valid(i)) {
                    s64 reg_val = regs_->get_regi_val(i);
                    int j = target_val.size();
                    for (; j >= 0; j--) {
                        if (target_val[j] == (u8) reg_val) {
                            reg_val >>= 8;
                        } else
                            break;
                    }
                    if (j == -1) {
                        sd.least_ld_insns--;
                        break;
                    }

                }
            }
        }
        return sd;
    }

    int State::compute_mem_similarity(State *target,const std::map<u8,std::set<int>>& live_memory) {
        return memory_->compute_similarity(target->memory_,live_memory);
    }

    bool State::operator<(const State &state) const {
        if (*regs_ < *state.regs_)
            return true;
        else if (*regs_ == *state.regs_) {
            if (*memory_ < *state.memory_)
                return true;
            else
                return false;
        } else
            return false;
    }

    void State::print_state() {
        regs_->print_regs();
        memory_->print_memory();
        printf("\n");
    }
}