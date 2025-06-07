#ifndef SUPERBPF_STATE_STATE_H
#define SUPERBPF_STATE_STATE_H

#include <set>

#include "src/state/memory.h"
#include "src/state/regs.h"

namespace superbpf {
    struct StateDistance {
        int diff_reg_num;  // how many regs are different
        std::vector<int> diff_mem_seg;  // store the maximum interval of different memory segments
        int least_ld_insns;  // the least num of ld/alu insns needed to provide values for st insns
        int least_st_insns;  // the least num of store insns need

        int total_dis() {
            return diff_reg_num + least_st_insns;
        }
    };

    class State {
        int version_;
        Regs *regs_;
        Memory *memory_;
        bool strict_alignment_;
        int testcase_no_;
    public:
        State(int version) {
            version_ = version;
            regs_ = new Regs(version_, MAX_BPF_REG);
            memory_ = new Memory(version_);
            strict_alignment_ = true;
            testcase_no_ = -1;
        }

        State(State *state) {
            version_ = state->version_;
            regs_ = new Regs(version_, MAX_BPF_REG);
            memory_ = new Memory(version_);
            regs_->copy_from_regs(state->regs_);
            memory_->copy_from_memory(state->memory_);
            strict_alignment_ = state->strict_alignment_;
            testcase_no_ = -1;
        }

        ~State() {
            delete regs_;
            delete memory_;
        }

        int version() const;

        bool strict_alignment() const;

        bool is_regi_valid(u8 reg_i);

        s64 get_regi_val(u8 reg_i);

        RegType get_regi_type(u8 reg_i);

        int get_regi_off(u8 reg_i);

        Reg *get_regi(u8 reg_i);

        std::set<u8> get_valid_reg_ids();

        bool is_memi_valid(u64 addr, int size);

        /* Get memory['addr', 'addr' + 'size')' value. */
        s64 get_memi_val(u64 addr, int size);

        /* Get memory['addr', 'addr' + 'size')' value. */
        vector<u8> get_mem_vals(u64 addr, int size);

        /* Set r['reg_i'].value as 'val' */
        void set_regi_val(u8 reg_i, s64 val);

        /* Set r['reg_i'].type as 'type' */
        void set_regi_type(u8 reg_i, RegType type);

        void set_regi_off(u8 reg_i, int off);

        void set_regi(u8 reg_i, s64 val, RegType type,int type_off);

        /* Set memory['addr'] by value 'val' */
        void set_memi_val(u64 addr, u8 val);

        /* Set memory['addr', 'addr' + 'size') by value 'val' */
        void set_memi_val(u64 addr, int size, s64 val);

        void set_memi(u64 addr,u8 val,RegType mem_type,int type_off);

        void set_mems(u64 addr,int size,s64 val,RegType mem_type,int type_off);

        void add_mem_unit(u64 addr,RegType mem_type,int type_off);

        void set_stk_valid(u64 base_addr);

        void set_reg_mem_vals(std::map<u8, s64> reg_vals, std::map<u64, std::vector<u8>> mem_vals,
                              std::map<u64, int> mem_areas);

        /* Set regs' and memory's values by copying state 'state' */
        void copy_from_state(State *state);

        void set_testcase_no(int no);

        u64 expand_mem_areas();

        void refresh();

        bool check_equivalence(State *state, const std::set<int>& live_regs,const std::map<u8,std::set<int>>& live_memory,
                               const StaticInfo& init_static_info);

        /* Compute the distance with state 'target'.
         * 'Distance' means the least number of insns needed to transfer from current state to state 'target'.
         * Reg distance and memory distance are computed separately. */
        StateDistance compute_dis(State *target, const std::set<int>& live_regs,const std::map<u8,std::set<int>>& live_memory);

        int compute_mem_similarity(State *target,const std::map<u8,std::set<int>>& live_memory);

        bool operator<(const State &state) const;

        bool operator==(const State &state) const {
            return (testcase_no_ == state.testcase_no_) && (*regs_ == *state.regs_) && (*memory_ == *state.memory_);
        }

        void print_state();
    };
}

#endif //SUPERBPF_STATE_STATE_H
