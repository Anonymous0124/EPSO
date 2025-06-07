#ifndef SUPERBPF_TESTCASE_TESTCASEGEN_H
#define SUPERBPF_TESTCASE_TESTCASEGEN_H

#include <set>

#include "z3++.h"

#include "src/cfg/cfg.h"
#include "src/instruction/insn.h"
#include "src/instruction/insn_simulator.h"
#include "src/state/state.h"
#include "testcase.h"

namespace superbpf {
    /*
     * Testcase Generator.
     *
     * Functionality: generates testcases.
     */
    class TestcaseGen {
    public:
        TestcaseGen() {
            srand((unsigned) time(NULL));  // set seed
            testcase_init_info_ = new StaticInfo();
        }

        ~TestcaseGen() {
            for (State *state: states_)
                delete state;
//            if(testcase_init_info_!= nullptr)
//                delete testcase_init_info_;
//            if(testcase_init_info_!= nullptr)
//                delete testcase_init_info_;
        }

        /* set target instruction sequences, optional parameter: initial information */
        void set_prog(vector<Insn> &target, const StaticInfo &init_info = StaticInfo());

        /* Set live-out regs. */
        void set_live_out_regs(vector<u8> regs);

        /* Get a stochastically generated testcase, using 'testcase_init_info_'. */
        Testcase *gen_random_testcase();

        Testcase *gen_testcase_with_init_state(State *init_state);

        Testcase *gen_testcase_with_half_redundant_init_state(State *init_state);

        Testcase *gen_testcase_with_redundant_init_state(State *init_state);

        map<u64, int> get_ld_mem_areas();

        map<u64, int> get_st_mem_areas();

        map<u64, int> get_mem_areas();

        State *get_init_state();

        State *get_final_state();

        void print_insns();

        void print_states();

        void print_mem_areas();

    private:
        /* target instruction sequences */
        vector<Insn> prog_;

        StaticInfo *testcase_init_info_;

        vector<State *> states_;

        vector<u8> regs_live_out_;

        set<u64> ld_mem_addrs_;

        set<u64> st_mem_addrs_;

        map<u64, int> ld_mem_areas_;

        map<u64, int> st_mem_areas_;

        map<u64, int> mem_areas_;
        enum MemType {
            LD,
            ST,
            OVERALL
        };

        /* simulates the execution of insns */
        InsnSimulator insn_simulator;

        void backprop_reg_val(int start, u8 reg_i, s64 reg_val);

        /* Back propagate random memory value. */
        void backprop_random_mem_val(int start, u64 addr, int size,RegType mem_type,int type_off);

        void backprop_mem_vals(int start, u64 addr, vector<u8> mem_vals,RegType type,int type_off);

        void backprop_uninit_mem(int start, u64 addr, int size,RegType mem_type,int type_off);

        /* Get a random s64 number.*/
        u8 get_random_u8();

        /* Get a random s64 number.*/
        s64 get_random_s64(const RegType &reg_type);

        /* Get a random s64 number in [lower, upper).*/
        s64 get_random_s64(s64 lower, s64 upper, const RegType &reg_type);

        void insert_mem_addrs(u64 target_addr, int target_size, bool is_ld);

        /* Randomize initial state when needed and compute final state (assuming 'prog_' is set by now) */
        void run();

        void run_with_init_state(State *init_state);

        void run_with_redundant_init_state(State *init_state);

        void compute_mem_areas(MemType mem_type);

        void print_mem_areas(MemType mem_type);

        int bpfsize2byte(int bpf_size);

        void clear();
    };
}

#endif //SUPERBPF_TESTCASE_TESTCASEGEN_H