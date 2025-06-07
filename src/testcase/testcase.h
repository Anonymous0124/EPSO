#ifndef SUPERBPF_TESTCASE_TESTCASE_H
#define SUPERBPF_TESTCASE_TESTCASE_H

#include <map>

#include "z3++.h"

#include "src/ebpf/bpf.h"
#include "src/state/state.h"

using std::map;
using std::vector;

namespace superbpf {
    class Testcase {
        State *init_state_;
        State *final_state_;
        map<u64, int> ld_mem_areas_;  // load memory areas
        map<u64, int> st_mem_areas_;  // store memory areas
        map<u64, int> mem_areas_;  // store/load memory areas

    public:
        Testcase() {}

        ~Testcase() {
            delete init_state_;
            delete final_state_;
        }

        Testcase(map<u8, s64> init_reg_vals, map<u8, s64> final_reg_vals, map<u64, vector<u8>> init_mem_vals,
                 map<u64, vector<u8>> final_mem_vals,
                 map<u64, int> ld_mem_areas, map<u64, int> st_mem_areas, map<u64, int> mem_areas) {
            init_state_ = new State(0);
            init_state_->set_reg_mem_vals(init_reg_vals, init_mem_vals, mem_areas);
            final_state_ = new State(0);
            final_state_->set_reg_mem_vals(final_reg_vals, final_mem_vals, mem_areas);
            ld_mem_areas_ = ld_mem_areas;
            st_mem_areas_ = st_mem_areas;
            mem_areas_ = mem_areas;
        }

        Testcase(State *init_state, State *final_state,
                 map<u64, int> &ld_mem_areas, map<u64, int> &st_mem_areas,
                 map<u64, int> &mem_areas) {
            init_state_ = init_state;
            final_state_ = final_state;
            ld_mem_areas_ = ld_mem_areas;
            st_mem_areas_ = st_mem_areas;
            mem_areas_ = mem_areas;
        }

        Testcase(Testcase *testcase) {
            init_state_ = new State(testcase->init_state_);
            final_state_ = new State(testcase->final_state_);
            ld_mem_areas_ = testcase->ld_mem_areas_;
            st_mem_areas_ = testcase->st_mem_areas_;
            mem_areas_ = testcase->mem_areas_;
        }

        State *init_state();

        State *final_state();

        map<u64, int> get_ld_mem_areas();

        map<u64, int> get_st_mem_areas();

        map<u64, int> get_mem_areas();

        void print_testcase();
    };
}

#endif //SUPERBPF_TESTCASE_TESTCASE_H
