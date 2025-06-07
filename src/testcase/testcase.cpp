#include "src/testcase/testcase.h"

using namespace std;
using namespace superbpf;

namespace superbpf {

    State *Testcase::init_state() {
        return init_state_;
    }

    State *Testcase::final_state() {
        return final_state_;
    }

    map<u64, int> Testcase::get_ld_mem_areas() {
        return ld_mem_areas_;
    }

    map<u64, int> Testcase::get_st_mem_areas() {
        return st_mem_areas_;
    }

    map<u64, int> Testcase::get_mem_areas() {
        return mem_areas_;
    }

    void Testcase::print_testcase() {
        printf("Testcase content:\n");
        printf("Initial state:\n");
        init_state_->print_state();
        printf("Final state:\n");
        final_state_->print_state();
        printf("ld_areas:\n");
        for (auto it: ld_mem_areas_) {
            printf("[0x%lx, %d] ", it.first, it.second);
        }
        printf("\n");
        printf("st_areas:\n");
        for (auto it: st_mem_areas_) {
            printf("[0x%lx, %d] ", it.first, it.second);
        }
        printf("\n");
        printf("mem_areas:\n");
        for (auto it: mem_areas_) {
            printf("[0x%lx, %d] ", it.first, it.second);
        }
        printf("\n");

        for (int i = 0; i < 60; i++)
            printf("-");
        printf("\n");
    }

}

