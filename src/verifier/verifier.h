#ifndef SUPERBPF_VERIFIER_H
#define SUPERBPF_VERIFIER_H

#include <iostream>

#include <linux/bpf.h>

#include "src/instruction/insn.h"
#include "src/state/state.h"

namespace superbpf {

    class Verifier {
        static long long hit_times_;

        static int opt_level_;

        static int bpf_size_to_bytes(int bpf_size);

        /* Refers to function 'is_pointer_value' and '__is_pointer_value' in verifier.c */
        static bool may_be_pointer_value(State *cur_state, int regno);

        static bool must_be_pointer_value(State *cur_state, int regno);

        static bool type_is_pkt_pointer(RegType type);

        static bool reg_is_pkt_pointer(Reg *reg);

        static bool type_is_sk_pointer(RegType type);

        static bool is_ctx_reg(State *cur_state, int regno);

        static bool is_sk_reg(State *cur_state, int regno);

        static bool is_pkt_reg(State *cur_state, int regno);

        static bool is_flow_key_reg(State *cur_state, int regno);

        static bool may_access_direct_pkt_data(State *cur_state,
                                               const struct bpf_call_arg_meta *meta,
                                               bpf_access_type t);

        static int check_map_access_type(State *cur_state, u32 regno,
                                         int off, int size, bpf_access_type type);

        static int check_map_access(State *cur_state, u32 regno,
                                    int off, int size, bool zero_size_allowed);

        static int
        check_mem_region_access(State *cur_state, u32 regno, int off, int size, u32 mem_size, bool zero_size_allowed);

        static int check_flow_keys_access(State *cur_state, int off, int size);

        /* Refers to function 'check_alu_op' in verifier.c. */
        static int check_alu_op(State *cur_state, const Insn &insn);

        static int check_ptr_alignment(State *cur_state, Reg *reg, int off, int size, bool strict_alignment_once);

        static int check_pkt_ptr_alignment(State *cur_state, Reg *reg, int off, int size, bool strict);

        static int check_generic_ptr_alignment(State *cur_state, Reg *reg, int off, int size, bool strict);

        /* Refers to function 'check_mem_access' in verifier.c. */
        static int check_mem_access(State *cur_state, u32 regno,
                                    int off, int bpf_size, bpf_access_type t,
                                    int value_regno, bool strict_alignment_once);

        static int check_xadd(State *cur_state, const Insn &insn);

        static void hit(){
            hit_times_++;
        }

    public:
        static void set_opt_level_2();
        /* Refers to function 'do_check' in verifier.c, add parameter 'insn'. */
        static int do_check(State *cur_state, const Insn &insn);

        static void refresh_hit_times(){
            hit_times_=0;
        }

        static long long get_hit_times(){
            return hit_times_;
        }
    };
}


#endif //SUPERBPF_VERIFIER_H
