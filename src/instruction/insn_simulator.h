#ifndef SUPERBPF_INSTRUCTION_INSNSIMULATOR_H
#define SUPERBPF_INSTRUCTION_INSNSIMULATOR_H

#include "src/instruction/insn.h"
#include "src/state/state.h"

using std::set;

namespace superbpf {
    /*
     * Simulates the effects of instructions.
     * Effects are reflected by state transition from 'cur_state' to 'next_state'.
     */
    class InsnSimulator {
        /* host endian : 1 for little endian, 2 for big endian */
        static char host_endian_;

        set <u64> last_ld_addrs_;

        static bpf_prog_type prog_type_;
        static bpf_attach_type attach_type_;

        uint16_t bswap16(uint16_t int16);

        uint32_t bswap32(uint32_t int32);

        uint64_t bswap64(uint64_t int64);

        void bpf_alu(u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm,
                     State *cur_state, State *next_state);

        void bpf_ldx(u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm,
                     State *cur_state, State *next_state);

        void bpf_ld_imm(u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, s32 imm2,
                        State *cur_state, State *next_state);

        void bpf_ld(u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, s32 imm2,
                    State *cur_state, State *next_state);

        void bpf_store(u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm,
                       State *cur_state, State *next_state);

        void bpf_atomic(u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm,
                        State *cur_state, State *next_state);

        void nop(State *cur_state, State *next_state);

        int bpfsize2byte(int bpf_size);

    public:

        static void set_prog_attach_type(bpf_prog_type prog_type,bpf_attach_type attach_type);

        static void set_host_endian(char host_endian);

        void run(u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm,
                 State *cur_state, State *next_state, s32 imm2 = 0);

        void run(Insn &insn, State *cur_state, State *next_state, s32 imm2 = 0);

        set <u64> &last_ld_addrs();

        static int64_t compute_val(u8 op,int64_t dst_val,int64_t src_val);
    };
}


#endif //SUPERBPF_INSTRUCTION_INSNSIMULATOR_H