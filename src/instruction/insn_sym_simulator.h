#ifndef SUPERBPF_INSTRUCTION_INSNSYMSIMULATOR_H
#define SUPERBPF_INSTRUCTION_INSNSYMSIMULATOR_H

#include "z3++.h"

#include "ebpf/bpf.h"
#include "symstate/sym_regs.h"
#include "symstate/sym_memory.h"

namespace superbpf {
/*
 * class InsnSymSimulator
 * Simulates the effects of instructions when states are symbolic.
 * Effects are reflected by state transition.
 *
 * Mainly used by class 'Validator'.
 */
    class InsnSymSimulator {
    private:
        /* host endian : 1 for little endian, 2 for big endian */
        static char host_endian_;
        static bool is_target_;

    public:
        static void set_target(bool is_target);
        /* BPF_ALU & BPF_ALU64 */
        static void bpf_alu_func(z3::context &c, u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm,
                                 SymRegsValidation &regs, SymMemoryValidation &mem);

        /* NOP */
        static void nop(z3::context &c, u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm,
                        SymRegsValidation &regs, SymMemoryValidation &mem);

        static void bpf_map_store(z3::context &c, u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm,
                              SymRegsValidation &regs, SymMemoryValidation &mem);
        /* BPF_MEM | BPF_ST & BPF_MEM | BPF_STX */
        static void bpf_store(z3::context &c, u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm,
                              SymRegsValidation &regs, SymMemoryValidation &mem);

        static void bpf_map_load(z3::context &c, u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, SymRegsValidation &regs,
                          SymMemoryValidation &mem);

        /* BPF_MEM | BPF_LDX */
        static void bpf_load(z3::context &c, u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm,
                             SymRegsValidation &regs, SymMemoryValidation &mem);

        static void bpf_map_atomic(z3::context &c, u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, SymRegsValidation &regs,
        SymMemoryValidation &mem);

        /* BPF_ATOMIC | BPF_STX */
        static void bpf_atomic(z3::context &c, u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm,
                               SymRegsValidation &regs, SymMemoryValidation &mem);

        /* set host endian */
        static void set_host_endian(char host_endian);

    private:
        static void bpf_end(z3::context &c, u8 code, u8 dst_reg, s32 imm, SymRegsValidation &regs);

        static int bpf_size2byte(int bpf_size);
    };
}


#endif //SUPERBPF_INSTRUCTION_INSNSYMSIMULATOR_H
