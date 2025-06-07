#include "insn_simulator.h"

#include "src/ebpf/ctx.h"
using namespace std;
using namespace superbpf;

namespace superbpf {
    char InsnSimulator::host_endian_ = 0;
    bpf_prog_type InsnSimulator::prog_type_=BPF_PROG_TYPE_UNSPEC;
    bpf_attach_type InsnSimulator::attach_type_=BPF_CGROUP_INET_INGRESS;  // init

    uint16_t InsnSimulator::bswap16(uint16_t int16) {
        uint16_t res = 0;
        for (int i = 0; i < 2; i++) {
            res = (res << 8) + (u8) int16;
            int16 >>= 8;
        }
        return res;
    }

    uint32_t InsnSimulator::bswap32(uint32_t int32) {
        uint32_t res = 0;
        for (int i = 0; i < 4; i++) {
            res = (res << 8) + (u8) int32;
            int32 >>= 8;
        }
        return res;
    }

    uint64_t InsnSimulator::bswap64(uint64_t int64) {
        uint64_t res = 0;
        for (int i = 0; i < 8; i++) {
            res = (res << 8) + (u8) int64;
            int64 >>= 8;
        }
        return res;
    }

    void
    InsnSimulator::bpf_alu(u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, State *cur_state, State *next_state) {

        int insn_class = BPF_CLASS(code), insn_op = BPF_OP(code), insn_src = BPF_SRC(code);
        assert((insn_class == BPF_ALU64) || (insn_class == BPF_ALU));

        s64 dst_val = 0, src_val = imm, res_val = 0; // BPF_ALU64
        RegType res_type = cur_state->get_regi_type(dst_reg);
        int res_off=0;
        if (insn_op != BPF_MOV)
            dst_val = cur_state->get_regi_val(dst_reg);
        if (insn_src == BPF_X && insn_op != BPF_END && insn_op != BPF_NEG) {
            src_val = cur_state->get_regi_val(src_reg);
            if (cur_state->get_regi_type(dst_reg) != SCALAR_VALUE &&
                cur_state->get_regi_type(src_reg) != SCALAR_VALUE) {
                res_type = SCALAR_VALUE;
            }
        }
        if (insn_class == BPF_ALU && insn_op != BPF_END) {
            dst_val = dst_val&0xffffffff;
            src_val = src_val&0xffffffff;
        }
//        if ((insn_op == BPF_DIV) || (insn_op == BPF_MOD))
//            assert(src_val != 0);
        switch (insn_op) {
            case BPF_ADD:
                res_val = dst_val + src_val;
                break;
            case BPF_SUB:
                res_val = dst_val - src_val;
                break;
            case BPF_MUL:
                res_val = dst_val * src_val;
                break;
            case BPF_DIV:
                if (src_val == 0) {
                    if (dst_val > 0)
                        res_val = INT64_MAX;
                    else
                        res_val = INT64_MIN;
                } else {
//                    assert(dst_val==-9223372036854775808);
                    res_val = (double) dst_val / (double) src_val;
                }
                break;
            case BPF_OR:
                res_val = dst_val | src_val;
                break;
            case BPF_AND:
                res_val = dst_val & src_val;
                break;
            case BPF_LSH:
                res_val = dst_val << src_val;
                break;
            case BPF_RSH:
                res_val = (u64) dst_val >> src_val;
                break;
            case BPF_NEG:
                res_val = -dst_val;
                break;
            case BPF_MOD:
                if (src_val == 0) {
                    if (dst_val > 0)
                        res_val = INT64_MAX;
                    else
                        res_val = INT64_MIN;
                } else
                    res_val = dst_val % src_val;
                break;
            case BPF_XOR:
                res_val = dst_val ^ src_val;
                break;
            case BPF_MOV:
                res_val = src_val;
                if (insn_src == BPF_X) {
                    res_type = cur_state->get_regi_type(src_reg);
                    res_off=cur_state->get_regi_off(src_reg);
                }
                else
                    res_type = SCALAR_VALUE;
                break;
            case BPF_ARSH:
                res_val = dst_val >> src_val;
                break;
            case BPF_END:
                assert(host_endian_ == 1 || host_endian_ == 2);
                assert(insn_src == BPF_TO_LE || BPF_TO_BE);
                assert((imm == 16) || (imm == 32) || (imm == 64));
                if ((insn_src == BPF_TO_LE && host_endian_ == 2) || (insn_src == BPF_TO_BE && host_endian_ == 1)) {
                    switch (imm) {
                        case 16:
                            res_val = bswap16((u16) dst_val);
                            break;
                        case 32:
                            res_val = bswap32((u32) dst_val);
                            break;
                        case 64:
                            res_val = bswap64((u64) dst_val);
                            break;
                    }
                }
                break;
        }

        next_state->copy_from_state(cur_state);
        next_state->set_regi_type(dst_reg, res_type);
        next_state->set_regi_val(dst_reg, res_val);
        if(res_type!=SCALAR_VALUE){
            if(insn_src==BPF_K){
                res_off = compute_val(insn_op, cur_state->get_regi_off(dst_reg), imm);
            }
            else{
                if(insn_op!=BPF_MOV)
                    res_off=cur_state->get_regi_off(dst_reg);
                // todo: attention
            }
        }
        next_state->set_regi_off(dst_reg,res_off);
    }

    void
    InsnSimulator::bpf_ldx(u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, State *cur_state, State *next_state) {
        /*
         * BPF_MEM | <size> | BPF_LDX means: dst = *(size *) (src + offset)
         */
        int insn_class = BPF_CLASS(code), insn_mode = BPF_MODE(code), size = bpfsize2byte(BPF_SIZE(code));
        next_state->copy_from_state(cur_state);
        assert(insn_class == BPF_LDX && insn_mode == BPF_MEM);
        u64 addr = (u64) (cur_state->get_regi_val(src_reg) + off);
        s64 val = cur_state->get_memi_val(addr, size);
        next_state->set_regi_val(dst_reg, val);
        RegType src_reg_type = cur_state->get_regi_type(src_reg);
        if (src_reg_type == PTR_TO_CTX) {
            RegType reg_type = SCALAR_VALUE;
//            bool is_valid_access = is_ctx_valid_access(prog_type_, attach_type_, off, size, BPF_READ,
//                                                       reg_type);
            next_state->set_regi_type(dst_reg, reg_type);
            next_state->set_regi_off(dst_reg,0);
        }
        else if (src_reg_type == PTR_TO_STACK)
            next_state->set_regi_type(dst_reg, STACK_VALUE);
        else  // TODO
            next_state->set_regi_type(dst_reg, SCALAR_VALUE);
        for (u64 i = addr; i < addr + size; i++)
            last_ld_addrs_.insert(i);
    }

    void InsnSimulator::bpf_ld_imm(u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, s32 imm2,
                                   State *cur_state, State *next_state) {
        /*
         * code = BPF_IMM | BPF_DW | BPF_LD, src = 0x1: dst = map_by_fd(imm)
         */
        next_state->copy_from_state(cur_state);
        switch (src_reg) {
            case 1:
                // referring to function 'check_ld_imm' in verifier.c
                u64 new_imm = ((u64) (u32) imm) | ((u64) (u32) imm2) << 32;
                next_state->set_regi(dst_reg, new_imm, CONST_PTR_TO_MAP,0);
                break;
        }
    }

    void InsnSimulator::bpf_ld(u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, s32 imm2,
                               State *cur_state, State *next_state) {
        u8 bpf_mode = BPF_MODE(code);
        assert(BPF_CLASS(code) == BPF_LD && BPF_SIZE(code) == BPF_DW);
        switch (bpf_mode) {
            case BPF_IMM:
                bpf_ld_imm(code, dst_reg, src_reg, off, imm, imm2, cur_state, next_state);
                break;
        }
    }

    void
    InsnSimulator::bpf_store(u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, State *cur_state, State *next_state) {
        /*
         * BPF_MEM | <size> | BPF_STX means: *(dst + offset) = src
         */
        int insn_class = BPF_CLASS(code), insn_mode = BPF_MODE(code), size = bpfsize2byte(BPF_SIZE(code));
        next_state->copy_from_state(cur_state);
        u64 addr = (u64) (cur_state->get_regi_val(dst_reg) + off);
        auto type=cur_state->get_regi_type(dst_reg);
        auto type_off=cur_state->get_regi_off(dst_reg);
        s64 val;
        if (insn_class == BPF_STX) {
            if (insn_mode == BPF_MEM) {
                val = cur_state->get_regi_val(src_reg);
            }
        } else if (insn_class == BPF_ST) {
            if (insn_mode == BPF_MEM) {
                val = imm;
            }
        }
        next_state->set_mems(addr, size, val,type,type_off+off);
//        if(type==PTR_TO_STACK){
//            next_state->set_stk_valid(addr);
//        }
    }

    void
    InsnSimulator::bpf_atomic(u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, State *cur_state, State *next_state) {
        /*
         * Atomic operations are operations that operate on memory and can not be interrupted or corrupted
         * by other access to the same memory region by other eBPF programs or means outside of this specification.
         *
         * All atomic operations supported by eBPF are encoded as store operations that use the BPF_ATOMIC mode modifier as follows:
         *      BPF_ATOMIC | BPF_W | BPF_STX for 32-bit operations
         *      BPF_ATOMIC | BPF_DW | BPF_STX for 64-bit operations
         * 8-bit and 16-bit wide atomic operations are not supported.
         *
         * The 'imm' field is used to encode the actual atomic operation. Simple atomic operation use a subset of the values defined
         * to encode arithmetic operations in the 'imm' field to encode the atomic operation:
         *      BPF_ADD, BPF_OR, BPF_AND, BPF_XOR
         *
         * BPF_ATOMIC | BPF_W  | BPF_STX with 'imm' = BPF_ADD means:
         *      *(u32 *)(dst + offset) += src
         * BPF_ATOMIC | BPF_DW | BPF_STX with 'imm' = BPF ADD means:
         *      *(u64 *)(dst + offset) += src
         */
        int insn_class = BPF_CLASS(code), insn_mode = BPF_MODE(code), byte_size = bpfsize2byte(BPF_SIZE(code));
        assert(insn_class == BPF_STX || insn_class == BPF_ST);
        assert(insn_mode == BPF_ATOMIC);
        assert(byte_size == 4 || byte_size == 8);
        next_state->copy_from_state(cur_state);
        u64 addr = (u64) (cur_state->get_regi_val(dst_reg) + off);
        s64 mem_val = cur_state->get_memi_val(addr, byte_size);
        s64 src_val = cur_state->get_regi_val(src_reg);
        switch (imm) {
            case BPF_ADD:
                next_state->set_memi_val(addr, byte_size, mem_val + src_val);
                break;
            case BPF_OR:
                next_state->set_memi_val(addr, byte_size, mem_val | src_val);
                break;
            case BPF_AND:
                next_state->set_memi_val(addr, byte_size, mem_val & src_val);
                break;
            case BPF_XOR:
                next_state->set_memi_val(addr, byte_size, mem_val ^ src_val);
                break;
            default:
                assert(0);
        }
    }

    void InsnSimulator::set_prog_attach_type(bpf_prog_type prog_type,bpf_attach_type attach_type){
        prog_type_=prog_type;
        attach_type_=attach_type;
    }

    void InsnSimulator::set_host_endian(char host_endian) {
        assert(host_endian == 1 || host_endian == 2);
        host_endian_ = host_endian;
    }

    void InsnSimulator::run(u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, State *cur_state, State *next_state,
                            s32 imm2) {
        next_state->refresh();
        last_ld_addrs_.clear();
        int insn_class = BPF_CLASS(code), insn_mode = BPF_MODE(code);
        if (code == 0) {
            nop(cur_state, next_state);
            return;
        }
        if ((insn_class == BPF_ALU64) || (insn_class == BPF_ALU))
            bpf_alu(code, dst_reg, src_reg, off, imm, cur_state, next_state);
        else if (insn_class == BPF_LDX)
            bpf_ldx(code, dst_reg, src_reg, off, imm, cur_state, next_state);
        else if (insn_class == BPF_LD)
            bpf_ld(code, dst_reg, src_reg, off, imm, imm2, cur_state, next_state);
        else if ((insn_class == BPF_ST) || (insn_class == BPF_STX && insn_mode == BPF_MEM))
            bpf_store(code, dst_reg, src_reg, off, imm, cur_state, next_state);
        else if (insn_class == BPF_STX && insn_mode == BPF_ATOMIC)
            bpf_atomic(code, dst_reg, src_reg, off, imm, cur_state, next_state);
        else if (code == JA && off == 0)
            nop(cur_state, next_state);
    }

    void InsnSimulator::nop(State *cur_state, State *next_state) {
        next_state->copy_from_state(cur_state);
    }

    void InsnSimulator::run(Insn &insn, State *cur_state, State *next_state, s32 imm2) {
        run(insn._opcode, insn._dst_reg, insn._src_reg, insn._off, insn._imm,
            cur_state, next_state, imm2);
    }



    int InsnSimulator::bpfsize2byte(int bpf_size) {
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

    set<u64> &InsnSimulator::last_ld_addrs() {
        return last_ld_addrs_;
    }

    int64_t InsnSimulator::compute_val(u8 op,int64_t dst_val,int64_t src_val){
        int64_t res_val;
        switch(op){
            case BPF_ADD:
                res_val = dst_val + src_val;
                break;
            case BPF_SUB:
                res_val = dst_val - src_val;
                break;
            case BPF_MUL:
                res_val = dst_val * src_val;
                break;
            case BPF_DIV:
                if (src_val == 0) {
                    if (dst_val > 0)
                        res_val = INT64_MAX;
                    else
                        res_val = INT64_MIN;
                } else {
                    res_val = (double) dst_val / (double) src_val;
                }
                break;
            case BPF_OR:
                res_val = dst_val | src_val;
                break;
            case BPF_AND:
                res_val = dst_val & src_val;
                break;
            case BPF_LSH:
                res_val = dst_val << src_val;
                break;
            case BPF_RSH:
                res_val = (u64) dst_val >> src_val;
                break;
            case BPF_NEG:
                res_val = -dst_val;
                break;
            case BPF_MOD:
                if (src_val == 0) {
                    if (dst_val > 0)
                        res_val = INT64_MAX;
                    else
                        res_val = INT64_MIN;
                } else
                    res_val = dst_val % src_val;
                break;
            case BPF_XOR:
                res_val = dst_val ^ src_val;
                break;
            case BPF_MOV:
                res_val = src_val;
                break;
            case BPF_ARSH:
                res_val = dst_val >> src_val;
                break;
            default:
                assert(0);
        }
        return res_val;
    }
}