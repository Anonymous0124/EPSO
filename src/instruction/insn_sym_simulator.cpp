#include "instruction/insn_sym_simulator.h"
#include "insn_sym_simulator.h"

using namespace superbpf;
using namespace z3;

namespace superbpf {
#define REF_OP(op) static_cast<z3::expr(*)(z3::expr const &, z3::expr const &)>(&(z3::operator op));
#define REF_FUNC(func) static_cast<z3::expr(*)(z3::expr const &, z3::expr const &)>(&(z3::func));
#define REF_UOP(op) static_cast<z3::expr(*)(z3::expr const &)>(&(z3::operator op));

    char InsnSymSimulator::host_endian_ = 0;
    bool InsnSymSimulator::is_target_=false;

    void InsnSymSimulator::set_target(bool is_target){
        is_target_=is_target;
    }

    void InsnSymSimulator::bpf_alu_func(context &c, u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm,
                                        SymRegsValidation &regs, SymMemoryValidation &mem) {
        int insn_class = BPF_CLASS(code), insn_op = BPF_OP(code), insn_src = BPF_SRC(code);
        RegType res_type;
        int res_off=0;
        int res_map_id=regs.get_map_id(dst_reg);
        auto dst_type=regs.get_reg_type(dst_reg);
        auto src_type=regs.get_reg_type(src_reg);
        auto dst_off=regs.get_reg_off(dst_reg);
        auto src_off=regs.get_reg_off(src_reg);
        if(insn_src==BPF_K)
            src_off=imm;
        res_type=dst_type;
        if (insn_src == BPF_X && insn_op != BPF_END && insn_op != BPF_NEG) {
            if (res_type!= SCALAR_VALUE &&src_type!= SCALAR_VALUE) {
                res_type = SCALAR_VALUE;
            }
        }
        std::function<z3::expr(z3::expr const &, z3::expr const &)> op;
        std::function<z3::expr(z3::expr const &)> uop;
        switch (insn_op) {
            case BPF_ADD:
                op = REF_OP(+);
                res_off=dst_off+src_off;
                break;
            case BPF_SUB:
                op = REF_OP(-);
                res_off=dst_off-src_off;
                break;
            case BPF_MUL:
                op = REF_OP(*);
                res_off=dst_off*src_off;
                break;
            case BPF_DIV:
                op = REF_OP(/);
                if(src_off!=0)
                    res_off=dst_off/src_off;
                else
                    res_off=0;
                break;
            case BPF_OR :
                op = REF_OP(|);
                res_off=dst_off|src_off;
                break;
            case BPF_AND:
                op = REF_OP(&);
                res_off=dst_off&src_off;
                break;
            case BPF_LSH:
                op = REF_FUNC(shl);
                res_off=dst_off<<src_off;
                break;
            case BPF_RSH:
                op = REF_FUNC(lshr);
                res_off=dst_off>>src_off;
                break;
            case BPF_NEG:
                uop = REF_UOP(-);
                res_off=-dst_off;
                break;
            case BPF_MOD:
                op = REF_OP(%);
                res_off=dst_off%src_off;
                break;
            case BPF_XOR:
                op = REF_OP(^);
                res_off=dst_off^src_off;
                break;
            case BPF_MOV:
                if (insn_src == BPF_X) {
                    res_type = src_type;
                    res_map_id=regs.get_map_id(src_reg);
                }
                else {
                    res_type = SCALAR_VALUE;
                }
                res_off=src_off;
                break;
            case BPF_ARSH:
                op = REF_FUNC(ashr);
                res_off=dst_off>>src_off;
                break;
            case BPF_END:
                break;
            default:
                assert(0);
        }
        z3::expr src_a(c);
        z3::expr src_b(c);
        switch (insn_src) {
            case BPF_X:
                src_a = regs.get_reg_value(dst_reg);
                src_b = regs.get_reg_value(src_reg);
                break;
            case BPF_K:
                src_a = regs.get_reg_value(dst_reg);
                src_b = c.bv_val(imm, 64);
                break;
            default:
                assert(0);
        }

        switch (insn_class) {
            case BPF_ALU64:
                switch (insn_op) {
                    case BPF_MOV:
                        regs.set_reg_value_with_type(c, dst_reg, src_b,res_type);
                        break;
                    case BPF_NEG:
                        regs.set_reg_value_with_type(c, dst_reg, -src_a,res_type);
                        break;
                    case BPF_END:
                        assert(0); // ALU64 class should not use BPF_END
                    default:
                        regs.set_reg_value_with_type(c, dst_reg, op(src_a, src_b),res_type);
                        break;
                }
                break;
            case BPF_ALU:
                switch (insn_op) {
                    case BPF_MOV:
                        regs.set_reg_value_with_type(c, dst_reg, z3::concat(c.bv_val(0, 32), src_b.extract(31, 0)),res_type);
                        break;
                    case BPF_NEG:
                        regs.set_reg_value_with_type(c, dst_reg, z3::concat(c.bv_val(0, 32), -(src_a.extract(31, 0))),res_type);
                        break;
                    case BPF_END:
                        bpf_end(c, code, dst_reg, imm, regs);
                        break;
                    default:
                        regs.set_reg_value_with_type(c, dst_reg,
                                           z3::concat(c.bv_val(0, 32), op(src_a.extract(31, 0), src_b.extract(31, 0))),res_type);
                        break;
                }
                break;
            default:
                assert(0);
        }
        regs.set_reg_off(dst_reg,res_off);
        if(regs.get_reg_type(dst_reg)!=(PTR_TO_MAP_VALUE|PTR_TO_MAP_VALUE_OR_NULL))
            res_map_id=-1;
        regs.set_reg_map_id(dst_reg,res_map_id);
    }

    void InsnSymSimulator::bpf_map_store(context &c, u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, SymRegsValidation &regs,
                                     SymMemoryValidation &mem){
        int insn_class = BPF_CLASS(code), insn_mode = BPF_MODE(code), size = BPF_SIZE(code);
        int n_bytes = bpf_size2byte(size);
        expr base_addr = regs.get_reg_value(dst_reg) + c.bv_val(off, 64);
        int map_id=regs.get_map_id(dst_reg);
        int type_off=regs.get_reg_off(dst_reg);
        switch (insn_class) {
            case BPF_STX:
                mem.set_map_value(c, map_id,base_addr, regs.get_reg_value(src_reg), n_bytes);
                break;
            case BPF_ST:
                mem.set_map_value(c, map_id,base_addr, c.bv_val(imm, 64),n_bytes);
                break;
            default:
                assert(0);
                break;
        }
        mem.set_mem_addr_boundry(c, base_addr, n_bytes,0,INT32_MAX);
        if(is_target_)
            mem.set_base_addr_aligned(c, base_addr, n_bytes);
        for(int i=0;i<n_bytes;i++){
            mem.add_map_ptr(map_id,type_off+off+i,mem.get_map_value(map_id,base_addr+c.bv_val(i,64)));
        }
    }

    void
    InsnSymSimulator::bpf_store(context &c, u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, SymRegsValidation &regs,
                                SymMemoryValidation &mem) {
        auto mem_type=regs.get_reg_type(dst_reg);
//        if(mem_type==PTR_TO_MAP_VALUE){
//            bpf_map_store(c,code,dst_reg,src_reg,off,imm,regs,mem);
//            return;
//        }
        int insn_class = BPF_CLASS(code), insn_mode = BPF_MODE(code), size = BPF_SIZE(code);
        int n_bytes = bpf_size2byte(size);
        expr addr = regs.get_reg_value(dst_reg) + c.bv_val(off, 64);
        int type_off=regs.get_reg_off(dst_reg);
        auto [boundary_start,boundary_end]=mem.get_boundary(mem_type);
        switch (insn_class) {
            case BPF_STX:
                mem.set_mem_value(c, addr, regs.get_reg_value(src_reg), n_bytes);
                break;
            case BPF_ST:
                mem.set_mem_value(c, addr, c.bv_val(imm, 64), n_bytes);
                break;
            default:
                assert(0);
        }
        mem.set_mem_addr_boundry(c, addr, n_bytes,boundary_start,boundary_end);
        if(is_target_)
            mem.set_base_addr_aligned(c, addr, n_bytes);
        for(int i=0;i<n_bytes;i++){
            mem.add_ptr(mem_type,type_off+off+i,mem.get_mem_value(addr+c.bv_val(i,64)));
        }
    }

    void
    InsnSymSimulator::bpf_map_atomic(context &c, u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, SymRegsValidation &regs,
                                 SymMemoryValidation &mem) {
        int size = BPF_SIZE(code);
        int n_bytes = bpf_size2byte(size);
        int map_id=regs.get_map_id(dst_reg);
        expr addr = regs.get_reg_value(dst_reg) + c.bv_val(off, 64);
        expr mem_val = mem.get_map_value(map_id,addr, n_bytes);
        expr src_val = regs.get_reg_value(src_reg);
        if (n_bytes == 4)
            src_val = src_val.extract(31, 0);
        int type_off=regs.get_reg_off(dst_reg);
        switch (imm) {
            case BPF_ADD:
                mem.set_mem_value(c, addr, mem_val + src_val, n_bytes);
                break;
            case BPF_OR:
                mem.set_mem_value(c, addr, mem_val | src_val, n_bytes);
                break;
            case BPF_AND:
                mem.set_mem_value(c, addr, mem_val & src_val, n_bytes);
                break;
            case BPF_XOR:
                mem.set_mem_value(c, addr, mem_val ^ src_val, n_bytes);
                break;
            default:
                assert(0);
        }
        mem.set_mem_addr_boundry(c, addr, n_bytes,0,INT32_MAX);
        if(is_target_)
            mem.set_base_addr_aligned(c, addr, n_bytes);
        for(int i=0;i<n_bytes;i++){
            mem.add_map_ptr(map_id,type_off+off+i,mem.get_mem_value(addr+c.bv_val(i,64)));
        }
    }

    void
    InsnSymSimulator::bpf_atomic(context &c, u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, SymRegsValidation &regs,
                                 SymMemoryValidation &mem) {
        int size = BPF_SIZE(code);
        int n_bytes = bpf_size2byte(size);
        auto mem_type=regs.get_reg_type(dst_reg);
//        if(mem_type==PTR_TO_MAP_VALUE){
//            bpf_map_atomic(c,code,dst_reg,src_reg,off,imm,regs,mem);
//            return;
//        }
        expr addr = regs.get_reg_value(dst_reg) + c.bv_val(off, 64);
        expr mem_val = mem.get_mem_value(addr, n_bytes);
        expr src_val = regs.get_reg_value(src_reg);
        if (n_bytes == 4)
            src_val = src_val.extract(31, 0);
        int type_off=regs.get_reg_off(dst_reg);
        auto [boundary_start,boundary_end]=mem.get_boundary(mem_type);
        switch (imm) {
            case BPF_ADD:
                mem.set_mem_value(c, addr, mem_val + src_val, n_bytes);
                break;
            case BPF_OR:
                mem.set_mem_value(c, addr, mem_val | src_val, n_bytes);
                break;
            case BPF_AND:
                mem.set_mem_value(c, addr, mem_val & src_val, n_bytes);
                break;
            case BPF_XOR:
                mem.set_mem_value(c, addr, mem_val ^ src_val, n_bytes);
                break;
            default:
                assert(0);
        }
        mem.set_mem_addr_boundry(c, addr, n_bytes,boundary_start,boundary_end);
        if(is_target_)
            mem.set_base_addr_aligned(c, addr, n_bytes);
        for(int i=0;i<n_bytes;i++){
            mem.add_ptr(mem_type,type_off+off+i,mem.get_mem_value(addr+c.bv_val(i,64)));
        }
    }

    void InsnSymSimulator::nop(context &c, u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, SymRegsValidation &regs,
                               SymMemoryValidation &mem) {
        regs.set_regs_unchange(c);
        mem.set_mem_unchange(c);
    }

    void
    InsnSymSimulator::bpf_map_load(context &c, u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, SymRegsValidation &regs,
                               SymMemoryValidation &mem) {
        int insn_class = BPF_CLASS(code), insn_mode = BPF_MODE(code), size = BPF_SIZE(code);
        int n_bytes = bpf_size2byte(size);
        int map_id=regs.get_map_id(src_reg);
        expr addr = regs.get_reg_value(src_reg) + c.bv_val(off, 64);
        int type_off=regs.get_reg_off(src_reg);
        mem.set_mem_addr_boundry(c, addr, n_bytes,0,INT32_MAX);
        if(is_target_)
            mem.set_base_addr_aligned(c, addr, n_bytes);
        for(int i=0;i<n_bytes;i++){
            mem.add_map_ptr(map_id,type_off+off+i,mem.get_map_value(map_id,addr+c.bv_val(i,64)));
        }
        if (insn_class == BPF_LDX) {
            z3::expr val = mem.get_map_value(map_id,addr, n_bytes);
            if (n_bytes < 8) {
                val = z3::concat(c.bv_val(0, (8 - n_bytes) * 8), val);
            }
            regs.set_reg_value_with_type(c, dst_reg, val,SCALAR_VALUE);
            regs.set_reg_off(dst_reg,0);
        } else {
            assert(0);
        }
    }

    void
    InsnSymSimulator::bpf_load(context &c, u8 code, u8 dst_reg, u8 src_reg, s16 off, s32 imm, SymRegsValidation &regs,
                               SymMemoryValidation &mem) {
        int insn_class = BPF_CLASS(code), insn_mode = BPF_MODE(code), size = BPF_SIZE(code);
        int n_bytes = bpf_size2byte(size);
        auto mem_type=regs.get_reg_type(src_reg);
//        if(mem_type==PTR_TO_MAP_VALUE){
//            bpf_map_load(c,code,dst_reg,src_reg,off,imm,regs,mem);
//            return;
//        }
        expr addr = regs.get_reg_value(src_reg) + c.bv_val(off, 64);
        int type_off=regs.get_reg_off(src_reg);
        auto [boundary_start,boundary_end]=mem.get_boundary(mem_type);
        mem.set_mem_addr_boundry(c, addr, n_bytes,boundary_start,boundary_end);
        if(is_target_)
            mem.set_base_addr_aligned(c, addr, n_bytes);
        for(int i=0;i<n_bytes;i++){
            mem.add_ptr(mem_type,type_off+off+i,mem.get_mem_value(addr+c.bv_val(i,64)));
        }
        if (insn_class == BPF_LDX) {
            z3::expr val = mem.get_mem_value(addr, n_bytes);
            if (n_bytes < 8) {
                val = z3::concat(c.bv_val(0, (8 - n_bytes) * 8), val);
            }
            regs.set_reg_value_with_type(c, dst_reg, val,SCALAR_VALUE);
            regs.set_reg_off(dst_reg,0);
        } else {
            assert(0);
        }
    }

    void InsnSymSimulator::set_host_endian(char host_endian) {
        assert(host_endian == 1 || host_endian == 2);
        host_endian_ = host_endian;
    }

    void InsnSymSimulator::bpf_end(context &c, u8 code, u8 dst_reg, s32 imm, SymRegsValidation &regs) {
        int insn_src = BPF_SRC(code);
        assert(insn_src == BPF_TO_LE || BPF_TO_BE);
        assert(imm == 16 || imm == 32 || imm == 64);
        assert(host_endian_ == 1 || host_endian_ == 2);
        z3::expr val(c);
        // according to the kernel doc, the semantics of BPF_END insn is equivalent to macro htole16/32/64 or htobe16/32/64,
        // which are defined in endian.h.
        // thus if imm < 64, the top (64 - imm) bits of the dst reg will be cleared to 0.
        if ((insn_src == BPF_TO_LE && host_endian_ == 2) || (insn_src == BPF_TO_BE && host_endian_ == 1)) {
            z3::expr_vector val_vec(c);
            for (int i = 0; i < imm / 8; i++) {
                val_vec.push_back(regs.get_reg_value(dst_reg).extract(i * 8 + 7, i * 8));
            }
            val = z3::concat(val_vec);
        } else {
            val = regs.get_reg_value(dst_reg).extract(imm - 1, 0);
        }
        if (imm < 64) {
            val = z3::concat(c.bv_val(0, 64 - imm), val);
        }
        auto res_type=regs.get_reg_type(dst_reg);
        regs.set_reg_value_with_type(c, dst_reg, val,res_type);
    }

    int InsnSymSimulator::bpf_size2byte(int bpf_size) {
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
}