#include "verifier.h"

using namespace std;

namespace superbpf {

    int Verifier::opt_level_ = 1;

    long long Verifier::hit_times_=0;

    int Verifier::bpf_size_to_bytes(int bpf_size) {
        int bytes = -EINVAL;
        if (bpf_size == BPF_B)
            bytes = sizeof(u8);
        else if (bpf_size == BPF_H)
            bytes = sizeof(u16);
        else if (bpf_size == BPF_W)
            bytes = sizeof(u32);
        else if (bpf_size == BPF_DW)
            bytes = sizeof(u64);
        return bytes;
    }

    bool Verifier::may_be_pointer_value(State *cur_state, int regno) {
        // TODO: add flag 'allow_ptr_leaks'
        RegType type = cur_state->get_regi_type(regno);
        return (type != SCALAR_VALUE && type != NOT_INIT);
    }

    bool Verifier::must_be_pointer_value(State *cur_state, int regno) {
        // TODO: add flag 'allow_ptr_leaks'
        RegType type = cur_state->get_regi_type(regno);
        return (type != SCALAR_VALUE && type != NOT_INIT && type != LD_IMM_VALUE && type != STACK_VALUE &&
                type != MEM_VALUE &&
                type != CTX_VALUE && type != MIXED_TYPE);
    }

    bool Verifier::type_is_pkt_pointer(RegType type) {
        return type == PTR_TO_PACKET ||
               type == PTR_TO_PACKET_META;
    }

    bool Verifier::type_is_sk_pointer(RegType type) {
        return type == PTR_TO_SOCKET ||
               type == PTR_TO_SOCK_COMMON ||
               type == PTR_TO_TCP_SOCK ||
               type == PTR_TO_XDP_SOCK;
    }

    bool Verifier::reg_is_pkt_pointer(Reg *reg) {
        return type_is_pkt_pointer(reg->type());
    }

    bool Verifier::is_ctx_reg(State *cur_state, int regno) {
        return cur_state->get_regi_type(regno) == PTR_TO_CTX;
    }

    bool Verifier::is_sk_reg(State *cur_state, int regno) {
        return type_is_sk_pointer(cur_state->get_regi_type(regno));
    }

    bool Verifier::is_pkt_reg(State *cur_state, int regno) {
        return type_is_pkt_pointer(cur_state->get_regi_type(regno));
    }

    bool Verifier::is_flow_key_reg(State *cur_state, int regno) {
        /* Separate to is_ctx_reg() since we still want to allow BPF_ST here. */
        return cur_state->get_regi_type(regno) == PTR_TO_FLOW_KEYS;
    }

    bool Verifier::may_access_direct_pkt_data(State *cur_state,
                                              const struct bpf_call_arg_meta *meta,
                                              bpf_access_type t) {
        // TODO
        return true;
    }

    int Verifier::check_map_access_type(State *cur_state, u32 regno, int off, int size, bpf_access_type type) {
        // skip: check if map is readable or writable
        return 0;
    }

    /* check read/write into a map element with possible variable offset */
    int Verifier::check_map_access(State *cur_state, u32 regno, int off, int size, bool zero_size_allowed) {
        // skip: check_mem_region_access
        // skip: if(map_value_has_spin_lock) ...
        return 0;
    }

    /* check read/write into a memory region with possible variable offset */
    int Verifier::check_mem_region_access(State *cur_state, u32 regno, int off, int size, u32 mem_size,
                                          bool zero_size_allowed) {
        return 0;
    }

    int Verifier::check_flow_keys_access(State *cur_state, int off, int size) {
        if (size < 0 || off < 0 || (u64) off + size > sizeof(bpf_flow_keys)) {
            printf("\033[34minvalid access to flow keys off=%d size=%d\n\033[0m", off, size);
            hit_times_++;
            return -EACCES;
        }
        return 0;
    }

    int Verifier::do_check(State *cur_state, const Insn &insn) {
        int err = 0;
        u8 insn_class = BPF_CLASS(insn._opcode);
        if (insn_class == BPF_ALU || insn_class == BPF_ALU64) {
            err = check_alu_op(cur_state, insn);
            if (err)
                return err;
        } else if (insn_class == BPF_LDX) {
            // skip: check if 'src_reg' is readable and 'dst_reg' is writable
            err = check_mem_access(cur_state, insn._src_reg,
                                   insn._off, BPF_SIZE(insn._opcode),
                                   BPF_READ, insn._dst_reg, false);
            if (err)
                return err;
//            if (cur_state->get_regi_type(insn._src_reg) == MIXED_TYPE) {
//                printf("same insn cannot be used with different pointers\n");
//                hit_times_++;
//                return -EINVAL;
//            }
        } else if (insn_class == BPF_STX) {
            if (BPF_MODE(insn._opcode) == BPF_XADD) {
                err = check_xadd(cur_state, insn);
                return err;
            }
            // skip: check if 'src_reg' and 'dst_reg' is readable
            /* check that memory (dst_reg + off) is writeable */
            err = check_mem_access(cur_state, insn._dst_reg,
                                   insn._off, BPF_SIZE(insn._opcode),
                                   BPF_WRITE, insn._src_reg, false);
            if (err)
                return err;
//            if (cur_state->get_regi_type(insn._dst_reg) == MIXED_TYPE) {
//                printf("same insn cannot be used with different pointers\n");
//                hit_times_++;
//                return -EINVAL;
//            }
        } else if (insn_class == BPF_ST) {
            // skip: check if reserved fields are used in 'insn'
            // skip: check if 'src_reg' and 'dst_reg' is readable
            if (cur_state->get_regi_type(insn._dst_reg) == PTR_TO_CTX) {
                printf("\033[34mBPF_ST stores into R%d %s is not allowed\n\033[0m", insn._dst_reg,
                       reg_type_str.at(cur_state->get_regi_type(insn._dst_reg)).c_str());
                hit_times_++;
                return -EACCES;
            }
            if (opt_level_ == 1) {
                // This rule is added due to the inaccuracy of range analysis of verifier.
                if (cur_state->get_regi_type(insn._dst_reg) == PTR_TO_STACK) {
                    printf("\033[34mBPF_ST stores into R%d %s is not allowed\n\033[0m", insn._dst_reg,
                           reg_type_str.at(cur_state->get_regi_type(insn._dst_reg)).c_str());
                    hit_times_++;
                    return -EACCES;
                }
            }
            /* check that memory (dst_reg + off) is writeable */
            err = check_mem_access(cur_state, insn._dst_reg,
                                   insn._off, BPF_SIZE(insn._opcode),
                                   BPF_WRITE, -1, false);
            if (err)
                return err;

        }
        return 0;
    }

    int Verifier::check_alu_op(State *cur_state, const Insn &insn) {
        u8 insn_op = BPF_OP(insn._opcode);
        if (insn_op == BPF_END || insn_op == BPF_NEG) {
            // skip: check if reserved fields are used in 'insn'
            // skip: check if 'dst_reg' is readable
            if (must_be_pointer_value(cur_state, insn._dst_reg)) {
                printf("\033[34mR%d pointer arithmetic prohibited\n\033[0m", insn._dst_reg);
                hit_times_++;
                return -EACCES;
            }
            // skip: check if 'dst_reg' is writable
        } else if (insn_op == BPF_MOV) {
            // skip: check if reserved fields are used in 'insn'
            // skip: check if 'dst_reg' is writable
            if (BPF_SRC(insn._opcode) == BPF_X) {
                // TODO: change reg type
                if (BPF_CLASS(insn._opcode) == BPF_ALU64) {
                    // TODO: propagate scalar value
                } else {
                    if (must_be_pointer_value(cur_state, insn._src_reg)) {
                        printf("\033[34mR%d partial copy of pointer\n\033[0m", insn._src_reg);
                        hit_times_++;
                        return -EACCES;
                    }
                    // TODO: propagate scalar value
                }
            } else {
                // TODO: mark_reg_known
                // TODO: change reg type
            }
        } else if (insn_op > BPF_END) {
            printf("\033[34minvalid BPF_ALU opcode %x\n\033[0m", insn_op);
            hit_times_++;
            return -EINVAL;
        } else {
            /* all other ALU ops: and, sub, xor, add, ... */
            // skip: check if reserved fields are used in 'insn'
            // skip: check if 'dst_reg' is readable
            if ((insn_op == BPF_MOD || insn_op == BPF_DIV) && BPF_SRC(insn._opcode) == BPF_K && insn._imm == 0) {
                printf("\033[34mdiv by zero\n\033[0m");
                hit_times_++;
                return -EINVAL;
            }
            if ((insn_op == BPF_LSH || insn_op == BPF_RSH ||
                 insn_op == BPF_ARSH) && BPF_SRC(insn._opcode) == BPF_K) {
                int size = BPF_CLASS(insn._opcode) == BPF_ALU64 ? 64 : 32;
                if (insn._imm < 0 || insn._imm >= size) {
                    printf("\033[34minvalid shift %d\n\033[0m", insn._imm);
                    hit_times_++;
                    return -EINVAL;
                }
            }
            // skip: check if 'dst_reg' is writable
            // TODO: adjust_reg_min_max_vals
        }
        return 0;
    }

    int Verifier::check_ptr_alignment(State *cur_state, Reg *reg, int off, int size, bool strict_alignment_once) {
        bool strict = cur_state->strict_alignment() || strict_alignment_once;
        switch (reg->type()) {
            case PTR_TO_PACKET:
            case PTR_TO_PACKET_META:
                /* Special case, because of NET_IP_ALIGN. Given metadata sits
                 * right in front, treat it the very same way.
                 */
                return check_pkt_ptr_alignment(cur_state, reg, off, size, strict);
            case PTR_TO_STACK:
                /* The stack spill tracking logic in check_stack_write()
                 * and check_stack_read() relies on stack accesses being
                 * aligned.
                 */
                strict = true;
                break;
            default:
                break;
        }
        return check_generic_ptr_alignment(cur_state, reg, off, size, strict);
    }

    int Verifier::check_pkt_ptr_alignment(State *cur_state, Reg *reg, int off, int size, bool strict) {
        int ip_align=0;
        /* Byte size accesses are always allowed. */
        if (!strict || size == 1)
            return 0;
//        ip_align = 2;
        if ((reg->off() + off + ip_align) & (size - 1)) {
            printf("\033[34mmisaligned packet access off %d+%d+%d size %d\n\033[0m", ip_align, reg->off(),off,
                   size);  // different from verifier
            hit_times_++;
            return -EACCES;
        }
        return 0;
    }

    int Verifier::check_generic_ptr_alignment(State *cur_state, Reg *reg, int off, int size, bool strict) {
        // TODO
        /* Byte size accesses are always allowed. */
        if (!strict || size == 1)
            return 0;
        assert(reg->is_valid());
        if ((reg->off() + off) & (size - 1)) {
            printf("\033[34mmisaligned access off %d+%d size %d\n\033[0m", reg->off(),off, size);  // different from verifier
            hit_times_++;
            return -EACCES;
        }
        return 0;
    }

    /* check whether memory at (regno + off) is accessible for t = (read | write)
     * if t==write, value_regno is a register which value is stored into memory
     * if t==read, value_regno is a register which will receive the value from memory
     * if t==write && value_regno==-1, some unknown value is stored into memory
     * if t==read && value_regno==-1, don't care what we read from memory
     */
    int Verifier::check_mem_access(State *cur_state, u32 regno,
                                   int off, int bpf_size, bpf_access_type t,
                                   int value_regno, bool strict_alignment_once) {
        int err = 0;
        int size = bpf_size_to_bytes(bpf_size);
        Reg *reg = cur_state->get_regi(regno);
        err = check_ptr_alignment(cur_state, reg, off, size, strict_alignment_once);
        if (err)
            return err;
        if (reg->type() == PTR_TO_MAP_VALUE) {
            if (t == BPF_WRITE && value_regno >= 0 &&
                must_be_pointer_value(cur_state, value_regno)) {
                printf("\033[34mR%d leaks addr into map\n\033[0m", value_regno);
                hit_times_++;
                return -EACCES;
            }
            err = check_map_access_type(cur_state, regno, off, size, t);
            if (err)
                return err;
            err = check_map_access(cur_state, regno, off, size, false);

        } else if (reg->type() == PTR_TO_MEM) {
            if (t == BPF_WRITE && value_regno >= 0 &&
                must_be_pointer_value(cur_state, value_regno)) {
                printf("\033[34mR%d leaks addr into mem\n\033[0m", value_regno);
                hit_times_++;
                return -EACCES;
            }
            // skip: check_mem_region_access
        } else if (reg->type() == PTR_TO_CTX) {
            if (t == BPF_WRITE && value_regno >= 0 &&
                must_be_pointer_value(cur_state, value_regno)) {
                printf("\033[34mR%d leaks addr into ctx\n\033[0m", value_regno);
                hit_times_++;
                return -EACCES;
            }
            // skip: check_ctx_reg
            // skip: check_ctx_access
            // TODO: change reg type
            /* ctx access returns either a scalar, or a
             * PTR_TO_PACKET[_META,_END]. In the latter
             * case, we know the offset is zero.
             */
        } else if (reg->type() == PTR_TO_STACK) {
            // skip: check_stack_access
            // TODO
//            state = func(env, reg);
//            err = update_stack_depth(env, state, off);
//            if (err)
//                return err;
//
//            if (t == BPF_WRITE)
//                err = check_stack_write(env, state, off, size,
//                                        value_regno, insn_idx);
//            else
//                err = check_stack_read(env, state, off, size,
//                                       value_regno);
        } else if (reg_is_pkt_pointer(reg)) {
            // TODO
            if (t == BPF_WRITE && !may_access_direct_pkt_data(cur_state, NULL, t)) {
                printf("\033[34mcannot write into packet\n\033[0m");
                hit_times_++;
                return -EACCES;
            }
            if (t == BPF_WRITE && value_regno >= 0 &&
                must_be_pointer_value(cur_state, value_regno)) {
                printf("\033[34mR%d leaks addr into packet\n\033[0m", value_regno);
                hit_times_++;
                return -EACCES;
            }
            // skip: check_packet_access
        } else if (reg->type() == PTR_TO_FLOW_KEYS) {
            if (t == BPF_WRITE && value_regno >= 0 &&
                must_be_pointer_value(cur_state, value_regno)) {
                printf("\033[34mR%d leaks addr into packet\n\033[0m", value_regno);
                hit_times_++;
                return -EACCES;
            }

            err = check_flow_keys_access(cur_state, off, size);
        } else if (type_is_sk_pointer(reg->type())) {
            if (t == BPF_WRITE) {
                printf("\033[34mR%d cannot write into %s\n\033[0m", regno, reg_type_str.at(reg->type()).c_str());
                hit_times_++;
                return -EACCES;
            }
            // skip: check_sock_access
        } else if (reg->type() == PTR_TO_TP_BUFFER) {
            // skip: check_tp_buffer_access
        } else if (reg->type() == PTR_TO_BTF_ID) {
            // skip: check_ptr_to_btf_access
        } else if (reg->type() == CONST_PTR_TO_MAP) {
            // skip: check_ptr_to_map_access
        } else if (reg->type() == PTR_TO_RDONLY_BUF) {
            if (t == BPF_WRITE) {
                printf("\033[34mR%d cannot write into %s\n\033[0m", regno, reg_type_str.at(reg->type()).c_str());
                hit_times_++;
                return -EACCES;
            }
            // skip: check_buffer_access
        } else if (reg->type() == PTR_TO_RDWR_BUF) {
            // skip: check_buffer_access
        } else if (reg->type() == LD_IMM_VALUE || reg->type() == STACK_VALUE || reg->type() == CTX_VALUE ||
                   reg->type() == MEM_VALUE ||
                   reg->type() == MIXED_TYPE) {
            // TODO
        } else {
            printf("\033[34mR%d invalid mem access '%s'\n\033[0m", regno, reg_type_str.at(reg->type()).c_str());
            hit_times_++;
            return -EACCES;
        }
        return err;
    }

    int Verifier::check_xadd(State *cur_state, const Insn &insn) {
        // skip: check if reserved fields are used in 'insn'
        // skip: check if 'src_reg' and 'dst_reg' are readable
        if (must_be_pointer_value(cur_state, insn._src_reg)) {
            printf("\033[34mR%d leaks addr into mem\n\033[0m", insn._src_reg);
            hit_times_++;
            return -EACCES;
        }
        if (is_ctx_reg(cur_state, insn._dst_reg) ||
            is_pkt_reg(cur_state, insn._dst_reg) ||
            is_flow_key_reg(cur_state, insn._dst_reg) ||
            is_sk_reg(cur_state, insn._dst_reg)) {
            printf("\033[34mBPF_XADD stores into R%d %s is not allowed\n\033[0m", insn._dst_reg,
                   reg_type_str.at(cur_state->get_regi_type(insn._dst_reg)).c_str());
            hit_times_++;
            return -EACCES;
        }
        return 0;
    }

    void Verifier::set_opt_level_2() {
        opt_level_ = 2;
    }
}
