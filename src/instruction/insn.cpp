#include "insn.h"

#include <iomanip>
#include <iostream>

using namespace std;
using namespace superbpf;

namespace superbpf {
#define getStr(opcode) case opcode: return #opcode;

    OPCODE_IDX opcode_2_idx(int opcode) {
        switch (opcode) {
            case NOP:
                return IDX_NOP;
            case ADD64XC:
                return IDX_ADD64XC;
            case ADD64XY:
                return IDX_ADD64XY;
            case SUB64XY:
                return IDX_SUB64XY;
            case MUL64XC:
                return IDX_MUL64XC;
            case DIV64XC:
                return IDX_DIV64XC;
            case OR64XC:
                return IDX_OR64XC;
            case OR64XY:
                return IDX_OR64XY;
            case AND64XC:
                return IDX_AND64XC;
            case AND64XY:
                return IDX_AND64XY;
            case LSH64XC:
                return IDX_LSH64XC;
            case LSH64XY:
                return IDX_LSH64XY;
            case RSH64XC:
                return IDX_RSH64XC;
            case RSH64XY:
                return IDX_RSH64XY;
            case NEG64XC:
                return IDX_NEG64XC;
            case XOR64XC:
                return IDX_XOR64XC;
            case XOR64XY:
                return IDX_XOR64XY;
            case MOV64XC:
                return IDX_MOV64XC;
            case MOV64XY:
                return IDX_MOV64XY;
            case ARSH64XC:
                return IDX_ARSH64XC;
            case ARSH64XY:
                return IDX_ARSH64XY;
            case ADD32XC:
                return IDX_ADD32XC;
            case ADD32XY:
                return IDX_ADD32XY;
            case OR32XC:
                return IDX_OR32XC;
            case OR32XY:
                return IDX_OR32XY;
            case AND32XC:
                return IDX_AND32XC;
            case AND32XY:
                return IDX_AND32XY;
            case LSH32XC:
                return IDX_LSH32XC;
            case LSH32XY:
                return IDX_LSH32XY;
            case RSH32XC:
                return IDX_RSH32XC;
            case RSH32XY:
                return IDX_RSH32XY;
            case MOV32XC:
                return IDX_MOV32XC;
            case MOV32XY:
                return IDX_MOV32XY;
            case ARSH32XC:
                return IDX_ARSH32XC;
            case ARSH32XY:
                return IDX_ARSH32XY;
            case LE:
                return IDX_LE;
            case BE:
                return IDX_BE;
            case LDDW:
                return IDX_LDDW;
            case LDXB:
                return IDX_LDXB;
            case STXB:
                return IDX_STXB;
            case LDXH:
                return IDX_LDXH;
            case STXH:
                return IDX_STXH;
            case LDXW:
                return IDX_LDXW;
            case STXW:
                return IDX_STXW;
            case LDXDW:
                return IDX_LDXDW;
            case STXDW:
                return IDX_STXDW;
            case STB:
                return IDX_STB;
            case STH:
                return IDX_STH;
            case STW:
                return IDX_STW;
            case STDW:
                return IDX_STDW;
            case XADD64:
                return IDX_XADD64;
            case XADD32:
                return IDX_XADD32;
            case LDABSH:
                return IDX_LDABSH;
            case LDINDH:
                return IDX_LDINDH;
            case JA:
                return IDX_JA;
            case JEQXC:
                return IDX_JEQXC;
            case JEQXY:
                return IDX_JEQXY;
            case JNEXC:
                return IDX_JNEXC;
            case JNEXY:
                return IDX_JNEXY;
            case JGTXC:
                return IDX_JGTXC;
            case JGTXY:
                return IDX_JGTXY;
            case JGEXC:
                return IDX_JLEXC;
            case JGEXY:
                return IDX_JLEXY;
            case JSGTXC:
                return IDX_JSGTXC;
            case JSGTXY:
                return IDX_JSGTXY;
            case JSGEXC:
                return IDX_JSGEXC;
            case JSGEXY:
                return IDX_JSGEXY;
            case JLTXC:
                return IDX_JLTXC;
            case JLTXY:
                return IDX_JLTXY;
            case JLEXC:
                return IDX_JLEXC;
            case JLEXY:
                return IDX_JLEXY;
            case JSLTXC:
                return IDX_JSGTXC;
            case JSLTXY:
                return IDX_JSGTXY;
            case JSLEXC:
                return IDX_JSGEXC;
            case JSLEXY:
                return IDX_JSGEXY;
            case JEQ32XC:
                return IDX_JEQ32XC;
            case JEQ32XY:
                return IDX_JEQ32XY;
            case JNE32XC:
                return IDX_JNE32XC;
            case JNE32XY:
                return IDX_JNE32XY;
            case JGT32XC:
                return IDX_JGT32XC;
            case JGT32XY:
                return IDX_JGT32XY;
            case JGE32XC:
                return IDX_JLE32XC;
            case JGE32XY:
                return IDX_JLE32XY;
            case JSGT32XC:
                return IDX_JSGT32XC;
            case JSGT32XY:
                return IDX_JSGT32XY;
            case JSGE32XC:
                return IDX_JSGE32XC;
            case JSGE32XY:
                return IDX_JSGE32XY;
            case JLT32XC:
                return IDX_JLT32XC;
            case JLT32XY:
                return IDX_JLT32XY;
            case JLE32XC:
                return IDX_JLE32XC;
            case JLE32XY:
                return IDX_JLE32XY;
            case JSLT32XC:
                return IDX_JSGT32XC;
            case JSLT32XY:
                return IDX_JSGT32XY;
            case JSLE32XC:
                return IDX_JSGE32XC;
            case JSLE32XY:
                return IDX_JSGE32XY;
            case CALL:
                return IDX_CALL;
            case EXIT:
                return IDX_EXIT;
            default:
                return IDX_NOP;
        }
    }

    std::string opcode_2_str(int opcode) {
        switch (opcode) {
            getStr(NOP)
            getStr(ADD64XC)
            getStr(ADD64XY)
            getStr(SUB64XY)
            getStr(MUL64XC)
            getStr(DIV64XC)
            getStr(OR64XC)
            getStr(OR64XY)
            getStr(AND64XC)
            getStr(AND64XY)
            getStr(LSH64XC)
            getStr(LSH64XY)
            getStr(RSH64XC)
            getStr(RSH64XY)
            getStr(NEG64XC)
            getStr(XOR64XC)
            getStr(XOR64XY)
            getStr(MOV64XC)
            getStr(MOV64XY)
            getStr(ARSH64XC)
            getStr(ARSH64XY)
            getStr(ADD32XC)
            getStr(ADD32XY)
            getStr(OR32XC)
            getStr(OR32XY)
            getStr(AND32XC)
            getStr(AND32XY)
            getStr(LSH32XC)
            getStr(LSH32XY)
            getStr(RSH32XC)
            getStr(RSH32XY)
            getStr(MOV32XC)
            getStr(MOV32XY)
            getStr(ARSH32XC)
            getStr(ARSH32XY)
            getStr(LE)
            getStr(BE)
            getStr(LDDW)
            getStr(LDXB)
            getStr(STXB)
            getStr(LDXH)
            getStr(STXH)
            getStr(LDXW)
            getStr(STXW)
            getStr(LDXDW)
            getStr(STXDW)
            getStr(STB)
            getStr(STH)
            getStr(STW)
            getStr(STDW)
            getStr(XADD64)
            getStr(XADD32)
            getStr(LDABSH)
            getStr(LDINDH)
            getStr(JA)
            getStr(JEQXC)
            getStr(JEQXY)
            getStr(JGTXC)
            getStr(JGTXY)
            getStr(JGEXC)
            getStr(JGEXY)
            getStr(JNEXC)
            getStr(JNEXY)
            getStr(JSGTXC)
            getStr(JSGTXY)
            getStr(JEQ32XC)
            getStr(JEQ32XY)
            getStr(JNE32XC)
            getStr(JNE32XY)
            getStr(CALL)
            getStr(EXIT)
            default:
                return "NOP";
        }
    }

    std::string regNameString(int reg) {
        return "r" + std::to_string(reg);
    }

    int sizeflag_2_num(int flag) {
        switch (flag) {
            case BPF_B: {
                return 8;
            }
            case BPF_H: {
                return 16;
            }
            case BPF_W: {
                return 32;
            }
            case BPF_DW: {
                return 64;
            }
            default: {
                std::cout << "Invalid flag" << std::endl;
                return -1;
            }
        }
    }

    OPCODE_TYPES Insn::getType() const {
        return opcode_type[opcode_2_idx(_opcode)];
    }

    bool Insn::isJump() const {
        switch (getType()) {
            case OP_COND_JMP:
            case OP_UNCOND_JMP:
                return true;
            default:
                return false;
        }
    }

    bool Insn::isGoto0() const{
        return _opcode==05 && _dst_reg==0 && _src_reg==0&& _off==0 && _imm==0;
    };

    bool Insn::is_st() {
        int insn_class = BPF_CLASS(_opcode);
        return (insn_class == BPF_ST) || (insn_class == BPF_STX);
    }

    bool Insn::is_atomic() {
        return (BPF_CLASS(_opcode) == BPF_STX) || (BPF_MODE(_opcode) == BPF_ATOMIC);
    }

    bool Insn::is_ldx() {
        int insn_class = BPF_CLASS(_opcode);
        return (insn_class == BPF_LDX);
    }

    int Insn::getJumpDst() const {
        switch (getType()) {
            case (OP_UNCOND_JMP):
            case (OP_COND_JMP):
                return _off;
            default:
                std::cout << "Error: opcode is not jmp" << std::endl;
                return 0;
        }
    }

    int Insn::getRegDef() const {
        // TODO: incomplete
        switch (getType()) {
            case OP_CALL: {
                return 0;
            }
            case OP_ALU_OR_LDDW:
                return _dst_reg;
            case OP_LD: {
                return _dst_reg;
            }
            default:
                return INT_MIN;
        }
    }

    // TODO: simplify implementation
    vector<int> Insn::getRegUses() const {
        // copy from inst.cc
        std::vector<int> regs;
        switch (_opcode) {
            case NOP:
                break;
            case ADD64XC:
                regs = {_dst_reg};
                break;
            case ADD64XY:
                regs = {_dst_reg, _src_reg};
                break;
            case SUB64XC:
                regs = {_dst_reg};
                break;
            case SUB64XY:
                regs = {_dst_reg, _src_reg};
                break;
            case MUL64XC:
                regs = {_dst_reg};
                break;
            case MUL64XY:
                regs = {_dst_reg, _src_reg};
                break;
            case DIV64XC:
                regs = {_dst_reg};
                break;
            case DIV64XY:
                regs = {_dst_reg, _src_reg};
                break;
            case OR64XC:
                regs = {_dst_reg};
                break;
            case OR64XY:
                regs = {_dst_reg, _src_reg};
                break;
            case AND64XC:
                regs = {_dst_reg};
                break;
            case AND64XY:
                regs = {_dst_reg, _src_reg};
                break;
            case LSH64XC:
                regs = {_dst_reg};
                break;
            case LSH64XY:
                regs = {_dst_reg, _src_reg};
                break;
            case RSH64XC:
                regs = {_dst_reg};
                break;
            case RSH64XY:
                regs = {_dst_reg, _src_reg};
                break;
            case NEG64XC:
                regs = {_dst_reg};
                break;
            case NEG64XY:
                regs = {_dst_reg};
                break;
            case MOD64XC:
                regs = {_dst_reg};
                break;
            case MOD64XY:
                regs = {_dst_reg, _src_reg};
                break;
            case XOR64XC:
                regs = {_dst_reg};
                break;
            case XOR64XY:
                regs = {_dst_reg, _src_reg};
                break;
            case MOV64XC:
                break;
            case MOV64XY:
                regs = {_src_reg};
                break;
            case ARSH64XC:
                regs = {_dst_reg};
                break;
            case ARSH64XY:
                regs = {_dst_reg, _src_reg};
                break;
            case ADD32XC:
                regs = {_dst_reg};
                break;
            case ADD32XY:
                regs = {_dst_reg, _src_reg};
                break;
            case OR32XC:
                regs = {_dst_reg};
                break;
            case OR32XY:
                regs = {_dst_reg, _src_reg};
                break;
            case AND32XC:
                regs = {_dst_reg};
                break;
            case AND32XY:
                regs = {_dst_reg, _src_reg};
                break;
            case LSH32XC:
                regs = {_dst_reg};
                break;
            case LSH32XY:
                regs = {_dst_reg, _src_reg};
                break;
            case RSH32XC:
                regs = {_dst_reg};
                break;
            case RSH32XY:
                regs = {_dst_reg, _src_reg};
                break;
            case MOD32XC:
                regs = {_dst_reg};
                break;
            case MOD32XY:
                regs = {_dst_reg, _src_reg};
                break;
            case XOR32XC:
                regs = {_dst_reg};
                break;
            case XOR32XY:
                regs = {_dst_reg, _src_reg};
                break;
            case MOV32XC:
                break;
            case MOV32XY:
                regs = {_src_reg};
                break;
            case ARSH32XC:
                regs = {_dst_reg};
                break;
            case ARSH32XY:
                regs = {_dst_reg, _src_reg};
                break;
            case LE:
                regs = {_dst_reg};
                break;
            case BE:
                regs = {_dst_reg};
                break;
            case LDDW:
                break;
            case LDXB:
                regs = {_src_reg};
                break;
            case STXB:
                regs = {_dst_reg, _src_reg};
                break;
            case LDXH:
                regs = {_src_reg};
                break;
            case STXH:
                regs = {_dst_reg, _src_reg};
                break;
            case LDXW:
                regs = {_src_reg};
                break;
            case STXW:
                regs = {_dst_reg, _src_reg};
                break;
            case LDXDW:
                regs = {_src_reg};
                break;
            case STXDW:
                regs = {_dst_reg, _src_reg};
                break;
            case STB:
                regs = {_dst_reg};
                break;
            case STH:
                regs = {_dst_reg};
                break;
            case STW:
                regs = {_dst_reg};
                break;
            case STDW:
                regs = {_dst_reg};
                break;
            case XADD64:
                regs = {_dst_reg, _src_reg};
                break;
            case XADD32:
                regs = {_dst_reg, _src_reg};
                break;
            case LDABSB:
                regs = {6};
                break;
            case LDABSH:
                regs = {6};
                break;
            case LDABSW:
                regs = {6};
                break;
            case LDABSDW:
                regs = {6};
                break;
            case LDINDB:
                regs = {6, _src_reg};
                break;
            case LDINDH:
                regs = {6, _src_reg};
                break;
            case LDINDW:
                regs = {6, _src_reg};
                break;
            case LDINDDW:
                regs = {6, _src_reg};
                break;
            case JA:
                break;
            case JEQXC:
                regs = {_dst_reg};
                break;
            case JEQXY:
                regs = {_dst_reg, _src_reg};
                break;
            case JGTXC:
                regs = {_dst_reg};
                break;
            case JGTXY:
                regs = {_dst_reg, _src_reg};
                break;
            case JGEXC:
                regs = {_dst_reg};
                break;
            case JGEXY:
                regs = {_dst_reg, _src_reg};
                break;
            case JNEXC:
                regs = {_dst_reg};
                break;
            case JNEXY:
                regs = {_dst_reg, _src_reg};
                break;
            case JSGTXC:
                regs = {_dst_reg};
                break;
            case JSGTXY:
                regs = {_dst_reg, _src_reg};
                break;
            case JSGEXC:
                regs = {_dst_reg};
                break;
            case JSGEXY:
                regs = {_dst_reg, _src_reg};
                break;
            case JEQ32XC:
                regs = {_dst_reg};
                break;
            case JEQ32XY:
                regs = {_dst_reg, _src_reg};
                break;
            case JNE32XC:
                regs = {_dst_reg};
                break;
            case JNE32XY:
                regs = {_dst_reg, _src_reg};
                break;
            case CALL:
                switch (_imm) {
                    case BPF_FUNC_map_lookup_elem:  // call 1
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_map_update_elem:  // call 2
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_map_delete_elem:  // call 3
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_probe_read:  // call 4
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_ktime_get_ns:  // call 5
                        break;  // no paras
                    case BPF_FUNC_trace_printk:  // call 6
                        regs = {1, 2, 3, 4, 5};  // TODO: para3 - para5 are available parameters, not must provided.
                    case BPF_FUNC_get_prandom_u32:  // call 7
                        break;
                    case BPF_FUNC_get_smp_processor_id:  // call 8
                        break;
                    case BPF_FUNC_skb_store_bytes:  // call 9
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_l3_csum_replace:  // call 10
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_l4_csum_replace:  // call 11
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_tail_call:  // call 12
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_clone_redirect:  // call 13
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_get_current_pid_tgid:  // call 14
                        break;
                    case BPF_FUNC_get_current_uid_gid:  // call 15
                        break;
                    case BPF_FUNC_get_current_comm:  // call 16
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_get_cgroup_classid:  // call 17
                        regs = {1};
                        break;
                    case BPF_FUNC_skb_vlan_push:  // call 18
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_skb_vlan_pop:  // call 19
                        regs = {1};
                        break;
                    case BPF_FUNC_skb_get_tunnel_key:  // call 20
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_skb_set_tunnel_key:  // call 21
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_perf_event_read:  // call 22
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_redirect:  // call 23
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_get_route_realm:  // call 24
                        regs = {1};
                        break;
                    case BPF_FUNC_perf_event_output:  // call 25
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_skb_load_bytes:  // call 26
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_get_stackid:  // call 27
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_csum_diff:  // call 28
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_skb_get_tunnel_opt:  // call 29
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_skb_set_tunnel_opt:  // call 30
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_skb_change_proto:  // call 31
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_skb_change_type:  // call 32
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_skb_under_cgroup:  // call 33
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_get_hash_recalc:  // call 34
                        regs = {1};
                        break;
                    case BPF_FUNC_get_current_task:  // call 35
                        break;
                    case BPF_FUNC_probe_write_user:  // call 36
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_current_task_under_cgroup:  // call 37
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_skb_change_tail:  // call 38
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_skb_pull_data:  // call 39
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_csum_update:  // call 40
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_set_hash_invalid:  // call 41
                        regs = {1};
                        break;
                    case BPF_FUNC_get_numa_node_id:  // call 42
                        break;
                    case BPF_FUNC_skb_change_head:  // call 43
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_xdp_adjust_head:  // call 44
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_probe_read_str:  // call 45
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_get_socket_cookie:  // call 46
                        regs = {1};
                        break;
                    case BPF_FUNC_get_socket_uid:  // call 47
                        regs = {1};
                        break;
                    case BPF_FUNC_set_hash:  // call 48
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_setsockopt:  // call 49
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_skb_adjust_room:  // call 50
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_redirect_map:  // call 51
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_sk_redirect_map:  // call 52
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_sock_map_update:  // call 53
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_xdp_adjust_meta:  // call 54
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_perf_event_read_value:  // call 55
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_perf_prog_read_value:  // call 56
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_getsockopt:  // call 57
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_override_return:  // call 58
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_sock_ops_cb_flags_set:  // call 59
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_msg_redirect_map:  // call 60
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_msg_apply_bytes:  // call 61
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_msg_cork_bytes:  // call 62
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_msg_pull_data:  // call 63
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_bind:  // call 64
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_xdp_adjust_tail:  // call 65
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_skb_get_xfrm_state:  // call 66
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_get_stack:  // call 67
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_skb_load_bytes_relative:  // call 68
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_fib_lookup:  // call 69
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_sock_hash_update:  // call 70
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_msg_redirect_hash:  // call 71
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_sk_redirect_hash:  // call 72
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_lwt_push_encap:  // call 73
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_lwt_seg6_store_bytes:  // call 74
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_lwt_seg6_adjust_srh:  // call 75
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_lwt_seg6_action:  // call 76
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_rc_repeat:  // call 77
                        regs = {1};
                        break;
                    case BPF_FUNC_rc_keydown:  // call 78
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_skb_cgroup_id:  // call 79
                        regs = {1};
                        break;
                    case BPF_FUNC_get_current_cgroup_id:  // call 80
                        break;
                    case BPF_FUNC_get_local_storage:  // call 81
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_sk_select_reuseport:  // call 82
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_skb_ancestor_cgroup_id:  // call 83
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_sk_lookup_tcp:  // call 84
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_sk_lookup_udp:  // call 85
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_sk_release:  // call 86
                        regs = {1};
                        break;
                    case BPF_FUNC_map_push_elem:  // call 87
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_map_pop_elem:  // call 88
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_map_peek_elem:  // call 89
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_msg_push_data:  // call 90
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_msg_pop_data:  // call 91
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_rc_pointer_rel:  // call 92
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_spin_lock:  // call 93
                        regs = {1};
                        break;
                    case BPF_FUNC_spin_unlock:  // call 94
                        regs = {1};
                        break;
                    case BPF_FUNC_sk_fullsock:  // call 95
                        regs = {1};
                        break;
                    case BPF_FUNC_tcp_sock:  // call 96
                        regs = {1};
                        break;
                    case BPF_FUNC_skb_ecn_set_ce:  // call 97
                        regs = {1};
                        break;
                    case BPF_FUNC_get_listener_sock:  // call 98
                        regs = {1};
                        break;
                    case BPF_FUNC_skc_lookup_tcp:  // call 99
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_tcp_check_syncookie:  // call 100
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_sysctl_get_name:  // call 101
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_sysctl_get_current_value:  // call 102
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_sysctl_get_new_value:  // call 103
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_sysctl_set_new_value:  // call 104
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_strtol:  // call 105
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_strtoul:  // call 106
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_sk_storage_get:  // call 107
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_sk_storage_delete:  // call 108
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_send_signal:  // call 109
                        regs = {1};
                        break;
                    case BPF_FUNC_tcp_gen_syncookie:  // call 110
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_skb_output:  // call 111
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_probe_read_user:  // call 112
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_probe_read_kernel:  // call 113
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_probe_read_user_str:  // call 114
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_probe_read_kernel_str:  // call 115
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_tcp_send_ack:  // call 116
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_send_signal_thread:  // call 117
                        regs = {1};
                        break;
                    case BPF_FUNC_jiffies64:  // call 118
                        break;
                    case BPF_FUNC_read_branch_records:  // call 119
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_get_ns_current_pid_tgid:  // call 120
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_xdp_output:  // call 121
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_get_netns_cookie:  // call 122
                        regs = {1};
                        break;
                    case BPF_FUNC_get_current_ancestor_cgroup_id:  // call 123
                        regs = {1};
                        break;
                    case BPF_FUNC_sk_assign:  // call 124
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_ktime_get_boot_ns:  // call 125
                        break;
                    case BPF_FUNC_seq_printf:  // call 126
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_seq_write:  // call 127
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_sk_cgroup_id:  // call 128
                        regs = {1};
                        break;
                    case BPF_FUNC_sk_ancestor_cgroup_id:  // call 129
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_ringbuf_output:  // call 130
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_ringbuf_reserve:  // call 131
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_ringbuf_submit:  // call 132
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_ringbuf_discard:  // call 133
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_ringbuf_query:  // call 134
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_csum_level:  // call 135
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_skc_to_tcp6_sock:  // call 136
                        regs = {1};
                        break;
                    case BPF_FUNC_skc_to_tcp_sock:  // call 137
                        regs = {1};
                        break;
                    case BPF_FUNC_skc_to_tcp_timewait_sock:  // call 138
                        regs = {1};
                        break;
                    case BPF_FUNC_skc_to_tcp_request_sock:  // call 139
                        regs = {1};
                        break;
                    case BPF_FUNC_skc_to_udp6_sock:  // call 140
                        regs = {1};
                        break;
                    case BPF_FUNC_get_task_stack:  // call 141
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_load_hdr_opt:  // call 142
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_store_hdr_opt:  // call 143
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_reserve_hdr_opt:  // call 144
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_inode_storage_get:  // call 145
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_inode_storage_delete:  // call 146
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_d_path:  // call 147
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_copy_from_user:  // call 148
                        regs = {1, 2, 3};
                        break;
                    case BPF_FUNC_snprintf_btf:  // call 149
                        regs = {1, 2, 3, 4, 5};
                        break;
                    case BPF_FUNC_seq_printf_btf:  // call 150
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_skb_cgroup_classid:  // call 151
                        regs = {1};
                        break;
                    case BPF_FUNC_redirect_neigh:  // call 152
                        regs = {1, 2, 3, 4};
                        break;
                    case BPF_FUNC_per_cpu_ptr:  // call 153
                        regs = {1, 2};
                        break;
                    case BPF_FUNC_this_cpu_ptr:  // call 154
                        regs = {1};
                        break;
                    case BPF_FUNC_redirect_peer:  // call 155
                        regs = {1, 2};
                        break;
//                    case BPF_FUNC_task_storage_get:  // call 156
//                        regs = {1, 2, 3, 4};
//                        break;
//                    case BPF_FUNC_task_storage_delete:  // call 157
//                        regs = {1, 2};
//                        break;
//                    case BPF_FUNC_get_current_task_btf:  // call 158
//                        regs = {1};
//                        break;
//                    case BPF_FUNC_bprm_opts_set:  // call 159
//                        regs = {1, 2};
//                        break;
//                    case BPF_FUNC_ktime_get_coarse_ns:  // call 160
//                        break;
//                    case BPF_FUNC_ima_inode_hash:  // call 161
//                        regs = {1, 2, 3};
//                        break;
//                    case BPF_FUNC_sock_from_file:  // call 162
//                        regs = {1};
//                        break;
//                    case BPF_FUNC_check_mtu:  // call 163
//                        regs = {1, 2, 3, 4, 5};
//                        break;
//                    case BPF_FUNC_for_each_map_elem:  // call 164
//                        regs = {1, 2, 3, 4};
//                        break;
//                    case BPF_FUNC_snprintf:  // call 165
//                        regs = {1, 2, 3, 4, 5};
//                        break;
//                    case BPF_FUNC_sys_bpf:  // call 166
//                        regs = {1, 2, 3};
//                        break;
//                    case BPF_FUNC_btf_find_by_name_kind:  // call 167
//                        regs = {1, 2, 3, 4};
//                        break;
//                    case BPF_FUNC_sys_close:  // call 168
//                        regs = {1};
//                        break;
//                    case BPF_FUNC_timer_init:  // call 169
//                        regs = {1, 2, 3};
//                        break;
//                    case BPF_FUNC_timer_set_callback:  // call 170
//                        regs = {1, 2};
//                        break;
//                    case BPF_FUNC_timer_start:  // call 171
//                        regs = {1, 2, 3};
//                        break;
//                    case BPF_FUNC_timer_cancel:  // call 172
//                        regs = {1};
//                        break;
//                    case BPF_FUNC_get_func_ip:  // call 173
//                        regs = {1};
//                        break;
//                    case BPF_FUNC_get_attach_cookie:  // call 174
//                        regs = {1};
//                        break;
//                    case BPF_FUNC_task_pt_regs:  // call 175
//                        regs = {1};
//                        break;
//                    case BPF_FUNC_get_branch_snapshot:  // call 176
//                        regs = {1, 2, 3};
//                        break;
//                    case BPF_FUNC_trace_vprintk:  // call 177
//                        regs = {1, 2, 3, 4};
//                        break;
//                    case BPF_FUNC_skc_to_unix_sock:  // call 178
//                        regs = {1};
//                        break;
//                    case BPF_FUNC_kallsyms_lookup_name:  // call 179
//                        regs = {1, 2, 3, 4};
//                        break;
//                    case BPF_FUNC_find_vma:  // call 180
//                        regs = {1, 2, 3, 4, 5};
//                        break;
//                    case BPF_FUNC_loop:  // call 181
//                        regs = {1, 2, 3, 4};
//                        break;
//                    case BPF_FUNC_strncmp:  // call 182
//                        regs = {1, 2, 3};
//                        break;
//                    case BPF_FUNC_get_func_arg:  // call 183
//                        regs = {1, 2, 3};
//                        break;
//                    case BPF_FUNC_get_func_ret:  // call 184
//                        regs = {1, 2};
//                        break;
//                    case BPF_FUNC_get_func_arg_cnt:  // call 185
//                        regs = {1};
//                        break;
//                    case BPF_FUNC_get_retval:  // call 186
//                        break;
//                    case BPF_FUNC_set_retval:  // call 187
//                        regs = {1};
//                        break;
//                    case BPF_FUNC_xdp_get_buff_len:  // call 188
//                        regs = {1};
//                        break;
//                    case BPF_FUNC_xdp_load_bytes:  // call 189
//                        regs = {1, 2, 3, 4};
//                        break;
//                    case BPF_FUNC_xdp_store_bytes:  // call 190
//                        regs = {1, 2, 3, 4};
//                        break;
//                    case BPF_FUNC_copy_from_user_task:  // call 191
//                        regs = {1, 2, 3, 4, 5};
//                        break;
//                    case BPF_FUNC_skb_set_tstamp:  // call 192
//                        regs = {1, 2, 3};
//                        break;
//                    case BPF_FUNC_ima_file_hash:  // call 193
//                        regs = {1, 2, 3};
//                        break;
//                    case BPF_FUNC_kptr_xchg:  // call 194
//                        regs = {1, 2};
//                        break;
//                    case BPF_FUNC_map_lookup_percpu_elem:  // call 195
//                        regs = {1, 2, 3};
//                        break;
//                    case BPF_FUNC_skc_to_mptcp_sock:  // call 196
//                        regs = {1};
//                        break;
//                    case BPF_FUNC_dynptr_from_mem:  // call 197
//                        regs = {1, 2, 3, 4};
//                        break;
//                    case BPF_FUNC_ringbuf_reserve_dynptr:  // call 198
//                        regs = {1, 2, 3, 4};
//                        break;
//                    case BPF_FUNC_ringbuf_submit_dynptr:  // call 199
//                        regs = {1, 2};
//                        break;
//                    case BPF_FUNC_ringbuf_discard_dynptr:  // call 200
//                        regs = {1, 2};
//                        break;
//                    case BPF_FUNC_dynptr_read:  // call 201
//                        regs = {1, 2, 3, 4, 5};
//                        break;
//                    case BPF_FUNC_dynptr_write:  // call 202
//                        regs = {1, 2, 3, 4, 5};
//                        break;
//                    case BPF_FUNC_dynptr_data:  // call 203
//                        regs = {1, 2, 3};
//                        break;
//                    case BPF_FUNC_tcp_raw_gen_syncookie_ipv4:  // call 204
//                        regs = {1, 2, 3};
//                        break;
//                    case BPF_FUNC_tcp_raw_gen_syncookie_ipv6:  // call 205
//                        regs = {1, 2, 3};
//                        break;
//                    case BPF_FUNC_tcp_raw_check_syncookie_ipv4:  // call 206
//                        regs = {1, 2};
//                        break;
//                    case BPF_FUNC_tcp_raw_check_syncookie_ipv6:  // call 207
//                        regs = {1, 2};
//                        break;
//                    case BPF_FUNC_ktime_get_tai_ns:  // call 208
//                        break;
//                    case BPF_FUNC_user_ringbuf_drain:  // call 209
//                        regs = {1, 2, 3, 4};
//                        break;
//                    case BPF_FUNC_cgrp_storage_get:  // call 210
//                        regs = {1, 2, 3, 4};
//                        break;
//                    case BPF_FUNC_cgrp_storage_delete:  // call 211
//                        regs = {1, 2};
//                        break;
                    default:
                        regs = {1, 2, 3, 4, 5};
                }
            case EXIT:
                break;
            default:
                regs = {_dst_reg, _src_reg};  // TODO: assert
                break; /* cout << "unknown opcode" << endl; */
        }
        return regs;
    }

    std::ostream &operator<<(std::ostream &os, const Insn &insn) {
        os << std::hex << opcode_2_str(insn._opcode) << " "\
 << regNameString(insn._dst_reg) << " "\
 << regNameString(insn._src_reg) << " "\
 << insn._off << " "\
 << insn._imm << " " << std::dec;
        return os;
    }

    string Insn::get_insn_name() const{
        switch (_opcode) {
            case 0:
                return "NOP";
            case BPF_ALU64 | BPF_NOP:
                return "NOP";
            case BPF_ALU64 | BPF_ADD | BPF_X:
                return "BPF_ADD_X";
            case BPF_ALU64 | BPF_ADD | BPF_K:
                return "BPF_ADD_K";
            case BPF_ALU64 | BPF_SUB | BPF_X:
                return "BPF_SUB_X";
            case BPF_ALU64 | BPF_SUB | BPF_K:
                return "BPF_SUB_K";
            case BPF_ALU64 | BPF_MUL | BPF_X:
                return "BPF_MUL_X";
            case BPF_ALU64 | BPF_MUL | BPF_K:
                return "BPF_MUL_K";
            case BPF_ALU64 | BPF_DIV | BPF_X:
                return "BPF_DIV_X";
            case BPF_ALU64 | BPF_DIV | BPF_K:
                return "BPF_DIV_K";
            case BPF_ALU64 | BPF_OR | BPF_X:
                return "BPF_OR_X";
            case BPF_ALU64 | BPF_OR | BPF_K:
                return "BPF_OR_K";
            case BPF_ALU64 | BPF_AND | BPF_X:
                return "BPF_AND_X";
            case BPF_ALU64 | BPF_AND | BPF_K:
                return "BPF_AND_K";
            case BPF_ALU64 | BPF_LSH | BPF_X:
                return "BPF_LSH_X";
            case BPF_ALU64 | BPF_LSH | BPF_K:
                return "BPF_LSH_K";
            case BPF_ALU64 | BPF_RSH | BPF_X:
                return "BPF_RSH_X";
            case BPF_ALU64 | BPF_RSH | BPF_K:
                return "BPF_RSH_K";
            case BPF_ALU64 | BPF_NEG:
                return "BPF_NEG";
            case BPF_ALU64 | BPF_MOD | BPF_X:
                return "BPF_MOD_X";
            case BPF_ALU64 | BPF_MOD | BPF_K:
                return "BPF_MOD_K";
            case BPF_ALU64 | BPF_XOR | BPF_X:
                return "BPF_XOR_X";
            case BPF_ALU64 | BPF_XOR | BPF_K:
                return "BPF_XOR_K";
            case BPF_ALU64 | BPF_MOV | BPF_X:
                return "BPF_MOV_X";
            case BPF_ALU64 | BPF_MOV | BPF_K:
                return "BPF_MOV_K";
            case BPF_ALU64 | BPF_ARSH | BPF_X:
                return "BPF_ARSH_X";
            case BPF_ALU64 | BPF_ARSH | BPF_K:
                return "BPF_ARSH_K";
            case BPF_ALU64 | BPF_TO_LE | BPF_END:
                return "BPF_TO_LE";
            case BPF_ALU64 | BPF_TO_BE | BPF_END:
                return "BPF_TO_BE";
            case BPF_ALU | BPF_NOP:
                return "NOP";
            case BPF_ALU | BPF_ADD|BPF_X:
                return "BPF_ADD32_X";
            case BPF_ALU | BPF_ADD|BPF_K:
                return "BPF_ADD32_K";
            case BPF_ALU | BPF_SUB|BPF_X:
                return "BPF_SUB32_X";
            case BPF_ALU | BPF_SUB|BPF_K:
                return "BPF_SUB32_K";
            case BPF_ALU | BPF_MUL|BPF_X:
                return "BPF_MUL32_X";
            case BPF_ALU | BPF_MUL|BPF_K:
                return "BPF_MUL32_K";
            case BPF_ALU | BPF_DIV|BPF_X:
                return "BPF_DIV32_X";
            case BPF_ALU | BPF_DIV|BPF_K:
                return "BPF_DIV32_K";
            case BPF_ALU | BPF_OR|BPF_X:
                return "BPF_OR32_X";
            case BPF_ALU | BPF_OR|BPF_K:
                return "BPF_OR32_K";
            case BPF_ALU | BPF_AND|BPF_X:
                return "BPF_AND32_X";
            case BPF_ALU | BPF_AND|BPF_K:
                return "BPF_AND32_K";
            case BPF_ALU | BPF_LSH|BPF_X:
                return "BPF_LSH32_X";
            case BPF_ALU | BPF_LSH|BPF_K:
                return "BPF_LSH32_K";
            case BPF_ALU | BPF_RSH|BPF_X:
                return "BPF_RSH32_X";
            case BPF_ALU | BPF_RSH|BPF_K:
                return "BPF_RSH32_K";
            case BPF_ALU | BPF_NEG|BPF_X:
                return "BPF_NEG32_X";
            case BPF_ALU | BPF_NEG|BPF_K:
                return "BPF_NEG32_K";
            case BPF_ALU | BPF_MOD|BPF_X:
                return "BPF_MOD32_X";
            case BPF_ALU | BPF_MOD|BPF_K:
                return "BPF_MOD32_K";
            case BPF_ALU | BPF_XOR|BPF_X:
                return "BPF_XOR32_X";
            case BPF_ALU | BPF_XOR|BPF_K:
                return "BPF_XOR32_K";
            case BPF_ALU | BPF_MOV|BPF_X:
                return "BPF_MOV32_X";
            case BPF_ALU | BPF_MOV|BPF_K:
                return "BPF_MOV32_K";
            case BPF_ALU | BPF_ARSH|BPF_X:
                return "BPF_ARSH32_X";
            case BPF_ALU | BPF_ARSH|BPF_K:
                return "BPF_ARSH32_K";
            case BPF_ALU | BPF_TO_LE | BPF_END:
                return "BPF_TO_LE32";
            case BPF_ALU | BPF_TO_BE | BPF_END:
                return "BPF_TO_BE32";
            case BPF_JMP | BPF_JA:
                return "BPF_JA";
            case BPF_JMP | BPF_JEQ | BPF_X:
                return "BPF_JEQ_X";
            case BPF_JMP | BPF_JEQ | BPF_K:
                return "BPF_JEQ_K";
            case BPF_JMP | BPF_JGT | BPF_X:
                return "BPF_JGT_X";
            case BPF_JMP | BPF_JGT | BPF_K:
                return "BPF_JGT_K";
            case BPF_JMP | BPF_JGE | BPF_X:
                return "BPF_JGE_X";
            case BPF_JMP | BPF_JGE | BPF_K:
                return "BPF_JGE_K";
            case BPF_JMP | BPF_JSET | BPF_X:
                return "BPF_JSET_X";
            case BPF_JMP | BPF_JSET | BPF_K:
                return "BPF_JSET_K";
            case BPF_JMP | BPF_JNE | BPF_X:
                return "BPF_JNE_X";
            case BPF_JMP | BPF_JNE | BPF_K:
                return "BPF_JNE_K";
            case BPF_JMP | BPF_JSGT | BPF_X:
                return "BPF_JSGT_X";
            case BPF_JMP | BPF_JSGT | BPF_K:
                return "BPF_JSGT_K";
            case BPF_JMP | BPF_JSGE | BPF_X:
                return "BPF_JSGE_X";
            case BPF_JMP | BPF_JSGE | BPF_K:
                return "BPF_JSGE_K";
            case BPF_JMP | BPF_CALL:
                return "BPF_CALL";
            case BPF_JMP | BPF_EXIT:
                return "BPF_EXIT";
            case BPF_JMP | BPF_JLT | BPF_X:
                return "BPF_JLT_X";
            case BPF_JMP | BPF_JLT | BPF_K:
                return "BPF_JLT_K";
            case BPF_JMP | BPF_JLE | BPF_X:
                return "BPF_JLE_X";
            case BPF_JMP | BPF_JLE | BPF_K:
                return "BPF_JLE_K";
            case BPF_JMP | BPF_JSLT | BPF_X:
                return "BPF_JSLT_X";
            case BPF_JMP | BPF_JSLT | BPF_K:
                return "BPF_JSLT_K";
            case BPF_JMP | BPF_JSLE | BPF_X:
                return "BPF_JSLE_X";
            case BPF_JMP | BPF_JSLE | BPF_K:
                return "BPF_JSLE_K";
            case BPF_STX | BPF_MEM | BPF_B:
                return "BPF_STX_MEM_B";
            case BPF_STX | BPF_MEM | BPF_H:
                return "BPF_STX_MEM_H";
            case BPF_STX | BPF_MEM | BPF_W:
                return "BPF_STX_MEM_W";
            case BPF_STX | BPF_MEM | BPF_DW:
                return "BPF_STX_MEM_DW";
            case BPF_STX | BPF_XADD | BPF_W:
                return "BPF_STX_XADD_W";
            case BPF_STX | BPF_XADD | BPF_DW:
                return "BPF_STX_XADD_DW";
            case BPF_ST | BPF_MEM | BPF_B:
                return "BPF_ST_MEM_B";
            case BPF_ST | BPF_MEM | BPF_H:
                return "BPF_ST_MEM_H";
            case BPF_ST | BPF_MEM | BPF_W:
                return "BPF_ST_MEM_W";
            case BPF_ST | BPF_MEM | BPF_DW:
                return "BPF_ST_MEM_DW";
            case BPF_LDX | BPF_MEM | BPF_B:
                return "BPF_LDX_MEM_B";
            case BPF_LDX | BPF_MEM | BPF_H:
                return "BPF_LDX_MEM_H";
            case BPF_LDX | BPF_MEM | BPF_W:
                return "BPF_LDX_MEM_W";
            case BPF_LDX | BPF_MEM | BPF_DW:
                return "BPF_LDX_MEM_DW";
            case BPF_LD | BPF_MEM | BPF_B:
                return "BPF_LD_MEM_B";
            case BPF_LD | BPF_MEM | BPF_H:
                return "BPF_LD_MEM_H";
            case BPF_LD | BPF_MEM | BPF_W:
                return "BPF_LD_MEM_W";
            case BPF_LD | BPF_MEM | BPF_DW:
                return "BPF_LD_MEM_DW";
            case BPF_LD | BPF_IMM | BPF_DW:
                return "BPF_LD_IMM_DW";
            case BPF_LD | BPF_ABS | BPF_B:
                return "BPF_LD_ABS_B";
            case BPF_LD | BPF_ABS | BPF_H:
                return "BPF_LD_ABS_H";
            case BPF_LD | BPF_ABS | BPF_W:
                return "BPF_LD_ABS_W";
            case BPF_LD | BPF_ABS | BPF_DW:
                return "BPF_LD_ABS_DW";
            case BPF_LD | BPF_IND | BPF_B:
                return "BPF_LD_IND_B";
            case BPF_LD | BPF_IND | BPF_H:
                return "BPF_LD_IND_H";
            case BPF_LD | BPF_IND | BPF_W:
                return "BPF_LD_IND_W";
            case BPF_LD | BPF_IND | BPF_DW:
                return "BPF_LD_IND_DW";
            default:
                return "UNKNOWN";
        }
    }

    bool Insn::isShiftX() const {
        return (_opcode == (LSH64XY) || _opcode == (LSH32XY)
                || _opcode == (RSH64XY) || _opcode == (RSH32XY)
                || _opcode == (ARSH64XY) || _opcode == (ARSH32XY));
    }

    bool Insn::isShift() const {
        return (_opcode == (LSH64XC) || _opcode == (LSH32XC)
                || _opcode == (RSH64XC) || _opcode == (RSH32XC)
                || _opcode == (ARSH64XC) || _opcode == (ARSH32XC)
                ||isShiftX());
    }

    bool Insn::isDivModX() const {
        return (_opcode == (DIV64XY) || _opcode == (DIV32XY)
                || _opcode == (MOD64XY) || _opcode == (MOD32XY));
    }

    bool Insn::isDivModK() const {
        return (_opcode == (DIV64XC) || _opcode == (DIV32XC)
                || _opcode == (MOD64XC) || _opcode == (MOD32XC));
    }

    bool Insn::isSplit() const {
        int type = getType();
        return (type == OP_RET)
               || (type == OP_UNCOND_JMP) || (type == OP_COND_JMP)
               || (type == OP_CALL)
               || (BPF_CLASS(_opcode) == BPF_LD)
               || (_opcode == 0)
               || (_is_reloc == 1)
               || (_is_core_reloc == 1);
    }

    set <u8> Insn::get_related_opcodes() {
        return related_opcodes.at(_opcode);
    }

    double Insn::get_runtime() {
        double res=1;
        if (_opcode == CALL) {
            if (call_runtime.find(_imm) != call_runtime.end())
                res = call_runtime[_imm];
        } else if (_opcode == BE) {
            if (be_runtime.find(_imm) != be_runtime.end())
                res = be_runtime[_imm];
        } else if (_opcode == LE) {
            if (le_runtime.find(_imm) != le_runtime.end())
                res = le_runtime[_imm];
        } else {
            if (insn_runtime.find(_opcode) != insn_runtime.end())
                res = insn_runtime[_opcode];
        }
        return res;
    }

    void Insn::print_insn() const{
        cout << left << setw(16) << get_insn_name() << setfill(' ') <<
             setw(8) << _dst_reg << setw(8) << _src_reg
             << "0x" << hex << setw(9) << _off << "0x" << _imm << dec << endl;
        if (_is_reloc == 1) {
            cout << "    Reloc: map_idx: " << _reloc_map_idx << endl;
        }
        if (_is_core_reloc == 1) {
            cout << "    CO-RE Reloc: " << endl;
        }
    }

    bool Insn::is_length_2() const {
        return BPF_CLASS(_opcode) == BPF_LD && BPF_SIZE(_opcode) == BPF_DW;
    }
}


