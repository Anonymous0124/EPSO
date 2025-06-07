/* Copied from linux/bpf.h, linux/bpf_common.h
 * commit: 9e6c535c64adf6155e4a11fe8d63b384fe3452f8
 */
#ifndef SUPERBPF_EBPF_BPF_H
#define SUPERBPF_EBPF_BPF_H

#include <map>
#include <string>

namespace superbpf {
// copied frome 'include/uapi/linux/bpf_common.h'
/* Insn classes */
#define BPF_CLASS(code) ((code) & 0x07)
#define   BPF_LD    0x00
#define   BPF_LDX   0x01
#define   BPF_ST    0x02
#define   BPF_STX   0x03
#define   BPF_ALU   0x04
#define   BPF_JMP   0x05
#define   BPF_RET   0x06
#define   BPF_MISC  0x07

/* ld/ldx fields */
#define BPF_SIZE(code)  ((code) & 0x18)
#define   BPF_W   0x00 /* 32-bit */
#define   BPF_H   0x08 /* 16-bit */
#define   BPF_B   0x10 /*  8-bit */
/* eBPF   BPF_DW    0x18  64-bit */
#define BPF_MODE(code)  ((code) & 0xe0)
#define   BPF_IMM   0x00
#define   BPF_ABS   0x20
#define   BPF_IND   0x40
#define   BPF_MEM   0x60
#define   BPF_LEN   0x80
#define   BPF_MSH   0xa0

/* alu/jmp fields */
#define BPF_OP(code)    ((code) & 0xf0)
#define   BPF_ADD   0x00
#define   BPF_SUB   0x10
#define   BPF_MUL   0x20
#define   BPF_DIV   0x30
#define   BPF_OR    0x40
#define   BPF_AND   0x50
#define   BPF_LSH   0x60
#define   BPF_RSH   0x70
#define   BPF_NEG   0x80
#define   BPF_MOD   0x90
#define   BPF_XOR   0xa0
#define   BPF_NOP   0xe0

#define   BPF_JA    0x00
#define   BPF_JEQ   0x10
#define   BPF_JGT   0x20
#define   BPF_JGE   0x30
#define   BPF_JSET  0x40
#define BPF_SRC(code)   ((code) & 0x08)
#define   BPF_K     0x00
#define   BPF_X     0x08

/* instruction classes */
#define BPF_JMP32 0x06  /* jmp mode in word width */
#define BPF_ALU64 0x07  /* alu mode in double word width */

/* ld/ldx fields */
#define BPF_DW        0x18    /* double word (64-bit) */
#define BPF_ATOMIC    0xc0    /* atomic memory ops - op type in immediate */
#define BPF_XADD    0xc0    /* exclusive add - legacy name */

/* alu/jmp fields */
#define BPF_MOV   0xb0  /* mov reg to reg */
#define BPF_ARSH  0xc0  /* sign extending arithmetic shift right */

/* change endianness of a register */
#define BPF_END   0xd0  /* flags for endianness conversion: */
#define BPF_TO_LE 0x00  /* convert to little-endian */
#define BPF_TO_BE 0x08  /* convert to big-endian */
#define BPF_FROM_LE BPF_TO_LE
#define BPF_FROM_BE BPF_TO_BE

/* jmp encodings */
#define BPF_JNE   0x50  /* jump != */
#define BPF_JLT   0xa0  /* LT is unsigned, '<' */
#define BPF_JLE   0xb0  /* LE is unsigned, '<=' */
#define BPF_JSGT  0x60  /* SGT is signed '>', GT in x86 */
#define BPF_JSGE  0x70  /* SGE is signed '>=', GE in x86 */
#define BPF_JSLT  0xc0  /* SLT is signed, '<' */
#define BPF_JSLE  0xd0  /* SLE is signed, '<=' */
#define BPF_CALL  0x80  /* function call */
#define BPF_EXIT  0x90  /* function return */

/* atomic op type fields (stored in immediate) */
#define BPF_FETCH    0x01    /* not an opcode on its own, used to build others */
#define BPF_XCHG    (0xe0 | BPF_FETCH)    /* atomic exchange */
#define BPF_CMPXCHG    (0xf0 | BPF_FETCH)    /* atomic compare-and-write */

// copied from include/uapi/linux/bpf.h
#define ___BPF_FUNC_MAPPER(FN, ctx...)            \
    FN(unspec, 0, ##ctx)                \
    FN(map_lookup_elem, 1, ##ctx)            \
    FN(map_update_elem, 2, ##ctx)            \
    FN(map_delete_elem, 3, ##ctx)            \
    FN(probe_read, 4, ##ctx)            \
    FN(ktime_get_ns, 5, ##ctx)            \
    FN(trace_printk, 6, ##ctx)            \
    FN(get_prandom_u32, 7, ##ctx)            \
    FN(get_smp_processor_id, 8, ##ctx)        \
    FN(skb_store_bytes, 9, ##ctx)            \
    FN(l3_csum_replace, 10, ##ctx)            \
    FN(l4_csum_replace, 11, ##ctx)            \
    FN(tail_call, 12, ##ctx)            \
    FN(clone_redirect, 13, ##ctx)            \
    FN(get_current_pid_tgid, 14, ##ctx)        \
    FN(get_current_uid_gid, 15, ##ctx)        \
    FN(get_current_comm, 16, ##ctx)            \
    FN(get_cgroup_classid, 17, ##ctx)        \
    FN(skb_vlan_push, 18, ##ctx)            \
    FN(skb_vlan_pop, 19, ##ctx)            \
    FN(skb_get_tunnel_key, 20, ##ctx)        \
    FN(skb_set_tunnel_key, 21, ##ctx)        \
    FN(perf_event_read, 22, ##ctx)            \
    FN(redirect, 23, ##ctx)                \
    FN(get_route_realm, 24, ##ctx)            \
    FN(perf_event_output, 25, ##ctx)        \
    FN(skb_load_bytes, 26, ##ctx)            \
    FN(get_stackid, 27, ##ctx)            \
    FN(csum_diff, 28, ##ctx)            \
    FN(skb_get_tunnel_opt, 29, ##ctx)        \
    FN(skb_set_tunnel_opt, 30, ##ctx)        \
    FN(skb_change_proto, 31, ##ctx)            \
    FN(skb_change_type, 32, ##ctx)            \
    FN(skb_under_cgroup, 33, ##ctx)            \
    FN(get_hash_recalc, 34, ##ctx)            \
    FN(get_current_task, 35, ##ctx)            \
    FN(probe_write_user, 36, ##ctx)            \
    FN(current_task_under_cgroup, 37, ##ctx)    \
    FN(skb_change_tail, 38, ##ctx)            \
    FN(skb_pull_data, 39, ##ctx)            \
    FN(csum_update, 40, ##ctx)            \
    FN(set_hash_invalid, 41, ##ctx)            \
    FN(get_numa_node_id, 42, ##ctx)            \
    FN(skb_change_head, 43, ##ctx)            \
    FN(xdp_adjust_head, 44, ##ctx)            \
    FN(probe_read_str, 45, ##ctx)            \
    FN(get_socket_cookie, 46, ##ctx)        \
    FN(get_socket_uid, 47, ##ctx)            \
    FN(set_hash, 48, ##ctx)                \
    FN(setsockopt, 49, ##ctx)            \
    FN(skb_adjust_room, 50, ##ctx)            \
    FN(redirect_map, 51, ##ctx)            \
    FN(sk_redirect_map, 52, ##ctx)            \
    FN(sock_map_update, 53, ##ctx)            \
    FN(xdp_adjust_meta, 54, ##ctx)            \
    FN(perf_event_read_value, 55, ##ctx)        \
    FN(perf_prog_read_value, 56, ##ctx)        \
    FN(getsockopt, 57, ##ctx)            \
    FN(override_return, 58, ##ctx)            \
    FN(sock_ops_cb_flags_set, 59, ##ctx)        \
    FN(msg_redirect_map, 60, ##ctx)            \
    FN(msg_apply_bytes, 61, ##ctx)            \
    FN(msg_cork_bytes, 62, ##ctx)            \
    FN(msg_pull_data, 63, ##ctx)            \
    FN(bind, 64, ##ctx)                \
    FN(xdp_adjust_tail, 65, ##ctx)            \
    FN(skb_get_xfrm_state, 66, ##ctx)        \
    FN(get_stack, 67, ##ctx)            \
    FN(skb_load_bytes_relative, 68, ##ctx)        \
    FN(fib_lookup, 69, ##ctx)            \
    FN(sock_hash_update, 70, ##ctx)            \
    FN(msg_redirect_hash, 71, ##ctx)        \
    FN(sk_redirect_hash, 72, ##ctx)            \
    FN(lwt_push_encap, 73, ##ctx)            \
    FN(lwt_seg6_store_bytes, 74, ##ctx)        \
    FN(lwt_seg6_adjust_srh, 75, ##ctx)        \
    FN(lwt_seg6_action, 76, ##ctx)            \
    FN(rc_repeat, 77, ##ctx)            \
    FN(rc_keydown, 78, ##ctx)            \
    FN(skb_cgroup_id, 79, ##ctx)            \
    FN(get_current_cgroup_id, 80, ##ctx)        \
    FN(get_local_storage, 81, ##ctx)        \
    FN(sk_select_reuseport, 82, ##ctx)        \
    FN(skb_ancestor_cgroup_id, 83, ##ctx)        \
    FN(sk_lookup_tcp, 84, ##ctx)            \
    FN(sk_lookup_udp, 85, ##ctx)            \
    FN(sk_release, 86, ##ctx)            \
    FN(map_push_elem, 87, ##ctx)            \
    FN(map_pop_elem, 88, ##ctx)            \
    FN(map_peek_elem, 89, ##ctx)            \
    FN(msg_push_data, 90, ##ctx)            \
    FN(msg_pop_data, 91, ##ctx)            \
    FN(rc_pointer_rel, 92, ##ctx)            \
    FN(spin_lock, 93, ##ctx)            \
    FN(spin_unlock, 94, ##ctx)            \
    FN(sk_fullsock, 95, ##ctx)            \
    FN(tcp_sock, 96, ##ctx)                \
    FN(skb_ecn_set_ce, 97, ##ctx)            \
    FN(get_listener_sock, 98, ##ctx)        \
    FN(skc_lookup_tcp, 99, ##ctx)            \
    FN(tcp_check_syncookie, 100, ##ctx)        \
    FN(sysctl_get_name, 101, ##ctx)            \
    FN(sysctl_get_current_value, 102, ##ctx)    \
    FN(sysctl_get_new_value, 103, ##ctx)        \
    FN(sysctl_set_new_value, 104, ##ctx)        \
    FN(strtol, 105, ##ctx)                \
    FN(strtoul, 106, ##ctx)                \
    FN(sk_storage_get, 107, ##ctx)            \
    FN(sk_storage_delete, 108, ##ctx)        \
    FN(send_signal, 109, ##ctx)            \
    FN(tcp_gen_syncookie, 110, ##ctx)        \
    FN(skb_output, 111, ##ctx)            \
    FN(probe_read_user, 112, ##ctx)            \
    FN(probe_read_kernel, 113, ##ctx)        \
    FN(probe_read_user_str, 114, ##ctx)        \
    FN(probe_read_kernel_str, 115, ##ctx)        \
    FN(tcp_send_ack, 116, ##ctx)            \
    FN(send_signal_thread, 117, ##ctx)        \
    FN(jiffies64, 118, ##ctx)            \
    FN(read_branch_records, 119, ##ctx)        \
    FN(get_ns_current_pid_tgid, 120, ##ctx)        \
    FN(xdp_output, 121, ##ctx)            \
    FN(get_netns_cookie, 122, ##ctx)        \
    FN(get_current_ancestor_cgroup_id, 123, ##ctx)    \
    FN(sk_assign, 124, ##ctx)            \
    FN(ktime_get_boot_ns, 125, ##ctx)        \
    FN(seq_printf, 126, ##ctx)            \
    FN(seq_write, 127, ##ctx)            \
    FN(sk_cgroup_id, 128, ##ctx)            \
    FN(sk_ancestor_cgroup_id, 129, ##ctx)        \
    FN(ringbuf_output, 130, ##ctx)            \
    FN(ringbuf_reserve, 131, ##ctx)            \
    FN(ringbuf_submit, 132, ##ctx)            \
    FN(ringbuf_discard, 133, ##ctx)            \
    FN(ringbuf_query, 134, ##ctx)            \
    FN(csum_level, 135, ##ctx)            \
    FN(skc_to_tcp6_sock, 136, ##ctx)        \
    FN(skc_to_tcp_sock, 137, ##ctx)            \
    FN(skc_to_tcp_timewait_sock, 138, ##ctx)    \
    FN(skc_to_tcp_request_sock, 139, ##ctx)        \
    FN(skc_to_udp6_sock, 140, ##ctx)        \
    FN(get_task_stack, 141, ##ctx)            \
    FN(load_hdr_opt, 142, ##ctx)            \
    FN(store_hdr_opt, 143, ##ctx)            \
    FN(reserve_hdr_opt, 144, ##ctx)            \
    FN(inode_storage_get, 145, ##ctx)        \
    FN(inode_storage_delete, 146, ##ctx)        \
    FN(d_path, 147, ##ctx)                \
    FN(copy_from_user, 148, ##ctx)            \
    FN(snprintf_btf, 149, ##ctx)            \
    FN(seq_printf_btf, 150, ##ctx)            \
    FN(skb_cgroup_classid, 151, ##ctx)        \
    FN(redirect_neigh, 152, ##ctx)            \
    FN(per_cpu_ptr, 153, ##ctx)            \
    FN(this_cpu_ptr, 154, ##ctx)            \
    FN(redirect_peer, 155, ##ctx)            \
//    FN(task_storage_get, 156, ##ctx)        \
//    FN(task_storage_delete, 157, ##ctx)        \
//    FN(get_current_task_btf, 158, ##ctx)        \
//    FN(bprm_opts_set, 159, ##ctx)            \
//    FN(ktime_get_coarse_ns, 160, ##ctx)        \
//    FN(ima_inode_hash, 161, ##ctx)            \
//    FN(sock_from_file, 162, ##ctx)            \
//    FN(check_mtu, 163, ##ctx)            \
//    FN(for_each_map_elem, 164, ##ctx)        \
//    FN(snprintf, 165, ##ctx)            \
//    FN(sys_bpf, 166, ##ctx)                \
//    FN(btf_find_by_name_kind, 167, ##ctx)        \
//    FN(sys_close, 168, ##ctx)            \
//    FN(timer_init, 169, ##ctx)            \
//    FN(timer_set_callback, 170, ##ctx)        \
//    FN(timer_start, 171, ##ctx)            \
//    FN(timer_cancel, 172, ##ctx)            \
//    FN(get_func_ip, 173, ##ctx)            \
//    FN(get_attach_cookie, 174, ##ctx)        \
//    FN(task_pt_regs, 175, ##ctx)            \
//    FN(get_branch_snapshot, 176, ##ctx)        \
//    FN(trace_vprintk, 177, ##ctx)            \
//    FN(skc_to_unix_sock, 178, ##ctx)        \
//    FN(kallsyms_lookup_name, 179, ##ctx)        \
//    FN(find_vma, 180, ##ctx)            \
//    FN(loop, 181, ##ctx)                \
//    FN(strncmp, 182, ##ctx)                \
//    FN(get_func_arg, 183, ##ctx)            \
//    FN(get_func_ret, 184, ##ctx)            \
//    FN(get_func_arg_cnt, 185, ##ctx)        \
//    FN(get_retval, 186, ##ctx)            \
//    FN(set_retval, 187, ##ctx)            \
//    FN(xdp_get_buff_len, 188, ##ctx)        \
//    FN(xdp_load_bytes, 189, ##ctx)            \
//    FN(xdp_store_bytes, 190, ##ctx)            \
//    FN(copy_from_user_task, 191, ##ctx)        \
//    FN(skb_set_tstamp, 192, ##ctx)            \
//    FN(ima_file_hash, 193, ##ctx)            \
//    FN(kptr_xchg, 194, ##ctx)            \
//    FN(map_lookup_percpu_elem, 195, ##ctx)        \
//    FN(skc_to_mptcp_sock, 196, ##ctx)        \
//    FN(dynptr_from_mem, 197, ##ctx)            \
//    FN(ringbuf_reserve_dynptr, 198, ##ctx)        \
//    FN(ringbuf_submit_dynptr, 199, ##ctx)        \
//    FN(ringbuf_discard_dynptr, 200, ##ctx)        \
//    FN(dynptr_read, 201, ##ctx)            \
//    FN(dynptr_write, 202, ##ctx)            \
//    FN(dynptr_data, 203, ##ctx)            \
//    FN(tcp_raw_gen_syncookie_ipv4, 204, ##ctx)    \
//    FN(tcp_raw_gen_syncookie_ipv6, 205, ##ctx)    \
//    FN(tcp_raw_check_syncookie_ipv4, 206, ##ctx)    \
//    FN(tcp_raw_check_syncookie_ipv6, 207, ##ctx)    \
//    FN(ktime_get_tai_ns, 208, ##ctx)        \
//    FN(user_ringbuf_drain, 209, ##ctx)        \
//    FN(cgrp_storage_get, 210, ##ctx)        \
//    FN(cgrp_storage_delete, 211, ##ctx)        \

/* integer value in 'imm' field of BPF_CALL instruction selects which helper
 * function eBPF program intends to call
 */
#define __BPF_ENUM_FN(x, y) BPF_FUNC_ ## x = y,
    enum bpf_func_id {
        ___BPF_FUNC_MAPPER(__BPF_ENUM_FN)
        __BPF_FUNC_MAX_ID,
    };
#undef __BPF_ENUM_FN

    // copied from 'linux/bpf.h'
    /* types of values stored in eBPF registers */
    /* Pointer types represent:
     * pointer
     * pointer + imm
     * pointer + (u16) var
     * pointer + (u16) var + imm
     * if (range > 0) then [ptr, ptr + range - off) is safe to access
     * if (id > 0) means that some 'var' was added
     * if (off > 0) means that 'imm' was added
     */
    enum RegType {
        NOT_INIT = 0,         /* nothing was written into register */
        SCALAR_VALUE,         /* reg doesn't contain a valid pointer */
        PTR_TO_CTX,         /* reg points to bpf_context */
        CONST_PTR_TO_MAP,     /* reg points to struct bpf_map */
        PTR_TO_MAP_VALUE,     /* reg points to map element value */
        PTR_TO_MAP_VALUE_OR_NULL,/* points to map elem value or NULL */
        PTR_TO_STACK,         /* reg == frame_pointer + offset */
        PTR_TO_PACKET_META,     /* skb->data - meta_len */
        PTR_TO_PACKET,         /* reg points to skb->data */
        PTR_TO_PACKET_END,     /* skb->data + headlen */
        PTR_TO_FLOW_KEYS,     /* reg points to bpf_flow_keys */
        PTR_TO_SOCKET,         /* reg points to struct bpf_sock */
        PTR_TO_SOCKET_OR_NULL,     /* reg points to struct bpf_sock or NULL */
        PTR_TO_SOCK_COMMON,     /* reg points to sock_common */
        PTR_TO_SOCK_COMMON_OR_NULL, /* reg points to sock_common or NULL */
        PTR_TO_TCP_SOCK,     /* reg points to struct tcp_sock */
        PTR_TO_TCP_SOCK_OR_NULL, /* reg points to struct tcp_sock or NULL */
        PTR_TO_TP_BUFFER,     /* reg points to a writable raw tp's buffer */
        PTR_TO_XDP_SOCK,     /* reg points to struct xdp_sock */
        /* PTR_TO_BTF_ID points to a kernel struct that does not need
         * to be null checked by the BPF program. This does not imply the
         * pointer is _not_ null and in practice this can easily be a null
         * pointer when reading pointer chains. The assumption is program
         * context will handle null pointer dereference typically via fault
         * handling. The verifier must keep this in mind and can make no
         * assumptions about null or non-null when doing branch analysis.
         * Further, when passed into helpers the helpers can not, without
         * additional context, assume the value is non-null.
         */
        PTR_TO_BTF_ID,
        /* PTR_TO_BTF_ID_OR_NULL points to a kernel struct that has not
         * been checked for null. Used primarily to inform the verifier
         * an explicit null check is required for this struct.
         */
        PTR_TO_BTF_ID_OR_NULL,
        PTR_TO_MEM,         /* reg points to valid memory region */
        PTR_TO_MEM_OR_NULL,     /* reg points to valid memory region or NULL */
        PTR_TO_RDONLY_BUF,     /* reg points to a readonly buffer */
        PTR_TO_RDONLY_BUF_OR_NULL, /* reg points to a readonly buffer or NULL */
        PTR_TO_RDWR_BUF,     /* reg points to a read/write buffer */
        PTR_TO_RDWR_BUF_OR_NULL, /* reg points to a read/write buffer or NULL */
        PTR_TO_PERCPU_BTF_ID,     /* reg points to a percpu kernel variable */

        LD_IMM_VALUE,  /* dst_reg if insn 'bpf_ld_imm' */
        STACK_VALUE,
        CTX_VALUE,
        MEM_VALUE,
        MIXED_TYPE,  /* have different types */
    };

    static std::map<RegType, RegType> type_exclude_null = {
            {PTR_TO_MAP_VALUE_OR_NULL,   PTR_TO_MAP_VALUE},
            {PTR_TO_SOCK_COMMON_OR_NULL, PTR_TO_SOCK_COMMON},
            {PTR_TO_TCP_SOCK_OR_NULL,    PTR_TO_TCP_SOCK},
            {PTR_TO_MEM_OR_NULL,         PTR_TO_MEM},
            {PTR_TO_BTF_ID_OR_NULL,      PTR_TO_BTF_ID},
            {PTR_TO_RDONLY_BUF_OR_NULL,  PTR_TO_RDONLY_BUF},
            {PTR_TO_RDWR_BUF_OR_NULL,    PTR_TO_RDONLY_BUF},
            {PTR_TO_SOCKET_OR_NULL,      PTR_TO_SOCKET},
    };

    static std::map<RegType, std::string> reg_type_str = {
            {NOT_INIT, "?"},
            {SCALAR_VALUE, "inv"},
            {PTR_TO_CTX, "ctx"},
            {CONST_PTR_TO_MAP, "map_ptr"},
            {PTR_TO_MAP_VALUE, "map_value"},
            {PTR_TO_MAP_VALUE_OR_NULL, "map_value_or_null"},
            {PTR_TO_STACK, "fp"},
            {PTR_TO_PACKET, "pkt"},
            {PTR_TO_PACKET_META, "pkt_meta"},
            {PTR_TO_PACKET_END, "pkt_end"},
            {PTR_TO_FLOW_KEYS, "flow_keys"},
            {PTR_TO_SOCKET, "sock"},
            {PTR_TO_SOCKET_OR_NULL, "sock_or_null"},
            {PTR_TO_SOCK_COMMON, "sock_common"},
            {PTR_TO_SOCK_COMMON_OR_NULL, "sock_common_or_null"},
            {PTR_TO_TCP_SOCK, "tcp_sock"},
            {PTR_TO_TCP_SOCK_OR_NULL, "tcp_sock_or_null"},
            {PTR_TO_TP_BUFFER, "tp_buffer"},
            {PTR_TO_XDP_SOCK, "xdp_sock"},
            {PTR_TO_BTF_ID, "ptr_"},
            {PTR_TO_BTF_ID_OR_NULL, "ptr_or_null"},
            {PTR_TO_PERCPU_BTF_ID, "percpu_ptr_"},
            {PTR_TO_MEM, "mem"},
            {PTR_TO_MEM_OR_NULL, "mem_or_null"},
            {PTR_TO_RDONLY_BUF, "rdonly_buf"},
            {PTR_TO_RDONLY_BUF_OR_NULL, "rdonly_buf_or_null"},
            {PTR_TO_RDWR_BUF, "rdwr_buf"},
            {PTR_TO_RDWR_BUF_OR_NULL, "rdwr_buf_or_null"},
            {LD_IMM_VALUE, "ld_imm_value"},
            {STACK_VALUE, "stack_value"},
            {CTX_VALUE, "ctx_value"},
            {MEM_VALUE, "mem_value"},
            {MIXED_TYPE, "mixed"}
    };

    enum bpf_access_type {
        BPF_READ = 1,
        BPF_WRITE = 2
    };

    typedef unsigned char u8;
    typedef unsigned short u16;
    typedef unsigned int u32;
    typedef unsigned long u64;
    typedef char s8;
    typedef short s16;
    typedef int s32;
    typedef long s64;
}


#endif //SUPERBPF_EBPF_BPF_H
