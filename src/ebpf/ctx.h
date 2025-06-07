#ifndef SUPERBPF_CTX_H
#define SUPERBPF_CTX_H

#include <bpf/libbpf.h>
#include <linux/if_ether.h>

#include "ebpf/bpf.h"

namespace superbpf {
    static std::map<bpf_prog_type,int> pkt_size={
            {BPF_PROG_TYPE_XDP,sizeof(ethhdr)},
    };
    /**
     * sizeof_field(TYPE, MEMBER)
     *
     * @TYPE: The structure containing the field of interest
     * @MEMBER: The field to return the size of
     */
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
    /**
     * offsetofend(TYPE, MEMBER)
     *
     * @TYPE: The type of the structure
     * @MEMBER: The member within the structure to get the end offset of
     */
#define offsetofend(TYPE, MEMBER) \
        (offsetof(TYPE, MEMBER)    + sizeof_field(TYPE, MEMBER))

#define bpf_ctx_range(TYPE, MEMBER)                        \
        offsetof(TYPE, MEMBER) ... offsetofend(TYPE, MEMBER) - 1

#define bpf_ctx_range_till(TYPE, MEMBER1, MEMBER2)                \
        offsetof(TYPE, MEMBER1) ... offsetofend(TYPE, MEMBER2) - 1

#if BITS_PER_LONG == 64
# define bpf_ctx_range_ptr(TYPE, MEMBER)					\
            offsetof(TYPE, MEMBER) ... offsetofend(TYPE, MEMBER) - 1
#else
# define bpf_ctx_range_ptr(TYPE, MEMBER)                    \
            offsetof(TYPE, MEMBER) ... offsetof(TYPE, MEMBER) + 8 - 1
#endif /* BITS_PER_LONG == 64 */

#define bpf_ctx_wide_access_ok(off, size, type, field)            \
    (size == sizeof(__u64) &&                    \
    off >= offsetof(type, field) &&                    \
    off + sizeof(__u64) <= offsetofend(type, field) &&        \
    off % sizeof(__u64) == 0)

#define PERF_MAX_TRACE_SIZE    2048
#define MAX_BPF_FUNC_ARGS 12

    struct user_pt_regs {
        __u64		regs[31];
        __u64		sp;
        __u64		pc;
        __u64		pstate;
    };

    struct pt_regs {
        union {
            struct user_pt_regs user_regs;
            struct {
                long uregs[26];
                long fp;
                long gp;
                long lp;
                long sp;
                long ipc;
#if defined(CONFIG_HWZOL)
                long lb;
    long le;
    long lc;
#else
                long dummy[3];
#endif
                long syscallno;
            };
        };
        long orig_r0;
        long ir0;
        long ipsw;
        long pipsw;
        long pipc;
        long pp0;
        long pp1;
        long fucop_ctl;
        long osp;
    };

    typedef struct user_pt_regs bpf_user_pt_regs_t;

    struct bpf_perf_event_data {
        bpf_user_pt_regs_t regs;
        __u64 sample_period;
        __u64 addr;
    };

    static std::map<bpf_prog_type,int> ctx_size={
            {BPF_PROG_TYPE_XDP,sizeof(xdp_md)},
            {BPF_PROG_TYPE_CGROUP_SKB,sizeof(__sk_buff)},
            {BPF_PROG_TYPE_CGROUP_SOCK,sizeof(bpf_sock)},
            {BPF_PROG_TYPE_CGROUP_SOCK_ADDR,sizeof(bpf_sock_addr)},
            {BPF_PROG_TYPE_KPROBE,sizeof(pt_regs)},
            {BPF_PROG_TYPE_PERF_EVENT,sizeof(bpf_perf_event_data)},
            {BPF_PROG_TYPE_SCHED_CLS,sizeof(__sk_buff)},
            {BPF_PROG_TYPE_SOCKET_FILTER,sizeof(__sk_buff)},
            {BPF_PROG_TYPE_SOCK_OPS,sizeof(bpf_sock_ops)},
            {BPF_PROG_TYPE_RAW_TRACEPOINT,8*MAX_BPF_FUNC_ARGS},
            {BPF_PROG_TYPE_TRACEPOINT,8*MAX_BPF_FUNC_ARGS},
            {BPF_PROG_TYPE_TRACING,8*MAX_BPF_FUNC_ARGS}, // TODO
    };

    bool is_ctx_valid_access(bpf_prog_type prog_type, bpf_attach_type expected_attach_type,
                             int off, int size, bpf_access_type access_type, RegType &reg_type);

    /* CGROUP_DEVICE */
    bool cgroup_dev_is_valid_access(int off, int size, bpf_access_type type, RegType &reg_type);

    /* CGROUP_SKB */
    bool cg_skb_is_valid_access(int off, int size, bpf_access_type type, RegType &reg_type);

    /* CGROUP_SOCK_OPT */
    bool cg_sockopt_is_valid_access(int off, int size, bpf_access_type type, bpf_attach_type expected_attach_type,
                                    RegType &reg_type);

    /* CGROUP_SOCK_ADDR */
    bool sock_addr_is_valid_access(int off, int size, bpf_access_type type, bpf_attach_type expected_attach_type,
                                   RegType &reg_type);

    /* CGROUP_SOCK */
    bool sock_filter_is_valid_access(int off, int size, bpf_access_type type, bpf_attach_type expected_attach_type);

    /* CGROUP_SYSCTL */
    bool sysctl_is_valid_access(int off, int size, enum bpf_access_type type);

    /* FLOW_DISSECTOR */
    bool flow_dissector_is_valid_access(int off, int size, bpf_access_type type, RegType &reg_type);

    /* KPROBE */
    bool kprobe_prog_is_valid_access(int off, int size, enum bpf_access_type type);

    /* LIRC_MODE2 */
    bool lirc_mode2_is_valid_access(int off, int size,bpf_access_type type);

    /* LWT_IN, LWT_OUT, LWT_SEG6LOCAL, LWT_XMIT */
    bool lwt_is_valid_access(int off, int size,bpf_access_type type,RegType& reg_type);

    /* PERF_EVENT */
    bool pe_prog_is_valid_access(int off, int size, enum bpf_access_type type);

    /* RAW_TRACEPOINT_WRITABLE */
    bool raw_tp_writable_prog_is_valid_access(int off, int size,bpf_access_type type,RegType &reg_type);

    /* RAW_TRACEPOINT */
    bool raw_tp_prog_is_valid_access(int off, int size,bpf_access_type type);

    /* SCHED_ACT, SCHED_CLS */
    bool tc_cls_act_is_valid_access(int off, int size,bpf_access_type type,RegType& reg_type);

    /* SK_LOOKUP */
    bool sk_lookup_is_valid_access(int off, int size,bpf_access_type type,RegType& reg_type);

    /* SK_MSG */
    bool sk_msg_is_valid_access(int off, int size,bpf_access_type type,RegType &reg_type);

    /* SK_REUSEPORT */
    bool sk_reuseport_is_valid_access(int off, int size,bpf_access_type type,RegType& reg_type);

    /* SK_SKB */
    bool sk_skb_is_valid_access(int off, int size,bpf_access_type type,RegType &reg_type);

    /* SOCKET_FILTER */
    bool
    bpf_ctx_narrow_access_ok(u32 off, u32 size, u32 size_default);

    bool bpf_skb_is_valid_access(int off, int size, enum bpf_access_type type, RegType &reg_type);

    bool sk_filter_is_valid_access(int off, int size,
                                   enum bpf_access_type type,
                                   bpf_attach_type expected_attach_type,
                                   RegType &reg_type);

    /* SOCK_OPS */
    bool sock_ops_is_valid_access(int off, int size,bpf_access_type type,RegType& reg_type);

    /* SYSCALL */
    bool syscall_prog_is_valid_access(int off, int size);

    /* TRACEPOINT */
    bool tp_prog_is_valid_access(int off, int size, enum bpf_access_type type);

    /* TRACING */
    bool tracing_prog_is_valid_access(int off, int size, enum bpf_access_type type);

    /* XDP */
    bool __is_valid_xdp_access(int off, int size);

    bool xdp_is_valid_access(int off, int size,
                             bpf_access_type type,
                             bpf_attach_type expected_attach_type,
                             RegType &reg_type);
}

#endif //SUPERBPF_CTX_H
