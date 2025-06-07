#include "ctx.h"

#include <bpf/libbpf.h>
#include <cassert>

#include "ebpf/bpf.h"

namespace superbpf{
    bool is_ctx_valid_access(bpf_prog_type prog_type, bpf_attach_type expected_attach_type,
                             int off, int size,bpf_access_type access_type,RegType& reg_type) {
        switch(prog_type){
            case BPF_PROG_TYPE_CGROUP_DEVICE:
                return cgroup_dev_is_valid_access(off,size,access_type,reg_type);
            case BPF_PROG_TYPE_CGROUP_SKB:
                return cg_skb_is_valid_access(off,size,access_type,reg_type);
            case BPF_PROG_TYPE_CGROUP_SOCKOPT:
                return cg_sockopt_is_valid_access(off,size,access_type,expected_attach_type,reg_type);
            case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
                return true;//sock_addr_is_valid_access(off,size,access_type,expected_attach_type,reg_type);
            case BPF_PROG_TYPE_CGROUP_SOCK:
                return sock_filter_is_valid_access(off,size,access_type,expected_attach_type);
            case BPF_PROG_TYPE_CGROUP_SYSCTL:
                return sysctl_is_valid_access(off,size,access_type);
            case BPF_PROG_TYPE_FLOW_DISSECTOR:
                return flow_dissector_is_valid_access(off,size,access_type,reg_type);
            case BPF_PROG_TYPE_KPROBE:
                return kprobe_prog_is_valid_access(off,size,access_type);
            case BPF_PROG_TYPE_LIRC_MODE2:
                return lirc_mode2_is_valid_access(off,size,access_type);
            case BPF_PROG_TYPE_LWT_IN:
            case BPF_PROG_TYPE_LWT_OUT:
            case BPF_PROG_TYPE_LWT_SEG6LOCAL:
            case BPF_PROG_TYPE_LWT_XMIT:
                return lwt_is_valid_access(off,size,access_type,reg_type);
            case BPF_PROG_TYPE_PERF_EVENT:
                return pe_prog_is_valid_access(off,size,access_type);
            case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
                return raw_tp_writable_prog_is_valid_access(off,size,access_type,reg_type);
            case BPF_PROG_TYPE_RAW_TRACEPOINT:
                return raw_tp_prog_is_valid_access(off,size,access_type);
            case BPF_PROG_TYPE_SCHED_ACT:
            case BPF_PROG_TYPE_SCHED_CLS:
                return tc_cls_act_is_valid_access(off,size,access_type,reg_type);
            case BPF_PROG_TYPE_SK_LOOKUP:
                return sk_lookup_is_valid_access(off,size,access_type,reg_type);
            case BPF_PROG_TYPE_SK_MSG:
                return sk_msg_is_valid_access(off,size,access_type,reg_type);
            case BPF_PROG_TYPE_SK_REUSEPORT:
                return sk_reuseport_is_valid_access(off,size,access_type,reg_type);
            case BPF_PROG_TYPE_SK_SKB:
                return sk_skb_is_valid_access(off,size,access_type,reg_type);
            case BPF_PROG_TYPE_SOCKET_FILTER:
                return sk_filter_is_valid_access(off,size,access_type,expected_attach_type,reg_type);
            case BPF_PROG_TYPE_SOCK_OPS:
                return sock_ops_is_valid_access(off,size,access_type,reg_type);
            case BPF_PROG_TYPE_SYSCALL:
                return syscall_prog_is_valid_access(off,size);
            case BPF_PROG_TYPE_TRACEPOINT:
                return tp_prog_is_valid_access(off,size,access_type);
            case BPF_PROG_TYPE_TRACING:
                return tracing_prog_is_valid_access(off,size,access_type);
            case BPF_PROG_TYPE_XDP:
                return xdp_is_valid_access(off,size,access_type,expected_attach_type,reg_type);
            default:
                assert(0);
        }
    }

    /*
     * CGROUP_DEVICE
     */
    bool cgroup_dev_is_valid_access(int off, int size,bpf_access_type type,RegType& reg_type)
    {
        const int size_default = sizeof(__u32);
        if (type == BPF_WRITE)
            return false;
        if (off < 0 || off + size > sizeof(struct bpf_cgroup_dev_ctx))
            return false;
        /* The verifier guarantees that size > 0. */
        if (off % size != 0)
            return false;
        switch (off) {
            case bpf_ctx_range(struct bpf_cgroup_dev_ctx, access_type):
                if (!bpf_ctx_narrow_access_ok(off, size, size_default))
                    return false;
                break;
            default:
                if (size != size_default)
                    return false;
        }
        return true;
    }

    /*
     * CGROUP_SOCKOPT
     */
    bool cg_sockopt_is_valid_access(int off, int size, bpf_access_type type, bpf_attach_type expected_attach_type,
                                    RegType& reg_type)
    {
        const int size_default = sizeof(__u32);
        if (off < 0 || off >= sizeof(struct bpf_sockopt))
            return false;
        if (off % size != 0)
            return false;
        if (type == BPF_WRITE) {
            switch (off) {
                case offsetof(struct bpf_sockopt, retval):
                    if (size != size_default)
                        return false;
                    return expected_attach_type ==
                           BPF_CGROUP_GETSOCKOPT;
                case offsetof(struct bpf_sockopt, optname):
//                    fallthrough;  // ?
                case offsetof(struct bpf_sockopt, level):
                    if (size != size_default)
                        return false;
                    return expected_attach_type ==
                           BPF_CGROUP_SETSOCKOPT;
                case offsetof(struct bpf_sockopt, optlen):
                    return size == size_default;
                default:
                    return false;
            }
        }

        switch (off) {
            case offsetof(struct bpf_sockopt, sk):
                if (size != sizeof(__u64))
                    return false;
                reg_type = PTR_TO_SOCKET;
                break;
            case offsetof(struct bpf_sockopt, optval):
                if (size != sizeof(__u64))
                    return false;
                reg_type = PTR_TO_PACKET;
                break;
            case offsetof(struct bpf_sockopt, optval_end):
                if (size != sizeof(__u64))
                    return false;
                reg_type = PTR_TO_PACKET_END;
                break;
            case offsetof(struct bpf_sockopt, retval):
                if (size != size_default)
                    return false;
                return expected_attach_type == BPF_CGROUP_GETSOCKOPT;
            default:
                if (size != size_default)
                    return false;
                break;
        }
        return true;
    }

    /*
     * CGROUP_SKB
     */
    bool cg_skb_is_valid_access(int off, int size,bpf_access_type type,RegType& reg_type)
    {
        switch (off) {
            case bpf_ctx_range(struct __sk_buff, tc_classid):
            case bpf_ctx_range(struct __sk_buff, data_meta):
            case bpf_ctx_range(struct __sk_buff, wire_len):
                return false;
            case bpf_ctx_range(struct __sk_buff, data):
            case bpf_ctx_range(struct __sk_buff, data_end):
//                if (!bpf_capable())
//                    return false;
                break;
        }

        if (type == BPF_WRITE) {
            switch (off) {
                case bpf_ctx_range(struct __sk_buff, mark):
                case bpf_ctx_range(struct __sk_buff, priority):
                case bpf_ctx_range_till(struct __sk_buff, cb[0], cb[4]):
                    break;
                case bpf_ctx_range(struct __sk_buff, tstamp):
//                    if (!bpf_capable())
//                        return false;
                    break;
                default:
                    return false;
            }
        }

        switch (off) {
            case bpf_ctx_range(struct __sk_buff, data):
                reg_type = PTR_TO_PACKET;
                break;
            case bpf_ctx_range(struct __sk_buff, data_end):
                reg_type = PTR_TO_PACKET_END;
                break;
        }

        return bpf_skb_is_valid_access(off, size, type,reg_type);
    }

    /*
     * CGROUP_SOCK_ADDR
     */
    bool sock_addr_is_valid_access(int off, int size,bpf_access_type type,bpf_attach_type expected_attach_type,RegType& reg_type)
    {
        const int size_default = sizeof(__u32);
        if (off < 0 || off >= sizeof(struct bpf_sock_addr))
            return false;
        if (off % size != 0)
            return false;
        /* Disallow access to IPv6 fields from IPv4 contex and vise
         * versa.
         */
        switch (off) {
            case bpf_ctx_range(struct bpf_sock_addr, user_ip4):
                switch (expected_attach_type) {
                    case BPF_CGROUP_INET4_BIND:
                    case BPF_CGROUP_INET4_CONNECT:
                    case BPF_CGROUP_INET4_GETPEERNAME:
                    case BPF_CGROUP_INET4_GETSOCKNAME:
                    case BPF_CGROUP_UDP4_SENDMSG:
                    case BPF_CGROUP_UDP4_RECVMSG:
                        break;
                    default:
                        return false;
                }
                break;
            case bpf_ctx_range_till(struct bpf_sock_addr, user_ip6[0], user_ip6[3]):
                switch (expected_attach_type) {
                    case BPF_CGROUP_INET6_BIND:
                    case BPF_CGROUP_INET6_CONNECT:
                    case BPF_CGROUP_INET6_GETPEERNAME:
                    case BPF_CGROUP_INET6_GETSOCKNAME:
                    case BPF_CGROUP_UDP6_SENDMSG:
                    case BPF_CGROUP_UDP6_RECVMSG:
                        break;
                    default:
                        return false;
                }
                break;
            case bpf_ctx_range(bpf_sock_addr, msg_src_ip4):
                switch (expected_attach_type) {
                    case BPF_CGROUP_UDP4_SENDMSG:
                        break;
                    default:
                        return false;
                }
                break;
            case bpf_ctx_range_till(struct bpf_sock_addr, msg_src_ip6[0],
                                    msg_src_ip6[3]):
                switch (expected_attach_type) {
                    case BPF_CGROUP_UDP6_SENDMSG:
                        break;
                    default:
                        return false;
                }
                break;
        }

        switch (off) {
            case bpf_ctx_range(struct bpf_sock_addr, user_ip4):
            case bpf_ctx_range_till(struct bpf_sock_addr, user_ip6[0], user_ip6[3]):
            case bpf_ctx_range(struct bpf_sock_addr, msg_src_ip4):
            case bpf_ctx_range_till(struct bpf_sock_addr, msg_src_ip6[0],
                                    msg_src_ip6[3]):
            case bpf_ctx_range(struct bpf_sock_addr, user_port):
                if (type == BPF_READ) {
                    if (bpf_ctx_wide_access_ok(off, size,
                                               struct bpf_sock_addr,
                                               user_ip6))
                        return true;

                    if (bpf_ctx_wide_access_ok(off, size,
                                               struct bpf_sock_addr,
                                               msg_src_ip6))
                        return true;

                    if (!bpf_ctx_narrow_access_ok(off, size, size_default))
                        return false;
                } else {
                    if (bpf_ctx_wide_access_ok(off, size,
                                               struct bpf_sock_addr,
                                               user_ip6))
                        return true;

                    if (bpf_ctx_wide_access_ok(off, size,
                                               struct bpf_sock_addr,
                                               msg_src_ip6))
                        return true;

                    if (size != size_default)
                        return false;
                }
                break;
            case offsetof(struct bpf_sock_addr, sk):
                if (type != BPF_READ)
                    return false;
                if (size != sizeof(__u64))
                    return false;
                reg_type = PTR_TO_SOCKET;
                break;
            default:
                if (type == BPF_READ) {
                    if (size != size_default)
                        return false;
                } else {
                    return false;
                }
        }

        return true;
    }

    /*
     * CGROUP_SOCK
     */
    bool bpf_sock_is_valid_access(int off, int size)
    {
        const int size_default = sizeof(__u32);

        if (off < 0 || off >= sizeof(struct bpf_sock))
            return false;
        if (off % size != 0)
            return false;
        switch (off) {
            case offsetof(struct bpf_sock, state):
            case offsetof(struct bpf_sock, family):
            case offsetof(struct bpf_sock, type):
            case offsetof(struct bpf_sock, protocol):
            case offsetof(struct bpf_sock, dst_port):
            case offsetof(struct bpf_sock, src_port):
            case offsetof(struct bpf_sock, rx_queue_mapping):
            case bpf_ctx_range(struct bpf_sock, src_ip4):
            case bpf_ctx_range_till(struct bpf_sock, src_ip6[0], src_ip6[3]):
            case bpf_ctx_range(struct bpf_sock, dst_ip4):
            case bpf_ctx_range_till(struct bpf_sock, dst_ip6[0], dst_ip6[3]):
                return bpf_ctx_narrow_access_ok(off, size, size_default);
        }

        return size == size_default;
    }

    bool __sock_filter_check_attach_type(int off,bpf_access_type access_type,bpf_attach_type attach_type)
    {
        switch (off) {
            case offsetof(struct bpf_sock, bound_dev_if):
            case offsetof(struct bpf_sock, mark):
            case offsetof(struct bpf_sock, priority):
                switch (attach_type) {
                    case BPF_CGROUP_INET_SOCK_CREATE:
                    case BPF_CGROUP_INET_SOCK_RELEASE:
                        goto full_access;
                    default:
                        return false;
                }
            case bpf_ctx_range(struct bpf_sock, src_ip4):
                switch (attach_type) {
                    case BPF_CGROUP_INET4_POST_BIND:
                        goto read_only;
                    default:
                        return false;
                }
            case bpf_ctx_range_till(struct bpf_sock, src_ip6[0], src_ip6[3]):
                switch (attach_type) {
                    case BPF_CGROUP_INET6_POST_BIND:
                        goto read_only;
                    default:
                        return false;
                }
            case bpf_ctx_range(struct bpf_sock, src_port):
                switch (attach_type) {
                    case BPF_CGROUP_INET4_POST_BIND:
                    case BPF_CGROUP_INET6_POST_BIND:
                        goto read_only;
                    default:
                        return false;
                }
        }
        read_only:
        return access_type == BPF_READ;
        full_access:
        return true;
    }

    bool sock_filter_is_valid_access(int off, int size,bpf_access_type type,bpf_attach_type expected_attach_type)
    {
        if (!bpf_sock_is_valid_access(off, size))
            return false;
        return true;
        // TODO
//        return __sock_filter_check_attach_type(off, type,expected_attach_type);
    }

    /*
     * CGROUP_SYSCTL
     */
    bool sysctl_is_valid_access(int off, int size, enum bpf_access_type type)
    {
        const int size_default = sizeof(__u32);

        if (off < 0 || off + size > sizeof(struct bpf_sysctl) || off % size)
            return false;

        switch (off) {
            case bpf_ctx_range(struct bpf_sysctl, write):
                if (type != BPF_READ)
                    return false;
                return bpf_ctx_narrow_access_ok(off, size, size_default);
            case bpf_ctx_range(struct bpf_sysctl, file_pos):
                if (type == BPF_READ) {
                    return bpf_ctx_narrow_access_ok(off, size, size_default);
                } else {
                    return size == size_default;
                }
            default:
                return false;
        }
    }

    /*
     * FLOW_DISSECTOR
     */
    bool flow_dissector_is_valid_access(int off, int size,bpf_access_type type,RegType &reg_type)
    {
        const int size_default = sizeof(__u32);
        if (off < 0 || off >= sizeof(struct __sk_buff))
            return false;
        if (type == BPF_WRITE)
            return false;
        switch (off) {
            case bpf_ctx_range(struct __sk_buff, data):
                if (size != size_default)
                    return false;
                reg_type = PTR_TO_PACKET;
                return true;
            case bpf_ctx_range(struct __sk_buff, data_end):
                if (size != size_default)
                    return false;
                reg_type = PTR_TO_PACKET_END;
                return true;
            case bpf_ctx_range_ptr(struct __sk_buff, flow_keys):
                if (size != sizeof(__u64))
                    return false;
                reg_type = PTR_TO_FLOW_KEYS;
                return true;
            default:
                return false;
        }
    }

    /*
     * KPROBE
     */
    bool kprobe_prog_is_valid_access(int off, int size, enum bpf_access_type type)
    {
        if (off < 0 || off >= sizeof(struct pt_regs))
            return false;
        if (type != BPF_READ)
            return false;
        if (off % size != 0)
            return false;
        /*
         * Assertion for 32 bit to make sure last 8 byte access
         * (BPF_DW) to the last 4 byte member is disallowed.
         */
        if (off + size > sizeof(struct pt_regs))
            return false;

        return true;
    }

    /* LIRC_MODE2 */
    bool lirc_mode2_is_valid_access(int off, int size,bpf_access_type type)
    {
        /* We have one field of u32 */
        return type == BPF_READ && off == 0 && size == sizeof(u32);
    }

    /*
     * LSM TODO
     */

    /*
     * LWT_IN, LWT_OUT, LWT_SEG6LOCAL, LWT_XMIT
     */
    bool lwt_is_valid_access(int off, int size,bpf_access_type type,RegType& reg_type)
    {
        switch (off) {
            case bpf_ctx_range(struct __sk_buff, tc_classid):
            case bpf_ctx_range_till(struct __sk_buff, family, local_port):
            case bpf_ctx_range(struct __sk_buff, data_meta):
            case bpf_ctx_range(struct __sk_buff, tstamp):
            case bpf_ctx_range(struct __sk_buff, wire_len):
                return false;
        }

        if (type == BPF_WRITE) {
            switch (off) {
                case bpf_ctx_range(struct __sk_buff, mark):
                case bpf_ctx_range(struct __sk_buff, priority):
                case bpf_ctx_range_till(struct __sk_buff, cb[0], cb[4]):
                    break;
                default:
                    return false;
            }
        }

        switch (off) {
            case bpf_ctx_range(struct __sk_buff, data):
                reg_type = PTR_TO_PACKET;
                break;
            case bpf_ctx_range(struct __sk_buff, data_end):
                reg_type = PTR_TO_PACKET_END;
                break;
        }
        return bpf_skb_is_valid_access(off, size, type, reg_type);
    }

    /*
     * PERF_EVENT
     */
    bool pe_prog_is_valid_access(int off, int size, enum bpf_access_type type)
    {
        const int size_u64 = sizeof(u64);

        if (off < 0 || off >= sizeof(struct bpf_perf_event_data))
            return false;
        if (type != BPF_READ)
            return false;
        if (off % size != 0) {
            if (sizeof(unsigned long) != 4)
                return false;
            if (size != 8)
                return false;
            if (off % size != 4)
                return false;
        }

        switch (off) {
            case bpf_ctx_range(struct bpf_perf_event_data, sample_period):
                if (!bpf_ctx_narrow_access_ok(off, size, size_u64))
                    return false;
                break;
            case bpf_ctx_range(struct bpf_perf_event_data, addr):
                if (!bpf_ctx_narrow_access_ok(off, size, size_u64))
                    return false;
                break;
            default:
                if (size != sizeof(long))
                    return false;
        }

        return true;
    }


    /*
     * RAW_TRACEPOINT(_WRITABLE)
     */
    bool raw_tp_prog_is_valid_access(int off, int size,bpf_access_type type)
    {
        if (off < 0 || off >= sizeof(__u64) * MAX_BPF_FUNC_ARGS)
            return false;
        if (type != BPF_READ)
            return false;
        if (off % size != 0)
            return false;
        return true;
    }

    bool raw_tp_writable_prog_is_valid_access(int off, int size,bpf_access_type type,RegType &reg_type)
    {
        if (off == 0) {
            if (size != sizeof(u64) || type != BPF_READ)
                return false;
            reg_type = PTR_TO_TP_BUFFER;
        }
        return raw_tp_prog_is_valid_access(off, size, type);
    }

    /*
     * SCHED_ACT, SCHED_CLS
     */
    bool tc_cls_act_is_valid_access(int off, int size,bpf_access_type type,RegType& reg_type)
    {
        if (type == BPF_WRITE) {
            switch (off) {
                case bpf_ctx_range(struct __sk_buff, mark):
                case bpf_ctx_range(struct __sk_buff, tc_index):
                case bpf_ctx_range(struct __sk_buff, priority):
                case bpf_ctx_range(struct __sk_buff, tc_classid):
                case bpf_ctx_range_till(struct __sk_buff, cb[0], cb[4]):
                case bpf_ctx_range(struct __sk_buff, tstamp):
                case bpf_ctx_range(struct __sk_buff, queue_mapping):
                    break;
                default:
                    return false;
            }
        }

        switch (off) {
            case bpf_ctx_range(struct __sk_buff, data):
                reg_type = PTR_TO_PACKET;
                break;
            case bpf_ctx_range(struct __sk_buff, data_meta):
                reg_type = PTR_TO_PACKET_META;
                break;
            case bpf_ctx_range(struct __sk_buff, data_end):
                reg_type = PTR_TO_PACKET_END;
                break;
            case bpf_ctx_range_till(struct __sk_buff, family, local_port):
                return false;
        }

        return bpf_skb_is_valid_access(off, size, type, reg_type);
    }

    /*
     * SK_LOOKUP
     */
    bool sk_lookup_is_valid_access(int off, int size,bpf_access_type type,RegType& reg_type)
    {
        if (off < 0 || off >= sizeof(struct bpf_sk_lookup))
            return false;
        if (off % size != 0)
            return false;
        if (type != BPF_READ)
            return false;

        switch (off) {
            case offsetof(struct bpf_sk_lookup, sk):
                reg_type = PTR_TO_SOCKET_OR_NULL;
                return size == sizeof(__u64);

            case bpf_ctx_range(struct bpf_sk_lookup, family):
            case bpf_ctx_range(struct bpf_sk_lookup, protocol):
            case bpf_ctx_range(struct bpf_sk_lookup, remote_ip4):
            case bpf_ctx_range(struct bpf_sk_lookup, local_ip4):
            case bpf_ctx_range_till(struct bpf_sk_lookup, remote_ip6[0], remote_ip6[3]):
            case bpf_ctx_range_till(struct bpf_sk_lookup, local_ip6[0], local_ip6[3]):
            case bpf_ctx_range(struct bpf_sk_lookup, remote_port):
            case bpf_ctx_range(struct bpf_sk_lookup, local_port):
                return bpf_ctx_narrow_access_ok(off, size, sizeof(__u32));

            default:
                return false;
        }
    }

    /*
     * SK_MSG
     */
    bool sk_msg_is_valid_access(int off, int size,bpf_access_type type,RegType &reg_type)
    {
        if (type == BPF_WRITE)
            return false;

        if (off % size != 0)
            return false;

        switch (off) {
            case offsetof(struct sk_msg_md, data):
                reg_type = PTR_TO_PACKET;
                if (size != sizeof(__u64))
                    return false;
                break;
            case offsetof(struct sk_msg_md, data_end):
                reg_type = PTR_TO_PACKET_END;
                if (size != sizeof(__u64))
                    return false;
                break;
            case offsetof(struct sk_msg_md, sk):
                if (size != sizeof(__u64))
                    return false;
                reg_type = PTR_TO_SOCKET;
                break;
            case bpf_ctx_range(struct sk_msg_md, family):
            case bpf_ctx_range(struct sk_msg_md, remote_ip4):
            case bpf_ctx_range(struct sk_msg_md, local_ip4):
            case bpf_ctx_range_till(struct sk_msg_md, remote_ip6[0], remote_ip6[3]):
            case bpf_ctx_range_till(struct sk_msg_md, local_ip6[0], local_ip6[3]):
            case bpf_ctx_range(struct sk_msg_md, remote_port):
            case bpf_ctx_range(struct sk_msg_md, local_port):
            case bpf_ctx_range(struct sk_msg_md, size):
                if (size != sizeof(__u32))
                    return false;
                break;
            default:
                return false;
        }
        return true;
    }

    /*
     * SK_REUSEPORT
     */
    bool sk_reuseport_is_valid_access(int off, int size,bpf_access_type type,RegType& reg_type)
    {
        const u32 size_default = sizeof(__u32);

        if (off < 0 || off >= sizeof(struct sk_reuseport_md) ||
            off % size || type != BPF_READ)
            return false;

        switch (off) {
            case offsetof(struct sk_reuseport_md, data):
                reg_type = PTR_TO_PACKET;
                return size == sizeof(__u64);

            case offsetof(struct sk_reuseport_md, data_end):
                reg_type = PTR_TO_PACKET_END;
                return size == sizeof(__u64);

            case offsetof(struct sk_reuseport_md, hash):
                return size == size_default;

            case offsetof(struct sk_reuseport_md, sk):
                reg_type = PTR_TO_SOCKET;
                return size == sizeof(__u64);

            case offsetof(struct sk_reuseport_md, migrating_sk):
                reg_type = PTR_TO_SOCK_COMMON_OR_NULL;
                return size == sizeof(__u64);

//                /* TODO: Fields that allow narrowing */
//            case bpf_ctx_range(struct sk_reuseport_md, eth_protocol):
//                if (size < sizeof_field(struct sk_buff, protocol))
//                    return false;
//                fallthrough;
            case bpf_ctx_range(struct sk_reuseport_md, ip_protocol):
            case bpf_ctx_range(struct sk_reuseport_md, bind_inany):
            case bpf_ctx_range(struct sk_reuseport_md, len):
                return bpf_ctx_narrow_access_ok(off, size, size_default);

            default:
                return false;
        }
    }

    /* SK_SKB */
    bool sk_skb_is_valid_access(int off, int size,bpf_access_type type,RegType &reg_type)
    {
        switch (off) {
            case bpf_ctx_range(struct __sk_buff, tc_classid):
            case bpf_ctx_range(struct __sk_buff, data_meta):
            case bpf_ctx_range(struct __sk_buff, tstamp):
            case bpf_ctx_range(struct __sk_buff, wire_len):
                return false;
        }

        if (type == BPF_WRITE) {
            switch (off) {
                case bpf_ctx_range(struct __sk_buff, tc_index):
                case bpf_ctx_range(struct __sk_buff, priority):
                    break;
                default:
                    return false;
            }
        }

        switch (off) {
            case bpf_ctx_range(struct __sk_buff, mark):
                return false;
            case bpf_ctx_range(struct __sk_buff, data):
                reg_type = PTR_TO_PACKET;
                break;
            case bpf_ctx_range(struct __sk_buff, data_end):
                reg_type = PTR_TO_PACKET_END;
                break;
        }

        return bpf_skb_is_valid_access(off, size, type, reg_type);
    }

    /*
     * SOCKET_FILTER
     */
    bool
    bpf_ctx_narrow_access_ok(u32 off, u32 size, u32 size_default)
    {
        return size <= size_default && (size & (size - 1)) == 0;
    }

    bool bpf_skb_is_valid_access(int off, int size, enum bpf_access_type type,RegType &reg_type)
    {
        const int size_default = sizeof(__u32);
        if (off < 0 || off >= sizeof(struct __sk_buff))
            return false;
        /* The verifier guarantees that size > 0. */
        if (off % size != 0)
            return false;
        switch (off) {
            case bpf_ctx_range_till(struct __sk_buff, cb[0], cb[4]):
                if (off + size > offsetofend(struct __sk_buff, cb[4]))
                    return false;
                break;
            case bpf_ctx_range_till(struct __sk_buff, remote_ip6[0], remote_ip6[3]):
            case bpf_ctx_range_till(struct __sk_buff, local_ip6[0], local_ip6[3]):
            case bpf_ctx_range_till(struct __sk_buff, remote_ip4, remote_ip4):
            case bpf_ctx_range_till(struct __sk_buff, local_ip4, local_ip4):
            case bpf_ctx_range(struct __sk_buff, data):
            case bpf_ctx_range(struct __sk_buff, data_meta):
            case bpf_ctx_range(struct __sk_buff, data_end):
                if (size != size_default)
                    return false;
                break;
            case bpf_ctx_range_ptr(struct __sk_buff, flow_keys):
                return false;
            case bpf_ctx_range(struct __sk_buff, tstamp):
                if (size != sizeof(__u64))
                    return false;
                break;
            case offsetof(struct __sk_buff, sk):
                if (type == BPF_WRITE || size != sizeof(__u64))
                    return false;
                reg_type = PTR_TO_SOCK_COMMON_OR_NULL;
                break;
            default:
                /* Only narrow read access allowed for now. */
                if (type == BPF_WRITE) {
                    if (size != size_default)
                        return false;
                } else {
                    if (!bpf_ctx_narrow_access_ok(off, size, size_default))
                        return false;
                }
        }
        return true;
    }

    bool sk_filter_is_valid_access(int off, int size,
                                   enum bpf_access_type type,
                                   bpf_attach_type expected_attach_type,
                                   RegType& reg_type)
    {
        switch (off) {
            case bpf_ctx_range(struct __sk_buff, tc_classid):
            case bpf_ctx_range(struct __sk_buff, data):
            case bpf_ctx_range(struct __sk_buff, data_meta):
            case bpf_ctx_range(struct __sk_buff, data_end):
            case bpf_ctx_range_till(struct __sk_buff, family, local_port):
            case bpf_ctx_range(struct __sk_buff, tstamp):
            case bpf_ctx_range(struct __sk_buff, wire_len):
                return false;
        }

        if (type == BPF_WRITE) {
            switch (off) {
                case bpf_ctx_range_till(struct __sk_buff, cb[0], cb[4]):
                    break;
                default:
                    return false;
            }
        }
        return bpf_skb_is_valid_access(off, size, type, reg_type);
    }

    /*
     * SOCK_OPS
     */
    bool sock_ops_is_valid_access(int off, int size,bpf_access_type type,RegType& reg_type)
    {
        const int size_default = sizeof(__u32);

        if (off < 0 || off >= sizeof(struct bpf_sock_ops))
            return false;

        /* The verifier guarantees that size > 0. */
        if (off % size != 0)
            return false;

        if (type == BPF_WRITE) {
            switch (off) {
                case offsetof(struct bpf_sock_ops, reply):
                case offsetof(struct bpf_sock_ops, sk_txhash):
                    if (size != size_default)
                        return false;
                    break;
                default:
                    return false;
            }
        } else {
            switch (off) {
                case bpf_ctx_range_till(struct bpf_sock_ops, bytes_received,
                                        bytes_acked):
                    if (size != sizeof(__u64))
                        return false;
                    break;
                case offsetof(struct bpf_sock_ops, sk):
                    if (size != sizeof(__u64))
                        return false;
                    reg_type = PTR_TO_SOCKET_OR_NULL;
                    break;
                case offsetof(struct bpf_sock_ops, skb_data):
                    if (size != sizeof(__u64))
                        return false;
                    reg_type = PTR_TO_PACKET;
                    break;
                case offsetof(struct bpf_sock_ops, skb_data_end):
                    if (size != sizeof(__u64))
                        return false;
                    reg_type = PTR_TO_PACKET_END;
                    break;
                case offsetof(struct bpf_sock_ops, skb_tcp_flags):
                    return bpf_ctx_narrow_access_ok(off, size,
                                                    size_default);
                default:
                    if (size != size_default)
                        return false;
                    break;
            }
        }

        return true;
    }

    /*
     * SYSCALL
     */
    bool syscall_prog_is_valid_access(int off, int size)
    {
        if (off < 0 || off >= UINT16_MAX)
            return false;
        if (off % size != 0)
            return false;
        return true;
    }

    /*
     * TRACEPOINT
     */
    bool tp_prog_is_valid_access(int off, int size, enum bpf_access_type type)
    {
        if (off < sizeof(void *) || off >= PERF_MAX_TRACE_SIZE)
            return false;
        if (type != BPF_READ)
            return false;
        if (off % size != 0)
            return false;
        return true;
    }

    /*
     * TRACING
     */
    bool tracing_prog_is_valid_access(int off, int size,enum bpf_access_type type)
    {
        if (off < 0 || off >= sizeof(__u64) * MAX_BPF_FUNC_ARGS)
            return false;
        if (type != BPF_READ)
            return false;
        if (off % size != 0)
            return false;
//        return btf_ctx_access(off, size, type, prog, info);  // TODO
        return true;
    }

    /*
     * XDP
     */
    bool __is_valid_xdp_access(int off, int size)
    {
        if (off < 0 || off >= sizeof(struct xdp_md))
            return false;
        if (off % size != 0)
            return false;
        if (size != sizeof(__u32))
            return false;

        return true;
    }

    bool xdp_is_valid_access(int off, int size,
                             bpf_access_type type,
                             bpf_attach_type expected_attach_type,
                             RegType& reg_type)
    {
        if (expected_attach_type != BPF_XDP_DEVMAP) {
            switch (off) {
                case offsetof(struct xdp_md, egress_ifindex):
                    return false;
            }
        }
        // TODO
//        if (type == BPF_WRITE) {
//            if (bpf_prog_is_dev_bound(prog->aux)) {
//                switch (off) {
//                    case offsetof(struct xdp_md, rx_queue_index):
//                        return __is_valid_xdp_access(off, size);
//                }
//            }
//            return false;
//        }
        switch (off) {
            case offsetof(struct xdp_md, data):
                reg_type = PTR_TO_PACKET;
                break;
            case offsetof(struct xdp_md, data_meta):
                reg_type = PTR_TO_PACKET_META;
                break;
            case offsetof(struct xdp_md, data_end):
                reg_type = PTR_TO_PACKET_END;
                break;
        }
        return __is_valid_xdp_access(off, size);
    }
}
