#ifndef SUPERBPF_STATE_MEMORY_H
#define SUPERBPF_STATE_MEMORY_H

#include <iomanip>
#include <map>
#include <set>
#include <vector>
#include <assert.h>

#include "src/ebpf/bpf.h"

using std::map;
using std::vector;

namespace superbpf {
//    enum MemType{
//        CTX=0,         /* reg points to bpf_context */
//        CONST_PTR_TO_MAP,     /* reg points to struct bpf_map */
//        PTR_TO_MAP_VALUE,     /* reg points to map element value */
//        PTR_TO_MAP_VALUE_OR_NULL,/* points to map elem value or NULL */
//        PTR_TO_STACK,         /* reg == frame_pointer + offset */
//        PTR_TO_PACKET_META,     /* skb->data - meta_len */
//        PTR_TO_PACKET,         /* reg points to skb->data */
//        PTR_TO_PACKET_END,     /* skb->data + headlen */
//        PTR_TO_FLOW_KEYS,     /* reg points to bpf_flow_keys */
//        PTR_TO_SOCKET,         /* reg points to struct bpf_sock */
//        PTR_TO_SOCKET_OR_NULL,     /* reg points to struct bpf_sock or NULL */
//        PTR_TO_SOCK_COMMON,     /* reg points to sock_common */
//        PTR_TO_SOCK_COMMON_OR_NULL, /* reg points to sock_common or NULL */
//        PTR_TO_TCP_SOCK,     /* reg points to struct tcp_sock */
//        PTR_TO_TCP_SOCK_OR_NULL, /* reg points to struct tcp_sock or NULL */
//        PTR_TO_TP_BUFFER,     /* reg points to a writable raw tp's buffer */
//        PTR_TO_XDP_SOCK,     /* reg points to struct xdp_sock */
//    };

/*
 * Memory unit.
 */
    class MemUnit {
        u8 value_;
        bool valid_;
        RegType type_;
        int off_;
    public:
        MemUnit() {
            value_ = 0;
            valid_ = false;
            type_ = NOT_INIT;
            off_ = 0;
        }

        MemUnit(u8 value) {
            value_ = value;
            valid_ = true;
            type_ = NOT_INIT;
            off_ = 0;
        }

        MemUnit(u8 value, RegType type, int off) {
            value_ = value;
            valid_ = true;
            type_ = type;
            off_ = off;
        }

        MemUnit(RegType type, int off) {
            value_ = 0;
            valid_ = false;
            type_ = type;
            off_ = off;
        }

        u8 value();

        std::pair<RegType,int> get_type_off();

        bool is_valid();

        void set_val(u8 val);

        void set_content(u8 val,RegType type,int type_off);

        void set_invalid();

        void copy_from_mem_unit(MemUnit *mem_unit);

        bool operator==(MemUnit &mem_unit);

        bool operator!=(MemUnit &mem_unit);

        bool operator<(const MemUnit &mem_unit);

        friend std::ostream &operator<<(std::ostream &output,
                                        const MemUnit &mem_uint);
        friend class Memory;
    };

/*
* Memory segment.
*/
    class Memory {
        int version_;
        map<u64, MemUnit *> mem_units_;  // <addr, memory_unit ptr>
//    vector<MemUnit*> memory_; // complete memory

    public:
        Memory(int version) {
            version_ = version;
        }

        ~Memory() {
            for (auto elem: mem_units_) {
                delete elem.second;
            }
        }

        u64 size() const;

        /* Evaluate if memory access to [addr, addr + size) is valid. */
        bool is_valid(u64 addr, int size);

        s64 get_val(u64 addr, int size);

        vector <u8> get_vals(u64 addr, int size);

        void set_val(u64 addr, u8 val);

        void set_val(u64 addr, int size, s64 val);

        void set_mems(u64 addr, int size, s64 val,RegType type,int type_off);

        void set_mem_unit(u64 addr,u8 val,RegType type,int type_off);

        void add_mem_unit(u64 addr, RegType type, int type_off);

        void set_mem_vals(std::map<u64, std::vector<u8>> mem_seg_vals, std::map<u64, int> mem_areas);

        void copy_from_memory(Memory *memory);

        void refresh();

        u64 expand_mem_areas();

        /* Compute the distance with memory 'target', 'distance' means the least number of insns
         * needed to transfer from current memory to memory 'target'*/
        std::vector<std::vector<u8>> compute_diff(Memory *target,const std::map<u8,std::set<int>>& live_memory);

        int compute_similarity(Memory *target,const std::map<u8,std::set<int>> &live_mem_addrs);

        bool check_equivalence(Memory *memory, const std::map<u8,std::set<int>> &live_mem_addrs);

        void set_stk_valid(u64 base_addr);

        MemUnit *operator[](u64 i);

        bool operator==(Memory &memory);

        bool operator<(Memory &memory);

        void print_memory();
    };
}

#endif //SUPERBPF_STATE_MEMORY_H
