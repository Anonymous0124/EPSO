#ifndef EBPFOPTIMIZER_SYM_MEMORY_VALIDATION_H
#define EBPFOPTIMIZER_SYM_MEMORY_VALIDATION_H

#include <string>
#include <map>
#include "z3++.h"

#include "src/ebpf/bpf.h"

using std::string;
using std::map;
using std::vector;

namespace superbpf {
    /*
     * class SymMemoryValidation:
     * record symbolic states of the memory (including maps) during symbolic execution.
     * used by class Validator.
     */
    class TypePtrs{
        RegType type_;
        std::unordered_map<int,z3::expr> ptrs_;  // <off,smt_var>
    public:
        TypePtrs(RegType type){
            type_=type;
        }

        std::unordered_map<int,z3::expr> ptrs(){
           return ptrs_;
        }

        void add_ptr(int off,const z3::expr& smt_var){
            if(ptrs_.find(off)==ptrs_.end()){
                ptrs_.insert({off,smt_var});
            }
            else
                ptrs_.at(off)=smt_var;
        }

        bool get_ptr(int off,z3::expr& ptr){
            if(ptrs_.find(off)==ptrs_.end())
                return false;
            ptr=ptrs_.at(off);
            return true;
        }
    };

    class MapPtrs{
        int map_id_;
        std::unordered_map<int,z3::expr> ptrs_;  // <off,smt_var>
    public:
        MapPtrs(int map_id){
            map_id_=map_id;
        }

        void add_ptr(int off,const z3::expr& smt_var){
            if(ptrs_.find(off)==ptrs_.end()){
                ptrs_.insert({off,smt_var});
            }
            else
                ptrs_.at(off)=smt_var;
        }

        bool get_ptr(int off,z3::expr& ptr){
            if(ptrs_.find(off)==ptrs_.end())
                return false;
            ptr=ptrs_.at(off);
            return true;
        }
    };

    class SymMemoryValidation {
    private:
        /* z3 context */
        z3::context &c_;
        /* to identify program (target and rewrite) */
        string prefix_;
        /* to identify version with respect to SSA */
        // int version_;
        int64_t stack_start_addr_;
        int64_t stack_end_addr_;
        int64_t pkt_start_addr_;
        int64_t pkt_end_addr_;
        int64_t ctx_start_addr_;
        int64_t ctx_end_addr_;
        int64_t other_start_addr_;
        int64_t other_end_addr_;
        /* vector of z3 expr declaration for memory area of stack and context, size of vector refers to current mem_ version */
        vector<z3::expr> mem_;
        /* vector of z3 expr defination for memory area of stack and context, size of vector refers to current mem_ version */
        vector<z3::expr> mem_define_;
        /* vector of z3 expr defination for limiting boundaries of memory area of stack and context, size of vector refers to current mem_ version */
        vector<z3::expr> mem_limit_;

        std::unordered_map<RegType,TypePtrs> type_off2smt_mem_;

        std::unordered_map<int,MapPtrs> map_off2smt_mem_;
        /* vectors of z3 expr declaration for maps (std::map - key: bpf map id, value: z3 expr for memory area of that map), size of each vector refers to current map version */
        map<int, vector<z3::expr>> maps_;
        /* vectors of z3 expr defination for maps (std::map - key: bpf map id, value: z3 expr for memory area of that map), size of each vector refers to current map version */
        map<int, vector<z3::expr>> maps_define_;

        /* public interfaces of class SymMemoryValidation
        * used by class SymState and class InsnSymSimulator
        */
    public:
        /* construction */
        SymMemoryValidation(z3::context &c, string prefix);

        std::pair<int64_t,int64_t> get_boundary(RegType mem_type);

        bool type_off2smt_var(RegType mem_type,int off,z3::expr& smt_var);

        std::unordered_map<RegType,TypePtrs> type_off2smt_mem(){
            return type_off2smt_mem_;
        }

        /* get memory value (in stack and context), return z3 expr of the memory value of addr; size of bytes */
        z3::expr get_mem_value(z3::expr addr, int size);

        z3::expr get_mem_value(z3::expr addr);

        /* get memory initial value (in stack and context), return z3 expr of the memory initial value of addr; size of bytes */
        z3::expr get_mem_init_value(z3::expr addr, int size);

        vector<z3::expr> get_mem_init_mem_units(z3::expr addr, int size);

        vector<z3::expr> get_mem_units(int version,z3::expr addr, int size);

        /* get memory symbol (in stack and context), return z3 expr of the whole memory */
        const z3::expr get_mem_sym();

        /* get memory initial symbol (in stack and context), return z3 expr of the whole initial memory */
        const z3::expr get_mem_init_sym();

        map<int,z3::expr> get_maps_init_sym();

        map<int,z3::expr> get_maps_final_sym();

        /* set memory value (in stack and context), with version of mem_ increased by one; size of bytes */
        void set_mem_value(z3::context &c, z3::expr addr, z3::expr value, int size);

        void set_mem_unchange(z3::context &c);

        void set_map_value(z3::context &c, int map_id,z3::expr addr, z3::expr value, int size);

        /* set memory addrs boundaries (in stack and context), with version of mem_ increased by one; size of bytes */
        void set_mem_addr_boundry(z3::context &c,z3::expr base_addr,int size,int64_t start, int64_t end);

        void set_base_addr_aligned(z3::context &c, z3::expr base_addr, int size);

        void add_ptr(RegType mem_type,int off,z3::expr ptr);

        void add_map_ptr(int map_id,int off,z3::expr ptr);
        /* get memory value (in maps), return z3 expr of the value of key in map */
        z3::expr get_map_value(int map_id, z3::expr key);

        z3::expr get_map_value(int map_id, z3::expr addr,int size);

        /* set memory value (in maps), with version of such map increased by one */
        void set_map_value(z3::context &c, int map_id, z3::expr key, z3::expr value);

        /* get the constraints of symbolic states of memory and maps */
        z3::expr_vector constraints();
    };
}

#endif //EBPFOPTIMIZER_SYM_MEMORY_VALIDATION_H
