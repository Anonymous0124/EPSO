#include "sym_memory.h"

#include <iostream>

using namespace superbpf;

namespace superbpf {
    SymMemoryValidation::SymMemoryValidation(z3::context &c, string prefix)
            : c_(c){
        prefix_ = prefix;
        string name = prefix_ + ".mem[" + std::to_string(mem_.size()) + "]";
        z3::expr mem(c.constant(name.c_str(), c.array_sort(c.bv_sort(64), c.bv_sort(8))));
        mem_.emplace_back(mem);
        stack_start_addr_=0;
        stack_end_addr_=1023;
        ctx_start_addr_=1024;
        ctx_end_addr_=2047;
        pkt_start_addr_=2048;
        pkt_end_addr_=3071;
        other_start_addr_=3072;
        other_end_addr_=4095;
    }

    std::pair<int64_t,int64_t> SymMemoryValidation::get_boundary(RegType mem_type){
        switch(mem_type){
            case PTR_TO_STACK:
                return {stack_start_addr_,stack_end_addr_};
            case PTR_TO_CTX:
                return {ctx_start_addr_,ctx_end_addr_};
            case PTR_TO_PACKET:
                return {pkt_start_addr_,pkt_end_addr_};
            default:
                return {other_start_addr_,other_end_addr_};
        }
    }

    bool SymMemoryValidation::type_off2smt_var(RegType mem_type,int off,z3::expr& smt_var){
        if(type_off2smt_mem_.find(mem_type)==type_off2smt_mem_.end())
            return false;
        bool res=type_off2smt_mem_.at(mem_type).get_ptr(off,smt_var);
        return res;
    }

    z3::expr SymMemoryValidation::get_mem_value(z3::expr addr, int size) {
        z3::expr_vector res_vec(c_);
        for (int i = size - 1; i >= 0; i--) {
            res_vec.push_back(mem_.back()[addr + i]);
        }
        assert(!res_vec.empty());
        return z3::concat(res_vec);
    }

    z3::expr SymMemoryValidation::get_mem_value(z3::expr addr) {
        return mem_.back()[addr];
    }

    z3::expr SymMemoryValidation::get_mem_init_value(z3::expr addr, int size) {
        z3::expr_vector res_vec(c_);
        for (int i = size - 1; i >= 0; i--) {
            res_vec.push_back(mem_.front()[addr + i]);
        }
        assert(!res_vec.empty());
        return z3::concat(res_vec);
    }

    vector<z3::expr> SymMemoryValidation::get_mem_init_mem_units(z3::expr addr, int size) {
        vector<z3::expr> res_vec;
        for (int i = 0; i < size; i++) {
            res_vec.emplace_back(mem_.front()[addr + i]);
        }
        assert(!res_vec.empty());
        return res_vec;
    }

    vector<z3::expr> SymMemoryValidation::get_mem_units(int version,z3::expr addr, int size){
        vector<z3::expr> res_vec;
        for (int i = 0; i < size; i++) {
            res_vec.emplace_back(mem_[version][addr + i]);
        }
        assert(!res_vec.empty());
        return res_vec;
    }

    const z3::expr SymMemoryValidation::get_mem_sym() {
        return mem_.back();
    }

    const z3::expr SymMemoryValidation::get_mem_init_sym() {
        return mem_.front();
    }

    map<int,z3::expr> SymMemoryValidation::get_maps_init_sym(){
        map<int,z3::expr> res;
        for(auto [map_id,maps]:maps_){
            res.insert({map_id,maps[0]});
        }
        return res;
    }

    map<int,z3::expr> SymMemoryValidation::get_maps_final_sym(){
        map<int,z3::expr> res;
        for(auto [map_id,maps]:maps_){
            res.insert({map_id,maps.back()});
        }
        return res;
    }

    void SymMemoryValidation::set_mem_value(z3::context &c, z3::expr addr, z3::expr value, int size) {
        for (int i = 0; i < size; i++) {
            string name = prefix_ + ".mem[" + std::to_string(mem_.size()) + "]";
            z3::expr new_mem(c.constant(name.c_str(), c.array_sort(c.bv_sort(64), c.bv_sort(8))));
            z3::expr new_mem_define = (new_mem ==
                                       z3::store(mem_.back(), addr + c.bv_val(i, 64), value.extract(i * 8 + 7, i * 8)));
            mem_.emplace_back(new_mem);
            mem_define_.emplace_back(new_mem_define);
        }
    }

    void SymMemoryValidation::set_mem_unchange(z3::context &c) {
        string name = prefix_ + ".mem[" + std::to_string(mem_.size()) + "]";
        z3::expr new_mem(c.constant(name.c_str(), c.array_sort(c.bv_sort(64), c.bv_sort(8))));
        z3::expr new_mem_define = (new_mem ==mem_.back());
        mem_.emplace_back(new_mem);
        mem_define_.emplace_back(new_mem_define);
    }

    void SymMemoryValidation::set_map_value(z3::context &c, int map_id,z3::expr addr, z3::expr value, int size) {
        for (int i = 0; i < size; i++) {
            string name = prefix_ + ".mem[" + std::to_string(mem_.size()) + "]";
            z3::expr new_mem(c.constant(name.c_str(), c.array_sort(c.bv_sort(64), c.bv_sort(8))));
            z3::expr new_mem_define = (new_mem ==
                                       z3::store(mem_.back(), addr + c.bv_val(i, 64), value.extract(i * 8 + 7, i * 8)));
            mem_.emplace_back(new_mem);
            mem_define_.emplace_back(new_mem_define);
        }
    }

    void SymMemoryValidation::set_mem_addr_boundry(z3::context &c,z3::expr base_addr,int size,int64_t start, int64_t end) {
        mem_limit_.emplace_back(base_addr>=c.bv_val(start,64));
        mem_limit_.emplace_back((base_addr+size-1)<=c.bv_val(end,64));
    }

    void SymMemoryValidation::set_base_addr_aligned(z3::context &c, z3::expr base_addr, int size) {
        int and_val = 0;
        switch (size) {
            case 1:
                and_val = 0;
                break;
            case 2:
                and_val = 1;
                break;
            case 4:
                and_val = 3;
                break;
            case 8:
                and_val = 7;
                break;
            default:
                assert(0);
        }
        mem_limit_.emplace_back((base_addr & and_val) == c.bv_val(0, 64));
    }

    void SymMemoryValidation::add_ptr(RegType mem_type,int off,z3::expr ptr){
        if(type_off2smt_mem_.count(mem_type)){
            type_off2smt_mem_.at(mem_type).add_ptr(off,ptr);
        }
        else{
            TypePtrs type_ptrs(mem_type);
            type_ptrs.add_ptr(off,ptr);
            type_off2smt_mem_.insert({mem_type,type_ptrs});
        }
    }

    void SymMemoryValidation::add_map_ptr(int map_id,int off,z3::expr ptr){
        if(map_off2smt_mem_.count(map_id)){
            map_off2smt_mem_.at(map_id).add_ptr(off,ptr);
        }
        else{
            MapPtrs map_ptrs(map_id);
            map_ptrs.add_ptr(off,ptr);
            map_off2smt_mem_.insert({map_id,map_ptrs});
        }
    }

    z3::expr SymMemoryValidation::get_map_value(int map_id, z3::expr key) {
        if (maps_.find(map_id) == maps_.end()) {
            string name = prefix_ + ".maps[" + std::to_string(map_id) + "][0]";
            z3::expr init_map(c_.constant(name.c_str(), c_.array_sort(c_.bv_sort(64), c_.bv_sort(8))));
            maps_[map_id].emplace_back(init_map);
        }
        return maps_[map_id].back()[key];
    }

    z3::expr SymMemoryValidation::get_map_value(int map_id, z3::expr addr,int size) {
        if (maps_.find(map_id) == maps_.end()) {
            string name = prefix_ + ".maps[" + std::to_string(map_id) + "][0]";
            z3::expr init_map(c_.constant(name.c_str(), c_.array_sort(c_.bv_sort(64), c_.bv_sort(8))));
            maps_[map_id].emplace_back(init_map);
        }
        z3::expr_vector res_vec(c_);
        for (int i = size - 1; i >= 0; i--) {
            res_vec.push_back(maps_[map_id].back()[addr + i]);
        }
        assert(!res_vec.empty());
        return z3::concat(res_vec);
    }

    void SymMemoryValidation::set_map_value(z3::context &c, int map_id, z3::expr key, z3::expr value) {
        // check whether map of map_id exists, if not, add init state of this map
        if (maps_.find(map_id) == maps_.end()) {
            string name = prefix_ + ".maps[" + std::to_string(map_id) + "][0]";
            z3::expr init_map(c.constant(name.c_str(), c.array_sort(c.bv_sort(64), c.bv_sort(8))));
            maps_[map_id].emplace_back(init_map);
        }
        string name = prefix_ + ".maps[" + std::to_string(map_id) + "][" + std::to_string(maps_[map_id].size()) + "]";
        z3::expr new_map(c.constant(name.c_str(), c.array_sort(c.bv_sort(64), c.bv_sort(8))));
        z3::expr new_map_define = (new_map == z3::store(maps_[map_id].back(), key, value));
        maps_[map_id].emplace_back(new_map);
        maps_define_[map_id].emplace_back(new_map_define);
    }

    z3::expr_vector SymMemoryValidation::constraints() {
        z3::expr_vector res_vec(c_);
        for (const auto& mem_define_elem: mem_define_) {
            res_vec.push_back(mem_define_elem);
        }
        for (const auto& mem_limit_elem: mem_limit_) {
            res_vec.push_back(mem_limit_elem);
        }
        for (const auto& map_define: maps_define_) {
            for (const auto& map_define_elem: map_define.second) {
                res_vec.push_back(map_define_elem);
            }
        }
        return res_vec;
    }
}
