#include "memory.h"

#include <cstdint>

#include <iostream>

using namespace std;
using namespace superbpf;

namespace superbpf {

    u8 MemUnit::value() {
        return value_;
    }

    std::pair<RegType, int> MemUnit::get_type_off() {
        return {type_, off_};
    }

    bool MemUnit::is_valid() {
        return valid_;
    }

    void MemUnit::set_val(u8 val) {
        value_ = val;
        valid_ = true;
    }

    void MemUnit::set_content(u8 val, RegType type, int type_off) {
        value_ = val;
        valid_ = true;
        type_ = type;
        off_ = type_off;
    }

    void MemUnit::set_invalid() {
        value_ = 0;
        valid_ = false;
    }

    void MemUnit::copy_from_mem_unit(MemUnit *mem_unit) {
        value_ = mem_unit->value_;
        valid_ = mem_unit->valid_;
        type_ = mem_unit->type_;
        off_ = mem_unit->off_;
    }

    bool MemUnit::operator==(MemUnit &mem_unit) {
        return (value_ == mem_unit.value_) && (valid_ == mem_unit.valid_);
    }

    bool MemUnit::operator!=(MemUnit &mem_unit) {
        return (value_ != mem_unit.value_) || (valid_ != mem_unit.valid_);
    }

    bool MemUnit::operator<(const MemUnit &mem_unit) {
        if (valid_ < mem_unit.valid_)
            return true;
        else if (valid_ == mem_unit.valid_) {
            if (value_ < mem_unit.value_)
                return true;
            else
                return false;
        } else
            return false;
    }

    std::ostream &operator<<(ostream &output, const MemUnit &mem_uint) {
        if (mem_uint.valid_)
            output << std::hex << mem_uint.value_;
        else
            output << "__";
        return output;
    }


    u64 Memory::size() const {
        return mem_units_.size();
    }

    bool Memory::is_valid(u64 addr, int size) {
        for (u64 i = addr; i < addr + size; i++) {
            if (mem_units_.find(i) == mem_units_.end() || !mem_units_.at(i)->is_valid())
                return false;
        }
        return true;
    }

    s64 Memory::get_val(u64 addr, int size) {
        u64 res = 0;
        for (u64 i = addr; i < addr + size; i++) {
            res += ((u64) mem_units_.at(i)->value() << (8 * (i - addr)));
        }
        res <<= (64 - 8 * size);
        res = ((u64) res) >> (64 - 8 * size);
        return res;
    }

    vector<u8> Memory::get_vals(u64 addr, int size) {
        vector<u8> vals;
        for (u64 i = addr; i < addr + size; i++) {
            vals.emplace_back(mem_units_.at(i)->value());
        }
        return vals;
    }

    void Memory::set_val(u64 addr, u8 val) {
        if (mem_units_.find(addr) == mem_units_.end())
            mem_units_.insert({addr, new MemUnit((u8) val)});
        else
            mem_units_.at(addr)->set_val((u8) val);
    }

    void Memory::set_val(u64 addr, int size, s64 val) {
        for (u64 i = addr; i < addr + size; i++) {
            if (mem_units_.find(i) == mem_units_.end())
                mem_units_.insert({i, new MemUnit((u8) val)});
            else
                mem_units_.at(i)->set_val((u8) val);
            val >>= 8;
        }
    }

    void Memory::set_mems(u64 addr, int size, s64 val,RegType type,int type_off) {
        for (u64 i = addr; i < addr + size; i++) {
            if (mem_units_.find(i) == mem_units_.end())
                mem_units_.insert({i, new MemUnit((u8) val,type,type_off+(int)(i-addr))});
            else
                mem_units_.at(i)->set_content((u8) val,type,type_off+(int)(i-addr));
            val >>= 8;
        }
    }

    void Memory::set_mem_unit(u64 addr, u8 val, RegType type, int type_off) {
        if (mem_units_.find(addr) == mem_units_.end())
            mem_units_.insert({addr, new MemUnit(val, type, type_off)});
        else
            mem_units_.at(addr)->set_content(val, type, type_off);
    }

    void Memory::add_mem_unit(u64 addr, RegType type, int type_off) {
        if (mem_units_.find(addr) == mem_units_.end())
            mem_units_.insert({addr, new MemUnit(type,type_off)});
    }

    void Memory::copy_from_memory(Memory *memory) {
        for (auto it = memory->mem_units_.begin(); it != memory->mem_units_.end(); it++) {
            u64 addr = it->first;
            if (mem_units_.find((addr)) == mem_units_.end())
                mem_units_.insert({addr, new MemUnit()});
            mem_units_.at(addr)->copy_from_mem_unit(it->second);
        }
    }

    void Memory::set_mem_vals(map<u64, vector<u8>> mem_seg_vals, map<u64, int> mem_areas) {
        for (auto it = mem_areas.begin(); it != mem_areas.end(); it++) {
            u64 addr = it->first;
            int size = it->second;
            for (int i = 0; i < size; i++) {
                mem_units_.insert({addr + i, new MemUnit()});
            }
        }
        for (auto it = mem_seg_vals.begin(); it != mem_seg_vals.end(); it++) {
            u64 base = it->first;
            vector<u8> &vals = it->second;
            for (int i = 0; i < vals.size(); i++) {
                mem_units_.at(base + i)->set_val(vals[i]);
            }
        }
    }

    void Memory::refresh() {
        for (auto it = mem_units_.begin(); it != mem_units_.end(); it++) {
            it->second->set_invalid();
        }
    }

    u64 Memory::expand_mem_areas(){
        u64 res=0;
        bool set=false;
        for(auto [addr,mem_unit]:mem_units_){
            auto [type,off]=mem_unit->get_type_off();
            if(type==PTR_TO_STACK){
                if(!set){
                    res=addr;
                    set=true;
                }
                if(mem_units_.count(addr+1)==0){
                    for(int i=1;i<4;i++){
                        auto* new_mem_unit=new MemUnit(0,PTR_TO_STACK,off+i);
                        mem_units_.insert({addr+i,new_mem_unit});
                    }
                    break;
                }
            }
        }
        return res;
    }

    std::vector<std::vector<u8>> Memory::compute_diff(Memory *target, const std::map<u8, std::set<int>> &live_memory) {
//        assert(mem_units_.size() == target->mem_units_.size());
        vector<vector<u8>> target_vals;
        if(mem_units_.size()!=target->mem_units_.size())
            return target_vals;
        for (auto it = mem_units_.begin(); it != mem_units_.end();) {
            u64 addr = it->first;
            MemUnit *mem_unit = it->second;
            auto [type, off] = mem_unit->get_type_off();
            if (live_memory.count(type) && live_memory.at(type).count(off)) {
                if (*mem_unit != *((*target)[addr])) {
                    vector<u8> target_val = {(*target)[addr]->value()};
                    int count = 1;
                    it++;
                    while (it != mem_units_.end() && (count < 8)) {
                        target_val.emplace_back((*target)[it->first]->value());
                        count++;
                        it++;
                    }
                    if (count == 8 || it == mem_units_.end())
                        target_vals.emplace_back(target_val);
                } else {
                    it++;
                }
            } else
                it++;
        }
        return target_vals;
    }

    int Memory::compute_similarity(Memory *target, const std::map<u8, std::set<int>> &live_mem_addrs) {
        assert(mem_units_.size() == target->size());
        int res = 0;
        for (auto it = mem_units_.begin(); it != mem_units_.end(); it++) {
            u64 addr = it->first;
            auto [type, off] = it->second->get_type_off();
            if (live_mem_addrs.count(type) && live_mem_addrs.at(type).count(off)) {
                if (*mem_units_.at(addr) != *((*target)[addr]))
                    res--;
            }
        }
        return res;
    }

    bool Memory::check_equivalence(Memory *memory, const std::map<u8, std::set<int>> &live_mem_addrs) {
        if (mem_units_.size() != memory->size())
            return false;
        bool res = true;
        for (auto it = mem_units_.begin(); it != mem_units_.end(); it++) {
            auto [type, off] = it->second->get_type_off();
            if(type==PTR_TO_STACK){
                if (live_mem_addrs.count(type) && live_mem_addrs.at(type).count(off))
                    res = ((*mem_units_.at(it->first) == *(memory->mem_units_.at(it->first))));
                if(!res)
                    return false;
            }
            else{
                res = ((*mem_units_.at(it->first) == *(memory->mem_units_.at(it->first))));
                if(!res)
                    return false;
            }
        }
        return res;
    }

    void Memory::set_stk_valid(u64 base_addr){
        for(auto &[addr,mem_unit]:mem_units_){
            if(mem_unit->type_==PTR_TO_STACK&&addr>base_addr){
                mem_unit->valid_=true;
            }
        }
    }

    MemUnit *Memory::operator[](u64 i) {
        return mem_units_.at(i);
    }

    bool Memory::operator==(Memory &memory) {
        if (mem_units_.size() != memory.size())
            return false;
        bool res = true;
        for (auto it = mem_units_.begin(); it != mem_units_.end(); it++) {
            res = res && (*mem_units_.at(it->first) == *(memory.mem_units_.at(it->first)));
        }
        return res;
    }

    bool Memory::operator<(Memory &memory) {
        assert(mem_units_.size() == memory.size());
        for (auto [addr, mem_unit_ptr]: mem_units_) {
            if (*mem_unit_ptr < *memory[addr])
                return true;
        }
        return false;
    }

    void Memory::print_memory() {
        printf("Memory: ");
        bool is_first = true;
        u64 last_addr = UINT64_MAX;
        for (auto it = mem_units_.begin(); it != mem_units_.end(); it++) {
            u64 addr = it->first;
            MemUnit *mem_unit = it->second;
            auto [type, off] = mem_unit->get_type_off();
            if (last_addr != addr - 1 || is_first) {
                if (is_first) {
                    if(mem_unit->is_valid())
                        printf("[0x%lx: %x(%s, %d)", addr, (u32) mem_unit->value(),reg_type_str[type].c_str(), off);
                    else
                        printf("[0x%lx: --(%s, %d)", addr,reg_type_str[type].c_str(), off);
                    is_first = false;
                } else {
                    if(mem_unit->is_valid())
                        printf("], [0x%lx: %x(%s, %d)", addr, (u32) mem_unit->value(), reg_type_str[type].c_str(), off);
                    else
                        printf("], [0x%lx: --(%s, %d)", addr, reg_type_str[type].c_str(), off);
                }
            } else {
                if(mem_unit->is_valid())
                    printf(", %x(%s, %d)", (u32) mem_unit->value(), reg_type_str[type].c_str(), off);
                else
                    printf(", --(%s, %d)", reg_type_str[type].c_str(), off);
            }
            last_addr = addr;
        }
        if (!mem_units_.empty())
            printf("]\n");
        else
            printf("\n");
    }

}
