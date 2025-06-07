#include "regs.h"

#include <iostream>

using namespace std;
using namespace superbpf;

namespace superbpf {

    void RegInfo::merge(const RegInfo &reg_info) {
        if (is_value_valid_) {
            if (!reg_info.is_value_valid_)
                is_value_valid_ = false;
            else {
                smin_value_ = (smin_value_ < reg_info.smin_value_) ? smin_value_ : reg_info.smin_value_;
                smax_value_ = (smax_value_ > reg_info.smax_value_) ? smax_value_ : reg_info.smax_value_;
            }
        }
        if (is_type_valid_) {
            if (!reg_info.is_type_valid_)
                is_type_valid_ = false;
            else if (reg_info.type_ != type_)
                type_ = MIXED_TYPE;
        }
    }

    bool RegInfo::operator==(const RegInfo &reg_info) {
        if (is_type_valid_ != reg_info.is_type_valid_ || is_value_valid_ != reg_info.is_value_valid_)
            return false;
        if (is_type_valid_) {
            if (type_ != reg_info.type_)
                return false;
        }
        if (is_value_valid_) {
            if (smin_value_ != reg_info.smin_value_ || smax_value_ != reg_info.smax_value_)
                return false;
        }
        return true;
    }

    bool RegInfo::operator!=(const RegInfo &reg_info) {
        return !((*this) == reg_info);
    }

    void RegInfo::print_reg_info() {
        if (is_value_valid_)
            cout << smin_value_ << "-" << smax_value_;
        else
            cout << "__";
        if (is_type_valid_) {
            if(type_==PTR_TO_STACK)
                cout << "(" << reg_type_str[type_]<<""<<off_<<")";
            else if(type_==SCALAR_VALUE)
                cout << "(" << reg_type_str[type_]<<")";
            else if(type_==PTR_TO_MAP_VALUE||type_==PTR_TO_MAP_VALUE_OR_NULL)
                cout << "(" << reg_type_str[type_]<<",id="<<map_id_<<",off="<<off_<<")";
            else
                cout << "(" << reg_type_str[type_]<<",off="<<off_<<")";
        }
        else
            cout << "(__)";

    }

    s64 Reg::value() {
        assert(type_ != NOT_INIT);
        return value_;
    }

    RegType Reg::type() {
        return type_;
    }

    int Reg::off(){
        return off_;
    }

    std::string Reg::type_str() {
        std::string res;
        switch (type_) {
            case CONST_PTR_TO_MAP:
                res = "CONST_PTR_TO_MAP";
                break;
        }
        return res;
    }

    s32 Reg::lower32() {
        assert(type_ != NOT_INIT);
        return (s32) value_;
    }

    s32 Reg::upper32() {
        assert(type_ != NOT_INIT);
        return (s32) (value_ >> 32);
    }

    bool Reg::is_valid() {
        return type_ != NOT_INIT;
    }

    void Reg::set_val(s64 value) {
        value_ = value;
        if (type_ == NOT_INIT)
            type_ = SCALAR_VALUE;
    }

    void Reg::set_type(RegType type) {
        if (type_ != NOT_INIT && type_ != type && type_ != SCALAR_VALUE)
            type_ = MIXED_TYPE;
        else
            type_ = type;
    }

    void Reg::set_off(int off) {
        off_=off;
    }

    void Reg::set(s64 value, RegType type,int type_off) {
        value_ = value;
        type_ = type;
        off_=type_off;
    }

    void Reg::set_invalid() {
        value_ = 0;
        type_ = NOT_INIT;
    }

    bool Reg::operator==(const Reg &r) {
        return (value_ == r.value_) && (type_ == r.type_);
    }

    bool Reg::operator!=(const Reg &r) {
        return (value_ != r.value_) || (type_ != r.type_);
    }

    bool Reg::operator<(const Reg &r) {
        if (type_ < r.type_)
            return true;
        else if (type_ == r.type_) {
            if (value_ < r.value_)
                return true;
            else
                return false;
        } else
            return false;
    }

    void Reg::operator=(const Reg &r) {
        value_ = r.value_;
        type_ = r.type_;
        off_=r.off_;
    }

    int Regs::size() const {
        return contents_.size();
    }

    bool Regs::is_regi_valid(u8 i) {
        return contents_[i]->is_valid();
    }

    s64 Regs::get_regi_val(u8 i) {
        return contents_[i]->value();
    }

    RegType Regs::get_regi_type(u8 i) {
        return contents_[i]->type();
    }

    int Regs::get_regi_off(u8 i) {
        return contents_[i]->off();
    }

    Reg *Regs::get_regi(u8 i) {
        return contents_[i];
    }

    set <u8> Regs::get_valid_reg_ids() {
        set<u8> res;
        for (int i = 0; i < contents_.size(); i++) {
            if (contents_[i]->is_valid()) {
                res.insert(i);
            }
        }
        return res;
    }

    map <u8, s64> Regs::get_valid_reg_vals() {
        map<u8, s64> res;
        for (int i = 0; i < contents_.size(); i++) {
            if (contents_[i]->is_valid()) {
                res.insert({i, contents_[i]->value()});
            }
        }
        return res;
    }

    void Regs::set_regi_val(u8 i, s64 val) {
        contents_[i]->set_val(val);
    }

    void Regs::set_regi_type(u8 i, RegType type) {
        contents_[i]->set_type(type);
    }

    void Regs::set_regi_off(u8 i, int off) {
        contents_[i]->set_off(off);
    }

    void Regs::set_regi(u8 i, s64 val, RegType type,int type_off) {
        contents_[i]->set(val, type,type_off);
    }

    void Regs::set_regs_val(map <u8, s64> &reg_vals) {
        for (auto it = reg_vals.begin(); it != reg_vals.end(); it++) {
            u8 reg_i = it->first;
            s64 val = it->second;
            set_regi_val(reg_i, val);
        }
    }

    void Regs::copy_from_regs(Regs *regs) {
        assert(contents_.size() == regs->size());
        for (int i = 0; i < contents_.size(); i++) {
            *contents_[i] = *(*regs)[i];
        }
    }

    void Regs::refresh() {
        for (Reg *reg: contents_) {
            reg->set_invalid();
        }
    }

    bool Regs::check_equivalence(Regs *regs, set<int> live_regs,const StaticInfo& init_static_info) {
        bool res = true;
        for (int i: live_regs) {
            if(*contents_[i] != *(regs->contents_[i])){
                if(contents_[i]->type()==NOT_INIT){ // refer to initial static information
                    auto reg_info=init_static_info.get_regi_info(i);
                    auto target_reg=regs->contents_[i];
                    if(reg_info.is_value_valid_&&reg_info.smin_value_==reg_info.smax_value_
                    &&reg_info.smin_value_==target_reg->value()
                    &&reg_info.is_type_valid_&&reg_info.type_==target_reg->type()){
                        continue;
                    }
                    else
                        res=false;
                }
                else
                    res=false;
            }
        }
        return res;
    }

    int Regs::compute_dis(Regs *target, set<int> live_regs) {
        int res = 0;
        for (int i: live_regs) {
            if (*(contents_[i]) != *((*target)[i]))
                res++;
        }
        return res;
    }

    Reg *&Regs::operator[](int i) {
        return contents_[i];
    }

    bool Regs::operator==(Regs &regs) {
        bool res = true;
        for (int i = 0; i < contents_.size(); i++) {
            res = res && (*contents_[i] == *regs[i]);
        }
        return res;
    }

    bool Regs::operator!=(Regs &regs) {
        bool res = false;
        for (int i = 0; i < contents_.size(); i++) {
            res = res || (*contents_[i] != *regs[i]);
        }
        return res;
    }

    void Regs::operator=(Regs &regs) {
        assert(contents_.size() == regs.size());
        for (int i = 0; i < contents_.size(); i++) {
            *contents_[i] = *regs[i];
        }
    }

    bool Regs::operator<(Regs &regs) {
        for (int i = 0; i < contents_.size(); i++) {
            if (*contents_[i] < *(regs[i]))
                return true;
        }
        return false;
    }

    void Regs::print_regs() {
        printf("Regs: ");
        for (int i = 0; i < contents_.size(); i++) {
            if (contents_[i]->is_valid())
                printf("r[%d][%d] = 0x%lx(%s, %d) | ", i, version_,
                       contents_[i]->value(), reg_type_str[contents_[i]->type()].c_str(),contents_[i]->off());
            else
                printf("r[%d][%d] = __ | ", i, version_);
        }
        printf("\n");
    }


    bool StaticInfo::empty() {
        return regs_info_.empty();
    }

    void StaticInfo::copy(const StaticInfo &init_info) {
        regs_info_ = init_info.regs_info_;
    }

    RegInfo StaticInfo::get_regi_info(int reg_id) const {
        if (regs_info_.find(reg_id) != regs_info_.end())
            return regs_info_.at(reg_id);
        else
            return {};
    }

    int64_t StaticInfo::get_regi_smin_val(int reg_id) {
        if (regs_info_.find(reg_id) != regs_info_.end())
            return regs_info_.at(reg_id).smin_value_;
        else
            return 0;
    }

    int64_t StaticInfo::get_regi_smax_val(int reg_id) {
        if (regs_info_.find(reg_id) != regs_info_.end())
            return regs_info_.at(reg_id).smax_value_;
        else
            return INT64_MAX;
    }

    RegType StaticInfo::get_regi_type(int reg_id) {
        if (regs_info_.find(reg_id) != regs_info_.end())
            return regs_info_.at(reg_id).type_;
        else
            return NOT_INIT;
    }

    int StaticInfo::get_regi_off(int reg_id) {
        if (regs_info_.find(reg_id) != regs_info_.end())
            return regs_info_.at(reg_id).off_;
        else
            return 0;
    }

    int StaticInfo::get_regi_mapid(int reg_id) {
        if (regs_info_.find(reg_id) != regs_info_.end())
            return regs_info_.at(reg_id).map_id_;
        else
            return -1;
    }

    void StaticInfo::set_regi_value(u8 reg_i, s64 val) {
        if (regs_info_.find(reg_i) != regs_info_.end()) {
            regs_info_.at(reg_i).smin_value_ = regs_info_.at(reg_i).smax_value_ = val;
            regs_info_.at(reg_i).is_value_valid_ = true;
        } else
            regs_info_.insert({reg_i, RegInfo(val, SCALAR_VALUE)});
    }

    void StaticInfo::set_regi_value_invalid(u8 reg_i) {
        if (regs_info_.find(reg_i) != regs_info_.end()) {
            regs_info_.at(reg_i).is_value_valid_ = false;
        }
    }

    void StaticInfo::set_regi_min_max_val(u8 reg_i, s64 min_val, s64 max_val) {
        if (regs_info_.find(reg_i) != regs_info_.end()) {
            regs_info_.at(reg_i).smin_value_ = min_val;
            regs_info_.at(reg_i).smax_value_ = max_val;
            regs_info_.at(reg_i).is_value_valid_ = true;
        } else
            regs_info_.insert({reg_i, RegInfo(min_val, max_val)});
    }

    void StaticInfo::set_regi_type(u8 reg_i, RegType type) {
        if (regs_info_.find(reg_i) != regs_info_.end()) {
            regs_info_.at(reg_i).type_ = type;
            regs_info_.at(reg_i).is_type_valid_ = true;
        } else
            regs_info_.insert({reg_i, RegInfo(type)});
    }

    void StaticInfo::set_regi_off(u8 reg_i, int off) {
        assert(regs_info_.find(reg_i) != regs_info_.end());
        regs_info_.at(reg_i).off_ = off;
    }

    void StaticInfo::set_regi_map_id(u8 reg_i, int map_id) {
        assert(regs_info_.find(reg_i) != regs_info_.end());
        regs_info_.at(reg_i).map_id_ = map_id;
    }

    void StaticInfo::set_regi_info(u8 reg_i, const RegInfo &reg_info) {
        RegInfo new_reg_info(reg_info);
        if (regs_info_.find(reg_i) != regs_info_.end())
            regs_info_.at(reg_i) = new_reg_info;
        else
            regs_info_.insert({reg_i, new_reg_info});
    }

    void StaticInfo::set_regs_info(map<uint8_t, RegInfo> regs_info) {
        regs_info_ = regs_info;
    }

    void StaticInfo::merge(const StaticInfo &static_info) {
        auto regs_info = static_info.regs_info_;
        for (auto it = regs_info_.begin(); it != regs_info_.end(); it++) {
            if (regs_info.find(it->first) != regs_info.end()) {
                it->second.merge(regs_info.at(it->first));
            }
        }
        for (auto it = regs_info.begin(); it != regs_info.end(); it++) {
            if (regs_info_.find(it->first) == regs_info_.end()) {
                regs_info_.insert({it->first, it->second});
            }
        }

    }

    void StaticInfo::print_info() {
        for (auto it: regs_info_) {
            std::cout << "r[" << (int) it.first << "] = ";
            it.second.print_reg_info();
            std::cout << " | ";
        }
        std::cout << std::endl;
    }

    bool StaticInfo::operator==(const StaticInfo &static_info) {
        auto regs_info = static_info.regs_info_;
        if (regs_info_.size() != regs_info.size())
            return false;
        for (auto it: regs_info_) {
            int regno = it.first;
            auto reg_info = it.second;
            if (regs_info.find(regno) == regs_info.end()) {
                return false;
            } else {
                if (reg_info != regs_info.at(regno))
                    return false;
            };
        }
        return true;

    }

    bool StaticInfo::operator!=(const StaticInfo &static_info) {
        return !((*this) == static_info);
    }
}
