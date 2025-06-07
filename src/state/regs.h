#ifndef SUPERBPF_STATE_REGS_H
#define SUPERBPF_STATE_REGS_H

#include <linux/bpf.h>
#include <map>
#include <set>
#include <vector>

#include "z3++.h"

#include "src/ebpf/bpf.h"

namespace superbpf {


    struct RegInfo {
        int64_t smin_value_;
        int64_t smax_value_;
        RegType type_;
        int off_;
        int map_id_;
        bool is_value_valid_;
        bool is_type_valid_;

        RegInfo() {
            is_value_valid_ = false;
            is_type_valid_ = false;
            smin_value_ = smax_value_ = 0;
            type_ = NOT_INIT;
            off_=0;
            map_id_=-1;
        }

        RegInfo(int64_t smin_value, int64_t smax_value, RegType type) {
            smin_value_ = smin_value;
            smax_value_ = smax_value;
            type_ = type;
            is_value_valid_ = true;
            is_type_valid_ = true;
            off_=0;
            map_id_=-1;
        }

        RegInfo(int64_t smin_value, int64_t smax_value) {
            smin_value_ = smin_value;
            smax_value_ = smax_value;
            is_value_valid_ = true;
            is_type_valid_ = false;
            off_=0;
            map_id_=-1;
        }

        RegInfo(int64_t value, RegType type) {
            smin_value_ = smax_value_ = value;
            type_ = type;
            is_value_valid_ = true;
            is_type_valid_ = true;
            off_=0;
            map_id_=-1;
        }


        RegInfo(RegType type) {
            type_ = type;
            off_=0;
            is_value_valid_ = false;
            is_type_valid_ = true;
            map_id_=-1;
        }

        RegInfo(const RegInfo &reg_info) {
            smin_value_ = reg_info.smin_value_;
            smax_value_ = reg_info.smax_value_;
            type_ = reg_info.type_;
            is_value_valid_ = reg_info.is_value_valid_;
            is_type_valid_ = reg_info.is_type_valid_;
            off_=reg_info.off_;
            map_id_=reg_info.map_id_;
        }

        void merge(const RegInfo &reg_info);

        bool operator==(const RegInfo &reg_info);

        bool operator!=(const RegInfo &reg_info);

        void print_reg_info();
    };

    /*
 * Static Information.
 * Contains information that can be obtained through static analysis.
 */
    class StaticInfo {
        std::map<uint8_t, RegInfo> regs_info_;  // regs' static information

    public:
        StaticInfo() {}

        StaticInfo(const StaticInfo &static_info) {
            regs_info_ = static_info.regs_info_;
        }

        bool empty();

        void copy(const StaticInfo &init_info);

        bool is_value_valid(int reg_id){
            return regs_info_[reg_id].is_value_valid_;
        }

        RegInfo get_regi_info(int reg_id) const;

        int64_t get_regi_smin_val(int reg_id);

        int64_t get_regi_smax_val(int reg_id);

        RegType get_regi_type(int reg_id);

        int get_regi_off(int reg_id);

        int get_regi_mapid(int reg_id);

        void set_regi_info(u8 reg_i, const RegInfo &reg_info);

        void set_regi_min_max_val(u8 reg_i, s64 min_val, s64 max_val);

        void set_regi_value(u8 reg_i, s64 val);

        void set_regi_value_invalid(u8 reg_i);

        void set_regi_type(u8 reg_i, RegType type);

        void set_regi_off(u8 reg_i, int off);

        void set_regi_map_id(u8 reg_i, int map_id);

        void set_regs_info(std::map<uint8_t, RegInfo> regs_info);

        void merge(const StaticInfo &static_info);

        void print_info();

        bool operator==(const StaticInfo &static_info);

        bool operator!=(const StaticInfo &static_info);
    };

    class Reg {
        s64 value_;
        RegType type_;
        int off_;
    public:
        Reg() {
            value_ = off_=0;
            type_ = NOT_INIT;
        }

        Reg(s64 value) {
            value_ = value;
            off_=0;
            type_ = SCALAR_VALUE;
        }

        /*
         * Get operations.
         */
        s64 value();

        RegType type();

        int off();

        std::string type_str();

        s32 lower32();

        s32 upper32();

        bool is_valid();

        /*
         * Set operations.
         */
        void set_val(s64 value);

        void set_type(RegType type);

        void set_off(int off);

        void set(s64 value, RegType type,int type_off);

        void set_invalid();

        bool operator==(const Reg &r);

        bool operator!=(const Reg &r);

        bool operator<(const Reg &r);

        void operator=(const Reg &r);
    };

    class Regs {
        int version_;
        std::vector<Reg *> contents_;
    public:
        Regs(int version, int size) {
            version_ = version;
            for (int i = 0; i < size; i++) {
                contents_.emplace_back(new Reg());
            }
        }

        ~Regs() {
            for (Reg *reg: contents_) {
                delete reg;
            }
        }
        /*
         * Get opertions.
         */
        int size() const;

        bool is_regi_valid(u8 i);

        s64 get_regi_val(u8 i);

        RegType get_regi_type(u8 i);

        int get_regi_off(u8 i);

        Reg *get_regi(u8 i);

        std::set<u8> get_valid_reg_ids();

        std::map<u8, s64> get_valid_reg_vals();

        void set_regi_val(u8 i, s64 val);

        void set_regi_type(u8 i, RegType type);

        void set_regi_off(u8 i, int off);

        void set_regi(u8 i, s64 val, RegType type,int type_off);

        void set_regs_val(std::map<u8, s64> &reg_vals);

        void copy_from_regs(Regs *regs);

        void refresh();

        bool check_equivalence(Regs *regs, std::set<int> live_regs,const StaticInfo& init_static_info);

        /* Compute the distance with regs 'target', 'distance' means the least number of insns
         * needed to transfer from current regs to regs 'target'*/
        int compute_dis(Regs *target, std::set<int> live_regs);

        Reg *&operator[](int i);

        bool operator==(Regs &regs);

        bool operator!=(Regs &regs);

        void operator=(Regs &regs);

        bool operator<(Regs &regs);

        void print_regs();
    };


}

#endif //SUPERBPF_STATE_REGS_H
