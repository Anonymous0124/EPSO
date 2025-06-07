#include "sym_regs.h"

using std::to_string;
using namespace superbpf;

namespace superbpf {

    z3::expr SymReg::get_val(){
        return val_;
    }

    int SymReg::get_off(){
        return off_;
    }

    int SymReg::get_map_id(){
        return map_id_;
    }

    RegType SymReg::get_type(){
        return type_;
    }

    vector<z3::expr> SymReg::constraints(){
        return constraints_;
    }

    void SymReg::set_val(const z3::expr& val){
        constraints_.emplace_back(val_==val);
    }

    void SymReg::set_val_above_zero(z3::context &c) {
        constraints_.emplace_back(val_.extract(0,0)==c.bv_val(0,1));
    }

    void SymReg::set_off(int off){
        off_=off;
    }

    void SymReg::set_map_id(int id){
        map_id_=id;
    }

    SymRegsValidation::SymRegsValidation(z3::context &c, const string& prefix,const StaticInfo& init_static_info)
            : c_(c) {
        prefix_ = prefix;
        regs_.resize(11);
        for (int i = 0; i <= 10; i++) {
            auto reg_info=init_static_info.get_regi_info(i);
            if(reg_info.is_type_valid_){
                SymReg reg(c,prefix,i,0,reg_info.type_);
                reg.set_off(reg_info.off_);
                reg.set_map_id(reg_info.map_id_);
                regs_[i].emplace_back(reg);
            }
            else{
                SymReg reg(c,prefix,i,0,NOT_INIT);
                reg.set_off(0);
                reg.set_map_id(-1);
                regs_[i].emplace_back(reg);
            }
        }
    }

    z3::expr SymRegsValidation::get_reg_value(int reg_number) {
        return regs_[reg_number].back().get_val();
    }

    z3::expr SymRegsValidation::get_reg_init_value(int reg_number) {
        return regs_[reg_number].front().get_val();
    }

    z3::expr SymRegsValidation::get_reg_value(int reg_number,int version) {
        return regs_[reg_number][version].get_val();
    }

    int SymRegsValidation::get_reg_off(int reg_number) {
        return regs_[reg_number].back().get_off();
    }

    int SymRegsValidation::get_map_id(int reg_number) {
        return regs_[reg_number].back().get_map_id();
    }

    int SymRegsValidation::get_reg_off(int reg_number,int version) {
        return regs_[reg_number][version].get_off();
    }

    int SymRegsValidation::get_reg_init_off(int reg_number) {
        return regs_[reg_number].front().get_off();
    }

    RegType SymRegsValidation::get_reg_type(int reg_number){
        return regs_[reg_number].back().get_type();
    }

    RegType SymRegsValidation::get_reg_type(int reg_number,int version){
        return regs_[reg_number][version].get_type();
    }

    void SymRegsValidation::set_reg_value_with_type(z3::context &c, int reg_number, const z3::expr& value,RegType type) {
        SymReg reg(c,prefix_,reg_number,regs_[reg_number].size(),type);
        reg.set_val(value);
        regs_[reg_number].emplace_back(reg);
    }

    void SymRegsValidation::set_regs_unchange(z3::context &c) {
        for(int i=0;i<regs_.size();i++){
            SymReg reg(c,prefix_,i,regs_[i].size(),regs_[i].back().get_type());
            reg.set_val(regs_[i].back().get_val());
            regs_[i].emplace_back(reg);
        }
    }

    void SymRegsValidation::set_reg_off(int reg_number,int off){
        regs_[reg_number].back().set_off(off);
    }

    void SymRegsValidation::set_reg_off(int reg_number,int version,int off){
        regs_[reg_number][version].set_off(off);
    }

    void SymRegsValidation::set_reg_map_id(int reg_number,int id){
        regs_[reg_number].back().set_map_id(id);
    }

    void SymRegsValidation::set_reg_map_id(int reg_number,int version,int id){
        regs_[reg_number][version].set_map_id(id);
    }

    void SymRegsValidation::set_reg_above_zero(z3::context &c, int reg_number) {
        regs_[reg_number].back().set_val_above_zero(c);
    }

    z3::expr_vector SymRegsValidation::constraints() {
        z3::expr_vector res_vec(c_);
        for(const auto& cur_regs:regs_){
            for(auto reg:cur_regs){
                auto constraints=reg.constraints();
                for(auto cons:constraints)
                    res_vec.push_back(cons);
            }
        }
        return res_vec;
    }
}
