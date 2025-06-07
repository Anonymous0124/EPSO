#ifndef SUPERBPF_SYMSTATE_SYMREGS_H
#define SUPERBPF_SYMSTATE_SYMREGS_H

#include <string>
#include <map>

#include "z3++.h"

#include "src/cfg/cfg.h"
#include "src/ebpf/bpf.h"

using std::string;
using std::vector;

namespace superbpf {
    class SymReg{
        z3::expr val_;
        RegType type_;
        int off_;
        int map_id_;

        vector<z3::expr> constraints_;
    public:
        SymReg(z3::context &c,const string& prefix,int idx,int version,RegType type):
        val_(c.bv_const((prefix+".reg_val["+std::to_string(idx)+"]["+std::to_string(version)+"]").c_str(),64)){
            type_=type;
            off_=0;
            map_id_=-1;
        }

        z3::expr get_val();

        int get_off();

        int get_map_id();

        RegType get_type();

        vector<z3::expr> constraints();

        void set_val(const z3::expr& val);

        void set_val_above_zero(z3::context &c);

        void set_off(int off);

        void set_map_id(int id);
    };
    /*
     * class SymRegsValidation:
     * record symbolic states of registers during symbolic execution.
     * used by class Validator.
     **/
    class SymRegsValidation {
    private:
        /* z3 context reference */
        z3::context &c_;
        /* to identify program (target and rewrite) */
        string prefix_;
        /* to identify version with respect to SSA */
        // int version_;
        /* vector of z3 exprs declaration for registers (R0 - R10), size of each inner vector refers to current reg version */
        vector<vector<SymReg>> regs_;

        /* public interfaces of class SymRegsValidation
         * used by class SymState and class InsnSymSimulator
         */
    public:
        /* construction */
        SymRegsValidation(z3::context &c, const string& prefix,const StaticInfo& init_static_info);

        /* get register value, return z3 expr of the value of register of reg_number */
        z3::expr get_reg_value(int reg_number);

        /* get register initial value, return z3 expr of the initial value of register of reg_number */
        z3::expr get_reg_init_value(int reg_number);

        /* get register initial value, return z3 expr of the initial value of register of reg_number */
        z3::expr get_reg_value(int reg_number,int version);

        int get_map_id(int reg_number);

        /* get register off, return z3 expr of the off of register of reg_number */
        int get_reg_off(int reg_number);

        /* get register off, return z3 expr of the off of register of reg_number */
        int get_reg_off(int reg_number,int version);

        /* get register initial off, return z3 expr of the initial off of register of reg_number */
        int get_reg_init_off(int reg_number);

        RegType get_reg_type(int reg_number);

        RegType get_reg_type(int reg_number,int version);

        /* set register value, with version of regs_ increased by one */
        void set_reg_value_with_type(z3::context &c, int reg_number, const z3::expr& value,RegType type);

        /* set register value, with version of regs_ increased by one */
        void set_reg_above_zero(z3::context &c, int reg_number);

        void set_regs_unchange(z3::context &c);

        void set_reg_off(int reg_number,int value);

        void set_reg_off(int reg_number,int version,int value);

        void set_reg_map_id(int reg_number,int id);

        void set_reg_map_id(int reg_number,int version,int id);

        /* get the constraints of symbolic states of registers */
        z3::expr_vector constraints();
    };
}


#endif //SUPERBPF_SYMSTATE_SYMREGS_H
