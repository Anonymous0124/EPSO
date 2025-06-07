#ifndef SUPERBPF_VALIDATOR_VALIDATOR_H
#define SUPERBPF_VALIDATOR_VALIDATOR_H

#include "z3++.h"

#include "cfg/cfg.h"
#include "state/state.h"
#include "symstate/sym_regs.h"
#include "symstate/sym_memory.h"
#include "testcase/testcase.h"

namespace superbpf {
    /*
     * class Validator:
     * Judge if the rewrite basic block is semantically equivalent to the original one.
     */
    class Validator {
        z3::context c_;
        Node *target_;
        SymRegsValidation target_regs_;
        SymMemoryValidation target_mem_;
        Node *rewrite_;
        SymRegsValidation rewrite_regs_;
        SymMemoryValidation rewrite_mem_;
        Testcase *counterexample_;

    public:
        /* Constructor of class Validator */
        Validator(Node *target, Node *rewrite);

        void print_states(vector<Insn>& insns,SymRegsValidation& regs,SymMemoryValidation& mem,z3::model &m);

        /* Verify the equivalence of target_ and rewrite_ */
        bool verify();

        /* Get counterexample, return null if not available. */
        Testcase *get_counterexample();

    private:
        z3::expr_vector symbolic_execution(Node *node, SymRegsValidation &regs, SymMemoryValidation &mem);

        z3::expr input_equal();

        z3::expr output_inequal();

        int bpfsize2byte(int bpf_size);

        map<u64, int> compute_mem_areas(std::set<u64> mem_addrs);

        void gen_counterexample(z3::model &m);

        void gen_counterexample_debug(z3::model &m);
    };

}

#endif //SUPERBPF_VALIDATOR_VALIDATOR_H
