#ifndef SUPERBPF_OPTIMIZER_OPTIMIZER_H
#define SUPERBPF_OPTIMIZER_OPTIMIZER_H

#include <iostream>
#include <linux/bpf.h>

#include "src/cfg/cfg.h"
#include "src/instruction/insn.h"
#include "src/synthesizer/synthesizer.h"
#include "src/verifier/verifier.h"

namespace superbpf {
    /*
     * Usage: input program type and instructions, output optimized instructions.
     */
    class Optimizer {
        PruningType pruning_type=ALL;

        static std::string cur_example_name;

        std::pair<Node*,std::pair<int,long long>> cegis(Node *cur_bb);

        double compute_insns_exec_time(std::vector<Insn> insns);

        void print_consumed_time(double consumed_time);

        void store_opt_pattern(const Node* origin,const Node* rewrite);

    public:
        void set_pruning_type(PruningType pt){
            pruning_type=pt;
        }
        /* Optimize without 'report file' outputted ('report file' records detailed information about
         * which and how blocks are optimized, suffixed with '_opt_report.txt'). */
        std::vector<Insn> optimize(bpf_prog_type prog_type, std::vector<Insn> &target_insns);

        /* Optimize with 'report file' outputted under the same directory with input file('report file' records detailed information about
         * which and how blocks are optimized, suffixed with '_opt_report.txt'). */
        std::vector<Insn>
        optimize_with_report_output(std::string infile_path, bpf_prog_type prog_type, std::vector<Insn> &target_insns,
                                    bool is_1st_sec);

        /* Optimize with 'report file' outputted to user-defined path('report file' records detailed information about
         * which and how blocks are optimized, suffixed with '_opt_report.txt'). */
        std::vector<Insn> optimize_with_report_output_to_path(std::string out_path, std::string sec_name,bpf_prog_type prog_type,bpf_attach_type attach_type,
                                                              std::vector<Insn> &target_insns,bool is_1st_sec);
    };
}


#endif //SUPERBPF_OPTIMIZER_OPTIMIZER_H
