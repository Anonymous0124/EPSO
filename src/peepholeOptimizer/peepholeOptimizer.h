#ifndef SUPERBPF_PEEPHOLEOPTIMIZER_H
#define SUPERBPF_PEEPHOLEOPTIMIZER_H

#include <iostream>
#include <vector>

#include <linux/bpf.h>

#include "src/cfg/cfg.h"
#include "src/instruction/insn.h"
#include "src/synthesizer/synthesizer.h"
#include "src/verifier/verifier.h"

namespace superbpf{
    class PeepholeOptimizer {
        int win_size_;

        static std::string cur_example_name;

        static vector<Insn> get_deserialized_insns(const std::string& insns_str,
                                            const std::unordered_map<int,int>& reg_id_map,
                                            const std::unordered_map<int,int>& reg_off_map,
                                            const std::unordered_map<int,int>& imm_map);

        bool check_safety(Node node);

        vector<Insn> recompose_insns(std::unordered_map<int,vector<Insn>> slices);

        void print_consumed_time(double consumed_time);

        int count_insns_except_ja(vector<Insn> &insns);

    public:
        explicit PeepholeOptimizer(int win_size){
            win_size_=win_size;
        }

        vector<Node> get_specific_insns(Node rough_node);

        Node* optimize_block(Node* origin_bb);

        vector<Node> match_pattern(Node* origin);

        Node* formalized_optimize_block(Node* origin_bb,bool allow_mem_combination);

        std::vector<Node> get_slices(Node* node,bool allow_mem_combination,map<int,set<int>>& slices);

        Node cegis(Node origin);

        void collect_block_opt_patterns(bpf_prog_type prog_type, bpf_attach_type attach_type,
                                                           vector<Insn> &target_insns,std::string example_name,int bb_idx);

        void collect_opt_patterns(bpf_prog_type prog_type,bpf_attach_type attach_type,
                                  std::vector<Insn> &target_insns,std::string example_name);

        /* Optimize with 'report file' outputted to user-defined path('report file' records detailed information about
             * which and how blocks are optimized, suffixed with '_opt_report.txt'). */
        std::vector<Insn> optimize_with_report_output_to_path(std::string out_path, std::string sec_name,bpf_prog_type prog_type,bpf_attach_type attach_type,
                                                              std::vector<Insn> &target_insns,bool is_1st_sec);
    };
}



#endif //SUPERBPF_PEEPHOLEOPTIMIZER_H
