#ifndef SUPERBPF_CFG_CFG_H
#define SUPERBPF_CFG_CFG_H

#include <linux/bpf.h>
#include <map>
#include <queue>
#include <set>

#include "z3++.h"

#include "src/instruction/insn.h"
#include "src/state/regs.h"

namespace superbpf {


    /* 'Node' represents a basic block in CFG.
     *
     * Functionality: record instructions and related static analysis information (live-in regs, live-out regs...)
     * in a basic block, as well as some testcases to be used by 'Synthesizer'.
     *
     * Usage: used as input to 'Synthesizer'.
     */
    class Node {
        int idx_;  // the 1st instruction's index in cfg
        std::vector<Insn> insns_;  // instructions
        std::vector<Insn> split_insns_;  // instructions that are not intended for optimization, such as jmp, etc.
        std::set<int> regs_live_in_;  // live-in regs
        std::set<int> regs_live_out_;  // live-out regs
        std::map<u8, std::set<int>> mem_live_in_;  // live-in memory
        std::map<u8, std::set<int>> mem_live_out_;  // live-out memory
        std::map<u8, std::set<int>> ld_mem_addrs_;
        std::map<u8, std::set<int>> st_mem_addrs_;
        std::set<int> used_imms_;  // immediate used by instructions in this basic block
        std::vector<StaticInfo> static_info_;  // static information
        StaticInfo branch_final_static_info_;  // final static information for another branch (if block ends with conditional jump)
        bpf_prog_type prog_type_;
        bpf_attach_type attach_type_;

        static void
        mem_addrs2areas(std::map<u8, std::set<int>> &mem_addrs, std::map<u8, std::set<std::pair<int, int>>> &mem_areas);

    public:
        Node(){}
        /* Get node's insns from a complete program, ranging from 'begin' to 'end' */
        Node(int idx, const std::vector<Insn> &prog, int begin, int end) {
            idx_ = idx;
            for (int i = begin; i <= end; i++) {
                insns_.emplace_back(prog[i]);
            }
            for (int i = begin; i <= end + 1; i++)
                static_info_.emplace_back();
        }

        Node(int idx, std::vector<Insn> insns) {
            idx_ = idx;
            insns_ = insns;
            for (int i = 0; i <= insns.size(); i++)
                static_info_.emplace_back();
        }

        Node(std::vector<Insn> insns) {
            idx_ = 0;
            insns_ = insns;
            for (int i = 0; i <= insns.size(); i++)
                static_info_.emplace_back();
        }

        Node(bpf_prog_type prog_type, int idx, std::vector<Insn> insns) {
            prog_type = prog_type;
            idx_ = idx;
            insns_ = insns;
            for (int i = 0; i <= insns.size(); i++)
                static_info_.emplace_back();
        }

        int idx();

        int size();

        std::vector<Insn> &insns();

        std::string get_serialized_insns_str(std::unordered_map<int,int>& reg_id_map,std::unordered_map<int,int>& reg_off_map,
                                             std::unordered_map<int,int>& imm_map,std::set<int> new_regs) const;

        void set_insns(std::vector<Insn> &insns) {
            insns_ = insns;
        }

        int getHeadIdx();

        /* Returns last instruction's index + 1. */
        int getTailIdx();

        StaticInfo init_static_info();

        StaticInfo final_static_info();

        std::set<int> regs_live_in() const;

        std::set<int> regs_live_out() const;

        std::map<u8, std::set<int>> mem_live_in();

        std::map<u8, std::set<int>> mem_live_out();

        StaticInfo branch_final_static_info();

        std::set<int> used_imms();

        std::vector<Insn> &get_split_insns();

        std::set<int> get_used_regs() const;

        std::set<int> get_defined_regs() const;

        std::map<u8, std::set<int>> get_used_mems();

        std::map<u8, std::set<int>> get_used_mems(int insn_i);

        std::map<u8, std::set<int>> get_defined_mems();

        std::map<u8, std::set<int>> get_defined_mems(int insn_i);

        /* Fill the rewrite with goto+0 and add get_split_insns. */
        std::vector<Insn> get_complete_insns(int empty_num);

        bpf_prog_type prog_type(){
            return prog_type_;
        }

        bpf_attach_type attach_type(){
            return attach_type_;
        }

        int get_insns_num();

        double get_score();

        /* Get node composed by insns between insns_[start, end). */
        Node *get_sub_node(int start, int end);

        /* Get node composed by selected insns */
        Node get_sub_node_by_selected_insns(std::vector<int> insn_idxes);

        void edit_insns(int start,int end,const std::vector<Insn>& rewrite_insns);

        void edit_insns(std::vector<int> insns_idxes,const std::vector<Insn>& rewrite_insns);

        void clear_invalid_insns();

        void clear_goto0_insns();

        /* Split jmp/call/return... insns. */
        void split_insns();

        void set_prog_attach_type(bpf_prog_type prog_type, bpf_attach_type attach_type);

        void set_regs_live_in(std::set<int> regs);

        void add_regs_live_out(std::set<int> regs);

        void set_mem_live_in(std::map<u8, std::set<int>> mems);

        void add_mem_live_out(std::map<u8, std::set<int>> mems);

        void set_init_static_info(const StaticInfo &init_info);

        void set_final_static_info(const StaticInfo &init_info);

        void set_split_insns(std::vector<Insn> insns);

        void compute_final_static_info();

        void record_used_imms();

        bool same_with_node(Node *node);

        int bpf_size_to_bytes(int bpf_size);

        void print_insns() const;

        void print_live_regs();

        void print_live_mems();

        void print_init_static_info();

        void print_static_info();

        bool operator<(const Node& other) const {
            return insns_.size()<other.insns_.size();
        }

    };

    /*
     * Control Flow Graph.
     */
    class CFG {
        std::map<int, Node *> nodes_;
        std::map<int, std::vector<int>> node_chidren_;
        std::map<int, std::vector<int>> node_parent_;
        bpf_prog_type prog_type_;
        bpf_attach_type attach_type_;

        void build_cfg(const std::vector<Insn> &insns);

        void addNode(const std::vector<Insn> &prog, int begin, int end, const std::vector<int> &children);

        /* Merge live-in regs from successors, used in live-out analysis. */
        std::set<int> merge_regs_live_in(std::vector<int> successors);

        /* Merge live-in memory areas from successors, used in live-out analysis. */
        std::map<u8, std::set<int>> merge_mem_live_in(std::vector<int> successors);

        StaticInfo merge_final_static_info(int node_id, std::vector<int> predecessors);

        void analyze_regs_live_out();

        void analyze_mem_liveness();

        void analyze_init_static_info();

        void record_used_imms();

    public:
        CFG() {}

        /* Given program type and instructions, construct cfg. */
        CFG(bpf_prog_type prog_type, const std::vector<Insn> &insns);

        CFG(bpf_prog_type prog_type, bpf_attach_type attach_type, const std::vector<Insn> &insns);

        Node *getNode(int node_idx);

        std::map<int, Node *> getAllNodes();

        std::vector<int> &getNodeChildren(int begin);

        std::vector<int> &getNodeParent(int begin);

        void static_analysis();

        /* Print basic block(i). */
        void print_bbi(int idx);

        /* Print the whole program. */
        void print_prog();

        /* Print live-out regs. */
        void print_live_regs();
    };
}


#endif //SUPERBPF_CFG_CFG_H
