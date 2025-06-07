#ifndef SUPERBPF_SYNTHESIZER_SYNTHESIZER_H
#define SUPERBPF_SYNTHESIZER_SYNTHESIZER_H

#include "src/cfg/cfg.h"
#include "src/instruction/insn_simulator.h"
#include "src/testcase/testcase_gen.h"
#include "src/verifier/verifier.h"

namespace superbpf {
    enum PruningType{
        ALL,
        OFF1, // without exhibiting negative optimization
        OFF2, // without distance judgement
        OFF3, // without saving failed states
        OFF4, // without exhibiting use without definition
        NONE, // without any pruning
    };

    class Synthesizer {
    protected:
        Node *origin_;
        double origin_score_;
        PruningType pruning_type=ALL;
        vector<Testcase *> testcases_;
        InsnSimulator insn_simulator_;  // simulates the execution of insns
        TestcaseGen *testcase_gen = new TestcaseGen();

        vector<u8> sorted_optional_opcodes_;
        set<s32> optional_imms_;
        set<s32> optional_imm2s_;
        set<s32> atomic_imms_;
        int ld_bytes_;

        double last_synthesis_time_;

        /* set 'sorted_optional_opcodes_' and 'optional_imms_' */
        void set_opt_sorted_opcodes_imms();

        void set_ld_bytes();

        set<u8> get_optional_dst_regs(u8 code, State *last_state, bool is_used, bool is_defed);

        set<u8> get_optional_src_regs(u8 code, State *last_state, bool is_used);

        set<s16> get_optional_offs_helper(vector<State *> states, u8 reg_id, int byte_num, bool is_st);

        set<s16> get_optional_offs(vector<State *> states, u8 opcode, u8 dst_reg, u8 src_reg);

        set<s32> get_optional_imms(u8 opcode);

        unsigned get_bytes_num(u8 opcode);

        double score_insns(vector<Insn> &insns);

        virtual void clear() = 0;

    public:
        Synthesizer() {}

        ~Synthesizer() {
//            delete origin_;
            for (Testcase *testcase: testcases_)
                delete testcase;
            delete testcase_gen;
        }

        void set_pruning_type(PruningType pt){
            pruning_type=pt;
        }

        virtual void set_prog(Node *origin) = 0;

        virtual void set_prog_with_random_testcase(Node *origin) = 0;

        virtual void set_prog_with_inited_testcases(Node *origin, vector<State *> init_states) = 0;

        Testcase *get_testcasei(int i);

        vector<Testcase *> get_testcases();

        virtual void add_testcase(Testcase *testcase);

        virtual Node *synthesize() = 0;

        Node *synthesize_using_patterns(Node* origin);

        void print_last_synthesis_time();
    };


    /*
     * StateComparator
     */
    class StateCmp {
    public:
        bool operator()(const State *s1, const State *s2) const {
            return !(*s1 == *s2);
        }
    };

    class DfsSynthesizer : public Synthesizer {
    protected:
        time_t begin_time_;
        vector<vector<State *>> states_;
        vector<Insn> cur_rewrite_insns_;  // current exploring rewrite insns
        int cur_max_depth_;
        map<State *, int, StateCmp> testcases_explored_states_;

        bool dfs(int depth);
//        bool dfs_without_pruning1(int depth);
        bool dfs_without_pruning2(int depth);
        bool dfs_without_pruning3(int depth);
        bool dfs_without_pruning4(int depth);
        bool dfs_no_pruning(int depth);

        void clear();

    public:
        // used by WinSynthesizer
        DfsSynthesizer() {
            insn_simulator_ = InsnSimulator();
        }

        ~DfsSynthesizer() {
            for (int i = 0; i < states_.size(); i++) {
                for (int j = 0; j < states_[0].size(); j++)
                    delete states_[i][j];
            }
            for (auto it: testcases_explored_states_) {
                delete it.first;
            }
        }

        DfsSynthesizer(Node *origin) {
            origin_ = origin;
            origin_score_ = score_insns(origin_->insns());
            set_opt_sorted_opcodes_imms();
            set_ld_bytes();
            // generate and insert a random testcase
            testcase_gen->set_prog(origin_->insns());
            add_testcase(testcase_gen->gen_random_testcase());
            insn_simulator_ = InsnSimulator();
        }

        // used by WinSynthesizer
        void set_prog(Node *origin);

        void add_testcase(Testcase *testcase);

        Node *synthesize();

        void set_prog_with_random_testcase(Node *origin);

        void set_prog_with_inited_testcases(Node *origin, vector<State *> init_states);
    };


    // Synthesizer using window decomposition
    class WinSynthesizer {
        PruningType pruning_type=ALL;
        Node *origin_;
        int win_size_;
        Synthesizer *synthesizer_;
        vector<Testcase *> testcases_;
        vector<State *> testcases_last_state_;
        InsnSimulator insn_simulator_;  // simulates the execution of insns
        TestcaseGen testcaseGen;
        static std::string cur_example_name;

    public:
        WinSynthesizer(Node *origin, int win_size,PruningType pruning_type) {
            origin_ = origin;
            win_size_ = win_size;
            synthesizer_ = new DfsSynthesizer();
            synthesizer_->set_pruning_type(pruning_type);
            testcaseGen.set_prog(origin->insns(), origin->init_static_info());
            add_testcase(testcaseGen.gen_random_testcase());
            add_testcase(testcaseGen.gen_random_testcase());
//            add_testcase(testcaseGen.gen_random_testcase());
        }

        ~WinSynthesizer() {
//            delete origin_;
            delete synthesizer_;
            for (Testcase *testcase: testcases_)
                delete testcase;
            for (State *state: testcases_last_state_)
                delete state;
        }

        void set_node(Node* node){
            origin_=node;
        }

        void set_example_name(std::string example_name){
            cur_example_name=example_name;
        }

        Node* match_pattern(Node* origin);

        void add_testcase(Testcase *testcase);

        Node *synthesize_with_context();

        void store_opt_pattern(const Node* origin,const Node* rewrite);
    };

    class BfsNode {
        vector<Insn> insns_;
        vector<State *> last_states_;
        short left_ld_bytes_;
        set<u64> testcase0_ld_addrs_;

    public:
        BfsNode(vector<Insn> &insns, vector<State *> last_states, short left_ld_bytes) {
            insns_ = insns;
            last_states_ = last_states;
            left_ld_bytes_ = left_ld_bytes;
        }

        BfsNode(vector<Insn> &insns, vector<State *> last_states, set<u64> &ld_addrs) {
            insns_ = insns;
            last_states_ = last_states;
            testcase0_ld_addrs_ = ld_addrs;
        }

        BfsNode(vector<State *> last_states, short left_ld_bytes) {
            last_states_ = last_states;
            left_ld_bytes_ = left_ld_bytes;
        }

        ~BfsNode() {
            for (State *state: last_states_) {
                delete state;
            }
        }

        vector<Insn> get_insns() {
            return insns_;
        }

        vector<State *> get_states() {
            return last_states_;
        }

        short left_ld_bytes() {
            return left_ld_bytes_;
        }

        set<u64> &ld_addrs() {
            return testcase0_ld_addrs_;
        }
    };

    class BfsSynthesizer : public Synthesizer {

    public:
        BfsSynthesizer(Node *origin) {
            origin_ = origin;
            origin_score_ = score_insns(origin_->insns());
            set_opt_sorted_opcodes_imms();
            set_ld_bytes();
            // generate and insert a random testcase
            testcase_gen->set_prog(origin_->insns());
            add_testcase(testcase_gen->gen_random_testcase());
            insn_simulator_ = InsnSimulator();
        }

        void add_testcase(Testcase *testcase);

        Node *synthesize();
    };
}

#endif //SUPERBPF_SYNTHESIZER_SYNTHESIZER_H
