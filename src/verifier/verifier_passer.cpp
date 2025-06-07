#include "verifier_passer.h"

#include <bpf/libbpf.h>
#include <regex>

#include "src/cfg/cfg.h"
#include "src/patcher/patcher.h"

using namespace std;

#define LOG_SIZE (64*1024)

int VerifierPasser::load_bpf_object(std::string filename, vector<bpf_prog_type> prog_type_vec, char *verifier_log) {
    char log_buf[LOG_SIZE];
    LIBBPF_OPTS(bpf_object_open_opts, opts,
                .kernel_log_buf = log_buf,
                .kernel_log_size = sizeof(log_buf),
                .kernel_log_level = 1,
    );
    auto obj = bpf_object__open_file(filename.c_str(), &opts);
    if (prog_type_vec.size() != 0) {
        bpf_program *prog;
        int i = 0;
        bpf_object__for_each_program (prog, obj) {
            bpf_program__set_type(prog, prog_type_vec[i]);
            i++;
        }
    }
    if (libbpf_get_error(obj)) {
        printf("ERROR: libbpf could not open file %s\n", filename.c_str());
        exit(1);
    }
    int ret = bpf_object__load(obj);
    strcpy(verifier_log, log_buf);
    return ret;
}


bpf_prog_type VerifierPasser::str2progtype(std::string progtype_str) {
    bpf_prog_type res;
    if (progtype_str == "BPF_PROG_TYPE_UNSPEC")
        res = (bpf_prog_type) 0;
    else if (progtype_str == "BPF_PROG_TYPE_SOCKET_FILTER")
        res = (bpf_prog_type) 1;
    else if (progtype_str == "BPF_PROG_TYPE_KPROBE")
        res = (bpf_prog_type) 2;
    else if (progtype_str == "BPF_PROG_TYPE_SCHED_CLS")
        res = (bpf_prog_type) 3;
    else if (progtype_str == "BPF_PROG_TYPE_SCHED_ACT")
        res = (bpf_prog_type) 4;
    else if (progtype_str == "BPF_PROG_TYPE_TRACEPOINT")
        res = (bpf_prog_type) 5;
    else if (progtype_str == "BPF_PROG_TYPE_XDP")
        res = (bpf_prog_type) 6;
    else if (progtype_str == "BPF_PROG_TYPE_PERF_EVENT")
        res = (bpf_prog_type) 7;
    else if (progtype_str == "BPF_PROG_TYPE_CGROUP_SKB")
        res = (bpf_prog_type) 8;
    else if (progtype_str == "BPF_PROG_TYPE_CGROUP_SOCK")
        res = (bpf_prog_type) 9;
    else if (progtype_str == "BPF_PROG_TYPE_LWT_IN")
        res = (bpf_prog_type) 10;
    else if (progtype_str == "BPF_PROG_TYPE_LWT_OUT")
        res = (bpf_prog_type) 11;
    else if (progtype_str == "BPF_PROG_TYPE_LWT_XMIT")
        res = (bpf_prog_type) 12;
    else if (progtype_str == "BPF_PROG_TYPE_SOCK_OPS")
        res = (bpf_prog_type) 13;
    else if (progtype_str == "BPF_PROG_TYPE_SK_SKB")
        res = (bpf_prog_type) 14;
    else if (progtype_str == "BPF_PROG_TYPE_CGROUP_DEVICE")
        res = (bpf_prog_type) 15;
    else if (progtype_str == "BPF_PROG_TYPE_SK_MSG")
        res = (bpf_prog_type) 16;
    else if (progtype_str == "BPF_PROG_TYPE_RAW_TRACEPOINT")
        res = (bpf_prog_type) 17;
    else if (progtype_str == "BPF_PROG_TYPE_CGROUP_SOCK_ADDR")
        res = (bpf_prog_type) 18;
    else if (progtype_str == "BPF_PROG_TYPE_LWT_SEG6LOCAL")
        res = (bpf_prog_type) 19;
    else if (progtype_str == "BPF_PROG_TYPE_LIRC_MODE2")
        res = (bpf_prog_type) 20;
    else if (progtype_str == "BPF_PROG_TYPE_SK_REUSEPORT")
        res = (bpf_prog_type) 21;
    else if (progtype_str == "BPF_PROG_TYPE_FLOW_DISSECTOR")
        res = (bpf_prog_type) 22;
    else if (progtype_str == "BPF_PROG_TYPE_CGROUP_SYSCTL")
        res = (bpf_prog_type) 23;
    else if (progtype_str == "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE")
        res = (bpf_prog_type) 24;
    else if (progtype_str == "BPF_PROG_TYPE_CGROUP_SOCKOPT")
        res = (bpf_prog_type) 25;
    else if (progtype_str == "BPF_PROG_TYPE_TRACING")
        res = (bpf_prog_type) 26;
    else if (progtype_str == "BPF_PROG_TYPE_STRUCT_OPS")
        res = (bpf_prog_type) 27;
    else if (progtype_str == "BPF_PROG_TYPE_EXT")
        res = (bpf_prog_type) 28;
    else if (progtype_str == "BPF_PROG_TYPE_LSM")
        res = (bpf_prog_type) 29;
    else if (progtype_str == "BPF_PROG_TYPE_SK_LOOKUP")
        res = (bpf_prog_type) 30;
    else if (progtype_str == "BPF_PROG_TYPE_SYSCALL")
        res = (bpf_prog_type) 31;
    else if (progtype_str == "BPF_PROG_TYPE_NETFILTER")
        res = (bpf_prog_type) 32;
    else
        res = BPF_PROG_TYPE_UNSPEC;
    return res;
}

void VerifierPasser::read_object_files() {
    superbpf::Patcher origin_patcher(origin_filepath_);
    auto origin_progs = origin_patcher.get_bpf_programs();
    for (int i = 0; i < origin_progs.size(); i++) {
        auto prog = origin_progs[i];
        auto sec_name = prog.get_sec_name();
        auto name = prog.get_name();
        origin_sections_[sec_name] = prog.get_insns();
        name_secname_map_[name] = sec_name;
    }
    superbpf::Patcher rewrite_patcher(rewrite_filepath_);
    auto rewrite_progs = rewrite_patcher.get_bpf_programs();
    for (int i = 0; i < rewrite_progs.size(); i++) {
        auto prog = rewrite_progs[i];
        auto sec_name = prog.get_sec_name();
        auto name = prog.get_name();
        rewrite_sections_[sec_name] = prog.get_insns();
        rewrite_cfgs_[name] = superbpf::CFG(prog.get_type(), prog.get_insns());
    }
}


void
VerifierPasser::pass_verifier() {
    superbpf::Patcher patcher(origin_filepath_);
    char *verifier_log = new char[LOG_SIZE];
    bool origin_pass_verifier = (load_bpf_object(origin_filepath_, prog_type_vec_, verifier_log) == 0);
    if (!origin_pass_verifier) {
        if (prog_type_vec_.empty()) {
            cout << endl << "Couldn't get valid verifier log. If libbpf outputs 'missing BPF prog type', "
                            "please set BPF prog type manually." << endl;
            cout << "Usage: " << "./verifier_passer"
                 << " <origin-bpf-object-file-path> <rewrite-bpf-object-file-path> <bpf-prog-type>" << endl;
            cout << "('bpf-prog-type' includes 'BPF_PROG_TYPE_SOCKET', 'BPF_PROGTYPE_XDP', etc.)" << endl << endl;
            cout
                    << "If libbpf didn't output 'missing BPF prog type', it seems that origin bpf object file couldn't be loaded successfully through libbpf API 'bpf_object__load'. "
                       "Verifier Passer cannot deal with this case.\n";
            exit(0);
        } else {
            cout << "\nOrigin bpf object file couldn't be loaded successfully through libbpf API 'bpf_object__load'.\n"
                    "Check that if BPF prog type is correctly set. If BPF prog type is already correctly set, then Verifier Passer cannot deal with this case."
                 << endl;
            exit(0);
        }
    }
    bool pass_verifier = (load_bpf_object(rewrite_filepath_, prog_type_vec_, verifier_log) == 0);
    if (pass_verifier) {
        cout << endl << "Current version already passed verifier." << endl;
        exit(0);
    }
    string log_copy(verifier_log);
    if (log_copy.find("processed") == std::string::npos) {  // no verifier log
        if (prog_type_vec_.empty()) {
            cout << endl << "Couldn't get valid verifier log. If libbpf outputs 'missing BPF prog type', "
                            "please set BPF prog type manually." << endl;
            cout << "Usage: " << "./verifier_passer"
                 << " <origin-bpf-object-file-path> <rewrite-bpf-object-file-path> <bpf-prog-type>" << endl;
            cout << "('bpf-prog-type' includes 'BPF_PROG_TYPE_SOCKET', 'BPF_PROGTYPE_XDP', etc.)" << endl << endl;
            cout
                    << "If libbpf didn't output 'missing BPF prog type', it seems that origin bpf object file couldn't be loaded successfully through libbpf API 'bpf_object__load'. "
                       "Verifier Passer cannot deal with this case.\n";
            exit(0);
        } else {
            cout
                    << "\nCouldn't get valid verifier log through libbpf API 'bpf_object__load'. Verifier Passer cannot deal with this case.\n";
            exit(0);
        }
    }
    int pos = rewrite_filepath_.find_last_of('.');
    string edited_rewrite_filepath = rewrite_filepath_.substr(0, pos) + "_edited" +
                                     rewrite_filepath_.substr(pos, rewrite_filepath_.size() - pos);
    map<string, set<int>> unreverted_blocks;
    for (auto cfg: rewrite_cfgs_) {
        unreverted_blocks[cfg.first] = set<int>();
        for (auto block: cfg.second.getAllNodes()) {
            unreverted_blocks[cfg.first].insert(block.first);
        }
    }
    while (!pass_verifier) {
        auto error_info = get_possible_error_blocks(verifier_log);
        string error_prog_name = error_info.first;
        vector<int> possible_error_blocks = error_info.second;
        int cur_revert_block_pos = 0;
        while (!pass_verifier && cur_revert_block_pos < possible_error_blocks.size()) {
            int block_begin = possible_error_blocks[cur_revert_block_pos];
            int block_end = rewrite_cfgs_[error_prog_name].getNode(block_begin)->getTailIdx();
            string error_sec_name = name_secname_map_[error_prog_name];
            for (int i = block_begin; i < block_end; i++) {
                rewrite_sections_[error_sec_name][i] = origin_sections_[error_sec_name][i];
            }
            unreverted_blocks[error_prog_name].erase(block_begin);
            cout << "Section \'" << error_sec_name << "\': " << block_begin << "-" << block_end - 1 << " reverted."
                 << endl;
            patcher.update_sections_to_new_file(rewrite_sections_, edited_rewrite_filepath);
            pass_verifier = (load_bpf_object(edited_rewrite_filepath, prog_type_vec_, verifier_log) == 0);
            cur_revert_block_pos++;
        }
        bool all_empty = true;
        for (auto it: unreverted_blocks) {
            if (!it.second.empty()) {
                all_empty = false;
                break;
            }
        }
        if (all_empty)
            break;
    }
    if (pass_verifier) {
        cout << "\n---\nEdited version can pass verifier now!" << endl;
        cout << "Edited result has written to file \'" << edited_rewrite_filepath << "\'" << endl;
    } else {
        cout << "\n---\nEdited version still cannot pass verifier now!" << endl;
        cout << "Verifier Passer cannot deal with this case." << endl;
    }
}

pair<string, vector<int>>
VerifierPasser::get_possible_error_blocks(const char *verifier_log) {
    char *log_copy = new char[LOG_SIZE];
    strcpy(log_copy, verifier_log);
    vector<string> log_lines;
    const char *split = "\n";
    char *temp = strtok(log_copy, split);
    while (temp != NULL) {
        log_lines.emplace_back(string(temp));
        temp = strtok(NULL, split);
    }
    delete[] log_copy;

    string error_prog_name;
    vector<int> possible_error_blocks;
    for (const auto &it: rewrite_cfgs_) {
        string name = it.first;
        if (log_lines[0].find(name) != log_lines[0].npos) {
            error_prog_name = name;
            superbpf::CFG cfg = it.second;
//            cfg->print_prog();
            smatch pieces;
            regex insn_regex("([0-9]*): .*");
            int error_insn_id;
            for (auto line: log_lines) {
                if (regex_match(line, pieces, insn_regex)) {
                    error_insn_id = stoi(pieces.str(1));
                }
            }
            set<int> blocks_set;
            queue<int> blocks_queue;
            for (auto it: cfg.getAllNodes()) {
                int block_start = it.second->getHeadIdx();
                int block_end = it.second->getTailIdx();
                if (block_start <= error_insn_id && error_insn_id < block_end) {
                    blocks_queue.push(block_start);
                }
            }
            while (!blocks_queue.empty()) {
                int cur_block = blocks_queue.front();
                if (blocks_set.find(cur_block) == blocks_set.end()) {
                    blocks_set.insert(cur_block);
                    possible_error_blocks.emplace_back(cur_block);
                }
                blocks_queue.pop();
                for (auto block: cfg.getNodeParent(cur_block)) {
                    if (blocks_set.find(block) == blocks_set.end()) {
                        blocks_queue.push(block);
                    }
                }
            }
        }
    }
    return make_pair(error_prog_name, possible_error_blocks);
}
