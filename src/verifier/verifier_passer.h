#ifndef SUPERBPF_VERIFIER_PASSER_H
#define SUPERBPF_VERIFIER_PASSER_H

#include <bpf/libbpf.h>
#include <string>

#include "src/cfg/cfg.h"
#include "src/instruction/insn.h"

/*
 * Verifier Passer
 */
class VerifierPasser{
    std::string origin_filepath_;
    std::string rewrite_filepath_;
    std::vector<bpf_prog_type> prog_type_vec_;
    std::map<std::string,std::string> name_secname_map_;  // <name, section name>
    std::map<std::string,superbpf::CFG> rewrite_cfgs_;  // <prog name, cfg>
    std::map<std::string,std::vector<superbpf::Insn>> origin_sections_;  // <section name, insns>
    std::map<std::string,std::vector<superbpf::Insn>> rewrite_sections_;  // <section name, insns>

    bpf_prog_type str2progtype(std::string prog_type_str);

    void read_object_files();

    std::pair<std::string,std::vector<int>> get_possible_error_blocks(const char* verifier_log);
public:
    VerifierPasser(std::string origin_filepath,std::string rewrite_filepath,std::vector<std::string> progtype_str_vec){
        origin_filepath_=origin_filepath;
        rewrite_filepath_=rewrite_filepath;
        for(int i = 0; i < progtype_str_vec.size(); i++) {
            prog_type_vec_.push_back(str2progtype(progtype_str_vec[i]));
        }
        read_object_files();
    }

    int load_bpf_object(std::string filename,std::vector<bpf_prog_type> prog_type_vec,char* verifier_log= nullptr);

    void pass_verifier();
};

#endif //SUPERBPF_VERIFIER_PASSER_H
