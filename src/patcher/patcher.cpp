#include "patcher/patcher.h"
#include "src/instruction/insn_simulator.h"
#include "src/instruction/insn_sym_simulator.h"
#include <fstream>
#include <elf.h>
#include <libelf.h>
#include <gelf.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "patcher.h"

using namespace std;
using namespace superbpf;

namespace superbpf {
    Patcher::Patcher(const std::string &path) : elf_name_(path) {
        obj_ = (bpf_object *) bpf_object__open(elf_name_.c_str());
        if (libbpf_get_error(obj_)) {
            printf("ERROR: libbpf could not open file %s\n", elf_name_.c_str());
            exit(1);
        }
        // get elf object file endian information
        Elf64_Ehdr elf_header;
        std::ifstream elf_file_in(elf_name_, std::ios::in | std::ios::binary);
        elf_file_in.read((char *) &elf_header, sizeof(elf_header));
        if (memcmp(elf_header.e_ident, ELFMAG, SELFMAG) != 0) {
            printf("ERROR: %s is not an ELF file\n", elf_name_.c_str());
            exit(1);
        }
        unsigned char host_endian = elf_header.e_ident[EI_DATA];
        // printf("host endian: %d\n", host_endian);
        InsnSimulator::set_host_endian(host_endian);
        InsnSymSimulator::set_host_endian(host_endian);
        elf_file_in.close();

        // get reloc of .btf.ext info
        process_reloc_btf_ext();

        for (int i = 0; i < obj_->nr_programs; i++) {
            bpf_program_descs_.push_back(BpfProgramDesc((bpf_program *) obj_->programs + i, btf_ext_reloc_table_));
        }
        for (int i = 0; i < obj_->nr_maps; i++) {
            bpf_map_descs_.push_back(BpfMapDesc((bpf_map *) obj_->maps + i));
        }
    }

    Patcher::~Patcher() {
        bpf_object__close((::bpf_object *) obj_);
    }

    std::vector<BpfProgramDesc> Patcher::get_bpf_programs() {
        return bpf_program_descs_;
    }

    std::vector<BpfMapDesc> Patcher::get_bpf_maps() {
        return bpf_map_descs_;
    }

    void Patcher::update_sections_to_new_file(std::map<std::string, std::vector<Insn>> &section_to_insns_map,
                                              const std::string output_file) {
        system(("cp " + elf_name_ + " " + elf_name_ + ".tmp").c_str());
        int count = 0;
        for (std::map<std::string, std::vector<Insn>>::iterator it = section_to_insns_map.begin();
             it != section_to_insns_map.end(); it++) {
            std::vector<struct bpf_insn> bpf_insns;
            for (Insn next_insn: it->second) {
                struct bpf_insn next_bpf_insn;
                next_bpf_insn.code = next_insn._opcode;
                next_bpf_insn.src_reg = next_insn._src_reg;
                next_bpf_insn.dst_reg = next_insn._dst_reg;
                next_bpf_insn.off = next_insn._off;
                next_bpf_insn.imm = next_insn._imm;
                bpf_insns.push_back(next_bpf_insn);

                /* code below should be commented if Insn::imm64_ field is unused */
                // if (is_imm64_exist(next_insn)) {
                //     struct bpf_insn next_bpf_insn_imm64;
                //     next_bpf_insn_imm64 = *(struct bpf_insn *) &(next_insn._imm64);
                //     next_bpf_insn_imm64.code = 0x0;
                //     next_bpf_insn_imm64.src_reg = 0x0;
                //     next_bpf_insn_imm64.dst_reg = 0x0;
                //     next_bpf_insn_imm64.off = 0x0;
                //     bpf_insns.push_back(next_bpf_insn_imm64);
                // }
            }

            print_bpf_insns_bytes_to(bpf_insns, std::string("insns.") + std::to_string(count) + ".tmp");
            std::string comm =
                    "llvm-objcopy --update-section " + it->first + "=" + "insns." + std::to_string(count) + ".tmp" + " "
                    + elf_name_ + ".tmp " + elf_name_ + ".tmp.out";
            // cout << "\ncomm: " << comm << endl;
            system(comm.c_str());
            system(("rm " + elf_name_ + ".tmp").c_str());
            system(("mv " + elf_name_ + ".tmp.out " + elf_name_ + ".tmp").c_str());
            count++;
        }

        system(("mv " + elf_name_ + ".tmp " + output_file).c_str());

        for (int i = 0; i < count; i++) {
            system((std::string("rm ") + ("insns.") + std::to_string(i) + ".tmp").c_str());
        }

        recover_some_elf_data(elf_name_, output_file);
    }

    void Patcher::recover_some_elf_data(const std::string file_original, const std::string file_rewrite) {
        // Open the ELF file.
        int elf_original_fd = open(file_original.c_str(), O_RDONLY);
        if (elf_original_fd < 0) {
            perror("open ELF");
            exit(1);
        }

        // Initialize libelf.
        if (elf_version(EV_CURRENT) == EV_NONE) {
            fprintf(stderr, "libelf initialization failed: %s\n", elf_errmsg(-1));
            close(elf_original_fd);
            exit(1);
        }

        // Open an ELF descriptor for the ELF file.
        Elf *elf_original = elf_begin(elf_original_fd, ELF_C_READ, NULL);
        if (!elf_original) {
            fprintf(stderr, "Failed to open ELF file: %s\n", elf_errmsg(-1));
            close(elf_original_fd);
            exit(1);
        }

        // Get the ELF header.
        GElf_Ehdr ehdr;
        if (!gelf_getehdr(elf_original, &ehdr)) {
            fprintf(stderr, "Failed to get ELF header: %s\n", elf_errmsg(-1));
            elf_end(elf_original);
            close(elf_original_fd);
            exit(1);
        }

        // Read information from the ELF header.
        Elf64_Off start_of_section_headers = ehdr.e_shoff;
        Elf64_Xword size_of_section_headers = ehdr.e_shentsize;
        Elf64_Half number_of_section_headers = ehdr.e_shnum;

        // // Print the information.
        // cout << "Start of section headers: " << (long long)start_of_section_headers << endl;
        // cout << "Size of section headers: " << (long long)size_of_section_headers << endl;
        // cout << "Number of section headers: " << number_of_section_headers << endl;

        // Locate the symbol table section.
        Elf_Scn *scn = NULL;
        Elf_Scn *symtab_section = NULL;
        size_t symtab_size = 0;
        Elf64_Off symtab_offset = 0;

        while ((scn = elf_nextscn(elf_original, scn)) != NULL) {
            GElf_Shdr shdr;
            if (!gelf_getshdr(scn, &shdr)) {
                fprintf(stderr, "Failed to get section header: %s\n", elf_errmsg(-1));
                elf_end(elf_original);
                close(elf_original_fd);
                exit(1);
            }

            if (shdr.sh_type == SHT_SYMTAB) {
                symtab_section = scn;
                symtab_size = shdr.sh_size;
                symtab_offset = shdr.sh_offset;
                break;
            }
        }

        if (!symtab_section) {
            fprintf(stderr, "Symbol table not found in the ELF file.\n");
            elf_end(elf_original);
            close(elf_original_fd);
            exit(1);
        }

        // // Print the start offset and size of the symbol table.
        // printf("Start offset of symbol table: 0x%llx\n", (long long)symtab_offset);
        // printf("Size of symbol table: 0x%llx\n", (long long)symtab_size);

        // Clean up.
        elf_end(elf_original);
        close(elf_original_fd);

        long data_shdr_start = ehdr.e_shoff;
        size_t data_shdr_size = ehdr.e_shentsize * ehdr.e_shnum;

        long data_symtab_start = symtab_offset;
        size_t data_symtab_size = symtab_size;

        FILE *fp_original = fopen(file_original.c_str(), "rb"); // Open the file in binary read mode
        if (fp_original == NULL) {
            perror("Failed to open file");
            exit(1);
        }

        // read shdr data

        // Seek to the specified offset
        if (fseek(fp_original, data_shdr_start, SEEK_SET) != 0) {
            perror("Failed to seek in the file");
            fclose(fp_original);
            exit(1);
        }

        // Allocate memory to store the data
        unsigned char *original_shdr_data = (unsigned char *) malloc(data_shdr_size);
        if (original_shdr_data == NULL) {
            perror("Failed to allocate memory for data");
            fclose(fp_original);
            exit(1);
        }

        // Read the data from the file
        size_t bytes_read = fread(original_shdr_data, 1, data_shdr_size, fp_original);
        if (bytes_read != data_shdr_size) {
            perror("Failed to read data from the file");
            free(original_shdr_data);
            fclose(fp_original);
            exit(1);
        }

        // read symtab data

        // Seek to the specified offset
        if (fseek(fp_original, data_symtab_start, SEEK_SET) != 0) {
            perror("Failed to seek in the file");
            fclose(fp_original);
            exit(1);
        }

        // Allocate memory to store the data
        unsigned char *original_symtab_data = (unsigned char *) malloc(data_symtab_size);
        if (original_symtab_data == NULL) {
            perror("Failed to allocate memory for data");
            fclose(fp_original);
            exit(1);
        }

        // Read the data from the file
        bytes_read = fread(original_symtab_data, 1, data_symtab_size, fp_original);
        if (bytes_read != data_symtab_size) {
            perror("Failed to read data from the file");
            free(original_symtab_data);
            fclose(fp_original);
            exit(1);
        }

        // Close the file
        fclose(fp_original);

        // Create or open the file in binary read-write mode
        FILE *fp_rewrite = fopen(file_rewrite.c_str(), "r+b");
        if (fp_rewrite == NULL) {
            perror("Failed to open file");
            exit(1);
        }

        // write shdr

        // Seek to the specified offset
        if (fseek(fp_rewrite, data_shdr_start, SEEK_SET) != 0) {
            perror("Failed to seek in the file");
            fclose(fp_rewrite);
            exit(1);
        }

        // Write the new data to the file
        size_t bytes_written = fwrite(original_shdr_data, 1, data_shdr_size, fp_rewrite);
        if (bytes_written != data_shdr_size) {
            perror("Failed to write data to the file");
            free(original_shdr_data);
            fclose(fp_rewrite);
            exit(1);
        }

        // write symtab

        // Seek to the specified offset
        if (fseek(fp_rewrite, data_symtab_start, SEEK_SET) != 0) {
            perror("Failed to seek in the file");
            fclose(fp_rewrite);
            exit(1);
        }

        // Write the new data to the file
        bytes_written = fwrite(original_symtab_data, 1, data_symtab_size, fp_rewrite);
        if (bytes_written != data_symtab_size) {
            perror("Failed to write data to the file");
            free(original_symtab_data);
            fclose(fp_rewrite);
            exit(1);
        }

        // Clean
        fclose(fp_rewrite);
        free(original_shdr_data);
        free(original_symtab_data);
    }

    void Patcher::print_bpf_insns_bytes_to(std::vector<struct bpf_insn> bpf_insns, std::string filename) {
        std::ofstream file_output(filename, std::ios::out | std::ios::binary);
        for (struct bpf_insn next_bpf_insn: bpf_insns) {
            __u8 *bv = (__u8 *) &next_bpf_insn;
            for (int i = 0; i < 8; i++) {
                file_output.write((char *) (bv + i), 1);
            }
        }
        file_output.close();
    }

    bool Patcher::is_imm64_exist(Insn insn) {
        if ((BPF_CLASS(insn._opcode) <= 0x3) && (BPF_MODE(insn._opcode) == BPF_IMM)) {
            return true;
        } else {
            return false;
        }
    }

    // copied and modified from libbpf.c
    void Patcher::process_reloc_btf_ext() {
        const struct btf_ext_info *seg;
        const struct btf_ext_info_sec *sec;
        const struct bpf_core_relo *rec;
        struct bpf_program *prog;
        int i;

        seg = &(obj_->btf_ext->core_relo_info);
        int sec_num = 0;
        for (sec = (btf_ext_info_sec *) (seg)->info;
             (void *) sec < (char *) ((seg)->info) + (seg)->len;
             sec = (btf_ext_info_sec *) ((char *) sec + sizeof(struct btf_ext_info_sec) +
                                         (seg)->rec_size * sec->num_info)) {
            int sec_idx = seg->sec_idxs[sec_num];
            sec_num++;
            for (i = 0, rec = (bpf_core_relo *) ((void *) &(sec)->data);
                 i < (sec)->num_info;
                 i++, rec = (bpf_core_relo *) ((char *) rec + (seg)->rec_size)) {
                int insn_idx = rec->insn_off / 8;
                prog = find_prog_by_sec_insn(obj_, sec_idx, insn_idx);
                btf_ext_reloc_table_[prog].insert(insn_idx);
                // cout << "reloc .btf.ext: " << "prog: " << prog << " insn idx: " << insn_idx << endl;
            }
        }

        // for(auto prog_reloc_info : btf_ext_reloc_table_) {
        //     auto prog_i = prog_reloc_info.first;
        //     for(auto insn_i : prog_reloc_info.second) {
        //         cout << "reloc .btf.ext: " << "prog: " << prog_i << " insn idx: " << insn_i << endl;
        //     }
        // }
    }

    // copied and modified from libbpf.c
    struct bpf_program *Patcher::find_prog_by_sec_insn(const struct bpf_object *obj,
                                                       size_t sec_idx, size_t insn_idx) {
        int l = 0, r = obj->nr_programs - 1, m;
        struct bpf_program *prog;

        if (!obj->nr_programs)
            return NULL;

        while (l < r) {
            m = l + (r - l + 1) / 2;
            prog = &((bpf_program *) (obj->programs))[m];

            if (prog->sec_idx < sec_idx ||
                (prog->sec_idx == sec_idx && prog->sec_insn_off <= insn_idx))
                l = m;
            else
                r = m - 1;
        }
        /* matching program could be at index l, but it still might be the
        * wrong one, so we need to double check conditions for the last time
        */
        prog = &((bpf_program *) (obj->programs))[l];
        if (prog->sec_idx == sec_idx && prog_contains_insn(prog, insn_idx))
            return prog;
        return NULL;
    }

    // copied from libbpf.c
    bool Patcher::prog_contains_insn(const struct bpf_program *prog, size_t insn_idx) {
        return insn_idx >= prog->sec_insn_off &&
               insn_idx < prog->sec_insn_off + prog->sec_insn_cnt;
    }


    BpfProgramDesc::BpfProgramDesc(const struct bpf_program *ptr_prog,
                                   const std::map<void *, std::set<int>> &btf_ext_reloc_table)
            : ptr_prog_(ptr_prog), btf_ext_reloc_table_(btf_ext_reloc_table) {
        type_ = ptr_prog_->type;
        attach_type_=ptr_prog_->expected_attach_type;
        bpf_insns_ = ptr_prog_->insns;
        bpf_insns_cnt_ = ptr_prog_->insns_cnt;
        // std::cout <<bpf_insns_cnt_ << std::endl;
        // std::cout << "prog: " << ptr_prog_->sec_name << " ptr: " << ptr_prog_ << std::endl;

        gen_insns();
        gen_relocs();
    }

    std::string BpfProgramDesc::get_sec_name() {
        return ptr_prog_->sec_name;
    }

    std::string BpfProgramDesc::get_name() {
        return ptr_prog_->name;
    }

    enum bpf_prog_type BpfProgramDesc::get_type() {
        return type_;
    }

    enum bpf_attach_type BpfProgramDesc::get_attach_type(){
        return attach_type_;
    }

    std::vector<Insn> BpfProgramDesc::get_insns() {
        return insns_;
    }

    void BpfProgramDesc::gen_insns() {
        for (int i = 0; i < bpf_insns_cnt_; i++) {
            insns_.push_back(Insn((unsigned int) (bpf_insns_[i].code), (unsigned int) (bpf_insns_[i].src_reg),
                                  (unsigned int) (bpf_insns_[i].dst_reg), bpf_insns_[i].off, bpf_insns_[i].imm));
            insns_.back()._is_reloc = 0;

            /* code below should be commented if Insn::imm64_ field is unused */
            // if ((BPF_CLASS(bpf_insns_[i].code) <= 0x03) && (BPF_MODE(bpf_insns_[i].code) == BPF_IMM)) {
            //     insns_.back()._imm64 = (uint64_t) (bpf_insns_[i + 1].imm) << 32 | (uint64_t) (bpf_insns_[i].imm);
            //     i++;
            // }

            // std::cout << "instruction " << i << " : ";
            // _insns.back().print();
            // std::cout << "\n";
        }
    }

    void BpfProgramDesc::gen_relocs() {
        // this implementation only valid when Insn::_imm64 is unused.
        for (int i = 0; i < ptr_prog_->nr_reloc; i++) {
            insns_[ptr_prog_->reloc_desc[i].insn_idx]._is_reloc = 1;
            insns_[ptr_prog_->reloc_desc[i].insn_idx]._reloc_map_idx = ptr_prog_->reloc_desc[i].map_idx;
            insns_[ptr_prog_->reloc_desc[i].insn_idx]._reloc_type = ptr_prog_->reloc_desc[i].type;
            // std::cout << "rel:insn_idx: " << ptr_prog_->reloc_desc[i].insn_idx << " ";
            // std::cout << "rel:map_idx: "<< ptr_prog_->reloc_desc[i].map_idx << " ";
            // std::cout << "rel:type: " << ptr_prog_->reloc_desc[i].type << " ";
            // std::cout << std::endl;
        }

        // process btf.ext reloc
        if (btf_ext_reloc_table_.find((void *) ptr_prog_) != btf_ext_reloc_table_.end()) {
            for (int insn_idx: btf_ext_reloc_table_.find((void *) ptr_prog_)->second) {
                insns_[insn_idx]._is_core_reloc = 1;
            }
        }
    }

    BpfMapDesc::BpfMapDesc(const struct bpf_map *ptr_map) : ptr_map_(ptr_map) {
        name_ = ptr_map_->name;
        type_ = ptr_map_->def.type;
        key_size_ = ptr_map_->def.key_size;
        value_size_ = ptr_map_->def.value_size;
        max_entries_ = ptr_map_->def.max_entries;
    }

    std::string BpfMapDesc::get_name() {
        return name_;
    }

    unsigned int BpfMapDesc::get_type() {
        return type_;
    }

    unsigned int BpfMapDesc::get_key_size() {
        return key_size_;
    }

    unsigned int BpfMapDesc::get_value_size() {
        return value_size_;
    }

    unsigned int BpfMapDesc::get_max_entries() {
        return max_entries_;
    }
}
