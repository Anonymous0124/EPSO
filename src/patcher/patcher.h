#ifndef SUPERBPF_PATCHER_PATCHER_H
#define SUPERBPF_PATCHER_PATCHER_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <bpf/libbpf.h>
#include "instruction/insn.h"

namespace superbpf {
// TODO: 这个类应该可以用一个文件路径来进行构造
// 然后根据不同的section给出相应的指令序列。
// 我们用某种方法替换指令序列之后，
// patcher可以将其还原为.o ELF文件

// 现在我们仅让它可以读取成型的insn文件
// 当然后续如果实在不行，也可以通过外部脚本处理好insn文件，然后交给patcher进行处理

// copied from libbpf_internal.h
#define for_each_btf_ext_sec(seg, sec)                    \
    for (sec = (seg)->info;                        \
         (void *)sec < (seg)->info + (seg)->len;            \
         sec = (void *)sec + sizeof(struct btf_ext_info_sec) +    \
           (seg)->rec_size * sec->num_info)

// copied from libbpf_internal.h
#define for_each_btf_ext_rec(seg, sec, i, rec)                \
    for (i = 0, rec = (void *)&(sec)->data;                \
         i < (sec)->num_info;                    \
         i++, rec = (void *)rec + (seg)->rec_size)


// copied from libbpf.c and do some changes
    struct elf_state {
        int fd;
        const void *obj_buf;
        size_t obj_buf_sz;
        // Elf *elf;
        // Elf64_Ehdr *ehdr;
        // Elf_Data *symbols;
        // Elf_Data *st_ops_data;
        // Elf_Data *st_ops_link_data;
        void *placeholder_1;
        void *placeholder_2;
        void *placeholder_3;
        void *placeholder_4;
        void *placeholder_5;
        size_t shstrndx; /* section index for section name strings */
        size_t strtabidx;
        struct elf_sec_desc *secs;
        size_t sec_cnt;
        int btf_maps_shndx;
        __u32 btf_maps_sec_btf_id;
        int text_shndx;
        int symbols_shndx;
        int st_ops_shndx;
        int st_ops_link_shndx;
    };

// copied from libbpf_internal.h
    struct btf_ext_header {
        __u16 magic;
        __u8 version;
        __u8 flags;
        __u32 hdr_len;

        /* All offsets are in bytes relative to the end of this header */
        __u32 func_info_off;
        __u32 func_info_len;
        __u32 line_info_off;
        __u32 line_info_len;

        /* optional part of .BTF.ext header */
        __u32 core_relo_off;
        __u32 core_relo_len;
    };

// copied from libbpf_internal.h
    struct btf_ext_info {
        /*
         * info points to the individual info section (e.g. func_info and
         * line_info) from the .BTF.ext. It does not include the __u32 rec_size.
         */
        void *info;
        __u32 rec_size;
        __u32 len;
        /* optional (maintained internally by libbpf) mapping between .BTF.ext
         * section and corresponding ELF section. This is used to join
         * information like CO-RE relocation records with corresponding BPF
         * programs defined in ELF sections
         */
        __u32 *sec_idxs;
        int sec_cnt;
    };

// copied from libbpf_internal.h
    struct btf_ext_info_sec {
        __u32 sec_name_off;
        __u32 num_info;
        /* Followed by num_info * record_size number of bytes */
        __u8 data[];
    };

// copied from libbpf_internal.h
    struct btf_ext {
        union {
            struct btf_ext_header *hdr;
            void *data;
        };
        struct btf_ext_info func_info;
        struct btf_ext_info line_info;
        struct btf_ext_info core_relo_info;
        __u32 data_size;
    };

// copied from libbpf.c and do some changes
    struct bpf_object {
        char name[BPF_OBJ_NAME_LEN];
        char license[64];
        __u32 kern_version;

        struct bpf_program *programs;
        size_t nr_programs;
        struct bpf_map *maps;
        size_t nr_maps;
        size_t maps_cap;

        char *kconfig;
        struct extern_desc *externs;
        int nr_extern;
        int kconfig_map_idx;

        bool loaded;
        bool has_subcalls;
        bool has_rodata;

        struct bpf_gen *gen_loader;

        /* Information when doing ELF related work. Only valid if efile.elf is not NULL */
        struct elf_state efile;

        struct btf *btf;
        struct btf_ext *btf_ext;

        /* Parse and load BTF vmlinux if any of the programs in the object need
         * it at load time.
         */
        struct btf *btf_vmlinux;
        /* Path to the custom BTF to be used for BPF CO-RE relocations as an
         * override for vmlinux BTF.
         */
        char *btf_custom_path;
        /* vmlinux BTF override for CO-RE relocations */
        struct btf *btf_vmlinux_override;
        /* Lazily initialized kernel module BTFs */
        struct module_btf *btf_modules;
        bool btf_modules_loaded;
        size_t btf_module_cnt;
        size_t btf_module_cap;

        /* optional log settings passed to BPF_BTF_LOAD and BPF_PROG_LOAD commands */
        char *log_buf;
        size_t log_size;
        __u32 log_level;

        int *fd_array;
        size_t fd_array_cap;
        size_t fd_array_cnt;

        struct usdt_manager *usdt_man;

        char path[];
    };

// copied from libbpf.c
    enum reloc_type {
        RELO_LD64,
        RELO_CALL,
        RELO_DATA,
        RELO_EXTERN_LD64,
        RELO_EXTERN_CALL,
        RELO_SUBPROG_ADDR,
        RELO_CORE,
    };

// copied from doc
    enum bpf_core_relo_kind {
        BPF_CORE_FIELD_BYTE_OFFSET = 0,  /* field byte offset */
        BPF_CORE_FIELD_BYTE_SIZE = 1,  /* field size in bytes */
        BPF_CORE_FIELD_EXISTS = 2,  /* field existence in target kernel */
        BPF_CORE_FIELD_SIGNED = 3,  /* field signedness (0 - unsigned, 1 - signed) */
        BPF_CORE_FIELD_LSHIFT_U64 = 4,  /* bitfield-specific left bitshift */
        BPF_CORE_FIELD_RSHIFT_U64 = 5,  /* bitfield-specific right bitshift */
        BPF_CORE_TYPE_ID_LOCAL = 6,  /* type ID in local BPF object */
        BPF_CORE_TYPE_ID_TARGET = 7,  /* type ID in target kernel */
        BPF_CORE_TYPE_EXISTS = 8,  /* type existence in target kernel */
        BPF_CORE_TYPE_SIZE = 9,  /* type size in bytes */
        BPF_CORE_ENUMVAL_EXISTS = 10, /* enum value existence in target kernel */
        BPF_CORE_ENUMVAL_VALUE = 11, /* enum value integer value */
        BPF_CORE_TYPE_MATCHES = 12, /* type match in target kernel */
    };

// copied from doc
    struct bpf_core_relo {
        __u32 insn_off;
        __u32 type_id;
        __u32 access_str_off;
        enum bpf_core_relo_kind kind;
    };

// copied from libbpf.c
    struct reloc_desc {
        enum reloc_type type;
        int insn_idx;
        union {
            const struct bpf_core_relo *core_relo; /* used when type == RELO_CORE */
            struct {
                int map_idx;
                int sym_off;
                int ext_idx;
            };
        };
    };

// copied from libbpf.c and do some changes
    struct bpf_program {
        char *name;
        char *sec_name;
        size_t sec_idx;
        const struct bpf_sec_def *sec_def;
        /* this program's instruction offset (in number of instructions)
         * within its containing ELF section
         */
        size_t sec_insn_off;
        /* number of original instructions in ELF section belonging to this
         * program, not taking into account subprogram instructions possible
         * appended later during relocation
         */
        size_t sec_insn_cnt;
        /* Offset (in number of instructions) of the start of instruction
         * belonging to this BPF program  within its containing main BPF
         * program. For the entry-point (main) BPF program, this is always
         * zero. For a sub-program, this gets reset before each of main BPF
         * programs are processed and relocated and is used to determined
         * whether sub-program was already appended to the main program, and
         * if yes, at which instruction offset.
         */
        size_t sub_insn_off;

        /* instructions that belong to BPF program; insns[0] is located at
         * sec_insn_off instruction within its ELF section in ELF file, so
         * when mapping ELF file instruction index to the local instruction,
         * one needs to subtract sec_insn_off; and vice versa.
         */
        struct bpf_insn *insns;
        /* actual number of instruction in this BPF program's image; for
         * entry-point BPF programs this includes the size of main program
         * itself plus all the used sub-programs, appended at the end
         */
        size_t insns_cnt;

        struct reloc_desc *reloc_desc;
        int nr_reloc;

        /* BPF verifier log settings */
        char *log_buf;
        size_t log_size;
        __u32 log_level;

        struct bpf_object *obj;

        int fd;
        bool autoload;
        bool autoattach;
        bool mark_btf_static;
        enum bpf_prog_type type;
        enum bpf_attach_type expected_attach_type;

        int prog_ifindex;
        __u32 attach_btf_obj_fd;
        __u32 attach_btf_id;
        __u32 attach_prog_fd;

        void *func_info;
        __u32 func_info_rec_size;
        __u32 func_info_cnt;

        void *line_info;
        __u32 line_info_rec_size;
        __u32 line_info_cnt;
        __u32 prog_flags;
    };

// copied from libbpf.c
    struct bpf_map_def {
        unsigned int type;
        unsigned int key_size;
        unsigned int value_size;
        unsigned int max_entries;
        unsigned int map_flags;
    };

// copied from libbpf.c
    enum libbpf_map_type {
        LIBBPF_MAP_UNSPEC,
        LIBBPF_MAP_DATA,
        LIBBPF_MAP_BSS,
        LIBBPF_MAP_RODATA,
        LIBBPF_MAP_KCONFIG,
    };

// copied from libbpf.c and do some changes
    struct bpf_map {
        struct bpf_object *obj;
        char *name;
        /* real_name is defined for special internal maps (.rodata*,
         * .data*, .bss, .kconfig) and preserves their original ELF section
         * name. This is important to be able to find corresponding BTF
         * DATASEC information.
         */
        char *real_name;
        int fd;
        int sec_idx;
        size_t sec_offset;
        int map_ifindex;
        int inner_map_fd;
        struct bpf_map_def def;
        __u32 numa_node;
        __u32 btf_var_idx;
        __u32 btf_key_type_id;
        __u32 btf_value_type_id;
        __u32 btf_vmlinux_value_type_id;
        enum libbpf_map_type libbpf_type;
        void *mmaped;
        struct bpf_struct_ops *st_ops;
        struct bpf_map *inner_map;
        void **init_slots;
        int init_slots_sz;
        char *pin_path;
        bool pinned;
        bool reused;
        bool autocreate;
        __u64 map_extra;
    };


    class BpfProgramDesc {
    private:
        const struct bpf_program *ptr_prog_;
        enum bpf_prog_type type_;
        enum bpf_attach_type attach_type_;
        const struct bpf_insn *bpf_insns_;
        size_t bpf_insns_cnt_;
        std::vector<Insn> insns_;
        const std::map<void *, std::set<int>> btf_ext_reloc_table_;

    public:
        BpfProgramDesc(const struct bpf_program *ptr_prog, const std::map<void *, std::set<int>> &btf_ext_reloc_table);

        std::string get_name();
        std::string get_sec_name();

        enum bpf_prog_type get_type();

        enum bpf_attach_type get_attach_type();

        std::vector<Insn> get_insns();

    private:
        void gen_insns();

        void gen_relocs();
    };

    class BpfMapDesc {
    private:
        const struct bpf_map *ptr_map_;
        std::string name_;
        unsigned int type_;
        unsigned int key_size_;
        unsigned int value_size_;
        unsigned int max_entries_;

    public:
        BpfMapDesc(const struct bpf_map *ptr_map);

        std::string get_name();

        unsigned int get_type();

        /* size of key in bytes */
        unsigned int get_key_size();

        /* size of value in bytes */
        unsigned int get_value_size();

        unsigned int get_max_entries();
    };

    class Patcher {
    private:
        std::string elf_name_;
        struct bpf_object *obj_;
        std::vector<BpfProgramDesc> bpf_program_descs_;
        std::vector<BpfMapDesc> bpf_map_descs_;
        std::map<void *, std::set<int>> btf_ext_reloc_table_;

    public:
        Patcher(const std::string &path);

        ~Patcher();

        std::vector<BpfProgramDesc> get_bpf_programs();

        std::vector<BpfMapDesc> get_bpf_maps();

        void update_sections_to_new_file(std::map<std::string, std::vector<Insn>> &section_to_insns_map,
                                         const std::string output_file);

    private:
        void recover_some_elf_data(const std::string file_original, const std::string file_rewrite);

        void print_bpf_insns_bytes_to(std::vector<struct bpf_insn> bpf_insns, std::string filename);

        bool is_imm64_exist(Insn insn);

        void process_reloc_btf_ext();

        struct bpf_program *find_prog_by_sec_insn(const struct bpf_object *obj, size_t sec_idx, size_t insn_idx);

        bool prog_contains_insn(const struct bpf_program *prog, size_t insn_idx);
    };
}


#endif //SUPERBPF_PATCHER_H
