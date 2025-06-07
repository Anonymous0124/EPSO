#ifndef SUPERBPF_INSTRUCTION_INSN_H
#define SUPERBPF_INSTRUCTION_INSN_H

#include <iostream>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "z3++.h"

#include "src/ebpf/bpf.h"

namespace superbpf {
    // Opcode types for instructions
    enum OPCODE_TYPES {
        OP_NOP = 0,
        OP_RET,
        OP_UNCOND_JMP,
        OP_COND_JMP,
        OP_ALU_OR_LDDW,
        OP_ST,
        OP_LD,
        OP_CALL,
    };

    enum OPCODE_IDX {
        IDX_NOP = 0,
        // ALU64
        IDX_ADD64XC,
        IDX_ADD64XY,
        IDX_SUB64XY,
        IDX_MUL64XC,
        IDX_DIV64XC,
        IDX_OR64XC,
        IDX_OR64XY,
        IDX_AND64XC,
        IDX_AND64XY,
        IDX_LSH64XC,
        IDX_LSH64XY,
        IDX_RSH64XC,
        IDX_RSH64XY,
        IDX_NEG64XC,
        IDX_XOR64XC,
        IDX_XOR64XY,
        IDX_MOV64XC,
        IDX_MOV64XY,
        IDX_ARSH64XC,
        IDX_ARSH64XY,
        // ALU32
        IDX_ADD32XC,
        IDX_ADD32XY,
        IDX_OR32XC,
        IDX_OR32XY,
        IDX_AND32XC,
        IDX_AND32XY,
        IDX_LSH32XC,
        IDX_LSH32XY,
        IDX_RSH32XC,
        IDX_RSH32XY,
        IDX_MOV32XC,
        IDX_MOV32XY,
        IDX_ARSH32XC,
        IDX_ARSH32XY,
        // Byteswap
        IDX_LE,
        IDX_BE,
        // LDDW: ldmapid/movdwxc
        IDX_LDDW,
        // SymMemory
        IDX_LDXB,
        IDX_STXB,
        IDX_LDXH,
        IDX_STXH,
        IDX_LDXW,
        IDX_STXW,
        IDX_LDXDW,
        IDX_STXDW,
        IDX_STB,
        IDX_STH,
        IDX_STW,
        IDX_STDW,
        IDX_XADD64,
        IDX_XADD32,
        IDX_ATOMIC64,
        IDX_ATOMIC32,
        IDX_LDABSH,
        IDX_LDINDH,
        // JMP
        IDX_JA,
        IDX_JEQXC,
        IDX_JEQXY,
        IDX_JNEXC,
        IDX_JNEXY,
        IDX_JGTXC,
        IDX_JGTXY,
        IDX_JGEXC,
        IDX_JGEXY,
        IDX_JSGTXC,
        IDX_JSGTXY,
        IDX_JSGEXC,
        IDX_JSGEXY,
        IDX_JLTXC,
        IDX_JLTXY,
        IDX_JLEXC,
        IDX_JLEXY,
        IDX_JSLTXC,
        IDX_JSLTXY,
        IDX_JSLEXC,
        IDX_JSLEXY,

        IDX_JEQ32XC,
        IDX_JEQ32XY,
        IDX_JNE32XC,
        IDX_JNE32XY,
        IDX_JGT32XC,
        IDX_JGT32XY,
        IDX_JGE32XC,
        IDX_JGE32XY,
        IDX_JSGT32XC,
        IDX_JSGT32XY,
        IDX_JSGE32XC,
        IDX_JSGE32XY,
        IDX_JLT32XC,
        IDX_JLT32XY,
        IDX_JLE32XC,
        IDX_JLE32XY,
        IDX_JSLT32XC,
        IDX_JSLT32XY,
        IDX_JSLE32XC,
        IDX_JSLE32XY,

        IDX_CALL, // function call
        // Exit
        IDX_EXIT,
        NUM_INSTR, // Number of opcode types
    };

    template<typename T>
    constexpr auto OPCODE_BPF_ALU64_IMM(T OP) { return BPF_ALU64 | BPF_OP(OP) | BPF_K; }

    template<typename T>
    constexpr auto OPCODE_BPF_ALU64_REG(T OP) { return BPF_ALU64 | BPF_OP(OP) | BPF_X; }

    template<typename T>
    constexpr auto OPCODE_BPF_ALU32_IMM(T OP) { return BPF_ALU | BPF_OP(OP) | BPF_K; }

    template<typename T>
    constexpr auto OPCODE_BPF_ALU32_REG(T OP) { return BPF_ALU | BPF_OP(OP) | BPF_X; }

    template<typename T>
    constexpr auto OPCODE_BPF_ENDIAN(T TYPE) { return BPF_ALU | BPF_END | BPF_SRC(TYPE); }

#define OPCODE_BPF_MOV64_IMM BPF_ALU64 | BPF_MOV | BPF_K
#define OPCODE_BPF_MOV64_REG BPF_ALU64 | BPF_MOV | BPF_X
#define OPCODE_BPF_MOV32_IMM BPF_ALU | BPF_MOV | BPF_K
#define OPCODE_BPF_MOV32_REG BPF_ALU | BPF_MOV | BPF_X
#define OPCODE_BPF_LDDW (BPF_LD | BPF_DW | BPF_IMM)

    template<typename T>
    constexpr auto OPCODE_BPF_LDX_MEM(T SIZE) { return BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM; }

    template<typename T>
    constexpr auto OPCODE_BPF_STX_MEM(T SIZE) { return BPF_STX | BPF_SIZE(SIZE) | BPF_MEM; }

    template<typename T>
    constexpr auto OPCODE_BPF_ST_MEM(T SIZE) { return BPF_ST | BPF_SIZE(SIZE) | BPF_MEM; }

    template<typename T>
    constexpr auto OPCODE_BPF_XADD(T SIZE) { return BPF_STX | BPF_XADD | BPF_SIZE(SIZE); }

    template<typename T>
    constexpr auto OPCODE_BPF_ATOMIC(T SIZE) { return BPF_STX | BPF_ATOMIC | BPF_SIZE(SIZE); }

    template<typename T>
    constexpr auto OPCODE_BPF_LDABS(T SIZE) { return BPF_LD | BPF_ABS | BPF_SIZE(SIZE); }

    template<typename T>
    constexpr auto OPCODE_BPF_LDIND(T SIZE) { return BPF_LD | BPF_IND | BPF_SIZE(SIZE); }

    template<typename T>
    constexpr auto OPCODE_BPF_JMP_IMM(T OP) { return BPF_JMP | BPF_OP(OP) | BPF_K; }

    template<typename T>
    constexpr auto OPCODE_BPF_JMP_REG(T OP) { return BPF_JMP | BPF_OP(OP) | BPF_X; }

    template<typename T>
    constexpr auto OPCODE_BPF_JMP32_IMM(T OP) { return BPF_JMP32 | BPF_OP(OP) | BPF_K; }

    template<typename T>
    constexpr auto OPCODE_BPF_JMP32_REG(T OP) { return BPF_JMP32 | BPF_OP(OP) | BPF_X; }

#define OPCODE_BPF_JMP_A BPF_JMP | BPF_JA
#define OPCODE_BPF_FUNC_CALL BPF_JMP | BPF_CALL
#define OPCODE_BPF_EXIT_INSN BPF_JMP | BPF_EXIT

// Insn opcodes
    enum OPCODES {
        NOP = 0,
        ADD64XC = OPCODE_BPF_ALU64_IMM(BPF_ADD),
        ADD64XY = OPCODE_BPF_ALU64_REG(BPF_ADD),
        SUB64XC = OPCODE_BPF_ALU64_IMM(BPF_SUB),
        SUB64XY = OPCODE_BPF_ALU64_REG(BPF_SUB),
        MUL64XC = OPCODE_BPF_ALU64_IMM(BPF_MUL),
        MUL64XY = OPCODE_BPF_ALU64_REG(BPF_MUL),
        DIV64XC = OPCODE_BPF_ALU64_IMM(BPF_DIV),
        DIV64XY = OPCODE_BPF_ALU64_REG(BPF_DIV),
        OR64XC = OPCODE_BPF_ALU64_IMM(BPF_OR),
        OR64XY = OPCODE_BPF_ALU64_REG(BPF_OR),
        AND64XC = OPCODE_BPF_ALU64_IMM(BPF_AND),
        AND64XY = OPCODE_BPF_ALU64_REG(BPF_AND),
        LSH64XC = OPCODE_BPF_ALU64_IMM(BPF_LSH),
        LSH64XY = OPCODE_BPF_ALU64_REG(BPF_LSH),
        RSH64XC = OPCODE_BPF_ALU64_IMM(BPF_RSH),
        RSH64XY = OPCODE_BPF_ALU64_REG(BPF_RSH),
        NEG64XC = OPCODE_BPF_ALU64_IMM(BPF_NEG),
        NEG64XY = OPCODE_BPF_ALU64_REG(BPF_NEG),
        MOD64XC = OPCODE_BPF_ALU64_IMM(BPF_MOD),
        MOD64XY = OPCODE_BPF_ALU64_REG(BPF_MOD),
        XOR64XC = OPCODE_BPF_ALU64_IMM(BPF_XOR),
        XOR64XY = OPCODE_BPF_ALU64_REG(BPF_XOR),
        MOV64XC = OPCODE_BPF_MOV64_IMM,
        MOV64XY = OPCODE_BPF_MOV64_REG,
        ARSH64XC = OPCODE_BPF_ALU64_IMM(BPF_ARSH),
        ARSH64XY = OPCODE_BPF_ALU64_REG(BPF_ARSH),
        ADD32XC = OPCODE_BPF_ALU32_IMM(BPF_ADD),
        ADD32XY = OPCODE_BPF_ALU32_REG(BPF_ADD),
        SUB32XC = OPCODE_BPF_ALU32_IMM(BPF_SUB),
        SUB32XY = OPCODE_BPF_ALU32_REG(BPF_SUB),
        MUL32XC = OPCODE_BPF_ALU32_IMM(BPF_MUL),
        MUL32XY = OPCODE_BPF_ALU32_REG(BPF_MUL),
        DIV32XC = OPCODE_BPF_ALU32_IMM(BPF_DIV),
        DIV32XY = OPCODE_BPF_ALU32_REG(BPF_DIV),
        OR32XC = OPCODE_BPF_ALU32_IMM(BPF_OR),
        OR32XY = OPCODE_BPF_ALU32_REG(BPF_OR),
        AND32XC = OPCODE_BPF_ALU32_IMM(BPF_AND),
        AND32XY = OPCODE_BPF_ALU32_REG(BPF_AND),
        MOD32XC = OPCODE_BPF_ALU32_IMM(BPF_MOD),
        MOD32XY = OPCODE_BPF_ALU32_REG(BPF_MOD),
        NEG32XC = OPCODE_BPF_ALU32_IMM(BPF_NEG),
        NEG32XY = OPCODE_BPF_ALU32_REG(BPF_NEG),
        XOR32XC = OPCODE_BPF_ALU32_IMM(BPF_XOR),
        XOR32XY = OPCODE_BPF_ALU32_REG(BPF_XOR),
        LSH32XC = OPCODE_BPF_ALU32_IMM(BPF_LSH),
        LSH32XY = OPCODE_BPF_ALU32_REG(BPF_LSH),
        RSH32XC = OPCODE_BPF_ALU32_IMM(BPF_RSH),
        RSH32XY = OPCODE_BPF_ALU32_REG(BPF_RSH),
        MOV32XC = OPCODE_BPF_MOV32_IMM,
        MOV32XY = OPCODE_BPF_MOV32_REG,
        ARSH32XC = OPCODE_BPF_ALU32_IMM(BPF_ARSH),
        ARSH32XY = OPCODE_BPF_ALU32_REG(BPF_ARSH),
        LE = OPCODE_BPF_ENDIAN(BPF_TO_LE),
        BE = OPCODE_BPF_ENDIAN(BPF_TO_BE),
        LDDW = OPCODE_BPF_LDDW,
        LDXB = OPCODE_BPF_LDX_MEM(BPF_B),
        STXB = OPCODE_BPF_STX_MEM(BPF_B),
        LDXH = OPCODE_BPF_LDX_MEM(BPF_H),
        STXH = OPCODE_BPF_STX_MEM(BPF_H),
        LDXW = OPCODE_BPF_LDX_MEM(BPF_W),
        STXW = OPCODE_BPF_STX_MEM(BPF_W),
        LDXDW = OPCODE_BPF_LDX_MEM(BPF_DW),
        STXDW = OPCODE_BPF_STX_MEM(BPF_DW),
        STB = OPCODE_BPF_ST_MEM(BPF_B),
        STH = OPCODE_BPF_ST_MEM(BPF_H),
        STW = OPCODE_BPF_ST_MEM(BPF_W),
        STDW = OPCODE_BPF_ST_MEM(BPF_DW),
        XADD64 = OPCODE_BPF_XADD(BPF_DW),
        XADD32 = OPCODE_BPF_XADD(BPF_W),
        ATOMIC64 = OPCODE_BPF_ATOMIC(BPF_DW),
        ATOMIC32 = OPCODE_BPF_ATOMIC(BPF_W),
        LDABSB = OPCODE_BPF_LDABS(BPF_B),
        LDABSH = OPCODE_BPF_LDABS(BPF_H),
        LDABSW = OPCODE_BPF_LDABS(BPF_W),
        LDABSDW = OPCODE_BPF_LDABS(BPF_DW),
        LDINDB = OPCODE_BPF_LDIND(BPF_B),
        LDINDH = OPCODE_BPF_LDIND(BPF_H),
        LDINDW = OPCODE_BPF_LDIND(BPF_W),
        LDINDDW = OPCODE_BPF_LDIND(BPF_DW),
        JA = OPCODE_BPF_JMP_A,
        JEQXC = OPCODE_BPF_JMP_IMM(BPF_JEQ),
        JEQXY = OPCODE_BPF_JMP_REG(BPF_JEQ),
        JNEXC = OPCODE_BPF_JMP_IMM(BPF_JNE),
        JNEXY = OPCODE_BPF_JMP_REG(BPF_JNE),
        JGTXC = OPCODE_BPF_JMP_IMM(BPF_JGT),
        JGTXY = OPCODE_BPF_JMP_REG(BPF_JGT),
        JGEXC = OPCODE_BPF_JMP_IMM(BPF_JGE),
        JGEXY = OPCODE_BPF_JMP_REG(BPF_JGE),
        JSGTXC = OPCODE_BPF_JMP_IMM(BPF_JSGT),
        JSGTXY = OPCODE_BPF_JMP_REG(BPF_JSGT),
        JSGEXC = OPCODE_BPF_JMP_IMM(BPF_JSGE),
        JSGEXY = OPCODE_BPF_JMP_REG(BPF_JSGE),
        JLTXC = OPCODE_BPF_JMP_IMM(BPF_JLT),
        JLTXY = OPCODE_BPF_JMP_REG(BPF_JLT),
        JLEXC = OPCODE_BPF_JMP_IMM(BPF_JLE),
        JLEXY = OPCODE_BPF_JMP_REG(BPF_JLE),
        JSLTXC = OPCODE_BPF_JMP_IMM(BPF_JSLT),
        JSLTXY = OPCODE_BPF_JMP_REG(BPF_JSLT),
        JSLEXC = OPCODE_BPF_JMP_IMM(BPF_JSLE),
        JSLEXY = OPCODE_BPF_JMP_REG(BPF_JSLE),
        JSETXC = OPCODE_BPF_JMP_IMM(BPF_JSET),
        JSETXY = OPCODE_BPF_JMP_REG(BPF_JSET),

        JEQ32XC = OPCODE_BPF_JMP32_IMM(BPF_JEQ),
        JEQ32XY = OPCODE_BPF_JMP32_REG(BPF_JEQ),
        JNE32XC = OPCODE_BPF_JMP32_IMM(BPF_JNE),
        JNE32XY = OPCODE_BPF_JMP32_REG(BPF_JNE),
        JGT32XC = OPCODE_BPF_JMP32_IMM(BPF_JGT),
        JGT32XY = OPCODE_BPF_JMP32_REG(BPF_JGT),
        JGE32XC = OPCODE_BPF_JMP32_IMM(BPF_JGE),
        JGE32XY = OPCODE_BPF_JMP32_REG(BPF_JGE),
        JSGT32XC = OPCODE_BPF_JMP32_IMM(BPF_JSGT),
        JSGT32XY = OPCODE_BPF_JMP32_REG(BPF_JSGT),
        JSGE32XC = OPCODE_BPF_JMP32_IMM(BPF_JSGE),
        JSGE32XY = OPCODE_BPF_JMP32_REG(BPF_JSGE),
        JLT32XC = OPCODE_BPF_JMP32_IMM(BPF_JLT),
        JLT32XY = OPCODE_BPF_JMP32_REG(BPF_JLT),
        JLE32XC = OPCODE_BPF_JMP32_IMM(BPF_JLE),
        JLE32XY = OPCODE_BPF_JMP32_REG(BPF_JLE),
        JSLT32XC = OPCODE_BPF_JMP32_IMM(BPF_JSLT),
        JSLT32XY = OPCODE_BPF_JMP32_REG(BPF_JSLT),
        JSLE32XC = OPCODE_BPF_JMP32_IMM(BPF_JSLE),
        JSLE32XY = OPCODE_BPF_JMP32_REG(BPF_JSLE),
        JSET32XC = OPCODE_BPF_JMP32_IMM(BPF_JSET),
        JSET32XY = OPCODE_BPF_JMP32_REG(BPF_JSET),

        CALL = OPCODE_BPF_FUNC_CALL,
        EXIT = OPCODE_BPF_EXIT_INSN,
    };

    static std::unordered_map<OPCODE_IDX, OPCODES> idx_2_opcode = {
            {IDX_NOP,      NOP},
            {IDX_ADD64XC,  ADD64XC},
            {IDX_ADD64XY,  ADD64XY},
            {IDX_SUB64XY,  SUB64XY},
            {IDX_MUL64XC,  MUL64XC},
            {IDX_DIV64XC,  DIV64XC},
            {IDX_OR64XC,   OR64XC},
            {IDX_OR64XY,   OR64XY},
            {IDX_AND64XC,  AND64XC},
            {IDX_AND64XY,  AND64XY},
            {IDX_LSH64XC,  LSH64XC},
            {IDX_LSH64XY,  LSH64XY},
            {IDX_RSH64XC,  RSH64XC},
            {IDX_RSH64XY,  RSH64XY},
            {IDX_NEG64XC,  NEG64XC},
            {IDX_XOR64XC,  XOR64XC},
            {IDX_XOR64XY,  XOR64XY},
            {IDX_MOV64XC,  MOV64XC},
            {IDX_MOV64XY,  MOV64XY},
            {IDX_ARSH64XC, ARSH64XC},
            {IDX_ARSH64XY, ARSH64XY},
            {IDX_ADD32XC,  ADD32XC},
            {IDX_ADD32XY,  ADD32XY},
            {IDX_OR32XC,   OR32XC},
            {IDX_OR32XY,   OR32XY},
            {IDX_AND32XC,  AND32XC},
            {IDX_AND32XY,  AND32XY},
            {IDX_LSH32XC,  LSH32XC},
            {IDX_LSH32XY,  LSH32XY},
            {IDX_RSH32XC,  RSH32XC},
            {IDX_RSH32XY,  RSH32XY},
            {IDX_MOV32XC,  MOV32XC},
            {IDX_MOV32XY,  MOV32XY},
            {IDX_ARSH32XC, ARSH32XC},
            {IDX_ARSH32XY, ARSH32XY},
            {IDX_LE,       LE},
            {IDX_BE,       BE},
            {IDX_LDDW,     LDDW},
            {IDX_LDXB,     LDXB},
            {IDX_STXB,     STXB},
            {IDX_LDXH,     LDXH},
            {IDX_STXH,     STXH},
            {IDX_LDXW,     LDXW},
            {IDX_STXW,     STXW},
            {IDX_LDXDW,    LDXDW},
            {IDX_STXDW,    STXDW},
            {IDX_STB,      STB},
            {IDX_STH,      STH},
            {IDX_STW,      STW},
            {IDX_STDW,     STDW},
            {IDX_XADD64,   XADD64},
            {IDX_XADD32,   XADD32},
            {IDX_ATOMIC64, ATOMIC64},
            {IDX_ATOMIC32, ATOMIC32},
            {IDX_LDABSH,   LDABSH},
            {IDX_LDINDH,   LDINDH},
            {IDX_JA,       JA},
            {IDX_JEQXC,    JEQXC},
            {IDX_JEQXY,    JEQXY},
            {IDX_JGTXC,    JGTXC},
            {IDX_JGTXY,    JGTXY},
            {IDX_JGEXC,    JGEXC},
            {IDX_JGEXY,    JGEXY},
            {IDX_JNEXC,    JNEXC},
            {IDX_JNEXY,    JNEXY},
            {IDX_JSGTXC,   JSGTXC},
            {IDX_JSGTXY,   JSGTXY},
            {IDX_JEQ32XC,  JEQ32XC},
            {IDX_JEQ32XY,  JEQ32XY},
            {IDX_JNE32XC,  JNE32XC},
            {IDX_JNE32XY,  JNE32XY},
            {IDX_CALL,     CALL},
            {IDX_EXIT,     EXIT},
    };

    static std::unordered_map<OPCODE_IDX, OPCODE_TYPES> opcode_type = {
            {IDX_NOP,      OP_NOP},
            {IDX_ADD64XC,  OP_ALU_OR_LDDW},
            {IDX_ADD64XY,  OP_ALU_OR_LDDW},
            {IDX_SUB64XY,  OP_ALU_OR_LDDW},
            {IDX_MUL64XC,  OP_ALU_OR_LDDW},
            {IDX_DIV64XC,  OP_ALU_OR_LDDW},
            {IDX_OR64XC,   OP_ALU_OR_LDDW},
            {IDX_OR64XY,   OP_ALU_OR_LDDW},
            {IDX_AND64XC,  OP_ALU_OR_LDDW},
            {IDX_AND64XY,  OP_ALU_OR_LDDW},
            {IDX_LSH64XC,  OP_ALU_OR_LDDW},
            {IDX_LSH64XY,  OP_ALU_OR_LDDW},
            {IDX_RSH64XC,  OP_ALU_OR_LDDW},
            {IDX_RSH64XY,  OP_ALU_OR_LDDW},
            {IDX_NEG64XC,  OP_ALU_OR_LDDW},
            {IDX_XOR64XC,  OP_ALU_OR_LDDW},
            {IDX_XOR64XY,  OP_ALU_OR_LDDW},
            {IDX_MOV64XC,  OP_ALU_OR_LDDW},
            {IDX_MOV64XY,  OP_ALU_OR_LDDW},
            {IDX_ARSH64XC, OP_ALU_OR_LDDW},
            {IDX_ARSH64XY, OP_ALU_OR_LDDW},
            {IDX_ADD32XC,  OP_ALU_OR_LDDW},
            {IDX_ADD32XY,  OP_ALU_OR_LDDW},
            {IDX_OR32XC,   OP_ALU_OR_LDDW},
            {IDX_OR32XY,   OP_ALU_OR_LDDW},
            {IDX_AND32XC,  OP_ALU_OR_LDDW},
            {IDX_AND32XY,  OP_ALU_OR_LDDW},
            {IDX_LSH32XC,  OP_ALU_OR_LDDW},
            {IDX_LSH32XY,  OP_ALU_OR_LDDW},
            {IDX_RSH32XC,  OP_ALU_OR_LDDW},
            {IDX_RSH32XY,  OP_ALU_OR_LDDW},
            {IDX_MOV32XC,  OP_ALU_OR_LDDW},
            {IDX_MOV32XY,  OP_ALU_OR_LDDW},
            {IDX_ARSH32XC, OP_ALU_OR_LDDW},
            {IDX_ARSH32XY, OP_ALU_OR_LDDW},
            {IDX_LE,       OP_ALU_OR_LDDW},
            {IDX_BE,       OP_ALU_OR_LDDW},
            {IDX_LDDW,     OP_ALU_OR_LDDW},
            {IDX_LDXB,     OP_LD},
            {IDX_STXB,     OP_ST},
            {IDX_LDXH,     OP_LD},
            {IDX_STXH,     OP_ST},
            {IDX_LDXW,     OP_LD},
            {IDX_STXW,     OP_ST},
            {IDX_LDXDW,    OP_LD},
            {IDX_STXDW,    OP_ST},
            {IDX_STB,      OP_ST},
            {IDX_STH,      OP_ST},
            {IDX_STW,      OP_ST},
            {IDX_STDW,     OP_ST},
            {IDX_XADD64,   OP_ST},
            {IDX_XADD32,   OP_ST},
            {IDX_ATOMIC64, OP_ST},
            {IDX_ATOMIC32, OP_ST},
            {IDX_LDABSH,   OP_LD},
            {IDX_LDINDH,   OP_LD},
            {IDX_JA,       OP_UNCOND_JMP},
            {IDX_JEQXC,    OP_COND_JMP},
            {IDX_JEQXY,    OP_COND_JMP},
            {IDX_JNEXC,    OP_COND_JMP},
            {IDX_JNEXY,    OP_COND_JMP},
            {IDX_JGTXC,    OP_COND_JMP},
            {IDX_JGTXY,    OP_COND_JMP},
            {IDX_JGEXC,    OP_COND_JMP},
            {IDX_JGEXY,    OP_COND_JMP},
            {IDX_JSGTXC,   OP_COND_JMP},
            {IDX_JSGTXY,   OP_COND_JMP},
            {IDX_JSGEXC,   OP_COND_JMP},
            {IDX_JSGEXY,   OP_COND_JMP},
            {IDX_JLTXC,    OP_COND_JMP},
            {IDX_JLTXY,    OP_COND_JMP},
            {IDX_JLEXC,    OP_COND_JMP},
            {IDX_JLEXY,    OP_COND_JMP},
            {IDX_JSLTXC,   OP_COND_JMP},
            {IDX_JSLTXY,   OP_COND_JMP},
            {IDX_JSLEXC,   OP_COND_JMP},
            {IDX_JSLEXY,   OP_COND_JMP},
            {IDX_JEQ32XC,  OP_COND_JMP},
            {IDX_JEQ32XY,  OP_COND_JMP},
            {IDX_JNE32XC,  OP_COND_JMP},
            {IDX_JNE32XY,  OP_COND_JMP},
            {IDX_JGT32XC,  OP_COND_JMP},
            {IDX_JGT32XY,  OP_COND_JMP},
            {IDX_JGE32XC,  OP_COND_JMP},
            {IDX_JGE32XY,  OP_COND_JMP},
            {IDX_JSGT32XC, OP_COND_JMP},
            {IDX_JSGT32XY, OP_COND_JMP},
            {IDX_JSGE32XC, OP_COND_JMP},
            {IDX_JSGE32XY, OP_COND_JMP},
            {IDX_JLT32XC,  OP_COND_JMP},
            {IDX_JLT32XY,  OP_COND_JMP},
            {IDX_JLE32XC,  OP_COND_JMP},
            {IDX_JLE32XY,  OP_COND_JMP},
            {IDX_JSLT32XC, OP_COND_JMP},
            {IDX_JSLT32XY, OP_COND_JMP},
            {IDX_JSLE32XC, OP_COND_JMP},
            {IDX_JSLE32XY, OP_COND_JMP},
            {IDX_CALL,     OP_CALL},
            {IDX_EXIT,     OP_RET},
    };

    static std::unordered_map<u8, int> opcode2byte_num = {
            {STXB,     1},
            {STXH,     2},
            {STXW,     4},
            {STXDW,    8},
            {STB,      1},
            {STH,      2},
            {STW,      4},
            {STDW,     8},
            {LDXB,     1},
            {LDXH,     2},
            {LDXW,     4},
            {LDXDW,    8},
            {ATOMIC32, 4},
            {ATOMIC64, 8},
    };

    static std::unordered_map<u8, std::set<u8>> related_opcodes = {
            {ADD64XY,  {ADD64XC,  ADD64XY}},
            {ADD64XC,  {ADD64XC}},
            {SUB64XY,  {SUB64XC,  SUB64XY}},
            {SUB64XC,  {SUB64XC}},
            {MUL64XY,  {MUL64XC,  MUL64XY, LSH64XC, LSH64XY}},
            {MUL64XC,  {MUL64XC,  LSH64XC}},
            {DIV64XY,  {DIV64XC,  DIV64XY, RSH64XC, RSH64XY}},
            {DIV64XC,  {DIV64XC,  RSH64XC}},
            {OR64XY,   {OR64XC,   OR64XY}},
            {OR64XC,   {OR64XC}},
            {AND64XY,  {AND64XC,  AND64XY}},
            {AND64XC,  {AND64XC}},
            {LSH64XY,  {LSH64XC,  LSH64XY,MOV32XY}},
            {LSH64XC,  {LSH64XC}},
            {RSH64XY,  {RSH64XC,  RSH64XY,MOV32XY}},
            {RSH64XC,  {RSH64XC}},
            {NEG64XY,  {NEG64XC,  NEG64XY}},
            {NEG64XC,  {NEG64XC}},
            {MOD64XY,  {MOD64XC,  MOD64XY}},
            {MOD64XC,  {MOD64XC}},
            {XOR64XY,  {XOR64XC,  XOR64XY}},
            {XOR64XC,  {XOR64XC}},
            {MOV64XY,  {MOV64XC,  MOV64XY}},
            {MOV64XC,  {MOV64XC}},
            {ARSH64XY, {ARSH64XC, ARSH64XY,MOV32XY}},
            {ARSH64XC, {ARSH64XC}},
            {ADD32XY,  {ADD32XC,  ADD32XY}},
            {ADD32XC,  {ADD32XC}},
            {SUB32XY,  {SUB32XC,  SUB32XY}},
            {SUB32XC,  {SUB32XC}},
            {MUL32XY,  {MUL32XC,  MUL32XY, LSH32XC, LSH32XY}},
            {MUL32XC,  {MUL32XC,  LSH32XC}},
            {DIV32XY,  {DIV32XC,  DIV32XY, RSH32XC, RSH32XY}},
            {DIV32XC,  {DIV32XC,  RSH32XC}},
            {OR32XY,   {OR32XC,   OR32XY}},
            {OR32XC,   {OR32XC}},
            {AND32XY,  {AND32XC,  AND32XY}},
            {AND32XC,  {AND32XC}},
            {LSH32XY,  {LSH32XC,  LSH32XY}},
            {LSH32XC,  {LSH32XC}},
            {RSH32XY,  {RSH32XC,  RSH32XY}},
            {RSH32XC,  {RSH32XC}},
            {NEG32XY,  {NEG32XC,  NEG32XY}},
            {NEG32XC,  {NEG32XC}},
            {MOD32XY,  {MOD32XC,  MOD32XY}},
            {MOD32XC,  {MOD32XC}},
            {XOR32XY,  {XOR32XC,  XOR32XY}},
            {XOR32XC,  {XOR32XC}},
            {MOV32XY,  {MOV32XC,  MOV32XY}},
            {MOV32XC,  {MOV32XC}},
            {ARSH32XY, {ARSH32XC, ARSH32XY}},
            {ARSH32XC, {ARSH32XC}},
            {LE,       {LE}},
            {BE,       {BE}},
//            {STXB,     {STXDW, STDW}},
            {STXB,     {STXB,     STXH,    STXW,    STB,    STH, STW}},
            {STXH,     {STXH,     STXW,    STXDW,   STH,   STW,    STDW}},
            {STXW,     {STXW,     STXDW,   STW,     STDW}},
            {STXDW,    {STXDW,    STDW}},
            {STB,      {STB,      STH,     STW}},
            {STH,      {STH,      STW,     STDW}},
            {STW,      {STW,      STDW}},
            {STDW,     {STDW}},
//            {LDXB,     {LDXB,LDXDW}},
            {LDXB,     {LDXB,     LDXH,    LDXW,    LDXDW}},
            {LDXH,     {LDXH,     LDXW,    LDXDW}},
            {LDXW,     {LDXW,     LDXDW}},
            {LDXDW,    {LDXDW}},
            {LDDW,     {LDDW}}, // BPF_LD | BPF_IMM |BPF_DW
            {XADD32,   {XADD32}},
            {XADD64,   {XADD64}},
            {ATOMIC32, {ATOMIC32}},
            {ATOMIC64, {ATOMIC64}},
    };

    static std::unordered_map<u8, std::set<u8>> related_opcodes2 = {
            {ADD64XY,  {ADD64XC,  ADD64XY,  ADD32XC,  ADD32XY}},
            {ADD64XC,  {ADD64XC,  ADD32XC}},
            {SUB64XY,  {SUB64XC,  SUB64XY,  SUB32XC,  SUB32XY}},
            {SUB64XC,  {SUB64XC,  SUB32XC}},
            {MUL64XY,  {MUL64XC,  MUL64XY,  LSH64XC,  LSH64XY, MUL32XC, MUL32XY, LSH32XC, LSH32XY}},
            {MUL64XC,  {MUL64XC,  LSH64XC,  MUL32XC,  LSH32XC}},
            {DIV64XY,  {DIV64XC,  DIV64XY,  RSH64XC,  RSH64XY, DIV32XC, DIV32XY, RSH32XC, RSH32XY}},
            {DIV64XC,  {DIV64XC,  RSH64XC,  DIV32XC,  RSH32XC}},
            {OR64XY,   {OR64XC,   OR64XY,   OR32XC,   OR32XY}},
            {OR64XC,   {OR64XC,   OR32XC}},
            {AND64XY,  {AND64XC,  AND64XY,  AND32XC,  AND32XY}},
            {AND64XC,  {AND64XC,  AND32XC}},
            {LSH64XY,  {LSH64XC,  LSH64XY,  LSH32XC,  LSH32XY}},
            {LSH64XC,  {LSH64XC,  LSH32XC}},
            {RSH64XY,  {RSH64XC,  RSH64XY,  RSH32XC,  RSH32XY}},
            {RSH64XC,  {RSH64XC,  RSH32XC}},
            {LSH32XY,  {LSH32XC,  LSH32XY}},
            {LSH32XC,  {LSH32XC}},
            {RSH32XY,  {RSH32XC,  RSH32XY}},
            {RSH32XC,  {RSH32XC}},
            {NEG64XY,  {NEG64XC,  NEG64XY,  NEG32XC,  NEG32XY}},
            {NEG64XC,  {NEG64XC,  NEG32XC}},
            {MOD64XY,  {MOD64XC,  MOD64XY,  MOD32XC,  MOD32XY}},
            {MOD64XC,  {MOD64XC,  MOD32XC}},
            {XOR64XY,  {XOR64XC,  XOR64XY,  XOR32XC,  XOR32XY}},
            {XOR64XC,  {XOR64XC,  XOR32XC}},
            {MOV64XY,  {MOV64XC,  MOV64XY,  MOV32XC,  MOV32XY}},
            {MOV64XC,  {MOV64XC,  MOV32XC}},
            {ARSH64XY, {ARSH64XC, ARSH64XY, ARSH32XC, ARSH32XY}},
            {ARSH64XC, {ARSH64XC, ARSH32XC}},
            {LE,       {LE}},
            {BE,       {BE}},
            {STXB,     {STXB,     STXH,     STXW,     STXDW,   STB,     STH,     STW,     STDW}},
            {STXH,     {STXH,     STXW,     STXDW,    STH,     STW,     STDW}},
            {STXW,     {STXW,     STXDW,    STW,      STDW}},
            {STXDW,    {STXDW,    STDW}},
            {STB,      {STB,      STH,      STW,      STDW}},
            {STH,      {STH,      STW,      STDW}},
            {STW,      {STW,      STDW}},
            {STDW,     {STDW}},
            {LDXB,     {LDXB,     LDXH,     LDXW,     LDXDW}},
            {LDXH,     {LDXH,     LDXW,     LDXDW}},
            {LDXW,     {LDXW,     LDXDW}},
            {LDXDW,    {LDXDW}},
            {LDDW,     {LDDW}}, // BPF_LD | BPF_IMM |BPF_DW
            {XADD32,   {XADD32}},
            {XADD64,   {XADD64}},
            {ATOMIC32, {ATOMIC32}},
            {ATOMIC64, {ATOMIC64}},
    };

    static std::unordered_map<u8, double> insn_runtime = {
            {ADD32XC,  0.366},
            {SUB32XC,  0.356},
            {MUL32XC,  1.025},
            {DIV32XC,  4.776},
            {AND32XC,  0.363},
            {OR32XC,   0.37},
            {LSH32XC,  0.329},
            {RSH32XC,  0.365},
            {XOR32XC,  0.36},
            {MOD32XC,  5.128},
            {ARSH32XC, 0.351},
            {NEG32XC,  0.375},
            {ADD32XY,  0.327},
            {SUB32XY,  0.333},
            {MUL32XY,  1.021},
            {DIV32XY,  5.152},
            {AND32XY,  0.33},
            {OR32XY,   0.359},
            {LSH32XY,  0.368},
            {RSH32XY,  0.368},
            {XOR32XY,  0.366},
            {MOD32XY,  5.22},
            {ARSH32XY, 0.369},
            {ADD64XC,  0.369},
            {SUB64XC,  0.369},
            {MUL64XC,  1.135},
            {DIV64XC,  5.182},
            {AND64XC,  0.375},
            {OR64XC,   0.37},
            {LSH64XC,  0.384},
            {RSH64XC,  0.38},
            {XOR64XC,  0.37},
            {MOD64XC,  5.239},
            {ARSH64XC, 0.379},
            {NEG64XC,  0.369},
            {ADD64XY,  0.369},
            {SUB64XY,  0.371},
            {MUL64XY,  1.135},
            {DIV64XY,  5.314},
            {AND64XY,  0.375},
            {OR64XY,   0.37},
            {LSH64XY,  0.384},
            {RSH64XY,  0.381},
            {XOR64XY,  0.38},
            {MOD64XY,  5.239},
            {ARSH64XY, 0.379},
            {MOV64XC,  0.095},
            {MOV64XY,  0.079},
            {MOV32XY,  0.085},
            {MOV32XC,  0.096},
            {JEQXC,    1.868},
            {JEQ32XC,  1.882},
            {JNEXC,    1.864},
            {JNE32XC,  0.181},
            {JGTXC,    0.181},
            {JSGTXC,   1.849},
            {JGEXC,    0.183},
            {JLTXC,    1.893},
            {JLEXC,    1.877},
            {JA,       0},
            {JSETXC,   0.212},
            {JEQXY,    1.875},
            {JEQ32XY,  1.832},
            {JNEXY,    1.896},
            {JNE32XY,  0.183},
            {JGTXY,    0.191},
            {JSGTXY,   1.834},
            {JGEXY,    0.181},
            {JLTXY,    1.887},
            {JLEXY,    1.875},
            {JSETXY,   0.201},
            {NOP,      0},
            {EXIT,     0},
            {STXB,     0.382},
            {STXH,     0.369},
            {STXW,     0.376},
            {STXDW,    0.381},
            {STB,      0.381},
            {STH,      0.381},
            {STW,      0.372},
            {STDW,     0.376},
            {XADD64,   6.616},
            {XADD32,   5.514},
            {LDXB,     0.179},
            {LDXH,     0.181},
            {LDXW,     0.18},
            {LDXDW,    0.182},
            {LDDW,     0.363},
            {LDABSB,   4.81},
            {LDABSH,   5.022},
            {LDABSW,   4.836},
            {BE,       0.159},
            {LE,       0.223}
    };

    static std::unordered_map<s32, double> call_runtime = {
            {1,  1.518},  // BPF_FUNC_map_lookup_elem
            {2,  19.03},  // BPF_FUNC_map_update_elem
            {3,  2.12},  // BPF_FUNC_map_delete_elem
            {7,  5.279},  // BPF_FUNC_get_prandom_u32
            {12, 1.85},  // BPF_FUNC_tail_call
    };

    static std::unordered_map<s32, double> be_runtime = {
            {16, 0.187},
            {32, 0.177},
            {64, 0.114},
    };

    static std::unordered_map<s32, double> le_runtime = {
            {16, 0.284},
            {32, 0.197},
            {64, 0.189},
    };

    static std::unordered_map<u8, double> insn_cyclops = {
            {ADD32XC,                  0.7},
            {SUB32XC,                  0.7},
            {MUL32XC,                  4.7},
            {DIV32XC,                  24.7},
            {AND32XC,                  0.7},
            {OR32XC,                   0.7},
            {LSH32XC,                  0.7},
            {RSH32XC,                  0.7},
            {XOR32XC,                  0.7},
            {MOD32XC,                  23.7},
            {NEG32XC,                  0.7},
            {ADD32XY,                  0.7},
            {SUB32XY,                  0.7},
            {MUL32XY,                  4.5},
            {DIV32XY,                  25.8},
            {AND32XY,                  0.7},
            {OR32XY,                   0.7},
            {LSH32XY,                  4},
            {RSH32XY,                  4.1},
            {XOR32XY,                  0.7},
            {MOD32XY,                  24.4},

            {ADD64XC,                  0.7},
            {SUB64XC,                  0.7},
            {MUL64XC,                  4.4},
            {DIV64XC,                  33.3},
            {AND64XC,                  0.7},
            {OR64XC,                   0.7},
            {LSH64XC,                  0.7},
            {RSH64XC,                  0.7},
            {XOR64XC,                  0.7},
            {MOD64XC,                  30.6},
            {ARSH64XC,                 0.7},
            {NEG64XC,                  0.7},
            {ADD64XY,                  0.7},
            {SUB64XY,                  0.7},
            {MUL64XY,                  4.8},
            {DIV64XY,                  34.7},
            {AND64XY,                  0.7},
            {OR64XY,                   0.7},
            {LSH64XY,                  4.1},
            {RSH64XY,                  4},
            {XOR64XY,                  0.7},
            {MOD64XY,                  31.5},
            {ARSH64XY,                 4},
            {MOV64XC,                  0.3},
            {MOV64XY,                  0.3},
            {MOV32XY,                  0.3},
            {JEQXC,                    2},
            {JNEXC,                    2.1},
            {JGTXC,                    0.7},
            {JGEXC,                    0.6},
//        {JLTXC,                    1.2},
//        {JLEXC,                    1.1},
            {JA,                       0.1},
//        {JSETXC,                   0.6},
            {JEQXY,                    2.2},
            {JNEXY,                    2},
            {JGTXY,                    0.6},
            {JGEXY,                    0.6},
//        {JLTXY,                    1.3},
//        {JLEXY,                    1.1},
//        {JSETXY,                   0.6},
            {STXB,                     0.8},
            {STXH,                     0.9},
            {STXW,                     0.9},
            {STXDW,                    0.9},
            {STB,                      0.9},
            {STH,                      3.3},
            {STW,                      0.9},
            {STDW,                     0.9},
            {XADD64,                   5.7},
            {ATOMIC64,                 5.7},  // TODO
            {LDXB,                     0.5},
            {LDXH,                     0.5},
            {LDXW,                     0.8},
            {LDXDW,                    0.8},
            {LDDW,                     0.6},
//        {LDABSB,                   5.6},
            {LDABSH,                   5},
//        {LDABSW,                   4.7},
//            {BPF_FUNC_map_lookup_elem, 2.7},
//            {BPF_FUNC_map_update_elem, 75.7},
//            {BPF_FUNC_map_delete_elem, 44.3},
            {MOV32XC,                  0.2},
            {ARSH32XC,                 0.8},
            {ARSH32XY,                 3.6},
            {BPF_FUNC_get_prandom_u32, 20.1},
            {BPF_FUNC_tail_call,       2.3},
            {XADD32,                   17.8},
            {ATOMIC32,                 17.8},  // TODO
            {BE,                       0.5},
            {LE,                       0.8},
//        {BE16,                     0.5},
//        {BE32,                     0.5},
//        {BE64,                     0.4},
//        {LE16,                     0.8},
//        {LE32,                     1},
//        {LE64,                     1},
            {JSGTXY,                   2.4},
            {JSGTXC,                   2},
            {JEQ32XY,                  0.9},
            {JEQ32XC,                  0.9},
//        {JNEQ32XY,                 0.8},
//        {JNEQ32XC,                 0.9}
    };

    static std::unordered_map<int32_t, RegType> helper_funcs_ret_type = {
            {BPF_FUNC_map_lookup_elem,      PTR_TO_MAP_VALUE_OR_NULL},  // 1
            {BPF_FUNC_map_update_elem,      SCALAR_VALUE},  // 2
            {BPF_FUNC_map_delete_elem,      SCALAR_VALUE},  // 3
            {BPF_FUNC_probe_read,           SCALAR_VALUE},  // 4
            {BPF_FUNC_ktime_get_ns,         SCALAR_VALUE},  // 5
            {BPF_FUNC_trace_printk,         SCALAR_VALUE},  // 6
            {BPF_FUNC_get_prandom_u32,      SCALAR_VALUE},  // 7
            {BPF_FUNC_get_smp_processor_id, SCALAR_VALUE},  // 8
            {BPF_FUNC_skb_store_bytes,      SCALAR_VALUE},  // 9
            {BPF_FUNC_l3_csum_replace,      SCALAR_VALUE},  // 10
            {BPF_FUNC_l4_csum_replace,      SCALAR_VALUE},  // 11
            {BPF_FUNC_tail_call,            SCALAR_VALUE},  // 12
            {BPF_FUNC_clone_redirect,       SCALAR_VALUE},  // 13
            {BPF_FUNC_get_current_pid_tgid, SCALAR_VALUE},  // 14
            {BPF_FUNC_get_current_uid_gid,  SCALAR_VALUE},  // 15
            {BPF_FUNC_get_current_comm,     SCALAR_VALUE},  // 16
            {BPF_FUNC_get_cgroup_classid,   SCALAR_VALUE},  // 17
            {BPF_FUNC_skb_vlan_push,        SCALAR_VALUE},  // 18
            {BPF_FUNC_skb_vlan_pop,         SCALAR_VALUE},  // 19
            {BPF_FUNC_skb_get_tunnel_key,   SCALAR_VALUE},  // 20
            {BPF_FUNC_skb_set_tunnel_key,   SCALAR_VALUE},  // 21
//    {BPF_FUNC_perf_event_read, 22, ##ctx)            \
//    {BPF_FUNC_redirect, 23, ##ctx)                \
//    {BPF_FUNC_get_route_realm, 24, ##ctx)            \
//    {BPF_FUNC_perf_event_output, 25, ##ctx)        \
//    {BPF_FUNC_skb_load_bytes, 26, ##ctx)            \
//    {BPF_FUNC_get_stackid, 27, ##ctx)            \
//    {BPF_FUNC_csum_diff, 28, ##ctx)            \
//    {BPF_FUNC_skb_get_tunnel_opt, 29, ##ctx)        \
//    {BPF_FUNC_skb_set_tunnel_opt, 30, ##ctx)        \
//    {BPF_FUNC_skb_change_proto, 31, ##ctx)            \
//    {BPF_FUNC_skb_change_type, 32, ##ctx)            \
//    {BPF_FUNC_skb_under_cgroup, 33, ##ctx)            \
//    {BPF_FUNC_get_hash_recalc, 34, ##ctx)            \

            {BPF_FUNC_get_current_task,     PTR_TO_MEM},  // 35
//    {BPF_FUNC_probe_write_user, 36, ##ctx)            \
//    {BPF_FUNC_current_task_under_cgroup, 37, ##ctx)    \
//    {BPF_FUNC_skb_change_tail, 38, ##ctx)            \
//    {BPF_FUNC_skb_pull_data, 39, ##ctx)            \
//    {BPF_FUNC_csum_update, 40, ##ctx)            \

            {BPF_FUNC_set_hash_invalid,     NOT_INIT},  // 41
//    {BPF_FUNC_get_numa_node_id, 42, ##ctx)            \
//    {BPF_FUNC_skb_change_head, 43, ##ctx)            \
//    {BPF_FUNC_xdp_adjust_head, 44, ##ctx)            \
//    {BPF_FUNC_probe_read_str, 45, ##ctx)            \
//    {BPF_FUNC_get_socket_cookie, 46, ##ctx)        \
//    {BPF_FUNC_get_socket_uid, 47, ##ctx)            \
//    {BPF_FUNC_set_hash, 48, ##ctx)                \
//    {BPF_FUNC_setsockopt, 49, ##ctx)            \
//    {BPF_FUNC_skb_adjust_room, 50, ##ctx)            \
//    {BPF_FUNC_redirect_map, 51, ##ctx)            \
//    {BPF_FUNC_sk_redirect_map, 52, ##ctx)            \
//    {BPF_FUNC_sock_map_update, 53, ##ctx)            \
//    {BPF_FUNC_xdp_adjust_meta, 54, ##ctx)            \
//    {BPF_FUNC_perf_event_read_value, 55, ##ctx)        \
//    {BPF_FUNC_perf_prog_read_value, 56, ##ctx)        \
//    {BPF_FUNC_getsockopt, 57, ##ctx)            \
//    {BPF_FUNC_override_return, 58, ##ctx)            \
//    {BPF_FUNC_sock_ops_cb_flags_set, 59, ##ctx)        \
//    {BPF_FUNC_msg_redirect_map, 60, ##ctx)            \
//    {BPF_FUNC_msg_apply_bytes, 61, ##ctx)            \
//    {BPF_FUNC_msg_cork_bytes, 62, ##ctx)            \
//    {BPF_FUNC_msg_pull_data, 63, ##ctx)            \
//    {BPF_FUNC_bind, 64, ##ctx)                \
//    {BPF_FUNC_xdp_adjust_tail, 65, ##ctx)            \
//    {BPF_FUNC_skb_get_xfrm_state, 66, ##ctx)        \
//    {BPF_FUNC_get_stack, 67, ##ctx)            \
//    {BPF_FUNC_skb_load_bytes_relative, 68, ##ctx)        \
//    {BPF_FUNC_fib_lookup, 69, ##ctx)            \
//    {BPF_FUNC_sock_hash_update, 70, ##ctx)            \
//    {BPF_FUNC_msg_redirect_hash, 71, ##ctx)        \
//    {BPF_FUNC_sk_redirect_hash, 72, ##ctx)            \
//    {BPF_FUNC_lwt_push_encap, 73, ##ctx)            \
//    {BPF_FUNC_lwt_seg6_store_bytes, 74, ##ctx)        \
//    {BPF_FUNC_lwt_seg6_adjust_srh, 75, ##ctx)        \
//    {BPF_FUNC_lwt_seg6_action, 76, ##ctx)            \
//    {BPF_FUNC_rc_repeat, 77, ##ctx)            \
//    {BPF_FUNC_rc_keydown, 78, ##ctx)            \
//    {BPF_FUNC_skb_cgroup_id, 79, ##ctx)            \
//    {BPF_FUNC_get_current_cgroup_id, 80, ##ctx)        \

            {BPF_FUNC_get_local_storage,    PTR_TO_MEM},  // 81
//    {BPF_FUNC_sk_select_reuseport, 82, ##ctx)        \
//    {BPF_FUNC_skb_ancestor_cgroup_id, 83, ##ctx)        \

            {BPF_FUNC_sk_lookup_tcp,        PTR_TO_SOCK_COMMON_OR_NULL},  // 84
            {BPF_FUNC_sk_lookup_udp,        PTR_TO_SOCK_COMMON_OR_NULL},  // 85
//    {BPF_FUNC_sk_release, 86, ##ctx)            \
//    {BPF_FUNC_map_push_elem, 87, ##ctx)            \
//    {BPF_FUNC_map_pop_elem, 88, ##ctx)            \
//    {BPF_FUNC_map_peek_elem, 89, ##ctx)            \
//    {BPF_FUNC_msg_push_data, 90, ##ctx)            \
//    {BPF_FUNC_msg_pop_data, 91, ##ctx)            \
//    {BPF_FUNC_rc_pointer_rel, 92, ##ctx)            \
//    {BPF_FUNC_spin_lock, 93, ##ctx)            \
//    {BPF_FUNC_spin_unlock, 94, ##ctx)            \

            {BPF_FUNC_sk_fullsock,          PTR_TO_SOCK_COMMON_OR_NULL},  // 95
            {BPF_FUNC_tcp_sock,             PTR_TO_TCP_SOCK_OR_NULL},  // 96
//    {BPF_FUNC_skb_ecn_set_ce, 97, ##ctx)            \

            {BPF_FUNC_get_listener_sock,    PTR_TO_SOCK_COMMON_OR_NULL},  // 98
            {BPF_FUNC_skc_lookup_tcp,       PTR_TO_SOCK_COMMON_OR_NULL},  // 99
//    {BPF_FUNC_tcp_check_syncookie, 100, ##ctx)        \
//    {BPF_FUNC_sysctl_get_name, 101, ##ctx)            \
//    {BPF_FUNC_sysctl_get_current_value, 102, ##ctx)    \
//    {BPF_FUNC_sysctl_get_new_value, 103, ##ctx)        \
//    {BPF_FUNC_sysctl_set_new_value, 104, ##ctx)        \
//    {BPF_FUNC_strtol, 105, ##ctx)                \
//    {BPF_FUNC_strtoul, 106, ##ctx)                \

            {BPF_FUNC_sk_storage_get,       PTR_TO_MEM_OR_NULL},  // 107
//    {BPF_FUNC_sk_storage_delete, 108, ##ctx)        \
//    {BPF_FUNC_send_signal, 109, ##ctx)            \
//    {BPF_FUNC_tcp_gen_syncookie, 110, ##ctx)        \
//    {BPF_FUNC_skb_output, 111, ##ctx)            \
//    {BPF_FUNC_probe_read_user, 112, ##ctx)            \
//    {BPF_FUNC_probe_read_kernel, 113, ##ctx)        \
//    {BPF_FUNC_probe_read_user_str, 114, ##ctx)        \
//    {BPF_FUNC_probe_read_kernel_str, 115, ##ctx)        \
//    {BPF_FUNC_tcp_send_ack, 116, ##ctx)            \
//    {BPF_FUNC_send_signal_thread, 117, ##ctx)        \
//    {BPF_FUNC_jiffies64, 118, ##ctx)            \
//    {BPF_FUNC_read_branch_records, 119, ##ctx)        \
//    {BPF_FUNC_get_ns_current_pid_tgid, 120, ##ctx)        \
//    {BPF_FUNC_xdp_output, 121, ##ctx)            \
//    {BPF_FUNC_get_netns_cookie, 122, ##ctx)        \
//    {BPF_FUNC_get_current_ancestor_cgroup_id, 123, ##ctx)    \
//    {BPF_FUNC_sk_assign, 124, ##ctx)            \
//    {BPF_FUNC_ktime_get_boot_ns, 125, ##ctx)        \
//    {BPF_FUNC_seq_printf, 126, ##ctx)            \
//    {BPF_FUNC_seq_write, 127, ##ctx)            \
//    {BPF_FUNC_sk_cgroup_id, 128, ##ctx)            \
//    {BPF_FUNC_sk_ancestor_cgroup_id, 129, ##ctx)        \
//    {BPF_FUNC_ringbuf_output, 130, ##ctx)            \
//    {BPF_FUNC_ringbuf_reserve, 131, ##ctx)            \
//    {BPF_FUNC_ringbuf_submit, 132, ##ctx)            \
//    {BPF_FUNC_ringbuf_discard, 133, ##ctx)            \
//    {BPF_FUNC_ringbuf_query, 134, ##ctx)            \
//    {BPF_FUNC_csum_level, 135, ##ctx)            \
//    {BPF_FUNC_skc_to_tcp6_sock, 136, ##ctx)        \
//    {BPF_FUNC_skc_to_tcp_sock, 137, ##ctx)            \
//    {BPF_FUNC_skc_to_tcp_timewait_sock, 138, ##ctx)    \
//    {BPF_FUNC_skc_to_tcp_request_sock, 139, ##ctx)        \
//    {BPF_FUNC_skc_to_udp6_sock, 140, ##ctx)        \
//    {BPF_FUNC_get_task_stack, 141, ##ctx)            \
//    {BPF_FUNC_load_hdr_opt, 142, ##ctx)            \
//    {BPF_FUNC_store_hdr_opt, 143, ##ctx)            \
//    {BPF_FUNC_reserve_hdr_opt, 144, ##ctx)            \
//    {BPF_FUNC_inode_storage_get, 145, ##ctx)        \
//    {BPF_FUNC_inode_storage_delete, 146, ##ctx)        \
//    {BPF_FUNC_d_path, 147, ##ctx)                \
//    {BPF_FUNC_copy_from_user, 148, ##ctx)            \
//    {BPF_FUNC_snprintf_btf, 149, ##ctx)            \
//    {BPF_FUNC_seq_printf_btf, 150, ##ctx)            \
//    {BPF_FUNC_skb_cgroup_classid, 151, ##ctx)        \
//    {BPF_FUNC_redirect_neigh, 152, ##ctx)            \
//    {BPF_FUNC_per_cpu_ptr, 153, ##ctx)            \
//    {BPF_FUNC_this_cpu_ptr, 154, ##ctx)            \
//    {BPF_FUNC_redirect_peer, 155, ##ctx)            \
//    {BPF_FUNC_task_storage_get, 156, ##ctx)        \
//    {BPF_FUNC_task_storage_delete, 157, ##ctx)        \
//    {BPF_FUNC_get_current_task_btf, 158, ##ctx)        \
//    {BPF_FUNC_bprm_opts_set, 159, ##ctx)            \
//    {BPF_FUNC_ktime_get_coarse_ns, 160, ##ctx)        \
//    {BPF_FUNC_ima_inode_hash, 161, ##ctx)            \
//    {BPF_FUNC_sock_from_file, 162, ##ctx)            \
//    {BPF_FUNC_check_mtu, 163, ##ctx)            \
//    {BPF_FUNC_for_each_map_elem, 164, ##ctx)        \
//    {BPF_FUNC_snprintf, 165, ##ctx)            \
//    {BPF_FUNC_sys_bpf, 166, ##ctx)                \
//    {BPF_FUNC_btf_find_by_name_kind, 167, ##ctx)        \
//    {BPF_FUNC_sys_close, 168, ##ctx)            \
//    {BPF_FUNC_timer_init, 169, ##ctx)            \
//    {BPF_FUNC_timer_set_callback, 170, ##ctx)        \
//    {BPF_FUNC_timer_start, 171, ##ctx)            \
//    {BPF_FUNC_timer_cancel, 172, ##ctx)            \
//    {BPF_FUNC_get_func_ip, 173, ##ctx)            \
//    {BPF_FUNC_get_attach_cookie, 174, ##ctx)        \
//    {BPF_FUNC_task_pt_regs, 175, ##ctx)            \
//    {BPF_FUNC_get_branch_snapshot, 176, ##ctx)        \
//    {BPF_FUNC_trace_vprintk, 177, ##ctx)            \
//    {BPF_FUNC_skc_to_unix_sock, 178, ##ctx)        \
//    {BPF_FUNC_kallsyms_lookup_name, 179, ##ctx)        \
//    {BPF_FUNC_find_vma, 180, ##ctx)            \
//    {BPF_FUNC_loop, 181, ##ctx)                \
//    {BPF_FUNC_strncmp, 182, ##ctx)                \
//    {BPF_FUNC_get_func_arg, 183, ##ctx)            \
//    {BPF_FUNC_get_func_ret, 184, ##ctx)            \
//    {BPF_FUNC_get_func_arg_cnt, 185, ##ctx)        \
//    {BPF_FUNC_get_retval, 186, ##ctx)            \
//    {BPF_FUNC_set_retval, 187, ##ctx)            \
//    {BPF_FUNC_xdp_get_buff_len, 188, ##ctx)        \
//    {BPF_FUNC_xdp_load_bytes, 189, ##ctx)            \
//    {BPF_FUNC_xdp_store_bytes, 190, ##ctx)            \
//    {BPF_FUNC_copy_from_user_task, 191, ##ctx)        \
//    {BPF_FUNC_skb_set_tstamp, 192, ##ctx)            \
//    {BPF_FUNC_ima_file_hash, 193, ##ctx)            \
//    {BPF_FUNC_kptr_xchg, 194, ##ctx)            \
//    {BPF_FUNC_map_lookup_percpu_elem, 195, ##ctx)        \
//    {BPF_FUNC_skc_to_mptcp_sock, 196, ##ctx)        \
//    {BPF_FUNC_dynptr_from_mem, 197, ##ctx)            \
//    {BPF_FUNC_ringbuf_reserve_dynptr, 198, ##ctx)        \
//    {BPF_FUNC_ringbuf_submit_dynptr, 199, ##ctx)        \
//    {BPF_FUNC_ringbuf_discard_dynptr, 200, ##ctx)        \
//    {BPF_FUNC_dynptr_read, 201, ##ctx)            \
//    {BPF_FUNC_dynptr_write, 202, ##ctx)            \
//    {BPF_FUNC_dynptr_data, 203, ##ctx)            \
//    {BPF_FUNC_tcp_raw_gen_syncookie_ipv4, 204, ##ctx)    \
//    {BPF_FUNC_tcp_raw_gen_syncookie_ipv6, 205, ##ctx)    \
//    {BPF_FUNC_tcp_raw_check_syncookie_ipv4, 206, ##ctx)    \
//    {BPF_FUNC_tcp_raw_check_syncookie_ipv6, 207, ##ctx)    \
//    {BPF_FUNC_ktime_get_tai_ns, 208, ##ctx)        \
//    {BPF_FUNC_user_ringbuf_drain, 209, ##ctx)        \
//    {BPF_FUNC_cgrp_storage_get, 210, ##ctx)        \
//    {BPF_FUNC_cgrp_storage_delete, 211, ##ctx)        \

    };

    std::string opcode_2_str(int opcode);

    OPCODE_IDX opcode_2_idx(int opcode);

// sizeflag 可以靠 BPF_SIZE(opcode)得到
    int sizeflag_2_num(int flag);

    struct BpfInsn {
        u8 code;        /* opcode */
        u8 dst_reg: 4;    /* dest register */
        u8 src_reg: 4;    /* source register */
        s16 off;        /* signed offset */
        s32 imm;        /* signed immediate constant */

        BpfInsn() {
            code = 0;
            dst_reg = 0;
            src_reg = 0;
            off = 0;
            imm = 0;
        }

        BpfInsn(u8 c, u8 d, u8 s, s16 o, s32 i) {
            code = c;
            dst_reg = d;
            src_reg = s;
            off = o;
            imm = i;
        }

        void set(u8 c, u8 d, u8 s, s16 o, s32 i) {
            code = c;
            dst_reg = d;
            src_reg = s;
            off = o;
            imm = i;
        }

        void print_insn() {
            printf("%-7x %-7u %-7u 0x%-8x 0x%x\n",
                   code, dst_reg, src_reg, off, imm);
        }
    };

    struct Insn {
        int _opcode;
        int32_t _dst_reg;
        int32_t _src_reg;
        int32_t _imm;
        int16_t _off;
        uint64_t _imm64;
        // fields for relocation:
        // ATTENTION: only valid when _imm64 is not used; for LDDW insn, fields below is valid in the former 8 bytes of the insn
        int _is_reloc; // 1 for need to reloc, 0 for else
        int _reloc_type; // 0 for RELO_LD64 (defined in libbpf.c:enum reloc_type)
        int _reloc_map_idx; // index in Patcher::bpf_map_descs_
        // fields for co-re relocation:
        int _is_core_reloc; // 1 for need to reloc, 0 for else

        Insn() {
            _opcode = 0;
            _dst_reg = -1;
            _src_reg = -2;
            _imm = 0;
            _off = 0;
            _imm64 = 0;
            _is_reloc = 0;
            _is_core_reloc = 0;
        }

        Insn(int opcode, int32_t src_reg, int32_t dst_reg, int16_t off, int32_t imm) {
            _opcode = opcode;
            _dst_reg = dst_reg;
            _src_reg = src_reg;
            _imm = imm;
            _off = off;
            _imm64 = 0;
            _is_reloc = 0;
            _is_core_reloc = 0;
        }

        OPCODE_TYPES getType() const;

        bool isJump() const;

        bool isGoto0() const;

        /* Return true if insn splits basic blocks */
        bool isSplit() const;

        bool isShiftX() const;

        bool isShift() const;

        bool isDivModX() const;

        bool isDivModK() const;

        /* Return true if insn belongs to ST/STX class */
        bool is_st();

        /* Return true if insn belongs to STX class and mode = BPF_ATOMIC */
        bool is_atomic();

        /* Return true if insn belongs to LD/LDX class */
        bool is_ldx();

        long long get_code(){
            return ((long long)_opcode<<56)|((long long)_dst_reg<<52)|((long long)_src_reg<<48)|((long long)_off<<32)|_imm;
        }
        bool is_src_reg_used(){
            bool res=((BPF_CLASS(_opcode)==BPF_ALU|| BPF_CLASS(_opcode)==BPF_ALU64)
                      &&BPF_SRC(_opcode)==BPF_X&&BPF_OP(_opcode)!=BPF_NEG&&BPF_OP(_opcode)!=BPF_END)
                     || BPF_CLASS(_opcode)==BPF_STX|| BPF_CLASS(_opcode)==BPF_LDX;
            return res;
        }

        bool is_dst_reg_used(){
            return ((BPF_CLASS(_opcode)==BPF_ALU|| BPF_CLASS(_opcode)==BPF_ALU64)&&BPF_OP(_opcode)!=BPF_MOV)
                   || BPF_CLASS(_opcode)==BPF_STX;
        }

        bool is_imm_used(){
            return ((BPF_CLASS(_opcode)==BPF_ALU|| BPF_CLASS(_opcode)==BPF_ALU64)&&BPF_SRC(_opcode)==BPF_K)
                   || BPF_CLASS(_opcode)==BPF_ST;
        }

        int get_bytes_num(){
            if(!is_st()&&!is_ldx()){
                return -1;
            }
            switch(BPF_SIZE(_opcode)){
                case BPF_B:return 1;
                case BPF_H:return 2;
                case BPF_W:return 4;
                case BPF_DW:return 8;
            }
            return -1;
        }

        bool is_length_2() const;

        int getJumpDst() const;

        int getRegDef() const;

        std::vector<int> getRegUses() const;

        std::string get_insn_name() const;

        std::set<u8> get_related_opcodes();

        double get_runtime();

        friend std::ostream &operator<<(std::ostream &os, const Insn &insn);

        bool operator==(Insn &insn) {
            return (_opcode == insn._opcode) && (_dst_reg == insn._dst_reg) &&
                   (_src_reg == insn._src_reg) && (_off == insn._off) && (_imm == insn._imm);
        }

        bool operator!=(Insn &insn) {
            return (_opcode != insn._opcode) || (_dst_reg != insn._dst_reg) ||
                   (_src_reg != insn._src_reg) || (_off != insn._off) || (_imm != insn._imm);
        }

        void print_insn() const;
    };
}


#endif //SUPERBPF_INSTRUCTION_INSN_H
