cmake_minimum_required(VERSION 3.22)
project(superbpf)

set(CMAKE_CXX_STANDARD 17)

find_library(
        Z3_LIBRARIES
        NAMES z3
        HINTS ${Z3_DIR} ENV Z3_DIR
        PATH_SUFFIXES bin lib)
find_path(
        Z3_INCLUDES
        NAMES z3++.h
        HINTS ${Z3_DIR} ENV Z3_DIR
        PATH_SUFFIXES include z3)
if (NOT Z3_LIBRARIES OR NOT Z3_INCLUDES)
    message(FATAL_ERROR "Z3 not found!")
endif ()
message(STATUS "Found Z3: ${Z3_LIBRARIES}")
message(STATUS "Z3 include dir: ${Z3_INCLUDES}")

#add_subdirectory(test)

include_directories(/usr/include/postgresql ${CMAKE_BINARY_DIR}/include ${Z3_INCLUDES} . src)

add_executable(epso
        tools/epso.cpp

        src/patcher/patcher.cpp

        src/ebpf/bpf.h
        src/ebpf/ctx.cpp

        src/instruction/insn.cpp
        src/instruction/insn_simulator.cpp
        src/instruction/insn_sym_simulator.cpp

        src/cfg/cfg.cpp

        src/state/regs.cpp
        src/state/memory.cpp
        src/state/state.cpp

        src/testcase/testcase.cpp
        src/testcase/testcase_gen.cpp

        src/synthesizer/synthesizer.cpp

        src/symstate/sym_regs.cpp
        src/symstate/sym_memory.cpp

        src/validator/validator.cpp

        src/optimizer/optimizer.cpp
        src/peepholeOptimizer/peepholeOptimizer.cpp

        src/verifier/verifier.cpp
)

add_executable(epso_pattern
        tools/epso_pattern.cpp

        src/patcher/patcher.cpp

        src/ebpf/bpf.h
        src/ebpf/ctx.cpp

        src/instruction/insn.cpp
        src/instruction/insn_simulator.cpp
        src/instruction/insn_sym_simulator.cpp

        src/cfg/cfg.cpp

        src/peepholeOptimizer/peepholeOptimizer.cpp

        src/state/regs.cpp
        src/state/memory.cpp
        src/state/state.cpp

        src/testcase/testcase.cpp
        src/testcase/testcase_gen.cpp

        src/synthesizer/synthesizer.cpp

        src/symstate/sym_regs.cpp
        src/symstate/sym_memory.cpp

        src/validator/validator.cpp

        src/optimizer/optimizer.cpp

        src/verifier/verifier.cpp
)

target_link_libraries(epso PRIVATE ${Z3_LIBRARIES} libbpf.a -lelf -lz -lpq -lpqxx)

target_link_libraries(epso_pattern PRIVATE ${Z3_LIBRARIES} libbpf.a -lelf -lz -lpq -lpqxx)
