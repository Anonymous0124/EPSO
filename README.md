# EPSO
Artifact for submission "EPSO: A Caching-Based Efficient Superoptimizer for BPF Bytecode"

## Abstract
Extended Berkeley Packet Filter (eBPF) allows developers to extend Linux kernel functionality without modifying its source code. To ensure system safety, an in-kernel safety checker, the verifier, enforces strict safety constraints (e.g., a limited program size) on eBPF programs loaded into the kernel. These constraints, combined with eBPF’s performance-critical use cases, make effective optimization essential. However, existing compilers (e.g., Clang) offer limited optimization support, and many semantics-preserving transformations are rejected by the verifier, which makes handcrafted optimization rule design both challenging and limited in effectiveness.
Superoptimization overcomes the limitations of rule-based methods by automatically discovering optimal transformations, but its high computational cost limits scalability. To address this, we propose EPSO, a caching-based superoptimizer that discovers rewrite rules via offline superoptimization, and reuses them to achieve high-quality optimizations with minimal runtime overhead. We evaluate EPSO on benchmarks from the Linux kernel and several eBPF-based projects, including Cilium, Katran, hXDP, Sysdig, Tetragon, and Tracee. EPSO discovers 624 rewrite rules and achieves up to 68.87% (avg. 20.01%) reduction in program size compared to Clang’s best output, outperforming the state-of-the-art BPF optimizer K2 on all benchmarks and Merlin on 81.60% of them. Additionally, EPSO reduces program runtime by an average of 6.60%, improving throughput and lowering latency in network applications.

## Installation and Compilation
Install clang, llvm, elfutils, libelf, libbpf, and zlib.

Install [Z3 v4.12.2](https://github.com/Z3Prover/z3/archive/refs/tags/z3-4.12.2.tar.gz) from source by following the official [Z3 build instructions](https://github.com/Z3Prover/z3#building-z3-using-make-and-gccclang) to install it.

Ensure that llvm-objcopy v15.0.0 is available on your system.
A prebuilt binary is provided in the dependencies/ directory. You can copy it to /usr/bin/ using:
```
sudo cp dependencies/llvm-objcopy /usr/bin/
```

To compile EPSO:
```
cd epso
cmake .
make
```

## Usage
EPSO supports two modes for BPF bytecode optimization:

1. Superoptimization (with rewrite rule collection)
```
./epso <input-file-path> <prog-type> <attach-type>
```
- The optimized BPF object is saved in the same directory as the input, with the suffix: `*_rewrite.o`
- A detailed optimization report is also generated with suffix: `*_opt_report.txt`

**Note:**
This mode uses PostgreSQL to collect and store rewrite rules. To configure your database:

Edit the following lines in `src/synthesizer/synthesizer.cpp`:
- Line 582–583: database host, database name, username, password
- Line 623: table name
  
And the expected structure of the rewrite_rules table is:
```
CREATE TABLE rewrite_rules (id SERIAL PRIMARY KEY, hit_times INT, sample_name TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, origin instruction[], rewrite instruction[], live_regs smallint[]);
```
2. Pattern-Based Optimization (using existing rewrite rules)
```
./epso_pattern <input-file-path> <prog-type> <attach-type>
```
- The optimized BPF object is saved with the suffix: `*_po_rewrite.o`
- A report is generated as: `*_po_opt_report.txt`

**Note:**
This mode also requires PostgreSQL access. To configure:

Edit the following lines in `src/peepholeOptimizer/peepholeOptimizer.cpp`:
- Line 1055–1056: specify database credentials and table name
