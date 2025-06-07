#include <fstream>
#include <iomanip>
#include <iostream>
#include <sys/stat.h>

#include "src/instruction/insn_simulator.h"
#include "src/optimizer/optimizer.h"
#include "src/patcher/patcher.h"
#include "src/verifier/verifier.h"

using namespace std;
using namespace superbpf;

bool isFolderExist(string folderPath) {
    struct stat info;
    if (stat(folderPath.c_str(), &info) != 0) {
        return false;
    }
    return (info.st_mode & S_IFDIR);
}

double compute_insns_exec_time(const std::vector<Insn> insns) {
    double res = 0;
    for (Insn insn: insns) {
        res += insn.get_runtime();
    }
    return res;
}

void print_consumed_time(double consumed_time) {
    cout << "Tool running time: ";
    if (consumed_time / 3600) {
        int hour = consumed_time / 3600;
        cout << hour << " h, ";
        consumed_time = consumed_time - 3600 * hour;
    }
    if (consumed_time / 60) {
        int min = consumed_time / 60;
        cout << min << " min, ";
        consumed_time = consumed_time - 60 * min;
    }
    cout << setprecision(2) << consumed_time << " s." << endl;
}

void output_opt_report(string output_path, int origin_insns_num, int rewrite_insns_num,
                       double origin_exec_time, double rewrite_exec_time, double opt_time) {
    fstream file;
    file.open(output_path, ios::out | ios::app);
    string line;
    // Backup streambuffers of  cout
    streambuf *stream_buffer_cout = cout.rdbuf();
    // Get the streambuffer of the file
    streambuf *stream_buffer_file = file.rdbuf();
    // Redirect cout to file
    cout.rdbuf(stream_buffer_file);
    cout << endl << "Overall optimization result:" << endl;
    cout << "Number of instructions: ";
    cout.flags(ios::fixed);
    cout << "origin: " << origin_insns_num << ", rewrite: " << rewrite_insns_num
         << ", compression: " << setprecision(3)
         << ((double) (origin_insns_num - rewrite_insns_num) / origin_insns_num) * 100 << "%" << endl;
    cout << "Instructions execution time: ";
    cout << "origin: " << origin_exec_time << " ns , rewrite: " << rewrite_exec_time << " ns, compression: "
         << setprecision(3) << (origin_exec_time - rewrite_exec_time) / origin_exec_time * 100 << "%" << endl;
    print_consumed_time(opt_time);
    // Redirect cout back to screen
    cout.rdbuf(stream_buffer_cout);
    file.close();
}

int count_insns_except_ja(vector<Insn> &insns) {
    int res = insns.size();
    for (int i = insns.size() - 1; i >= 0; i--) {
        auto insn = insns[i];
        if (insn._opcode == JA && insn._off == 0) {
            res--;
        }
    }
    return res;
}

vector<string> valid_prog_type_str = {
        "unspec",
        "socket_filter",
        "kprobe",
        "sched_cls",
        "sched_act",
        "tracepoint",
        "xdp",
        "perf_event",
        "cgroup_skb",
        "cgroup_sock",
        "lwt_in",
        "lwt_out",
        "lwt_xmit",
        "sock_ops",
        "sk_skb",
        "cgroup_device",
        "sk_msg",
        "raw_tracepoint",
        "cgroup_sock_addr",
        "lwt_seg6local",
        "lirc_mode2",
        "sk_reuseport",
        "flow_dissector",
        "cgroup_sysctl",
        "raw_tracepoint_writable",
        "cgroup_sockopt",
        "tracing",
        "struct_ops",
        "ext",
        "lsm",
        "sk_lookup",
        "syscall", /* a program that can execute syscalls */
        "netfilter",
};

bpf_prog_type str2progtype(const std::string& progtype_str) {
    bpf_prog_type res;
    if (progtype_str == "unspec")
        res = (bpf_prog_type) 0;
    else if (progtype_str == "socket_filter")
        res = (bpf_prog_type) 1;
    else if (progtype_str == "kprobe")
        res = (bpf_prog_type) 2;
    else if (progtype_str == "sched_cls")
        res = (bpf_prog_type) 3;
    else if (progtype_str == "sched_act")
        res = (bpf_prog_type) 4;
    else if (progtype_str == "tracepoint")
        res = (bpf_prog_type) 5;
    else if (progtype_str == "xdp")
        res = (bpf_prog_type) 6;
    else if (progtype_str == "perf_event")
        res = (bpf_prog_type) 7;
    else if (progtype_str == "cgroup_skb")
        res = (bpf_prog_type) 8;
    else if (progtype_str == "cgroup_sock")
        res = (bpf_prog_type) 9;
    else if (progtype_str == "lwt_in")
        res = (bpf_prog_type) 10;
    else if (progtype_str == "lwt_out")
        res = (bpf_prog_type) 11;
    else if (progtype_str == "lwt_xmit")
        res = (bpf_prog_type) 12;
    else if (progtype_str == "sock_ops")
        res = (bpf_prog_type) 13;
    else if (progtype_str == "sk_skb")
        res = (bpf_prog_type) 14;
    else if (progtype_str == "cgroup_device")
        res = (bpf_prog_type) 15;
    else if (progtype_str == "sk_msg")
        res = (bpf_prog_type) 16;
    else if (progtype_str == "raw_tracepoint")
        res = (bpf_prog_type) 17;
    else if (progtype_str == "cgroup_sock_addr")
        res = (bpf_prog_type) 18;
    else if (progtype_str == "lwt_seg6local")
        res = (bpf_prog_type) 19;
    else if (progtype_str == "lirc_mode2")
        res = (bpf_prog_type) 20;
    else if (progtype_str == "sk_reuseport")
        res = (bpf_prog_type) 21;
    else if (progtype_str == "flow_dissector")
        res = (bpf_prog_type) 22;
    else if (progtype_str == "cgroup_sysctl")
        res = (bpf_prog_type) 23;
    else if (progtype_str == "raw_tracepoint_writable")
        res = (bpf_prog_type) 24;
    else if (progtype_str == "cgroup_sockopt")
        res = (bpf_prog_type) 25;
    else if (progtype_str == "tracing")
        res = (bpf_prog_type) 26;
    else if (progtype_str == "struct_ops")
        res = (bpf_prog_type) 27;
    else if (progtype_str == "ext")
        res = (bpf_prog_type) 28;
    else if (progtype_str == "lsm")
        res = (bpf_prog_type) 29;
    else if (progtype_str == "sk_lookup")
        res = (bpf_prog_type) 30;
    else if (progtype_str == "syscall")
        res = (bpf_prog_type) 31;
    else if (progtype_str == "netfilter")
        res = (bpf_prog_type) 32;
    else
        res = BPF_PROG_TYPE_UNSPEC;
    return res;
}

bpf_attach_type str2attach_type(const string &attach_type_str) {
    bpf_attach_type res;
    if (attach_type_str == "inet_ingress" || attach_type_str == "unspec")
        res = (bpf_attach_type) 0;
    else if (attach_type_str == "inet_egress")
        res = (bpf_attach_type) 1;
    else if (attach_type_str == "inet_sock_create")
        res = (bpf_attach_type) 2;
    else if (attach_type_str == "sock_ops")
        res = (bpf_attach_type) 3;
    else if (attach_type_str == "sk_skb_stream_parser")
        res = (bpf_attach_type) 4;
    else if (attach_type_str == "sk_skb_stream_verdict")
        res = (bpf_attach_type) 5;
    else if (attach_type_str == "cgroup_device")
        res = (bpf_attach_type) 6;
    else if (attach_type_str == "sk_msg_verdict")
        res = (bpf_attach_type) 7;
    else if (attach_type_str == "cgroup_inet4_bind")
        res = (bpf_attach_type) 8;
    else if (attach_type_str == "cgroup_inet6_bind")
        res = (bpf_attach_type) 9;
    else if (attach_type_str == "cgroup_inet4_connect")
        res = (bpf_attach_type) 10;
    else if (attach_type_str == "cgroup_inet6_connect")
        res = (bpf_attach_type) 11;
    else if (attach_type_str == "inet4_post_bind")
        res = (bpf_attach_type) 12;
    else if (attach_type_str == "inet6_post_bind")
        res = (bpf_attach_type) 13;
    else if (attach_type_str == "cgroup_udp4_sendmsg")
        res = (bpf_attach_type) 14;
    else if (attach_type_str == "cgroup_udp6_sendmsg")
        res = (bpf_attach_type) 15;
    else if (attach_type_str == "lirc_mode2")
        res = (bpf_attach_type) 16;
    else if (attach_type_str == "flow_dissector")
        res = (bpf_attach_type) 17;
    else if (attach_type_str == "cgroup_sysctl")
        res = (bpf_attach_type) 18;
    else if (attach_type_str == "cgroup_udp4_recvmsg")
        res = (bpf_attach_type) 19;
    else if (attach_type_str == "cgroup_udp6_recvmsg")
        res = (bpf_attach_type) 20;
    else if (attach_type_str == "cgroup_getsockopt")
        res = (bpf_attach_type) 21;
    else if (attach_type_str == "cgroup_setsockopt")
        res = (bpf_attach_type) 22;
    else if (attach_type_str == "trace_raw_tp")
        res = (bpf_attach_type) 23;
    else if (attach_type_str == "trace_fentry")
        res = (bpf_attach_type) 24;
    else if (attach_type_str == "trace_fexit")
        res = (bpf_attach_type) 25;
    else if (attach_type_str == "modify_return")
        res = (bpf_attach_type) 26;
    else if (attach_type_str == "lsm_mac")
        res = (bpf_attach_type) 27;
    else if (attach_type_str == "trace_iter")
        res = (bpf_attach_type) 28;
    else if (attach_type_str == "cgroup_inet4_getpeername")
        res = (bpf_attach_type) 29;
    else if (attach_type_str == "cgroup_inet6_getpeername")
        res = (bpf_attach_type) 30;
    else if (attach_type_str == "cgroup_inet4_getsockname")
        res = (bpf_attach_type) 31;
    else if (attach_type_str == "cgroup_inet6_getsockname")
        res = (bpf_attach_type) 32;
    else if (attach_type_str == "xdp_devmap")
        res = (bpf_attach_type) 33;
    else if (attach_type_str == "cgroup_inet_sock_release")
        res = (bpf_attach_type) 34;
    else if (attach_type_str == "xdp_cpumap")
        res = (bpf_attach_type) 35;
    else if (attach_type_str == "sk_lookup")
        res = (bpf_attach_type) 36;
    else if (attach_type_str == "xdp")
        res = (bpf_attach_type) 37;
    else if (attach_type_str == "sk_skb_verdict")
        res = (bpf_attach_type) 38;
    else if (attach_type_str == "sk_reuseport_select")
        res = (bpf_attach_type) 39;
    else if (attach_type_str == "sk_reuseport_select_or_migrate")
        res = (bpf_attach_type) 40;
    else if (attach_type_str == "perf_event")
        res = (bpf_attach_type) 41;
    else
        assert(0);
    return res;
}

int main(int argc, char *argv[]) {
    string input_prog_type, input_attach_type;
    if (argc < 4 || string(argv[1]) == "-h" || string(argv[1]) == "--help" || string(argv[1]) == "--version") {
        cout << "EPSO" << endl;
        cout << "Usage: " << argv[0] << " <input-file-path> <prog-type> <attach-type>" << endl;
        exit(0);
    }
    input_prog_type = string(argv[2]);
    if (std::find(valid_prog_type_str.begin(), valid_prog_type_str.end(), input_prog_type) ==
        valid_prog_type_str.end()) {
        cout << "Please provide valid BPF prog type, such as: BPF_PROG_TYPE_SOCKET_FILTER." << endl;
        exit(0);
    }
    input_attach_type = string(argv[3]);
    bpf_attach_type attach_type = str2attach_type(input_attach_type);

    Verifier::set_opt_level_2();
    string in_file = argv[1];
    int pos1 = in_file.find_last_of('/');
    string in_filename = in_file.substr(pos1 + 1, in_file.size() - pos1);
    int pos2 = in_filename.find_first_of('.');
    string object_out_file, report_out_file;

    object_out_file = in_file.substr(0, pos1 + 1) + in_filename.substr(0, pos2) + "_rewrite" +
                      in_filename.substr(pos2, in_filename.size() - pos2);
    report_out_file = in_file.substr(0, pos1 + 1) + in_filename.substr(0, pos2) + "_opt_report.txt";

    cout << endl << "----------Optimizing code from file '" << in_file << "'----------" << endl;
    vector<Insn> origin_insns;
    // use patcher to set 'origin_insns' (there may be multiple sections in an object file,
    //  use loop to optimize section(s) one by one)
    Patcher patcher(in_file);
    auto progs = patcher.get_bpf_programs();
    std::map<std::string, std::vector<Insn>> rewrite_sections;
    Optimizer optimizer;

    time_t begin, end;
    begin = clock();
    int origin_insns_num = 0, rewrite_insns_num = 0;
    double origin_exec_time = 0, rewrte_exec_time = 0;
    for (int i = 0; i < progs.size(); i++) {
        auto prog = progs[i];
        auto prog_type = prog.get_type();
        auto sec_name = prog.get_sec_name();
        if (prog_type == BPF_PROG_TYPE_UNSPEC) {
            if (input_prog_type.empty()) {
                cout << "Please provide prog type" << endl;
                exit(0);
            } else
                prog_type = str2progtype(input_prog_type);
        }
        InsnSimulator::set_prog_attach_type(prog_type, attach_type);
        cout << "section " << sec_name << endl;
        vector<Insn> target_insns = prog.get_insns();
        vector<Insn> rewrite_insns;
        if (i == 0)
            rewrite_insns = optimizer.optimize_with_report_output_to_path(report_out_file, sec_name, prog_type,
                                                                          attach_type, target_insns,
                                                                          true);
        else
            rewrite_insns = optimizer.optimize_with_report_output_to_path(report_out_file, sec_name, prog_type,
                                                                          attach_type, target_insns,
                                                                          false);

        rewrite_sections[prog.get_sec_name()] = rewrite_insns;
        origin_insns_num += target_insns.size();
        rewrite_insns_num += count_insns_except_ja(rewrite_insns);
        origin_exec_time += compute_insns_exec_time(target_insns);
        rewrte_exec_time += compute_insns_exec_time(rewrite_insns);
    }
    end = clock();
    double opt_time = (double) (end - begin) / CLOCKS_PER_SEC;

    string report_filepath;
    output_opt_report(report_out_file, origin_insns_num, rewrite_insns_num,
                      origin_exec_time, rewrte_exec_time, opt_time);

    // use patcher to patch 'rewrite_insns' to new object file
    patcher.update_sections_to_new_file(rewrite_sections, object_out_file);
    cout << "\n---\nOptimized object file has written to file " << object_out_file << endl;
    cout << "Optimization report file has written to file " << report_out_file << endl;

    return 0;
}
