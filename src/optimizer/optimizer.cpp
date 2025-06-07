#include "optimizer.h"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <libpq-fe.h>
#include <pqxx/pqxx>
#include <thread>
#include <math.h>

#include "src/synthesizer/synthesizer.h"
#include "src/validator/validator.h"

using namespace std;
using namespace superbpf;

namespace superbpf {
    string Optimizer::cur_example_name;

    pair<Node*,pair<int,long long>> Optimizer::cegis(Node *cur_bb) {
        cur_bb->split_insns();
        if (cur_bb->size() == 0){
            return {cur_bb,{1,0}};
        }
        int candidate_id = 0;
        Node *rewrite= nullptr;
        bool validation_res = false;
        auto win_synthesizer = WinSynthesizer(cur_bb, 4,pruning_type);
        win_synthesizer.set_example_name(cur_example_name);
        while (!validation_res) {
            win_synthesizer.set_node(cur_bb);
            rewrite = win_synthesizer.synthesize_with_context();
            assert(rewrite!= nullptr);
            if (rewrite == nullptr) {
                break;
            }
            rewrite->set_init_static_info(cur_bb->init_static_info());
            rewrite->compute_final_static_info();
//            rewrite->print_insns();
            Validator validator(cur_bb,rewrite);
            validation_res = validator.verify();
            if (!validation_res) {
                auto counterexample=validator.get_counterexample();
//                counterexample->print_testcase();
                win_synthesizer.add_testcase(counterexample);
                delete rewrite;
                rewrite= nullptr;
            }
            candidate_id++;
            // TODO
            if (candidate_id >= 5) {
                break;
            }
            assert(candidate_id <= 5);
        }
        cout << "Pass validation after generating " << candidate_id << " candidate(s)." << endl << endl;
        if (rewrite != nullptr) {
            rewrite->set_split_insns(cur_bb->get_split_insns());
            rewrite->add_regs_live_out(cur_bb->regs_live_out());
        }
        return {rewrite,{candidate_id,Verifier::get_hit_times()}};
    }

    double Optimizer::compute_insns_exec_time(const std::vector<Insn> insns) {
        double res = 0;
        for (Insn insn: insns) {
            res+=insn.get_runtime();
        }
        return res;
    }

    void Optimizer::print_consumed_time(double consumed_time) {
        cout << "Total running time: ";
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
        cout << setprecision(2) << consumed_time << " s.\n" << endl;
    }


    void Optimizer::store_opt_pattern(const Node* origin,const Node* rewrite){
        unordered_map<int,int> reg_id_map; // <real reg id, serialized reg id>
        unordered_map<int,int> reg_off_map; // <real reg id, the first visited offset>
        unordered_map<int,int> imm_map; // <real imm, serialized imm>
        auto origin_used_regs=origin->get_used_regs(),rewrite_used_regs=rewrite->get_used_regs();
        set<int> diff_regs;
        set_difference(rewrite_used_regs.begin(),rewrite_used_regs.end(),origin_used_regs.begin(),origin_used_regs.end(),
                       inserter(diff_regs,diff_regs.begin()));
        string origin_insns_str= origin->get_serialized_insns_str(reg_id_map,reg_off_map,imm_map,set<int>());
        string rewrite_insns_str= rewrite->get_serialized_insns_str(reg_id_map,reg_off_map,imm_map,diff_regs);
        // check if the optimization pattern already exits
        try {
            // Connect to the PostgreSQL database
            pqxx::connection conn("dbname=zqdb user=zq password=123 host=localhost port=5432");
            string sql="SELECT origin, rewrite FROM opt_patterns WHERE origin = "+origin_insns_str+" and rewrite = "+rewrite_insns_str;
            if (conn.is_open()) {
                // Create a transactional object
                pqxx::work txn(conn);
                // Execute a SELECT query
                pqxx::result res = txn.exec(sql);
                // Process the result
                if(!res.empty()){
                    return;
                }
                // Commit the transaction (optional for SELECT queries)
                txn.commit();
            } else {
                std::cerr << "Failed to connect to the database!" << std::endl;
            }
            // Close the connection
            conn.disconnect();
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
        // store optimization pattern
        try {
            // Connect to the PostgreSQL database
            pqxx::connection conn("dbname=zqdb user=zq password=123 host=localhost port=5432");
            string live_regs_str;
            if(origin->regs_live_out().empty()){
                live_regs_str="ARRAY[]::INTEGER[]";
            }
            else{
                live_regs_str="ARRAY[";
                for(auto reg_id:origin->regs_live_out()){
                    if(reg_id_map.count(reg_id))
                        live_regs_str+=(to_string(reg_id_map.at(reg_id))+",");
                }
                live_regs_str.pop_back();
                live_regs_str+="]";
            };
            string sql="INSERT INTO opt_patterns (sample_name, origin, rewrite, live_regs) VALUES ('"
                       +cur_example_name+"',"+origin_insns_str+","+rewrite_insns_str+","+live_regs_str+");";
//            cout<<sql<<endl;
            if (conn.is_open()) {
                // Create a transactional object
                pqxx::work txn(conn);
                // Execute a SELECT query
                txn.exec(sql);
                txn.commit();
                printf("\033[32mOne new optimization pattern added.\n\n\033[0m");
            } else {
                std::cerr << "Failed to connect to the database!" << std::endl;
            }
            // Close the connection
            conn.disconnect();
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }

//        const char *conninfo = "dbname=zqdb user=zq password=123 host=localhost port=5432";
//        PGconn *conn= PQconnectdb(conninfo);
//
//        if(PQstatus(conn)!=CONNECTION_OK){
//            cerr<<"Connection to database failed: "<<PQerrorMessage(conn)<<endl;
//            PQfinish(conn);
//            return;
//        }
//
//        string rewrite_insns_str= rewrite->get_serialized_insns_str(reg_id_map,reg_off_map,imm_map);
//        string live_regs_str="ARRAY[";
//        for(auto reg_id:origin->regs_live_out()){
////            cout<<reg_id<<' ';
//            if(reg_id_map.count(reg_id))
//                live_regs_str+=(to_string(reg_id_map.at(reg_id))+",");
//        }
//        live_regs_str.pop_back();
//        live_regs_str+="]";
//        cout<<live_regs_str<<endl;
//        string sql="INSERT INTO opt_patterns (sample_name, origin, rewrite, live_regs) VALUES ('"
//                +cur_example_name+"',"+origin_insns_str+","+rewrite_insns_str+","+live_regs_str+");";
//        cout<<sql<<endl;
//        PQexec(conn,sql.c_str());
    }

    vector<Insn> Optimizer::optimize(bpf_prog_type prog_type, vector<Insn> &target_insns) {
        vector<Insn> rewrite_insns;
        if (target_insns.empty()) {
            cerr << "Insns empty." << endl;
            return rewrite_insns;
        }
        // construct cfg and analyze valid memory addresses, def-in and live-out variables
        CFG *origin = new CFG(prog_type, target_insns);
        origin->static_analysis();
        map<int, Node *> bbs = origin->getAllNodes();  // basic blocks

        time_t begin, end;
        begin = clock();
        set<int> optimized_bbs;
        map<int, Node *> rewrite_bbs;
        int optimized_insns_num = 0;
        for (auto it = bbs.begin(); it != bbs.end(); it++) {
            auto block_begin_time = clock();
            int bb_idx = it->first;
            cout << "Optimizing block " << bb_idx << "..." << endl;
            Node *origin_bb = bbs.at(bb_idx);
            auto [rewrite_bb,candidates_count] = cegis(origin_bb);
            if (rewrite_bb == nullptr)
                rewrite_bb = origin_bb;
            assert(rewrite_bb != nullptr);
            rewrite_bbs.insert({bb_idx, rewrite_bb});
            vector<Insn> cur_rewrite_insns = rewrite_bb->get_complete_insns(origin_bb->size() - rewrite_bb->size());
            rewrite_insns.insert(rewrite_insns.end(), cur_rewrite_insns.begin(), cur_rewrite_insns.end());
            double origin_score = origin_bb->get_score(), rewrite_score = rewrite_bb->get_score();
            assert((origin_score + 1e-6 < rewrite_score) || fabs(origin_score - rewrite_score) < 1e-6);
            if ((origin_score + 1e-6 < rewrite_score)) {
                optimized_bbs.insert(bb_idx);
                optimized_insns_num += (origin_bb->size() - rewrite_bb->size());
            }
            auto block_end_time = clock();
            double block_opt_time = (double) (block_end_time - block_begin_time) / CLOCKS_PER_SEC;
            print_consumed_time(block_opt_time);
        }
        end = clock();

        double opt_time = (double) (end - begin) / CLOCKS_PER_SEC;
        cout << "Number of instructions: ";
        cout << "origin: " << target_insns.size() << ", rewrite: " << target_insns.size() - optimized_insns_num << endl;
        print_consumed_time(opt_time);
        return rewrite_insns;
    }

    vector<Insn>
    Optimizer::optimize_with_report_output(string infile_path, bpf_prog_type prog_type, vector<Insn> &target_insns,
                                           bool is_1st_sec) {
        vector<Insn> rewrite_insns;
        if (target_insns.empty()) {
            cerr << "Insns empty." << endl;
            return rewrite_insns;
        }
        // construct cfg and analyze valid memory addresses, def-in and live-out variables
        CFG *origin = new CFG(prog_type, target_insns);
        origin->static_analysis();
//        origin->print_prog();
        map<int, Node *> bbs = origin->getAllNodes();  // basic blocks

        time_t begin, end;
        begin = clock();
        set<int> optimized_bbs;
        map<int, Node *> rewrite_bbs;
        int optimized_insns_num = 0;
        for (auto it = bbs.begin(); it != bbs.end(); it++) {
            int bb_idx = it->first;
            cout << "Optimizing block " << bb_idx << "..." << endl;
            auto block_begin_time = clock();
            Node *origin_bb = bbs.at(bb_idx);
            auto [rewrite_bb,count] = cegis(origin_bb);
            auto [candidates_count,verifier_hit_times]=count;
            if (rewrite_bb == nullptr)
                rewrite_bb = origin_bb;
//            if (rewrite_bb == nullptr)
//                cout << "Failed block: " << bb_idx << endl;
//            assert(rewrite_bb != nullptr);
            double origin_score = origin_bb->get_score(), rewrite_score = rewrite_bb->get_score();
            assert((origin_score + 1e-6 < rewrite_score) || fabs(origin_score - rewrite_score) < 1e-6);
            if ((origin_score + 1e-6 < rewrite_score)) {
                rewrite_bbs.insert({bb_idx, rewrite_bb});
                vector<Insn> cur_rewrite_insns = rewrite_bb->get_complete_insns(origin_bb->size() - rewrite_bb->size());
                rewrite_insns.insert(rewrite_insns.end(), cur_rewrite_insns.begin(), cur_rewrite_insns.end());
                optimized_bbs.insert(bb_idx);
                optimized_insns_num += (origin_bb->size() - rewrite_bb->size());
            } else {
                rewrite_bbs.insert({bb_idx, origin_bb});
                vector<Insn> origin_insns = origin_bb->get_complete_insns(0);
                rewrite_insns.insert(rewrite_insns.end(), origin_insns.begin(), origin_insns.end());
            }
            auto block_end_time = clock();
            double block_opt_time = (double) (block_end_time - block_begin_time) / CLOCKS_PER_SEC;
            cout<<"NI: "<<origin_bb->size()<<endl;
            print_consumed_time(block_opt_time);
        }
        end = clock();

        double opt_time = (double) (end - begin) / CLOCKS_PER_SEC;
        cout << "Number of instructions: ";
        cout << "origin: " << target_insns.size() << ", rewrite: " << target_insns.size() - optimized_insns_num << endl;
        print_consumed_time(opt_time);

        // output optimization result
        string::size_type pos1 = infile_path.find_last_of('/');
        string dir = infile_path.substr(0, pos1 + 1);
        string::size_type pos2 = infile_path.find_last_of('.');
        string section_name = infile_path.substr(pos1 + 1, pos2 - pos1 - 1);
        string res_file_path = dir + section_name + "_opt_report.txt";

        fstream file;
        if (is_1st_sec)
            file.open(res_file_path, ios::out);
        else
            file.open(res_file_path, ios::out | ios::app);
        string line;
        // Backup streambuffers of  cout
        streambuf *stream_buffer_cout = cout.rdbuf();
        // Get the streambuffer of the file
        streambuf *stream_buffer_file = file.rdbuf();
        // Redirect cout to file
        cout.rdbuf(stream_buffer_file);
        cout << "Optimized basic blocks: ";
        if (optimized_bbs.empty())
            cout << "none";
        cout << endl;
        for (int i: optimized_bbs) {
            cout << "Origin ";
            bbs.at(i)->print_insns();
            bbs.at(i)->print_live_regs();
            cout << endl << "Rewrite ";
            rewrite_bbs.at(i)->print_insns();
            for (int i = 0; i < 90; i++)
                cout << "-";
            cout << "\n";
        }
        cout << "Number of instructions: ";
        cout.flags(ios::fixed);
        cout << "origin: " << target_insns.size() << ", rewrite: " << target_insns.size() - optimized_insns_num
             << ", compression: " << setprecision(2) << ((double) optimized_insns_num / target_insns.size()) * 100
             << "%" << endl;
        cout << "Instructions execution time: ";
        auto origin_exec_time = compute_insns_exec_time(target_insns), rewrite_exec_time = compute_insns_exec_time(
                rewrite_insns);
        cout << "origin: " << origin_exec_time << " ns , rewrite: " << rewrite_exec_time << " ns, compression: "
             << setprecision(2) << (origin_exec_time - rewrite_exec_time) / origin_exec_time * 100 << "%" << endl;
        print_consumed_time(opt_time);
        for (int i = 0; i < 90; i++)
            cout << "=";
        cout << "\n";
        // Redirect cout back to screen
        cout.rdbuf(stream_buffer_cout);
        file.close();

        return rewrite_insns;
    }

//    vector<Insn>
//    Optimizer::optimize_with_report_output_to_path(string out_path, string sec_name, bpf_prog_type prog_type,bpf_attach_type attach_type,
//                                                   vector<Insn> &target_insns,
//                                                   bool is_1st_sec) {
//        vector<Insn> rewrite_insns;
//        if (target_insns.empty()) {
//            cerr << "Insns empty." << endl;
//            return rewrite_insns;
//        }
//        // construct cfg and analyze valid memory addresses, def-in and live-out variables
//        CFG *origin = new CFG(prog_type, attach_type,target_insns);
//        origin->static_analysis();
////        origin->print_prog();
//        map<int, Node *> bbs = origin->getAllNodes();  // basic blocks
//
//        time_t begin, end;
//        begin = clock();
//        set<int> optimized_bbs;
//        map<int, Node *> rewrite_bbs;
//        int optimized_insns_num = 0;
//        for (auto it = bbs.begin(); it != bbs.end(); it++) {
//            int bb_idx = it->first;
//            cout << "Optimizing block " << bb_idx << "..." << endl;
//            Node *origin_bb = bbs.at(bb_idx);
//            Node *origin_node_copy(origin_bb);
//            Node *rewrite_bb = cegis(origin_bb);
//            // TODO
//            if (rewrite_bb == nullptr)
//                rewrite_bb=origin_bb;
////            assert(rewrite_bb != nullptr);
//            double origin_score = origin_node_copy->get_score(), rewrite_score = rewrite_bb->get_score();
//            assert((origin_score + 1e-6 < rewrite_score) || fabs(origin_score - rewrite_score) < 1e-6);
//            if ((origin_score + 1e-6 < rewrite_score)) {
//                rewrite_bbs.insert({bb_idx, rewrite_bb});
//                vector<Insn> cur_rewrite_insns = rewrite_bb->get_complete_insns(origin_node_copy->size() - rewrite_bb->size());
//                rewrite_insns.insert(rewrite_insns.end(), cur_rewrite_insns.begin(), cur_rewrite_insns.end());
//                optimized_bbs.insert(bb_idx);
//                optimized_insns_num += (origin_node_copy->size() - rewrite_bb->size());
//            } else {
//                rewrite_bbs.insert({bb_idx, origin_bb});
//                vector<Insn> origin_insns = origin_bb->get_complete_insns(0);
//                rewrite_insns.insert(rewrite_insns.end(), origin_insns.begin(), origin_insns.end());
//            }
//        }
//        end = clock();
//
//        double opt_time = (double) (end - begin) / CLOCKS_PER_SEC;
////        cout << "Number of instructions: ";
////        cout << "origin: " << target_insns.size() << ", rewrite: " << target_insns.size() - optimized_insns_num << endl;
//        print_consumed_time(opt_time);
//
//        // output optimization result
//        fstream file;
//        if (is_1st_sec)
//            file.open(out_path, ios::out);
//        else
//            file.open(out_path, ios::out | ios::app);
//        string line;
//        // Backup streambuffers of  cout
//        streambuf *stream_buffer_cout = cout.rdbuf();
//        // Get the streambuffer of the file
//        streambuf *stream_buffer_file = file.rdbuf();
//        // Redirect cout to file
//        cout.rdbuf(stream_buffer_file);
//        cout << "section "<<sec_name << endl;
//        cout << "Optimized basic blocks: ";
//        if (optimized_bbs.empty())
//            cout << "none";
//        cout << endl;
//        for (int i: optimized_bbs) {
//            cout << "Origin ";
//            bbs.at(i)->print_insns();
//            bbs.at(i)->print_live_regs();
//            cout << endl << "Rewrite ";
//            rewrite_bbs.at(i)->print_insns();
//            for (int i = 0; i < 90; i++)
//                cout << "-";
//            cout << "\n";
//        }
//        cout << "Number of instructions: ";
//        cout.flags(ios::fixed);
//        cout << "origin: " << target_insns.size() << ", rewrite: " << target_insns.size() - optimized_insns_num
//             << ", compression: " << setprecision(3) << ((double) optimized_insns_num / target_insns.size()) * 100
//             << "%" << endl;
//        cout << "Instructions execution time: ";
//        auto origin_exec_time = compute_insns_exec_time(target_insns), rewrite_exec_time = compute_insns_exec_time(
//                rewrite_insns);
//        cout << "origin: " << origin_exec_time << " ns , rewrite: " << rewrite_exec_time << " ns, compression: "
//             << setprecision(3) << (origin_exec_time - rewrite_exec_time) / origin_exec_time * 100 << "%" << endl;
//        print_consumed_time(opt_time);
//        for (int i = 0; i < 90; i++)
//            cout << "=";
//        cout << "\n\n";
//        // Redirect cout back to screen
//        cout.rdbuf(stream_buffer_cout);
//        file.close();
//
//        delete origin;
////        for(auto it:bbs)
////            delete it.second;
////        for(auto it:rewrite_bbs)
////            delete it.second;
//        return rewrite_insns;
//    }


    vector<Insn>
    Optimizer::optimize_with_report_output_to_path(string out_path, string sec_name, bpf_prog_type prog_type,bpf_attach_type attach_type,
                                                   vector<Insn> &target_insns,
                                                   bool is_1st_sec) {
        cur_example_name=out_path+"|"+sec_name;
        // compactness
        vector<Insn> rewrite_insns;
        if (target_insns.empty()) {
            cerr << "Insns empty." << endl;
            return rewrite_insns;
        }
        // construct cfg and analyze valid memory addresses, def-in and live-out variables
        CFG *origin = new CFG(prog_type, attach_type,target_insns);
        for(auto [idx,node]:origin->getAllNodes()) {
            cout << idx << endl;
            node->print_insns();
        }
        origin->static_analysis();
//        origin->print_prog();
        map<int, Node *> bbs = origin->getAllNodes();  // basic blocks

        time_t begin, end;
        begin = clock();
        set<int> optimized_bbs;
        map<int, pair<Node *,pair<int,long long>>> rewrite_bbs;
        int optimized_insns_num = 0;
        map<int,double> blocks_opt_time;
        for (auto it = bbs.begin(); it != bbs.end(); it++) {
            int bb_idx = it->first;
//            if(bb_idx>=1710)
//                continue;
            cout << "Optimizing block " << bb_idx << "..." << endl;
            auto block_begin_time = clock();
            Node *origin_bb = bbs.at(bb_idx);
            Node *origin_node_copy(origin_bb);
            auto [rewrite_bb,count] = cegis(origin_bb);
            auto [candidates_count,verifier_hit_times]=count;
            // TODO
            if (rewrite_bb == nullptr) {
                cout<<"CEGIS loop over 5 times"<<endl;
                rewrite_bb = origin_bb;
            }
//            assert(rewrite_bb != nullptr);
            if (origin_bb->get_insns_num()>rewrite_bb->get_insns_num()) {  // TODO: '>' or '>=' ?
                rewrite_bbs.insert({bb_idx, {rewrite_bb,count}});
                vector<Insn> cur_rewrite_insns = rewrite_bb->get_complete_insns(origin_node_copy->size() - rewrite_bb->size());
                rewrite_insns.insert(rewrite_insns.end(), cur_rewrite_insns.begin(), cur_rewrite_insns.end());
                optimized_bbs.insert(bb_idx);
                optimized_insns_num += (origin_node_copy->size() - rewrite_bb->size());
//                store_opt_pattern(origin_bb,rewrite_bb);
            } else {
                rewrite_bbs.insert({bb_idx, {origin_bb,count}});
                vector<Insn> origin_insns = origin_bb->get_complete_insns(0);
                rewrite_insns.insert(rewrite_insns.end(), origin_insns.begin(), origin_insns.end());
            }
            auto block_end_time = clock();
            double block_opt_time = (double) (block_end_time - block_begin_time) / CLOCKS_PER_SEC;
            blocks_opt_time.insert({bb_idx,block_opt_time});
        }
        end = clock();

        double opt_time = (double) (end - begin) / CLOCKS_PER_SEC;
//        cout << "Number of instructions: ";
//        cout << "origin: " << target_insns.size() << ", rewrite: " << target_insns.size() - optimized_insns_num << endl;
        print_consumed_time(opt_time);

        // output optimization result
        fstream file;
        if (is_1st_sec)
            file.open(out_path, ios::out);
        else
            file.open(out_path, ios::out | ios::app);
        string line;
        // Backup streambuffers of  cout
        streambuf *stream_buffer_cout = cout.rdbuf();
        // Get the streambuffer of the file
        streambuf *stream_buffer_file = file.rdbuf();
        // Redirect cout to file
        cout.rdbuf(stream_buffer_file);
        cout << "section "<<sec_name << endl;
        cout << "Optimized basic blocks: ";
        if (optimized_bbs.empty())
            cout << "none";
        cout << endl;
        for (auto [i,node]:bbs) {
            cout<<"Block "<<i<<", NI: "<<node->size()<<endl;
            print_consumed_time(blocks_opt_time[i]);
            cout<<"Pass validation after generating "<<rewrite_bbs[i].second.first<<" candidate(s)."<<endl;
            cout<<"Hit verifier "<<rewrite_bbs[i].second.second<<" time(s) in the last generation.\n\n"<<endl;
        }
        for(int i:optimized_bbs){
            cout << "Origin ";
            bbs.at(i)->print_insns();
            bbs.at(i)->print_live_regs();
            cout << endl << "Rewrite ";
            rewrite_bbs.at(i).first->print_insns();
            for (int i = 0; i < 90; i++)
                cout << "-";
            cout << "\n";
        }
        cout << "Number of instructions: ";
        cout.flags(ios::fixed);
        cout << "origin: " << target_insns.size() << ", rewrite: " << target_insns.size() - optimized_insns_num
             << ", compression: " << setprecision(3) << ((double) optimized_insns_num / target_insns.size()) * 100
             << "%" << endl;
        cout << "Instructions execution time: ";
        auto origin_exec_time = compute_insns_exec_time(target_insns), rewrite_exec_time = compute_insns_exec_time(
                rewrite_insns);
        cout << "origin: " << origin_exec_time << " ns , rewrite: " << rewrite_exec_time << " ns, compression: "
             << setprecision(3) << (origin_exec_time - rewrite_exec_time) / origin_exec_time * 100 << "%" << endl;
        print_consumed_time(opt_time);
        for (int i = 0; i < 90; i++)
            cout << "=";
        cout << "\n\n";
        // Redirect cout back to screen
        cout.rdbuf(stream_buffer_cout);
        file.close();

        delete origin;
//        for(auto it:bbs)
//            delete it.second;
//        for(auto it:rewrite_bbs)
//            delete it.second;
        return rewrite_insns;
    }
}
