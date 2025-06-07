#include "peepholeOptimizer.h"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <libpq-fe.h>
#include <pqxx/pqxx>
#include <regex>
#include <thread>
#include <math.h>

#include "src/synthesizer/synthesizer.h"
#include "src/validator/validator.h"

using namespace std;

namespace superbpf{

    string PeepholeOptimizer::cur_example_name;

#include <iostream>
#include <map>
#include <set>
    using namespace std;

#include <vector>

#include <unordered_map>

#include <unordered_map>
#include <vector>
#include <iostream>

    class UnionFind {
    private:
        std::unordered_map<int, int> parent;
        std::unordered_map<int, int> rank;

        void add(int x) {
            if (!parent.count(x)) {
                parent[x] = x;
                rank[x] = 0;
            }
        }

    public:
        int find(int x) {
            add(x);
            if (parent[x] != x)
                parent[x] = find(parent[x]);
            return parent[x];
        }

        void unite(int x, int y) {
            int rx = find(x), ry = find(y);
            if (rx == ry) return;

            if (rank[rx] < rank[ry])
                parent[rx] = ry;
            else {
                parent[ry] = rx;
                if (rank[rx] == rank[ry]) rank[rx]++;
            }
        }

        bool connected(int x, int y) {
            return find(x) == find(y);
        }

        // 获取所有集合
        std::unordered_map<int, std::vector<int>> get_components() {
            std::unordered_map<int, std::vector<int>> groups;
            for (const auto& [x, _] : parent) {
                int root = find(x); // 路径压缩
                groups[root].push_back(x);
            }
            return groups;
        }
    };




//    vector<set<int>> get_components(UnionFind& uf) {
//        vector<set<int>> res;
//        const std::vector<int>& parent = uf.get_parents();
//        std::unordered_map<int, std::vector<int>> components;
//
//        for (int i = 0; i < parent.size(); ++i) {
//            int root = uf.find(i);  // 找到代表元
//            components[root].push_back(i);
//        }
//
//        for (const auto& [root, group] : components) {
//            set<int> cur_set={root};
//            cur_set.insert(group.begin(),group.end());
//        }
//    }

    bool dfs(pair<int, int> node,map<pair<int, int>, int>& visit_status,
             map<pair<int,int>,set<pair<int,int>>>& out_edges) {
        visit_status[node] = 1; // visiting

        for (const auto& neighbor : out_edges[node]) {
            if (visit_status[neighbor] == 1) {
                // 回边：说明存在环
                return true;
            }
            if (visit_status[neighbor] == 0) {
                if (dfs(neighbor,visit_status,out_edges)) return true;
            }
        }

        visit_status[node] = 2; // visited
        return false;
    }

    bool hasCycle(map<pair<int,int>,set<pair<int,int>>> out_edges) {
        map<pair<int, int>, int> visit_status;
        visit_status.clear();

        // 初始化所有出现过的节点为未访问
        for (const auto& [node, neighbors] : out_edges) {
            visit_status[node] = 0;
            for (const auto& neighbor : neighbors) {
                visit_status[neighbor] = 0;
            }
        }

        for (const auto& [node, status] : visit_status) {
            if (status == 0) {
                if (dfs(node,visit_status,out_edges)) return true;
            }
        }

        return false;
    }

    pair<bool,vector<pair<int,int>>> topologicalSort(map<pair<int,int>, set<pair<int,int>>> out_edges,
    map<pair<int,int>, set<pair<int,int>>> in_edges) {
        for(auto [i,idxes]:out_edges){
            cout<<i.first<<"-"<<i.second<<": ";
            for(auto idx:idxes){
                cout<<idx.first<<"-"<<idx.second<<", ";
            }
            cout<<endl;
        }
        for(auto [i,idxes]:in_edges){
            cout<<i.first<<"-"<<i.second<<": ";
            for(auto idx:idxes){
                cout<<idx.first<<"-"<<idx.second<<", ";
            }
            cout<<endl;
        }
        map<pair<int,int>, int> in_degree;
        set<pair<int,int>> all_nodes;

        // 收集所有出现过的节点（出边+入边）
        for (const auto& [u, neighbors] : out_edges) {
            all_nodes.insert(u);
            for (const auto& v : neighbors) {
                all_nodes.insert(v);
            }
        }

        for (const auto& [v, sources] : in_edges) {
            all_nodes.insert(v);
            for (const auto& u : sources) {
                all_nodes.insert(u);
            }
        }

        // 初始化入度为 0
        for (const auto& node : all_nodes) {
            in_degree[node] = 0;
        }

        // 统计实际入度
        for (const auto& [v, sources] : in_edges) {
            in_degree[v] = sources.size();
        }

        // 所有入度为 0 的点加入队列
        queue<pair<int,int>> q;
        for (const auto& [node, deg] : in_degree) {
            if (deg == 0) q.push(node);
        }

        vector<pair<int,int>> result;

        while (!q.empty()) {
            auto node = q.front(); q.pop();
            result.push_back(node);

            for (const auto& neighbor : out_edges[node]) {
                in_degree[neighbor]--;
                if (in_degree[neighbor] == 0) {
                    q.push(neighbor);
                }
            }
        }

        bool success=true;
        // 如果排序结果少于总节点数，说明有环
        if (result.size() != all_nodes.size()) {
            result.clear();
            success=false;
            cout<<"Graph has a cycle; topological sort not possible"<<endl;
        }

        return {success,result};
    }


    vector<Insn> PeepholeOptimizer::recompose_insns(unordered_map<int,vector<Insn>> slices){
        cout<<"slices: "<<endl;
        for(auto [id,insns]:slices){
            cout<<"id: "<<id<<endl;
            for(auto insn:insns)
                insn.print_insn();
            cout<<endl;
        }
        set<pair<int,int>> insns_set;
        map<pair<int,int>,set<pair<int,int>>> out_edges;
        map<pair<int,int>,set<pair<int,int>>> in_edges;
        // construct def-use graph
        for(auto [id,insns]:slices){
            // construct dependency edges of slice
            for(int i=0;i<insns.size();i++){
                // add edges with regs and mems using this insn
                auto insn=insns[i];
                auto use_regs=insn.getRegUses();
                int def_id=insn._dst_reg;
                if(insn.is_st()){
                    def_id=(insn._off<<8)|(insn.get_bytes_num()<<4)|insn._dst_reg;
                }
                set<int> use_insn_set;
                for(int j=i+1;j<insns.size();j++){
                    auto cur_insn=insns[j];
                    int cur_def_id=cur_insn._dst_reg;
                    if(cur_insn.is_st()){
                        cur_def_id=(cur_insn._off<<8)|(cur_insn.get_bytes_num()<<4)|cur_insn._dst_reg;
                    }
                    auto cur_use_regs=cur_insn.getRegUses();
                    auto cur_use_regs_set=set<int>(cur_use_regs.begin(),cur_use_regs.end());
                    if(cur_use_regs_set.count(def_id)){
                        out_edges[{id,i}].insert({id,j});
                        in_edges[{id,j}].insert({id,i});
                        use_insn_set.insert(j);
                    }
                    if(cur_insn.is_ldx()){
                        int cur_use_id=(cur_insn._off<<8)|(cur_insn.get_bytes_num()<<4)|cur_insn._src_reg;
                        if(cur_use_id==def_id){
                            out_edges[{id,i}].insert({id,j});
                            in_edges[{id,j}].insert({id,i});
                        }
                    }
                    if(cur_def_id==def_id) {
                        for(auto use_insn_i:use_insn_set){
                            if(use_insn_i!=j){
                                out_edges[{id,use_insn_i}].insert({id,j});
                                in_edges[{id,j}].insert({id,use_insn_i});
                            }
                        }
                        break;
                    }
                }
                // construct dependency edges between slice and existing insns
                pair<int,int> combine_id={-1,-1};
                // try to combine with the existing same insn
                for(auto [cur_id,cur_idx]:insns_set){
                    if(slices[cur_id][cur_idx]==insn){ // same with an existing insn
                        auto temp_in_edges=in_edges,temp_out_edges=out_edges;
                        for(auto key:in_edges[{id,i}]){
                            temp_out_edges[key].insert({cur_id,cur_idx});
                            temp_in_edges[{cur_id,cur_idx}].insert(key);
                        }
                        for(auto key:out_edges[{id,i}]){
                            temp_in_edges[key].insert({cur_id,cur_idx});
                            temp_out_edges[{cur_id,cur_idx}].insert(key);
                        }
                        if(!hasCycle(temp_out_edges)){
                            combine_id={cur_id,cur_idx};
                            out_edges=temp_out_edges;
                            in_edges=temp_in_edges;
                            break;
                        }
                    }
                }
                if(combine_id==pair<int,int>({-1,-1})){
                    set<int> use_set=set<int>(use_regs.begin(), use_regs.end());
                    if(insn.is_ldx()) {
                        int use_mem_id = (insn._off << 8) | (insn.get_bytes_num() << 4) | insn._src_reg;
                        use_set.insert(use_mem_id);
                    }
                    for(auto [cur_id,cur_i]:insns_set){
                        // construct edges with insns from other slices, requires:
                        // use without being defined, define without interrupting use
                        if(cur_id!=id){
                            auto cur_insn=slices[cur_id][cur_i];
                            // use without being define
//                            int cur_insn_def=cur_insn._dst_reg;
//                            if(cur_insn.is_st()){
//                                cur_insn_def=(cur_insn._off<<8)|(cur_insn.get_bytes_num()<<4)|cur_insn._dst_reg;
//                            }
//                            if(use_set.count(cur_insn_def)){
//                                for(int use_id:use_set){
//                                    if(use_id!=cur_insn_def)
//                                        continue;
//                                    else{
//                                        if(cur_id!=id){
//                                            out_edges[{id,i}].insert({cur_id,cur_i});
//                                            in_edges[{cur_id,cur_i}].insert({id,i});
//                                        }
//                                    }
//                                    int j;
//                                    for(j=i-1;j>=0;j--){
//                                        if(!insns[j].is_st()){
//                                            if(insns[j]._dst_reg==use_id)
//                                                break;
//                                        }
//                                        else{
//                                            int temp_def_mem_id = (insns[j]._off << 8) | (insns[j].get_bytes_num() << 4) | insns[j]._dst_reg;
//                                            if(temp_def_mem_id==use_id)
//                                                break;
//                                        }
//                                    }
//                                    if(j==-1){
//                                        out_edges[{id,i}].insert({cur_id,cur_i});
//                                        in_edges[{cur_id,cur_i}].insert({id,i});
//                                    }
//                                }
//                            }
                            // define without interrupting use
                            auto cur_insn_use=cur_insn.getRegUses();
                            if(cur_insn.is_ldx()){
                                int use_mem_id=(cur_insn._off<<8)|(cur_insn.get_bytes_num()<<4)|cur_insn._src_reg;
                                cur_insn_use.emplace_back(use_mem_id);
                            }
                            for(auto use_id:cur_insn_use) {
                                if(use_id!=def_id)
                                    continue;
                                in_edges[{id, i}].insert({cur_id, cur_i});
                                out_edges[{cur_id, cur_i}].insert({id, i});
//                                int j;
//                                for(j=cur_i-1;j>=0;j--){
//                                    if(!slices[cur_id][j].is_st()){
//                                        if(slices[cur_id][j]._dst_reg==use_id)
//                                            break;
//                                    }
//                                    else{
//                                        int temp_def_mem_id = (slices[cur_id][j]._off << 8) |
//                                                (slices[cur_id][j].get_bytes_num() << 4) | slices[cur_id][j]._dst_reg;
//                                        if(temp_def_mem_id==use_id)
//                                            break;
//                                    }
//
//                                }
//                                if (j==-1) {
//                                    in_edges[{id, i}].insert({cur_id, cur_i});
//                                    out_edges[{cur_id, cur_i}].insert({id, i});
//                                }
                            }
                        }
                    }
                }
                else{
                    out_edges[{id,i}]=out_edges[combine_id];
                    in_edges[{id,i}]=in_edges[combine_id];
                    out_edges.erase(combine_id);
                    in_edges.erase(combine_id);
                    insns_set.erase(combine_id);
                    for(auto out_id:out_edges[{id,i}]){
                        in_edges[out_id].erase(combine_id);
                        in_edges[out_id].insert({id,i});
                    }
                    for(auto in_id:in_edges[{id,i}]){
                        out_edges[in_id].erase(combine_id);
                        out_edges[in_id].insert({id,i});
                    }
                }
                insns_set.insert({id,i});
            }

        }

        vector<Insn> result;
        auto [success,topo_sort_res]= topologicalSort(out_edges,in_edges);
        if(!success){
            return result;
        }
        for(auto [id,idx]:topo_sort_res){
            result.emplace_back(slices[id][idx]);
        }
        for(auto[id,idx]:insns_set){
            if(find(topo_sort_res.begin(),topo_sort_res.end(),pair<int,int>({id,idx}))==topo_sort_res.end())
                result.emplace_back(slices[id][idx]);
        }
        return result;
    }

    Node* PeepholeOptimizer::formalized_optimize_block(Node* origin_bb,bool allow_mem_combination) {
        origin_bb->split_insns();
        origin_bb->print_insns();
        origin_bb->print_live_regs();
        if (origin_bb->size() == 0)
            return origin_bb;
        auto insns=origin_bb->insns();
        map<int,set<int>> slices;
        get_slices(origin_bb,allow_mem_combination,slices); // <key, value> : <reg_id/memory_area, indexes of related instructions>
        // How to represent memory_area by 'int': [32bits: offset (24 bits), size (4 bits), reg_id (4 bits)]
//        vector<int> slices_key_vec;
////        unordered_map<int,set<int>> usage_records; // <key, value> : <target_key, keys that use target_key>
//        unordered_map<int,set<int>> use;
//        unordered_map<int,set<int>> used;
//        for(int i=0;i<insns.size();i++) {
//            auto insn = insns[i];
//            int key = 0;
//            bool is_key_new=false;
//            if (insn.is_st()) { // operations that change memory
//                int bytes_num=insn.get_bytes_num();
//                if(allow_mem_combination){
//                    int key_to_erase=-1;
//                    for(auto [cur_id,cur_set]:slices){
//                        if((cur_id&0x0f)==insn._dst_reg){
//                            int cur_off=(cur_id&(int)0xffffff00)>>8;
//                            int cur_size=(cur_id&0x0f0)>>4;
//                            int min_addr=min(cur_off,(int)insn._off),max_addr=max(cur_off+cur_size,insn._off+bytes_num);
//                            if(max_addr-min_addr<=8){
//                                key=(min_addr<<8)|((max_addr-min_addr)<<4)|insn._dst_reg;
//                                key_to_erase=cur_id;
//                                break;
//                            }
//                        }
//                    }
//                    if(key==0) { // no combination
//                        key = (insn._off << 8) | (insn.get_bytes_num() << 4) | insn._dst_reg;
////                        is_key_new=true;
//                    }
//                    else{
//                        if(key!=key_to_erase){
//                            is_key_new=true;
//                            slices[key].insert(slices[key_to_erase].begin(),slices[key_to_erase].end());
//                            slices.erase(key_to_erase);
//                        }
//                    }
//                }
//                else{
//                    key=(insn._off<<8)|(insn.get_bytes_num()<<4)|insn._dst_reg;
//                }
//            } else { // operations that change registers
//                key = insn._dst_reg;
//            }
//            if(!slices.count(key)||is_key_new)
//                slices_key_vec.emplace_back(key);
//            if(slices.count(key)&&0<=key&&key<=10){
//                while(!slices[key].empty()){
//                    bool is_last_deleted=false;
//                    auto last_insn=insns[*slices[key].rbegin()];
//                    if(last_insn._dst_reg==key){
//                        if(!insn.is_dst_reg_used()&&(!insn.is_src_reg_used()||insn._src_reg!=key)) {
//                            slices[key].erase(*slices[key].rbegin());
//                            is_last_deleted=true;
//                        }
//                    }
//                    else{
//                        if(!insn.is_src_reg_used()||insn._src_reg!=last_insn._dst_reg){
//                            slices[key].erase(*slices[key].rbegin());
//                            is_last_deleted=true;
//                        }
//                    }
//                    if(!is_last_deleted)
//                        break;
//                }
//            }
//            slices[key].insert(i);
////            usage_records[key].insert(key);
//            if(insn.is_src_reg_used()){ // add src_reg related instructions
//                if(slices.count(insn._src_reg)) {
//                    slices[key].insert(slices[insn._src_reg].begin(), slices[insn._src_reg].end());
//                    if(key!=insn._src_reg) {
//                        use[key].insert(insn._src_reg);
//                        used[insn._src_reg].insert(key);
//                    }
//                }
//                if(insn.is_ldx()){
//                    int mem_id=(insn._off<<8)|(insn.get_bytes_num()<<4)|insn._src_reg;
//                    if(slices.count(mem_id)) {
//                        slices[key].insert(slices[mem_id].begin(), slices[mem_id].end());
//                        if(key!=mem_id) {
//                            use[key].insert(mem_id);
//                            used[mem_id].insert(key);
//                        }
//                    }
//                }
//            }
//        }


//        for(auto [id,slice]:slices){
//            cout<<id<<" | ";
//            if(id<0||id>10){
//                cout<<(id&0x0f)<<' '<<(id&0xffff00)<<' '<<(id&0x0f0)<<endl;
//            }
//            cout<<endl;
//            for(auto insn_i:slice)
//                cout<<insn_i<<' ';
//            cout<<endl;
//        }
        unordered_map<int,vector<Insn>> rewrite_insns;
//        Node *rewrite_bb=new Node(*origin_bb);
        set<int> optimized_id;
        for(auto [target_id,insn_idxes]:slices){
//            cout<<(target_id&0x0f)<<' '<<(target_id&0xffff00)<<' '<<(target_id&0x0f0)<<endl;
            vector<int> insn_idxes_vec(insn_idxes.begin(),insn_idxes.end());
            vector<Insn> slice_rewrite_insns;
            Node sub_node=origin_bb->get_sub_node_by_selected_insns(insn_idxes_vec);
            if(insn_idxes_vec.size()<=win_size_){
                bool optimized=false;
                vector<Node> rewrites=match_pattern(&sub_node);
                if(!rewrites.empty()) {
                    sort(rewrites.begin(),rewrites.end());
                    for(int i=0;i<rewrites.size();i++){
                        vector<Node> specific_rewrites= get_specific_insns(rewrites[i]);
                        int j=0;
                        for(j=0;j<specific_rewrites.size();j++){
                            auto specific_rewrite=specific_rewrites[j];
                            Validator validator(&sub_node,&specific_rewrite);
                            cout<<"Validation started."<<endl;
                            sub_node.print_insns();
                            specific_rewrite.print_insns();
                            if(validator.verify()) {
                                optimized=true;
                                slice_rewrite_insns=specific_rewrite.insns();
                                break;
                            }
                        }
                        if(j<specific_rewrites.size())
                            break;
                    }
                }
                if(!optimized){
                   slice_rewrite_insns=sub_node.insns();
                }
            }
            else{
                bool changed=false;
                do{
                    changed=false;
                    slice_rewrite_insns.clear();
                    int start = 0;
                    while (start < sub_node.size()) {
                        int end = min(start + win_size_,sub_node.size());
                        Node *origin_sub_node = sub_node.get_sub_node(start, end);
                        vector<Node>rewrite_sub_nodes = match_pattern(origin_sub_node);
                        if (rewrite_sub_nodes.empty()) {
                            slice_rewrite_insns.emplace_back(sub_node.insns()[start]);
                            start++;
                        } else {
                            sort(rewrite_sub_nodes.begin(),rewrite_sub_nodes.end());
                            int i;
                            for(i=0;i<rewrite_sub_nodes.size();i++){
                                vector<Node> specific_rewrites= get_specific_insns(rewrite_sub_nodes[i]);
                                int j;
                                for(j=0;j<specific_rewrites.size();j++){
                                    cout<<"Validation started."<<endl;
                                    origin_sub_node->print_insns();
                                    specific_rewrites[j].print_insns();
                                    Validator validator(origin_sub_node,&specific_rewrites[j]);
                                    if(validator.verify()) {
                                        changed=true;
                                        sub_node.edit_insns(start,end,specific_rewrites[j].insns());
                                        sub_node.compute_final_static_info();
                                        break;
                                    }
                                }
                                if(j!=specific_rewrites.size())
                                    break;
                            }
                            if(i==rewrite_sub_nodes.size()){
                                slice_rewrite_insns.emplace_back(sub_node.insns()[start]);
                                start++;
                            }
                        }
                    }
                    sub_node.set_insns(slice_rewrite_insns);
                    sub_node.compute_final_static_info();
                }while(changed);
            }
            rewrite_insns[target_id]=slice_rewrite_insns;

            sub_node.print_insns();
            cout<<"id: "<<target_id<<endl;
            for(auto insn:slice_rewrite_insns){
                insn.print_insn();
            }
            cout<<endl;
        }
//        for(auto [id,children]:use){
//            cout<<id<<" uses ";
//            for(auto child:children)
//                cout<<child<<", ";
//            cout<<endl;
//        }
//        for(auto [id,children]:used){
//            cout<<id<<" used by ";
//            for(auto child:children)
//                cout<<child<<", ";
//            cout<<endl;
//        }
        for(auto it=rewrite_insns.begin();it!=rewrite_insns.end();){
            auto [target_id,insn]=*it;
            if(0<=target_id&&target_id<=10){
                if(!origin_bb->regs_live_out().count(target_id)){
                    it=rewrite_insns.erase(it);
                }
                else
                    it++;
            }
            else{
                it++;
            }
        }


        auto final_rewrite_insns= recompose_insns(rewrite_insns);
        cout<<"rewrite insns"<<endl;
        for(auto insn: final_rewrite_insns)
            insn.print_insn();
        if(!rewrite_insns.empty()&&final_rewrite_insns.empty())
            final_rewrite_insns=origin_bb->insns();
        Node* rewrite_bb=new Node(origin_bb->idx(),final_rewrite_insns);
        rewrite_bb->set_prog_attach_type(origin_bb->prog_type(),origin_bb->attach_type());
        rewrite_bb->set_init_static_info(origin_bb->init_static_info());
        rewrite_bb->compute_final_static_info();
//        rewrite_bb->set_insns(rewrite_insns);
//        rewrite_bb->clear_invalid_insns();
//        rewrite_bb->compute_final_static_info();
        return rewrite_bb;
    }

//    Node* PeepholeOptimizer::formalized_optimize_block(Node* origin_bb,bool allow_mem_combination) {
//        origin_bb->split_insns();
//        if (origin_bb->size() == 0)
//            return origin_bb;
//        auto insns=origin_bb->insns();
//        map<int,set<int>> slices; // <key, value> : <reg_id/memory_area, indexes of related instructions>
//        // How to represent memory_area by 'int': [32bits: offset (24 bits), size (4 bits), reg_id (4 bits)]
//        vector<int> slices_key_vec;
//        unordered_map<int,vector<int>> usage_records; // <key, value> : <target_key, keys that use target_key>
//        unordered_map<int,set<int>> use;
//        unordered_map<int,set<int>> def;
//        for(int i=0;i<insns.size();i++) {
//            auto insn = insns[i];
//            int key = 0;
//            bool is_key_new=false;
//            if (insn.is_st()) { // operations that change memory
//                int bytes_num=insn.get_bytes_num();
//                if(allow_mem_combination){
//                    int key_to_erase=0;
//                    for(auto [cur_id,cur_set]:slices){
//                        if((cur_id&0xf)==insn._dst_reg){
//                            int cur_off=(cur_id&(int)0xffffff00)>>8;
//                            int cur_size=(cur_id&0x0f0)>>4;
//                            int min_addr=min(cur_off,(int)insn._off),max_addr=max(cur_off+cur_size,insn._off+bytes_num);
//                            if(max_addr-min_addr<=8){
//                                key=(min_addr<<8)|((max_addr-min_addr)<<4)|insn._dst_reg;
//                                key_to_erase=cur_id;
//                                break;
//                            }
//                        }
//                    }
//                    if(key==0)
//                        key=(insn._off<<8)|(insn.get_bytes_num()<<4)|insn._dst_reg;
//                    else{
//                        if(key!=key_to_erase){
//                            is_key_new=true;
//                            slices[key].insert(slices[key_to_erase].begin(),slices[key_to_erase].end());
//                            slices.erase(key_to_erase);
//                        }
//                    }
//                }
//                else{
//                    key=(insn._off<<8)|(insn.get_bytes_num()<<4)|insn._dst_reg;
//                }
//            } else { // operations that change registers
//                key = insn._dst_reg;
//            }
//            if(!slices.count(key)||is_key_new)
//                slices_key_vec.emplace_back(key);
//            if(slices.count(key)&&0<=key&&key<=10){
//                while(!slices[key].empty()){
//                    bool is_last_deleted=false;
//                    auto last_insn=insns[*slices[key].rbegin()];
//                    if(last_insn._dst_reg==key){
//                        if(!insn.is_dst_reg_used()&&(!insn.is_src_reg_used()||insn._src_reg!=key)) {
//                            slices[key].erase(*slices[key].rbegin());
//                            is_last_deleted=true;
//                        }
//                    }
//                    else{
//                        if(!insn.is_src_reg_used()||insn._src_reg!=last_insn._dst_reg){
//                            slices[key].erase(*slices[key].rbegin());
//                            is_last_deleted=true;
//                        }
//                    }
//                    if(!is_last_deleted)
//                        break;
//                }
//            }
//            slices[key].insert(i);
//            usage_records[key].emplace_back(key);
//            if(insn.is_src_reg_used()){ // add src_reg related instructions
//                if(slices.count(insn._src_reg))
//                    slices[key].insert(slices[insn._src_reg].begin(),slices[insn._src_reg].end());
//                if(insn.is_ldx()){
//                    int mem_id=(insn._off<<8)|(insn.get_bytes_num()<<4)|insn._src_reg;
//                    if(slices.count(mem_id))
//                        slices[key].insert(slices[mem_id].begin(),slices[mem_id].end());
//                }
//            }
//        }
//        vector<Insn> rewrite_insns;
////        Node *rewrite_bb=new Node(*origin_bb);
//        set<int> optimized_id;
//        for(auto target_id:slices_key_vec){
//            vector<pair<int,vector<Insn>>> candidate_rewrites;
//            for(auto cur_id:usage_records[target_id]){
//                if(!slices.count(cur_id)||slices[cur_id].empty())
//                    continue;
//                if(0<=cur_id&&cur_id<=10&&!origin_bb->regs_live_out().count(cur_id))
//                    continue;
//                if(optimized_id.count(cur_id))
//                    continue;
//                optimized_id.insert(cur_id);
//                auto insn_idxes=slices[cur_id];
//                vector<int> insn_idxes_vec(insn_idxes.begin(),insn_idxes.end());
//                if(insn_idxes_vec.size()<=win_size_){
//                    bool optimized=false;
//                    Node sub_node=origin_bb->get_sub_node_by_selected_insns(insn_idxes_vec);
//                    vector<Node> rewrites=match_pattern(&sub_node);
//                    if(!rewrites.empty()) {
//                        sort(rewrites.begin(),rewrites.end());
//                        for(int i=0;i<rewrites.size();i++){
//                            vector<Node> specific_rewrites= get_specific_insns(rewrites[i]);
//                            int j=0;
//                            for(j=0;j<specific_rewrites.size();j++){
//                                auto specific_rewrite=specific_rewrites[j];
//                                Validator validator(&sub_node,&specific_rewrite);
//                                cout<<"Validation started."<<endl;
//                                sub_node.print_insns();
//                                specific_rewrite.print_insns();
//                                if(validator.verify()) {
//                                    optimized=true;
//                                    candidate_rewrites.push_back({cur_id,specific_rewrite.insns()});
//                                    break;
//                                }
////                                else{
////                                    sub_node.print_insns();
////                                    specific_rewrite.print_insns();
////                                }
//                            }
//                            if(j<specific_rewrites.size())
//                                break;
//                        }
//                    }
//                    if(!optimized){
//                        candidate_rewrites.push_back({cur_id,sub_node.insns()});
//                    }
//                }
//                else{
//                    Node cur_sub_node=origin_bb->get_sub_node_by_selected_insns(insn_idxes_vec);
//                    vector<Insn> sub_rewrite_insns;
//                    bool changed=false;
//                    do{
//                        changed=false;
//                        sub_rewrite_insns.clear();
//                        int start = 0;
//                        while (start < cur_sub_node.size()) {
//                            int end = min(start + win_size_,cur_sub_node.size());
//                            Node *origin_sub_node = cur_sub_node.get_sub_node(start, end);
//                            vector<Node>rewrite_sub_nodes = match_pattern(origin_sub_node);
//                            if (rewrite_sub_nodes.empty()) {
//                                sub_rewrite_insns.emplace_back(cur_sub_node.insns()[start]);
//                                start++;
//                            } else {
//                                sort(rewrite_sub_nodes.begin(),rewrite_sub_nodes.end());
//                                int i;
//                                for(i=0;i<rewrite_sub_nodes.size();i++){
//                                    vector<Node> specific_rewrites= get_specific_insns(rewrite_sub_nodes[i]);
//                                    int j;
//                                    for(j=0;j<specific_rewrites.size();j++){
//                                        cout<<"Validation started."<<endl;
//                                        origin_sub_node->print_insns();
//                                        specific_rewrites[j].print_insns();
//                                        Validator validator(origin_sub_node,&specific_rewrites[j]);
//                                        if(validator.verify()) {
//                                            changed=true;
//                                            cur_sub_node.edit_insns(start,end,specific_rewrites[j].insns());
//                                            cur_sub_node.compute_final_static_info();
//                                            break;
//                                        }
//                                    }
//                                    if(j!=specific_rewrites.size())
//                                        break;
//                                }
//                                if(i==rewrite_sub_nodes.size()){
//                                    sub_rewrite_insns.emplace_back(cur_sub_node.insns()[start]);
//                                    start++;
//                                }
//                            }
//                        }
//                        cur_sub_node.set_insns(sub_rewrite_insns);
//                        cur_sub_node.compute_final_static_info();
//                    }while(changed);
//                    candidate_rewrites.push_back({cur_id,sub_rewrite_insns});
//                }
//            }
////            cout<<"id "<<target_id<<endl;
////            for(auto can:candidate_rewrites){
////                cout<<endl;
////                for(auto insn:can.second)
////                    insn.print_insn();
////                cout<<endl;
////            }
//            vector<int> p_candidates(candidate_rewrites.size(),0);
//            for(int i=0;i<candidate_rewrites.size();i++){
//                while(p_candidates[i]<candidate_rewrites[i].second.size()){
//                    rewrite_insns.emplace_back(candidate_rewrites[i].second[p_candidates[i]]);
//                    for(int j=i+1;j<candidate_rewrites.size();j++){
//                        if(p_candidates[j]==candidate_rewrites[j].second.size())
//                            continue;
//                        if(candidate_rewrites[j].second[p_candidates[j]]==candidate_rewrites[i].second[p_candidates[i]])
//                            p_candidates[j]++;
//                    }
//                    p_candidates[i]++;
//                }
//            }
//        }
//        Node* rewrite_bb=new Node(origin_bb->idx(),rewrite_insns);
//        rewrite_bb->set_prog_attach_type(origin_bb->prog_type(),origin_bb->attach_type());
//        rewrite_bb->set_init_static_info(origin_bb->init_static_info());
//        rewrite_bb->compute_final_static_info();
////        rewrite_bb->set_insns(rewrite_insns);
////        rewrite_bb->clear_invalid_insns();
////        rewrite_bb->compute_final_static_info();
//        return rewrite_bb;
//    }

    Node* PeepholeOptimizer::optimize_block(Node* origin_bb) {
        origin_bb->split_insns();
        if (origin_bb->size() == 0)
            return origin_bb;
        if (origin_bb->size() <= win_size_) {
            vector<Node> rewrites=match_pattern(origin_bb);
            if(!rewrites.empty()) {
                sort(rewrites.begin(),rewrites.end());
                for(int i=0;i<rewrites.size();i++){
//                    cout<<"rewrite:"<<endl;
//                    rewrites[i].print_insns();
                    vector<Node> specific_rewrites= get_specific_insns(rewrites[i]);
                    for(auto &specific_rewrite:specific_rewrites){
//                        specific_rewrite.print_insns();
                        Validator validator(origin_bb,&specific_rewrite);
                        if(validator.verify()) {
                            return new Node(specific_rewrite);
                        }
                    }
                }
            }
            return origin_bb;
        }
        // window decomposition
        Node* origin_copy=new Node(*origin_bb);
        vector<Insn> rewrite_insns;
        bool changed=false;
        do{
//            origin_copy->print_insns();
            changed=false;
            rewrite_insns.clear();
            int start = 0;
            while (start < origin_copy->size()) {
                int end = min(start + win_size_,origin_copy->size());
                Node *origin_sub_node = origin_copy->get_sub_node(start, end);
                vector<Node>rewrite_sub_nodes = match_pattern(origin_sub_node);
                if (rewrite_sub_nodes.empty()) {
                    rewrite_insns.emplace_back(origin_copy->insns()[start]);
                    start++;
                } else {
                    sort(rewrite_sub_nodes.begin(),rewrite_sub_nodes.end());
                    int i;
                    for(i=0;i<rewrite_sub_nodes.size();i++){
                        vector<Node> specific_rewrites= get_specific_insns(rewrite_sub_nodes[i]);
                        int j;
                        for(j=0;j<specific_rewrites.size();j++){
                            origin_sub_node->print_insns();
                            specific_rewrites[j].print_insns();
                            cout<<"Validation started."<<endl;
                            Validator validator(origin_sub_node,&specific_rewrites[j]);
                            if(validator.verify()) {
                                changed=true;
                                origin_copy->edit_insns(start,end,specific_rewrites[j].insns());
                                origin_copy->compute_final_static_info();
                                break;
                            }
                        }
                        if(j!=specific_rewrites.size())
                            break;
                    }
                    if(i==rewrite_sub_nodes.size()){
                        rewrite_insns.emplace_back(origin_copy->insns()[start]);
                        start++;
                    }
                }
            }
        }while(changed);
        Node *rewrite = new Node(origin_bb->idx(), rewrite_insns);
        return rewrite;
    }

    int superbpf::PeepholeOptimizer::count_insns_except_ja(vector<Insn> &insns) {
        int res = insns.size();
        for (int i = insns.size() - 1; i >= 0; i--) {
            auto insn = insns[i];
            if (insn._opcode == JA && insn._off == 0) {
                res--;
            }
        }
        return res;
    }

    vector<Insn>
    superbpf::PeepholeOptimizer::optimize_with_report_output_to_path(std::string out_path, std::string sec_name,
                                                                     bpf_prog_type prog_type, bpf_attach_type attach_type,
                                                                     vector<Insn> &target_insns, bool is_1st_sec) {
        // compactness
        vector<Insn> rewrite_insns;
        if (target_insns.empty()) {
            cerr << "Insns empty." << endl;
            return rewrite_insns;
        }
        // construct cfg and analyze valid memory addresses, def-in and live-out variables
        CFG *origin = new CFG(prog_type, attach_type,target_insns);
        origin->static_analysis();
        map<int, Node *> bbs = origin->getAllNodes();  // basic blocks

        time_t begin, end;
        begin = clock();
        set<int> optimized_bbs;
        map<int, Node*> rewrite_bbs;
        map<int,double> blocks_opt_time;
        for (auto it = bbs.begin(); it != bbs.end(); it++) {
            int bb_idx = it->first;
            cout << "Optimizing block " << bb_idx << "..." << endl;
            auto block_begin_time = clock();
            Node *cur_bb = bbs.at(bb_idx);
            Node *cur_bb_copy(cur_bb);
//            Node* temp_rewrite_bb= formalized_optimize_block(cur_bb,false);
            Node* rewrite_bb=formalized_optimize_block(cur_bb,true);
            rewrite_bb->set_prog_attach_type(cur_bb->prog_type(), cur_bb->attach_type());
            rewrite_bb->set_split_insns(cur_bb->get_split_insns());
            rewrite_bb->add_regs_live_out(cur_bb->regs_live_out());
            if (cur_bb->get_insns_num()>rewrite_bb->get_insns_num()) {  // TODO: '>' or '>=' ?
                rewrite_bbs.insert({bb_idx, rewrite_bb});
                vector<Insn> cur_rewrite_insns = rewrite_bb->get_complete_insns(cur_bb_copy->size() - rewrite_bb->size());
                rewrite_insns.insert(rewrite_insns.end(), cur_rewrite_insns.begin(), cur_rewrite_insns.end());
                optimized_bbs.insert(bb_idx);
            } else {
                rewrite_bbs.insert({bb_idx, cur_bb});
                vector<Insn> origin_insns = cur_bb->get_complete_insns(0);
                rewrite_insns.insert(rewrite_insns.end(), origin_insns.begin(), origin_insns.end());
            }
            auto block_end_time = clock();
            double block_opt_time = (double) (block_end_time - block_begin_time) / CLOCKS_PER_SEC;
            blocks_opt_time.insert({bb_idx,block_opt_time});
        }
        end = clock();

        double opt_time = (double) (end - begin) / CLOCKS_PER_SEC;
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
//        for (auto [i,node]:bbs) {
//            cout<<"Block "<<i<<", NI: "<<node->size()<<endl;
//            print_consumed_time(blocks_opt_time[i]);
//        }
        for(int i:optimized_bbs){
            cout << "Origin ";
            bbs.at(i)->print_insns();
            bbs.at(i)->print_live_regs();
            bbs.at(i)->print_live_mems();
            bbs.at(i)->print_init_static_info();
            cout << endl << "Rewrite ";
            rewrite_bbs.at(i)->print_insns();
            for (int i = 0; i < 90; i++)
                cout << "-";
            cout << "\n";
        }
        cout << "Number of instructions: ";
        cout.flags(ios::fixed);
        cout << "origin: " << target_insns.size() << ", rewrite: " << count_insns_except_ja(rewrite_insns)
             << ", compression: " << setprecision(3) << ((double) (target_insns.size()- count_insns_except_ja(rewrite_insns)) / target_insns.size()) * 100
             << "%" << endl;
//        cout << "Instructions execution time: ";
//        auto cur_bbexec_time = compute_insns_exec_time(target_insns), rewrite_exec_time = compute_insns_exec_time(
//                rewrite_insns);
//        cout << "origin: " << cur_bbexec_time << " ns , rewrite: " << rewrite_exec_time << " ns, compression: "
//             << setprecision(3) << (cur_bbexec_time - rewrite_exec_time) / cur_bbexec_time * 100 << "%" << endl;
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

    vector<Node> PeepholeOptimizer::match_pattern(Node* origin) {
        vector<Node> rewrites;
        // get serialized insns
        unordered_map<int,int> reg_id_map; // <real reg id, serialized reg id>
        unordered_map<int,int> reg_off_map; // <real reg id, the first visited offset>
        unordered_map<int,int> imm_map; // <real imm, serialized imm>
        string origin_insns_str= origin->get_serialized_insns_str(reg_id_map,reg_off_map,imm_map,set<int>());
        // search for rewrite
        try {
            // Connect to the PostgreSQL database
            pqxx::connection conn("dbname=xxdb user=xx password=xx host=localhost port=5432");
            string sql="SELECT id, rewrite FROM rewrite_rules WHERE origin = "+origin_insns_str;
            if (conn.is_open()) {
                // Create a transactional object
                pqxx::work txn(conn);
                // Execute a SELECT query
                pqxx::result res = txn.exec(sql);
                // Process the result
                if(!res.empty()){
                    for(auto item:res){
                        cout<<item[1].as<string>()<<endl;
                        vector<Insn> rewrite_insns= get_deserialized_insns(item[1].as<string>(),reg_id_map,reg_off_map,imm_map);
                        rewrites.emplace_back(Node(origin->idx(),rewrite_insns));
                    }

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
        return rewrites;
    }

    void PeepholeOptimizer::print_consumed_time(double consumed_time) {
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

    /* Attention: return res may contain instructions with srg_reg set as -1 */
    vector<Insn> PeepholeOptimizer::get_deserialized_insns(const std::string &insns_str,
                                                           const std::unordered_map<int, int> &reg_id_map,
                                                           const std::unordered_map<int, int> &reg_off_map,
                                                           const std::unordered_map<int, int> &imm_map){
        // reverse map
        unordered_map<int, int> reverse_reg_id_map; // <serialized reg id, real reg id>
        unordered_map<int, int> reverse_imm_map; // <serialized imm, real imm>
        for(auto [k,v]:reg_id_map){
            reverse_reg_id_map[v]=k;
        }
        for(auto [k,v]:imm_map){
            reverse_imm_map[v]=k;
        }
        // process string-type rewrite
        vector<Insn> insns;
        regex insns_num_regex(R"((\d*),(\d*),(-?\d*),(-?\d*),(-?\d*))");
//        cout<<insns_str<<endl;
        // Use sregex_iterator to find all matches
        unordered_map<int,unordered_map<int,int>> related_regs;
        for (std::sregex_iterator it(insns_str.begin(), insns_str.end(), insns_num_regex), end; it != end; ++it) {
//            cout<<(*it)[1].str()<<' '<<(*it)[2].str()<<' '<<(*it)[3].str()<<' '<<(*it)[4].str()<<' '<<(*it)[5].str()<<endl;
            vector<int> operands={stoi((*it)[1].str()),stoi((*it)[2].str()),stoi((*it)[3].str()),stoi((*it)[4].str()),stoi((*it)[4].str())};
            Insn insn;
            insn._opcode=operands[0];
            insn._dst_reg=reverse_reg_id_map[operands[1]];
            if(insn.is_src_reg_used()) {
                if(operands[2]==-1)
                    insn._src_reg=-1;
                else if(reverse_reg_id_map.count(operands[2]))
                    insn._src_reg = reverse_reg_id_map[operands[2]];
                else
                    return {};
            }
            else
                insn._src_reg=0;
            if(insn._opcode==MOV32XY||insn._opcode==MOV64XY){
                related_regs[insn._dst_reg].insert({insn._src_reg,0});
                related_regs[insn._src_reg].insert({insn._dst_reg,0});
            }
            else if(insn._opcode==ADD32XC||insn._opcode==ADD64XC){
                for(auto &[reg_id,off]:related_regs[insn._dst_reg]){
                    off+=insn._imm;
                    related_regs[reg_id][insn._dst_reg]-=insn._imm;
                }
            }
            else if(insn._opcode==SUB32XC||insn._opcode==SUB64XC){
                for(auto &[reg_id,off]:related_regs[insn._dst_reg]){
                    off-=insn._imm;
                    related_regs[reg_id][insn._dst_reg]+=insn._imm;
                }
            }
            else if(!insn.is_st()){ // all instructions that change dst_reg's value
                if(related_regs.count(insn._dst_reg)){
                    for(auto [reg_id,off]:related_regs[insn._dst_reg]){
                        related_regs[reg_id].erase(insn._dst_reg);
                    }
                    related_regs.erase(insn._dst_reg);
                }
            }
            if(insn.is_st()||insn.is_ldx()){
                // Attention: the action below is used to prevent rewrites' reg_off information from being lost
                // in situations where rewrite's base register is different from origins (usually because of
                // some registers have same values).
                int base_reg=insn.is_st()?insn._dst_reg:insn._src_reg;
                if(reg_off_map.count(base_reg)){
                    insn._off = reg_off_map.at(base_reg) + operands[3];
                }
                else{
                    bool found=false;
                    for(auto [reg_id,off]:related_regs[base_reg]){
                        if(reg_off_map.count(reg_id)){
                            found=true;
                            insn._off=reg_off_map.at(reg_id)+ operands[3]+off;
                            cout<<insn._dst_reg<<' '<<reg_id<<' '<<reg_off_map.at(reg_id)<<' '<<operands[3]<<' '<<off<<endl;
                            break;
                        }
                    }
                    if(!found) {
                        return {};
                    }
                }
            }
            else
                insn._off=0;
            insn._imm=stoi((*it)[5].str()); // TODO
            insns.emplace_back(insn);
        }
        return insns;
    }

    bool PeepholeOptimizer::check_safety(Node node) {
        vector<State *> states;
        for (int i = 0; i <= node.size(); i++) {
            states.emplace_back(new State(i));
        }
        TestcaseGen testcaseGen;
        InsnSimulator insnSimulator;
        auto testcase=testcaseGen.gen_random_testcase();
        states[0]->copy_from_state(testcase->init_state());
        auto insns=node.insns();
        for(int i=0;i<insns.size();i++){
            auto insn=insns[i];
            if (Verifier::do_check(states[i],insns[i]) != 0) {
                return false;
            }
            insnSimulator.run(insn._opcode, insn._dst_reg, insn._src_reg, insn._off, insn._imm,
                              states[i], states[i+1]);
        }
        return true;
    }

    void dfs(Node& cur_node,vector<int>& uncertain_src_reg_insns_no,vector<Node>& res,int cur_depth){
        if(cur_depth==uncertain_src_reg_insns_no.size()){
            res.emplace_back(cur_node);
            return;
        }
        for(int i=0;i<=10;i++){
            vector<Insn> insns=cur_node.insns();
            insns[uncertain_src_reg_insns_no[cur_depth]]._src_reg=i;
            cur_node.set_insns(insns);
            dfs(cur_node,uncertain_src_reg_insns_no,res,cur_depth+1);
        }
    }

    vector<Node> PeepholeOptimizer::get_specific_insns(Node rough_node) {
        vector<Node> res;
        vector<int> uncertain_src_reg_insns_no;
        for(int i=0;i<rough_node.insns().size();i++){
            auto insn=rough_node.insns()[i];
            if(insn._src_reg==-1)
                uncertain_src_reg_insns_no.emplace_back(i);
        }
        if(uncertain_src_reg_insns_no.empty()){
            res.emplace_back(rough_node);
            return res;
        }
        dfs(rough_node,uncertain_src_reg_insns_no,res,0);
        return res;
    }

    std::vector<Node> PeepholeOptimizer::get_slices(Node *node,bool allow_mem_combination,map<int,set<int>>& slices) {
        node->split_insns();
        vector<Node> res;
        auto insns=node->insns();
//        map<int,set<int>> slices; // <key, value> : <reg_id/memory_area, indexes of related instructions>
        // How to represent memory_area by 'int': [32bits: offset (24 bits), size (4 bits), reg_id (4 bits)]
        for(int i=0;i<insns.size();i++){
            auto insn=insns[i];
//            cout<<"insn "<<i<<": ";
            insns[i].print_insn();
            int key=0;
            if(insn.is_st()){ // operations that change memory
                int bytes_num=insn.get_bytes_num();
                if(allow_mem_combination){
                    int key_to_erase=0;
                    for(auto [cur_id,cur_set]:slices){
                        if((cur_id&0xf)==insn._dst_reg){
                            int cur_off=(cur_id&(int)0xffffff00)>>8;
                            int cur_size=(cur_id&0x0f0)>>4;
                            int min_addr=min(cur_off,(int)insn._off),max_addr=max(cur_off+cur_size,insn._off+bytes_num);
                            if(max_addr-min_addr<=8){ // size<=8
                                key=(min_addr<<8)|((max_addr-min_addr)<<4)|insn._dst_reg;
                                key_to_erase=cur_id;
                                break;
                            }
//                            if(!(cur_off>insn._off+bytes_num)&&!(insn._off>cur_off+cur_size)){
//                                int min_addr=min(cur_off,(int)insn._off),max_addr=max(cur_off+cur_size,insn._off+bytes_num);
//                                key=(min_addr<<8)|((max_addr-min_addr)<<4)|insn._dst_reg;
//                                key_to_erase=cur_id;
//                                break;
//                            }
                        }
                    }
                    if(key==0)
                        key=(insn._off<<8)|(insn.get_bytes_num()<<4)|insn._dst_reg;
                    else{
                        if(key!=key_to_erase){
                            slices[key].insert(slices[key_to_erase].begin(),slices[key_to_erase].end());
                            slices.erase(key_to_erase);
                        }
                    }
                }
                else{
                    key=(insn._off<<8)|(insn.get_bytes_num()<<4)|insn._dst_reg;
                }
            }
            else{ // operations that change registers
                key=insn._dst_reg;
            }
            if(slices.count(key)&&0<=key&&key<=10){
                while(!slices[key].empty()){
                    bool is_last_deleted=false;
                    auto last_insn=insns[*slices[key].rbegin()];
                    if(last_insn._dst_reg==key){
                        if(!insn.is_dst_reg_used()&&(!insn.is_src_reg_used()||insn._src_reg!=key)) {
                            slices[key].erase(*slices[key].rbegin());
                            is_last_deleted=true;
                        }
                    }
                    else{
                        if(!insn.is_src_reg_used()||insn._src_reg!=last_insn._dst_reg){
                            slices[key].erase(*slices[key].rbegin());
                            is_last_deleted=true;
                        }
                    }
                    if(!is_last_deleted)
                        break;
                }
            }
            slices[key].insert(i);
            if(insn.is_src_reg_used()){ // add src_reg related instructions
                if(slices.count(insn._src_reg))
                    slices[key].insert(slices[insn._src_reg].begin(),slices[insn._src_reg].end());
                if(insn.is_ldx()){
                    int mem_id=(insn._off<<8)|(insn.get_bytes_num()<<4)|insn._src_reg;
                    if(slices.count(mem_id))
                        slices[key].insert(slices[mem_id].begin(),slices[mem_id].end());
                }
            }
        }
        UnionFind uf;
        for(auto it=slices.begin();it!=slices.end();it++){
            int id1=it->first;
            int off1=(id1&(int)0xffffff00)>>8;
            int size1=(id1&0x0f0)>>4;
            int dst1=id1&0x0f;
            auto it_begin=it;
            it_begin++;
            for(auto it2=it_begin;it2!=slices.end();it2++){
                int id2=it2->first;
                if(id1==id2)
                    continue;
                int off2=(id2&(int)0xffffff00)>>8;
                int size2=(id2&0x0f0)>>4;
                int dst2=id2&0x0f;
                if(dst1==dst2){
                    int min_addr=(off1<off2)?off1:off2;
                    int max_addr=(off1+size1>off2+size2)?off1+size1:off2+size2;
                    if(!(off1>off2+size2)&&!(off2>off1+size1)){
                        uf.unite(id1,id2);
                    }
//                    if(max_addr-min_addr<=8){
//                        uf.unite(id1,id2);
//                    }
                }
            }
        }
        // combine adjacent memory regions
        auto uf_set=uf.get_components();
        for(auto [root,cur_set]:uf_set){
            int min_off=(root&(int)0xffffff00)>>8;
            int max_off=min_off+((root&0x0f0)>>4);
            int root_dst=root&0x0f;
            set<int> new_set=slices[root];
            slices.erase(root);
//            cout<<"root:"<<endl;
            for(auto cur_id:cur_set){
                if(!slices.count(cur_id))
                    continue;
                int off=(cur_id&(int)0xffffff00)>>8;
                int size=(cur_id&0x0f0)>>4;
                int dst=cur_id&0x0f;
                assert(root_dst==dst);
                min_off=(off<min_off)?off:min_off;
                max_off=(off+size>max_off?off+size:max_off);
                new_set.insert(slices[cur_id].begin(),slices[cur_id].end());
                slices.erase(cur_id);
            }
            int new_id=(min_off<<8)|((max_off-min_off)<<4)|root_dst;
            slices[new_id]=new_set;
        }
        for(auto [target_id,insn_idxes]:slices){
            if(0<=target_id&&target_id<=10){
                cout<<"r"<<target_id<<":"<<endl;
            }
            else{
                int base_reg=target_id&0xf,off=(target_id&(int)0xffffff00)>>8,size=(target_id&0xf0)>>4;
                printf("Mem: [r%d + %d, r%d + %d)\n",base_reg,off,base_reg,off+size);
            }
            for(auto i:insn_idxes){
                cout<<i<<": ";
                insns[i].print_insn();
            }
            cout<<endl;
            if(0<=target_id&&target_id<=10&&!node->regs_live_out().count(target_id))
                continue;
            vector<int> insn_idxes_vec(insn_idxes.begin(),insn_idxes.end());
            Node sub_node=node->get_sub_node_by_selected_insns(vector<int>(insn_idxes_vec.begin(),insn_idxes_vec.end()));
            res.emplace_back(sub_node);
        }
        return res;
    }

    Node PeepholeOptimizer::cegis(Node origin){ // used to optimize sub nodes
        int candidate_id = 0;
        Node rewrite(origin);
        bool validation_res = false;
        auto win_synthesizer = WinSynthesizer(&origin, win_size_,PruningType::ALL);
        origin.print_insns();
        origin.print_live_regs();
        origin.print_live_mems();
        win_synthesizer.set_example_name(cur_example_name);
        Node* cur_rewrite= nullptr;
        while (!validation_res) {
            win_synthesizer.set_node(&origin);
            cur_rewrite = win_synthesizer.synthesize_with_context();
            assert(cur_rewrite!= nullptr);
            if (cur_rewrite == nullptr) {
                return origin;
            }
            cur_rewrite->set_init_static_info(origin.init_static_info());
            cur_rewrite->compute_final_static_info();
            Validator validator(&origin,cur_rewrite);
            cout<<endl<<"Validation started."<<endl;
            origin.print_insns();
            cur_rewrite->print_insns();
            validation_res = validator.verify();
            cout<<endl;
            if (!validation_res) {
                auto counterexample=validator.get_counterexample();
                win_synthesizer.add_testcase(counterexample);
                counterexample->print_testcase();
                delete cur_rewrite;
                cur_rewrite= nullptr;
            }
            candidate_id++;
            // TODO
            if (candidate_id >= 5) {
                break;
            }
            assert(candidate_id <= 5);
        }
        if(cur_rewrite)
            rewrite=Node(*cur_rewrite);
        return rewrite;
    }

    void PeepholeOptimizer::collect_block_opt_patterns(bpf_prog_type prog_type, bpf_attach_type attach_type,
                                                 vector<Insn> &target_insns,string example_name,int bb_idx) {
        cur_example_name=example_name;
        CFG *origin = new CFG(prog_type,attach_type, target_insns);
        origin->static_analysis();
        map<int, Node *> bbs = origin->getAllNodes();  // basic blocks

        Node *origin_bb = bbs.at(bb_idx);
//        vector<Node> sub_nodes= get_slices(origin_bb,false);
//        for(auto sub_node:sub_nodes){
//            cegis(sub_node);
//        }
        map<int,set<int>> slices;
        vector<Node> sub_nodes= get_slices(origin_bb,true,slices);
        for(auto sub_node:sub_nodes){
            bool changed=true;
            auto cur_node=sub_node;
            while(changed){
                auto rewrite=cegis(cur_node);
                if(rewrite.size()==cur_node.size()){
                    changed=false;
                    break;
                }
                cur_node.set_insns(rewrite.insns());
                cur_node.compute_final_static_info();
            }
        }
    }

    void PeepholeOptimizer::collect_opt_patterns(bpf_prog_type prog_type, bpf_attach_type attach_type,
                                                 vector<Insn> &target_insns,string example_name) {
        cur_example_name=example_name;
        CFG *origin = new CFG(prog_type,attach_type, target_insns);
        origin->static_analysis();
        map<int, Node *> bbs = origin->getAllNodes();  // basic blocks

        for (auto it = bbs.begin(); it != bbs.end(); it++) {
            int bb_idx = it->first;
            cout << "Optimizing block " << bb_idx << "..." << endl;
            Node *origin_bb = bbs.at(bb_idx);
//            vector<Node> sub_nodes= get_slices(origin_bb,false);
//            for(auto sub_node:sub_nodes){
//                cegis(sub_node);
//            }
            map<int,set<int>> slices;
            auto sub_nodes= get_slices(origin_bb,true,slices);
            for(auto sub_node:sub_nodes){
                bool changed=true;
                auto cur_node=sub_node;
                while(changed){
                    if(cur_node.size()==0)
                        break;
                    auto rewrite=cegis(cur_node);
                    if(rewrite.size()==cur_node.size()){
                        changed=false;
                        break;
                    }
                    cur_node.set_insns(rewrite.insns());
                    cur_node.compute_final_static_info();
                }
            }
        }
    }
}

