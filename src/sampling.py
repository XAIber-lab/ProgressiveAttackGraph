import os, json, random
import networkx as nx

def random_sampling(G,start_node,len_paths):
    path = [start_node]
    for _ in range(len_paths - 1):
        neighbors = list(G.neighbors(path[-1]))
        if not neighbors:
            break
        next_node = random.choice(neighbors)
        path.append(next_node)

    edges_path = []
    for i in range(1,len(path)):
        edges_path.append((path[i-1],path[i]))
    return list(dict.fromkeys(edges_path))

def DFSampling(G,start_node,len_paths):
    return list(dict.fromkeys(nx.dfs_edges(G, source=start_node, depth_limit=len_paths)))

def BFSampling(G,start_node,len_paths):
    return list(dict.fromkeys(nx.bfs_edges(G, source=start_node, depth_limit=len_paths)))

def commit_paths_to_file(attack_paths,filename,iteration):
    existing_ids=[]
    count_duplicates=0
    all_paths=[]

    if os.path.exists(filename):
        with open(filename) as f: all_paths = json.load(f)
        existing_ids = [a_dict["id"] for a_dict in all_paths]
    
    for path in attack_paths:
        if path["id"] not in existing_ids:
            path["iteration"] = iteration
            all_paths.append(path)
        else: count_duplicates+=1
    
    with open(filename, "w") as outfile:
        json_data = json.dumps(all_paths, default=lambda o: o.__dict__, indent=2)
        outfile.write(json_data)

    if len(attack_paths)<=0: return len(all_paths), 0
    return len(all_paths), count_duplicates/len(attack_paths)

def write_base_sample_iteration(filename, list_stats):
    all_samples=[]

    if os.path.exists(filename):
        with open(filename) as f: all_samples = json.load(f)
    
    all_samples+=list_stats

    with open(filename, "w") as outfile:
        json_data = json.dumps(all_samples, default=lambda o: o.__dict__, indent=2)
        outfile.write(json_data)
