import json, itertools, os, logging, traceback, hashlib, statistics
import networkx as nx
from pebble import ProcessPool

from attack_paths import retrieve_privileges, get_vulns_by_hostname, get_derivative_features
import config as config

"""
This function generates the reachability graph from the network used as the base
to generate samples
"""
def build_reachability_graph(edges_reachability, devices):   
    G = nx.DiGraph()
    nodesId = []
    for edge_r in edges_reachability:
        src_id = edge_r["host_link"][0]
        dst_id = edge_r["host_link"][1]
        cve_list_dst = []

        for dev in devices:
            if dev["hostname"] == src_id:
                src_node = dev
            if dev["hostname"] == dst_id:
                dst_node = dev
                cve_list_dst = get_vulns_by_hostname(dst_id,devices)
        
        if src_node["hostname"] not in nodesId:
            nodesId.append(src_node["hostname"])
            G.add_node(edge_r["host_link"][0])
        if dst_node["hostname"] not in nodesId:
            nodesId.append(dst_node["hostname"])
            G.add_node(edge_r["host_link"][1])
        G.add_edge(edge_r["host_link"][0],edge_r["host_link"][1],vulns=cve_list_dst)
    return G

def reachability_to_attack(reachability_path,devices,vulnerabilities,path_vulns):
    trace = ""
    impacts=[]
    likelihoods=[]
    scores=[]

    counter_edge=0
    for edge in reachability_path:
        target_hostname = edge[1]
        attack_vuln = path_vulns[counter_edge]
        vuln,pre,post = retrieve_privileges(attack_vuln,vulnerabilities)
        src=pre+"@"+str(edge[0])
        dst=post+"@"+str(target_hostname)

        if edge == reachability_path[-1]: trace += src+"#"+attack_vuln+"#"+dst
        else: trace += src+"#"+attack_vuln+"#"+dst+"##"

        impact,likelihood,score=get_derivative_features(vuln)
        impacts.append(impact)
        likelihoods.append(likelihood)
        scores.append(score)
        counter_edge+=1

    return {
        "id": hashlib.sha256(str(trace).encode("utf-8")).hexdigest(),
        "trace": trace,
        "length": len(impacts),
        "impact": impacts[len(impacts)-1],
        "likelihood": statistics.mean(likelihoods),
        "score": statistics.median(scores),
    }

"""
This function generate all the attack paths (ground truth) for a given network
"""
def generate_all_paths(subfolder):
    logging.basicConfig(filename='logging/generation.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s: %(message)s')

    network_file = config.ROOT_FOLDER+subfolder+"/"+config.gt_folder+subfolder+".json"
    gt_paths_file = config.ROOT_FOLDER+subfolder+"/"+config.gt_paths
    if os.path.exists(gt_paths_file):
        logging.warning("Ground Truth %s already GENERATED.", gt_paths_file)
        return
    

    with open(network_file) as net_f:
            file_content = json.load(net_f)
    edges_reachability = file_content["edges"]
    devices = file_content["devices"]
    vulnerabilities = file_content["vulnerabilities"]
    
    G = build_reachability_graph(edges_reachability, devices)
    vulns = nx.get_edge_attributes(G,'vulns')

    logging.info("[START] generation of ground truth %s", gt_paths_file)

    try:
        for src in G.nodes:
            for dst in G.nodes:
                # if src != dst:
                attack_paths=[]
                for p in nx.all_simple_edge_paths(G,src,dst):
                    vulns_combination = []
                    for edge in p:
                        vulns_combination.append(vulns[edge])
                    all_comb = list(itertools.product(*vulns_combination))
                    for combination in all_comb:
                        AP = reachability_to_attack(p,devices,vulnerabilities,combination)
                        attack_paths.append(AP)

                existing_paths=[]
                if os.path.exists(gt_paths_file):
                    with open(gt_paths_file) as f: existing_paths = json.load(f)
                
                with open(gt_paths_file, "w") as outfile:
                    json_data = json.dumps(existing_paths+attack_paths, default=lambda o: o.__dict__, indent=2)
                    outfile.write(json_data)
                    
                logging.info("[ITERATION] file %s paths from source %d to dst %d computed: %d", gt_paths_file, src,dst, len(existing_paths+attack_paths))

        logging.info("[CONCLUSION] generation of %s with %d paths.", gt_paths_file, len(existing_paths+attack_paths))
    
    except Exception as e:
        traceback.print_exc()
        logging.error("[ERROR] %s on %s", e,gt_paths_file)
    
    return len(existing_paths+attack_paths)

if __name__ == "__main__":
    """
    Build ground truths (all paths generation)
    """
    parameters_gt = []
    for subfolder in os.listdir(config.ROOT_FOLDER):
        parameters_gt.append(subfolder)
    with ProcessPool(max_workers=config.num_cores) as pool:
        process = pool.map(generate_all_paths, parameters_gt)