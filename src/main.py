import os, logging, json, random, csv, traceback, time, statistics
from pebble import ProcessPool
import networkx as nx

from reachability_graph import build_dataset
from generation import generate_all_paths
import attack_paths as ap
import features_management as fm
import sampling as sampling
import steering as steering
import config as config

def sample_paths_reachability(G,rg_nodes,num_samples,method):
    sampled_paths=[]
    for i in range(0,num_samples):
        start_node = random.choice(rg_nodes)
        sampled_len = random.randint(2,len(rg_nodes))
        if method=="dfs":
            sampled_paths.append(sampling.DFSampling(G,start_node,sampled_len))
        elif method=="bfs":
            sampled_paths.append(sampling.BFSampling(G,start_node,sampled_len))
        else:
            sampled_paths.append(sampling.random_sampling(G,start_node,sampled_len))
    return [list(tupl) for tupl in {tuple(item) for item in sampled_paths} if list(tupl) != []]

def run_experiment(params):
    logging.basicConfig(filename='logging/experiments.log', level=logging.DEBUG, 
                        format='%(asctime)s - %(levelname)s: %(message)s')
    subfolder,sampling_method,query,steer_type,num_exp = params

    network_file = config.ROOT_FOLDER+subfolder+"/"+config.gt_folder+subfolder+".json"
    filename_sample_query = config.ROOT_FOLDER+subfolder+"/"+sampling_method+\
                "/exp"+str(num_exp)+config.get_query_samples_filename(steer_type)
    filename_sample_other = config.ROOT_FOLDER+subfolder+"/"+sampling_method+\
                "/exp"+str(num_exp)+config.get_samples_filename(steer_type)
    filename_sampling_stats = config.ROOT_FOLDER+subfolder+"/"+sampling_method+\
                "/exp"+str(num_exp)+"/"+config.stats_sampling
    filename_steering_stats = config.ROOT_FOLDER+subfolder+"/"+sampling_method+\
                "/exp"+str(num_exp)+"/"+config.stats_steering

    cc = config.collision_control
    if steer_type=="steering": cc = config.collision_control*2

    with open(network_file) as net_f: file_content = json.load(net_f)
    edges_reachability = file_content["edges"]
    devices = file_content["devices"]
    vulnerabilities = file_content["vulnerabilities"]

    if not os.path.exists(filename_steering_stats):
        config.write_header_steering_performance(filename_steering_stats)

    RG=nx.DiGraph()
    for net_edge in edges_reachability: 
        RG.add_edge(net_edge["host_link"][0],net_edge["host_link"][1])
    rg_nodes = list(RG.nodes())

    logging.info("[START] folder %s, experiment %d, sampling: %s, steering: %s", 
                 subfolder,num_exp,sampling_method,steer_type)

    """
    Ground truth of base features distribution
    """
    base_features_gt_filename = config.ROOT_FOLDER+subfolder+"/"+config.gt_base
    GT_base_stats = fm.base_features_distro(vulnerabilities)
    if not os.path.exists(base_features_gt_filename):
        with open(base_features_gt_filename, "w") as outfile:
            json_base_gt = json.dumps(GT_base_stats, default=lambda o: o.__dict__, indent=2)
            outfile.write(json_base_gt)

    """
    Sampling the reachability paths
    """
    steering_vulnerabilities=[]
    sampled_vulnerabilities=[]

    collisions_query=[0]
    collisions_other=[0]
    collision_condition_other=0
    collision_condition_query=0

    isSteering=False
    stopSteering=False
    track_precisions=[]
    low_precision_restart=[]
    median_num_restart=0
    median_precision=0

    count_iteration=0
    count_same_query=0
    old_num_query_paths=0
    start_generation = time.perf_counter()
    try:
        while(True):
            count_iteration+=1
            """
            Breaking conditions
            """
            if steer_type=="steering" and count_same_query==config.max_iteration_same_query: break
            if steer_type=="steering" and median_num_restart!=0 and collision_condition_query>=config.collision_end_value_query and \
            count_iteration-median_num_restart<=count_iteration*config.decision_num_restart: break
            if steer_type=="none" and collision_condition_other>=config.collision_end_value_other \
                        and collision_condition_query>=config.collision_end_value_query: break

            sampled_paths = sample_paths_reachability(RG,rg_nodes,config.num_samples,sampling_method)
            
            attack_paths_query = []
            attack_paths_other = []
            for path in sampled_paths:
                single_attack_path, path_vulns = ap.reachability_to_attack(path,devices,vulnerabilities,steering_vulnerabilities)
                if steering.isQuery(query,single_attack_path): attack_paths_query.append(single_attack_path)
                else: attack_paths_other.append(single_attack_path)
                
                for new_vuln in path_vulns:
                    existing_ids = [val['id'] for val in sampled_vulnerabilities]
                    if new_vuln["id"] not in existing_ids:
                        sampled_vulnerabilities.append(new_vuln)
            
            num_query_paths, coll_query = sampling.commit_paths_to_file(attack_paths_query,filename_sample_query,count_iteration)
            collisions_query.append(coll_query)
            num_other_paths, coll_other = sampling.commit_paths_to_file(attack_paths_other,filename_sample_other,count_iteration)
            collisions_other.append(coll_other)

            collision_condition_query = statistics.mean(collisions_query[-cc:])
            collision_condition_other = statistics.mean(collisions_other[-cc:])
            
            current_precision = len(attack_paths_query)/(len(attack_paths_query)+len(attack_paths_other))
            track_precisions.append(current_precision)

            if collision_condition_query >= config.start_steering_collision and \
             num_query_paths>=10 and num_other_paths>=10 and steer_type=="steering": isSteering=True
            
            start_steering = time.perf_counter()
            if isSteering and steer_type=="steering":
                if not stopSteering:
                    steering_vulnerabilities=steering.get_steering_vulns(filename_sample_query,filename_sample_other,vulnerabilities)
                    logging.info("[RESTART STEERING] of setting %s experiment %d at iteration %d",
                            subfolder,num_exp,count_iteration)
                    stopSteering=True

                median_precision = statistics.mean(track_precisions[-config.smoothing_window:])
                if median_precision > config.precision_control*current_precision:
                    stopSteering=False
                    
                    low_precision_restart.append(count_iteration)
                    if len(low_precision_restart)>5:
                        median_num_restart = statistics.mean(low_precision_restart[-config.decision_window:])
            
            if steer_type=="none":
                distro_sampled_vuln = fm.base_features_distro(sampled_vulnerabilities)
                stats_compare_vuln = fm.compare_stats(GT_base_stats, distro_sampled_vuln)

                stats_compare_vuln["type"] = "stats"
                stats_compare_vuln["collision_rate"] = (collision_condition_other+collision_condition_query)/2
                stats_compare_vuln["iteration"] = count_iteration
                stats_compare_vuln["sample_size"] = config.num_samples

                distro_sampled_vuln["type"] = "sample"
                distro_sampled_vuln["collision_rate"] = (collision_condition_other+collision_condition_query)/2
                distro_sampled_vuln["iteration"] = count_iteration
                distro_sampled_vuln["sample_size"] = config.num_samples

                sampling.write_base_sample_iteration(filename_sampling_stats,[distro_sampled_vuln,stats_compare_vuln])

            end_time = time.perf_counter()

            if old_num_query_paths == num_query_paths: count_same_query+=1
            else: count_same_query=0
            old_num_query_paths = num_query_paths

            with open(filename_steering_stats, "a", newline='') as f_steer:
                writer = csv.writer(f_steer)
                writer.writerow([count_iteration,config.num_samples,num_query_paths,
                                 num_other_paths,steer_type,isSteering,collision_condition_query,
                                 collision_condition_other,
                                 end_time-start_generation,end_time-start_steering,query["id"],median_precision])
                
            if count_iteration%25 == 0:
                if steer_type == "steering":
                    logging.info("Iteration %d of setting %s experiment %d %s: current/median precision %f/%f, median restart %f, collisions (query,other): %f - %f, num paths: %d",
                             count_iteration,subfolder,num_exp,steer_type,current_precision,median_precision,median_num_restart,collision_condition_query,collision_condition_other, num_query_paths)
                else:
                    logging.info("Iteration %d of setting %s experiment %d %s: collision query %f, collision other %f",
                             count_iteration,subfolder,num_exp,steer_type,collision_condition_query,collision_condition_other)
        logging.info("[END] folder %s, experiment %d, sampling: %s, steering: %s, collisions (query,other): %f - %f", subfolder,num_exp,sampling_method,steer_type,collision_condition_query,collision_condition_other)
        end_generation = time.perf_counter()
        logging.info("SAMPLE RATE: %d, TIME: %f, NUM PATH: %d",config.num_samples, end_generation-start_generation, num_query_paths)
    except Exception as e:
        traceback.print_exc()
        logging.error("[ERROR] %s on experiment %s, sampling: %s, steering: %s", e,subfolder,sampling_method,steer_type)
    

if __name__ == "__main__":
    if not os.path.exists("logging/"): os.mkdir("logging/")

    """
    Build dataset reachability graphs according to network settings 
    hosts,vulnerabilities,topology,diversity,distribution (see config file)
    """
    queries = [config.QUERY] 
    # queries = config.all_combination_queries()
    # queries = config.sok_queries
    
    build_dataset(clean_data=config.clean_dataset, num_exps=config.num_experiments*len(queries))

    params=[]
    parameters_gt = []
    for network in os.listdir(config.ROOT_FOLDER):
        parameters_gt.append(network)
        for method in config.sampling_algorithms:
            for steer_type in config.steering_types:
                count=1
                for experiment in range(1,config.num_experiments+1):
                    for q in queries:
                        params.append([network,method,q,steer_type,count])
                        count+=1
    
    if config.start_with_gt:
        with ProcessPool(max_workers=config.num_cores) as pool:
            process = pool.map(generate_all_paths, parameters_gt)

    with ProcessPool(max_workers=config.num_cores) as pool:
        process = pool.map(run_experiment, params)
        