import json, csv, itertools

start_with_gt = True

### BENCHMARK parameters
num_cores = 2
num_experiments = 1
clean_dataset = True
collision_end_value_query = 0.9
collision_end_value_other = 0.9

### SAMPLING parameters
num_samples = 100
sampling_algorithms = ["random"] #other options: "bfs", "dfs"
steering_types = ["steering","none"] if start_with_gt else ["steering"]

### STEERING parameters
precision_control = 1.3 # threshold for precision breakdown
decision_num_restart = 0.35 # percentage of iterations with precision breakdown
max_iteration_same_query = 50 # precision flatness control

### CONTROLS
start_steering_collision = 0.15 # percentage of query paths to start train decision tree
collision_control = 50 # number of tuples to calculate median collision rate
smoothing_window = 50 # number of tuples to calculate median precision
decision_window = 50 # number of tuples to calculate median iterations of precision breakdown

### NETWORK SETTING parameters
nhosts = [10]
nvulns = [10]
topologies = ["powerlaw"] # other options: "mesh","random","star","ring","tree","powerlaw","lan0","lan25","lan50"
distro = ["uniform"] # other options: "uniform","bernoulli","poisson","binomial"
diversity = [1]

### QUERIES parameters
sok_queries=[
    {'id': "q1",
    'length': [0,2]},
    {'id': "q2",
    'impact': [9,10]},
    {'id': "q3",
    'likelihood': [9.8,10]},
    {'id': "q4",
    'score': [7.5,10]},
    {'id': "q5",
    'impact': [8,10],
    'likelihood': [0,4]},
    {'id': "q6",
    'impact': [0,3],
    'likelihood': [9.7,10]},
    {'id': "q7",
    'score': [7,10]},
]

QUERY={
    'id': "0",
    'impact': [7,10],
    'likelihood': [7,10]
}

size_ranges=[[3,4],[3,6],[2,8],[2,4],[2,6],[1,8]]
def all_combination_queries():
    queries=[]
    for L in range(len(size_ranges) + 1):
        for subset in itertools.product(size_ranges, repeat=L):
            if len(subset) == 1:
                queries.append({
                'id': "impact:"+str(subset[0]),
                "impact": subset[0]
                })
                queries.append({
                'id': "score:"+str(subset[0]),
                "score": subset[0]
                })
                queries.append({
                'id': "likelihood:"+str(subset[0]),
                "likelihood": subset[0]
                })
            # elif len(subset) == 2:
            #     queries.append({
            #     'id': "impact:"+str(subset[0])+"#score:"+str(subset[1]),
            #     'impact': subset[0],
            #     'score': subset[1]
            #     })
            # elif len(subset) == 3:
            #     queries.append({
            #     'id': "impact:"+str(subset[0])+"#score:"+str(subset[1])+"#likelihood:"+str(subset[2]),
            #     'impact': subset[0],
            #     'score': subset[1],
            #     'likelihood': subset[2]
            #     })
    return queries

### NETWORK FILES parameters
ROOT_FOLDER = "dataset/"
stat_folder = "stats/"
plot_folder = "plot/"
samples_folder = "/samples/"
gt_folder = "ground_truth/"
gt_paths = gt_folder+"GT_paths.json"
gt_base = gt_folder+"GT_base.json"

stats_sampling = stat_folder+"sampling.json"
stats_steering = stat_folder+"steering.csv"

def get_query_samples_filename(steerType):
    return samples_folder+steerType+"Query_paths.json"
def get_samples_filename(steerType):
    return samples_folder+steerType+"Paths.json"

"""
Define structure of the steering performance file
"""
def write_header_steering_performance(file_steering):
    with open(file_steering, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["iteration","num_samples","num_query_paths","num_other_paths",
                         "steering_type","isSteering","collision_rate_query",
                         "collision_rate_other","time_generation","time_steering","query","precision"])

### Inventories
cpe_file = "src/inventory/services.json"
cve_file1 = "src/inventory/vulnerabilities1.json"
cve_file2 = "src/inventory/vulnerabilities2.json"
cve_file3 = "src/inventory/vulnerabilities3.json"

def get_pool_vulnerabilities(tot_vuln):
    if tot_vuln <= 14500:
        with open(cve_file1) as f1:
            return json.load(f1)["vulnerabilities"]
    elif 14500 < tot_vuln <= 29000:
        with open(cve_file1) as f1, open(cve_file2) as f2:
            vulns1 = json.load(f1)["vulnerabilities"]
            vulns2 = json.load(f2)["vulnerabilities"]
            return vulns1+vulns2
    else:
        with open(cve_file1) as f1, open(cve_file2) as f2, open(cve_file3) as f3:
            vulns1 = json.load(f1)["vulnerabilities"]
            vulns2 = json.load(f2)["vulnerabilities"]
            vulns3 = json.load(f3)["vulnerabilities"]
            return vulns1+vulns2+vulns3