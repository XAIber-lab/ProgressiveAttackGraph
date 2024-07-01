import os, json, statistics
import pandas as pd
import numpy as np
from scipy import stats
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

import warnings
warnings.filterwarnings("ignore")
pd.options.mode.chained_assignment = None

from steering import isQuery
import config

def get_name_steering_type(str_steer):
    if "none" in str_steer: return "StatAG"
    else: return "SteerAG"
def plot_lines_steering(folder,plot_folder,df_experiments,mins_stats,max_stats,sampling_algo="",tot_paths=None):
    plt.rcParams.update({'font.size': 18})
    figrecall, axsrecall = plt.subplots()
    figrecall.set_figwidth(10)
    figrecall.set_figheight(6)

    figprecision, axsprecision = plt.subplots()
    figprecision.set_figwidth(10)
    figprecision.set_figheight(6)

    if "isSteering" in df_experiments.columns:
        index_steering = list(df_experiments[df_experiments.isSteering == True]["iteration"])
        if len(index_steering)>0:
            print("Iteration where steering started: ", index_steering[0])
    
    if not tot_paths:
        tot_paths = max(list(df_experiments["num_query_paths"]))
    tot_min_paths=max(list(mins_stats["num_query_paths"]))
    tot_max_paths=max(list(max_stats["num_query_paths"]))
    
    grouped_by_sample = df_experiments.groupby(["steering_type"])
    grouped_by_min = mins_stats.groupby(["steering_type"])
    grouped_by_max = max_stats.groupby(["steering_type"])
    labels_legend = []
    for sample, item in grouped_by_sample:
        sample_df = grouped_by_sample.get_group(sample)

        x_vals = sample_df["iteration"]
        y_vals_recall = sample_df["num_query_paths"]/tot_paths
        y_vals_precision = sample_df["num_query_paths"].diff()/(sample_df["num_query_paths"].diff()+sample_df["num_other_paths"].diff())

        dfmin=grouped_by_min.get_group(sample)
        dfmax=grouped_by_max.get_group(sample)
        y_mins = dfmin["num_query_paths"]/tot_min_paths
        y_maxs = dfmax["num_query_paths"]/tot_max_paths

        y_mins_prec = dfmin["num_query_paths"].diff()/(dfmin["num_query_paths"].diff()+dfmin["num_other_paths"].diff())
        y_maxs_prec = dfmax["num_query_paths"].diff()/(dfmax["num_query_paths"].diff()+dfmax["num_other_paths"].diff())

        labels_legend.append(get_name_steering_type(sample[0]))
        
        axsrecall.plot(x_vals,y_vals_recall,linewidth = '1', label=get_name_steering_type(sample))
        # axsrecall.fill_between(x_vals, y_mins, y_maxs, alpha=.5)
        
        axsprecision.plot(x_vals,y_vals_precision,linewidth = '1', label=get_name_steering_type(sample))
        # axsprecision.fill_between(x_vals, y_mins_prec, y_maxs_prec, alpha=.5)
        
    axsrecall.set_xlabel("iterations")
    axsrecall.set_ylabel("recall")
    # axsrecall.set_ylim(0,1)
    # axsrecall.legend()

    axsprecision.set_xlabel("iterations")
    axsprecision.set_ylabel("precision")
    # axsprecision.set_ylim(0,1)
    # axsprecision.legend()

    figrecall.savefig(folder+plot_folder+sampling_algo+"_recall_steering.png", bbox_inches='tight')
    figprecision.savefig(folder+plot_folder+sampling_algo+"_precision_steering.png", bbox_inches='tight')


def isExperiment(n,v,t,d,u,s,setting):
    if setting['n'] == n and setting['v'] == v and setting['t'] == t and \
        setting['d'] == d and setting['u'] == u and setting['s'] == s:
        return True
    else: return False

def convert_samples_to_df(sampleFile1, sampleFile2):
    with open(sampleFile1) as f1, open(sampleFile2) as f2:
        other_s = json.load(f1)
        query_s = json.load(f2)
    all_samples = other_s+query_s
    return pd.DataFrame(all_samples)

def normalize_convert_samples(sampleFile):
    with open(sampleFile) as f:
        all_samples = json.load(f)
    all_stats=[]
    all_base=[]
    for sample in all_samples:
        if sample["type"] == "sample": all_base.append(sample)
        else: all_stats.append(sample)
    return pd.json_normalize(all_stats), pd.json_normalize(all_base)

def plot_delta_distribution_aggr(folder,plot_folder,df_exps,sampling_algo="",absoluteScale=False):
    plt.rcParams.update({'font.size': 18})
    fig, axs = plt.subplots(2, 1)
    fig.set_figwidth(12)
    fig.set_figheight(11)

    labels_legend=[]
    grouped_by_experiment = df_exps.groupby(['iteration']).median().reset_index()
    grouped_by_experimentMIN = df_exps.groupby(['iteration']).quantile(0.25).reset_index()
    grouped_by_experimentMAX = df_exps.groupby(['iteration']).quantile(0.75).reset_index()
    y_len=[]
    y_imp=[]
    y_lik=[]
    y_sco=[]
    x_iterations=[]
    prev_len_distro=[]
    prev_imp_distro=[]
    prev_lik_distro=[]
    prev_sco_distro=[]

    y_lenmin=[]
    y_impmin=[]
    y_likmin=[]
    y_scomin=[]

    y_lenmax=[]
    y_impmax=[]
    y_likmax=[]
    y_scomax=[]
    
    item = grouped_by_experiment
    itemMin = grouped_by_experimentMIN
    itemMax = grouped_by_experimentMAX
    for i in list(grouped_by_experiment["iteration"]):

        current_len_distro = list(item["length"])[0:i]
        current_imp_distro = list(item["impact"])[0:i]
        current_lik_distro = list(item["likelihood"])[0:i]
        current_sco_distro = list(item["score"])[0:i]

        current_len_distromin = list(itemMin["length"])[0:i]
        current_imp_distromin = list(itemMin["impact"])[0:i]
        current_lik_distromin = list(itemMin["likelihood"])[0:i]
        current_sco_distromin = list(itemMin["score"])[0:i]

        current_len_distromax = list(itemMax["length"])[0:i]
        current_imp_distromax = list(itemMax["impact"])[0:i]
        current_lik_distromax = list(itemMax["likelihood"])[0:i]
        current_sco_distromax = list(itemMax["score"])[0:i]
        
        if len(prev_len_distro)>1:
            res_len = stats.ks_2samp(prev_len_distro,current_len_distro)
            res_imp = stats.ks_2samp(prev_imp_distro,current_imp_distro)
            res_lik = stats.ks_2samp(prev_lik_distro,current_lik_distro)
            res_sco = stats.ks_2samp(prev_sco_distro,current_sco_distro)

            res_lenmin = stats.ks_2samp(prev_len_distromin,current_len_distromin)
            res_impmin = stats.ks_2samp(prev_imp_distromin,current_imp_distromin)
            res_likmin = stats.ks_2samp(prev_lik_distromin,current_lik_distromin)
            res_scomin = stats.ks_2samp(prev_sco_distromin,current_sco_distromin)

            res_lenmax = stats.ks_2samp(prev_len_distromax,current_len_distromax)
            res_impmax = stats.ks_2samp(prev_imp_distromax,current_imp_distromax)
            res_likmax = stats.ks_2samp(prev_lik_distromax,current_lik_distromax)
            res_scomax = stats.ks_2samp(prev_sco_distromax,current_sco_distromax)

            y_len.append(1-res_len.statistic*10)
            y_imp.append(1-res_imp.statistic*10)
            y_lik.append(1-res_lik.statistic*10)
            y_sco.append(1-res_sco.statistic*10)

            y_lenmin.append(1-res_lenmin.statistic*10)
            y_impmin.append(1-res_impmin.statistic*10)
            y_likmin.append(1-res_likmin.statistic*10)
            y_scomin.append(1-res_scomin.statistic*10)

            y_lenmax.append(1-res_lenmax.statistic*10)
            y_impmax.append(1-res_impmax.statistic*10)
            y_likmax.append(1-res_likmax.statistic*10)
            y_scomax.append(1-res_scomax.statistic*10)

            x_iterations.append(i)

        prev_len_distro=current_len_distro
        prev_imp_distro=current_imp_distro
        prev_lik_distro=current_lik_distro
        prev_sco_distro=current_sco_distro

        prev_len_distromin=current_len_distromin
        prev_imp_distromin=current_imp_distromin
        prev_lik_distromin=current_lik_distromin
        prev_sco_distromin=current_sco_distromin

        prev_len_distromax=current_len_distromax
        prev_imp_distromax=current_imp_distromax
        prev_lik_distromax=current_lik_distromax
        prev_sco_distromax=current_sco_distromax
        
        labels_legend.append(i)
    
    
    axs[0].plot(x_iterations, y_lik, linewidth = '1')
    axs[0].fill_between(x_iterations, y_likmin, y_likmax, alpha=.4)
    axs[0].set_ylabel("stability")
    axs[0].set_title("likelihood", y=0.95, pad=-20)
    # axs[0].set_xlabel("iterations")

    axs[1].plot(x_iterations, y_imp, linewidth = '1')
    axs[1].fill_between(x_iterations, y_impmin, y_impmax, alpha=.4)
    axs[1].set_ylabel("stability")
    axs[1].set_title("impact", y=0.95, pad=-20)
    axs[1].set_xlabel("iterations")
    
    # axs[2].plot(x_iterations, y_len, linewidth = '2')
    # axs[2].set_ylabel("stability")
    # axs[2].set_title("length", y=1.0, pad=-20)

    # axs[3].plot(x_iterations, y_sco, linewidth = '2')
    # axs[3].set_xlabel("iteration")
    # axs[3].set_ylabel("stability")
    # axs[3].set_title("score", y=1.0, pad=-20)

    if absoluteScale:
        axs[0].set_ylim(0,1.05)
        axs[1].set_ylim(0,1.05)
        # axs[2].set_ylim(0,1)
        # axs[3].set_ylim(0,1)

    plt.savefig(folder+plot_folder+sampling_algo+"_deltaDistroAggregated.png", bbox_inches='tight')

def plot_distance_boxplot(folder,plot_folder,df_exps,gt_file,sampling_algo=""):
    plt.rcParams.update({'font.size': 18})
    fig, axs = plt.subplots(2, 1)
    fig.set_figwidth(12)
    fig.set_figheight(11)

    with open(gt_file) as f: gt_paths = json.load(f)
    df_gt = pd.DataFrame(gt_paths)
    # gt_len=list(df_gt["length"])
    # gt_sco=list(df_gt["score"])
    gt_imp=list(df_gt["impact"])
    gt_lik=list(df_gt["likelihood"])


    clean_df_exps = pd.merge(df_exps, df_gt, how='inner', on=['id','trace','length','impact','likelihood','score'])
    
    grouped_by_experiment = clean_df_exps.groupby(["experiment"])
    # dict_ks_len={}
    # dict_ks_sco={}
    dict_ks_imp={}
    dict_ks_lik={}
    for exp_id, df_single_exp in grouped_by_experiment:
        grouped_by_iteration = df_single_exp.groupby(["iteration"])

        # s_len=[]
        # s_sco=[]
        s_imp=[]
        s_lik=[]
        for iter_id, df_iter in grouped_by_iteration:            
            # s_len+=list(df_iter["length"])
            # s_sco+=list(df_iter["score"])
            s_imp+=list(df_iter["impact"])
            s_lik+=list(df_iter["likelihood"])
            
            # res_len = stats.ks_2samp(gt_len,s_len)
            # res_sco = stats.ks_2samp(gt_sco,s_sco)
            res_imp = stats.ks_2samp(gt_imp,s_imp)
            res_lik = stats.ks_2samp(gt_lik,s_lik)

            # if iter_id in dict_ks_len.keys(): dict_ks_len[iter_id].append(res_len.statistic)
            # else: dict_ks_len[iter_id] = [res_len.statistic]

            # if iter_id in dict_ks_sco.keys(): dict_ks_sco[iter_id].append(res_sco.statistic)
            # else: dict_ks_sco[iter_id] = [res_sco.statistic]

            if iter_id in dict_ks_imp.keys(): dict_ks_imp[iter_id].append(res_imp.statistic)
            else: dict_ks_imp[iter_id] = [res_imp.statistic]

            if iter_id in dict_ks_lik.keys(): dict_ks_lik[iter_id].append(res_lik.statistic)
            else: dict_ks_lik[iter_id] = [res_lik.statistic]

    # dict_sampled_len = dict(sorted(dict_ks_len.items()))
    # dict_sampled_sco = dict(sorted(dict_ks_sco.items()))
    # len_vals=[]
    # len_k=[]
    # sco_vals=[]
    # sco_k=[]

    # dict_ks_imp = pd.read_csv(plot_folder+"/delta_imp.csv")
    # dict_ks_lik = pd.read_csv(plot_folder+"/delta_lik.csv")
    dict_sampled_imp = dict(sorted(dict_ks_imp.items()))
    dict_sampled_lik = dict(sorted(dict_ks_lik.items()))
    imp_vals=[]
    imp_k=[]
    lik_vals=[]
    lik_k=[]
    for i in range(0,len(dict_sampled_imp.values())):
        if i<=55:
            if i==0 or (i+1)%10==0:
                # len_vals.append(list(dict_sampled_len.values())[i])
                # len_k.append(list(dict_sampled_len.keys())[i])
                # sco_vals.append(list(dict_sampled_sco.values())[i])
                # sco_k.append(list(dict_sampled_sco.keys())[i])
                imp_vals.append(list(dict_sampled_imp.values())[i])
                imp_k.append(list(dict_sampled_imp.keys())[i])
                lik_vals.append(list(dict_sampled_lik.values())[i])
                lik_k.append(list(dict_sampled_lik.keys())[i])
        else:
            if (i+1)%100==0:
                # len_vals.append(list(dict_sampled_len.values())[i])
                # len_k.append(list(dict_sampled_len.keys())[i])
                # sco_vals.append(list(dict_sampled_sco.values())[i])
                # sco_k.append(list(dict_sampled_sco.keys())[i])
                imp_vals.append(list(dict_sampled_imp.values())[i])
                imp_k.append(list(dict_sampled_imp.keys())[i])
                lik_vals.append(list(dict_sampled_lik.values())[i])
                lik_k.append(list(dict_sampled_lik.keys())[i])
    
    # axs[2].boxplot(len_vals)
    # axs[2].set_xticklabels(len_k, rotation = 90)
    # axs[2].set_ylabel("KS distance")
    # axs[2].set_ylim(0,1)
    # axs[2].set_title("length", y=1.0, pad=-20)

    # axs[3].boxplot(sco_vals)
    # axs[3].set_xticklabels(sco_k, rotation = 90)
    # axs[3].set_ylim(0,1)
    # axs[3].set_ylabel("KS distance")
    # axs[3].set_xlabel("iteration")
    # axs[3].set_title("score", y=1.0, pad=-20)

    axs[0].boxplot(lik_vals)
    axs[0].set_xticklabels(lik_k, rotation = 90)
    axs[0].set_ylim(0,1)
    axs[0].set_ylabel("KS distance")
    axs[0].set_title("likelihood", y=1.0, pad=-20)

    axs[1].boxplot(imp_vals)
    axs[1].set_xticklabels(imp_k, rotation = 90)
    axs[1].set_ylabel("KS distance")
    axs[1].set_xlabel("iterations")
    axs[1].set_ylim(0,1)
    axs[1].set_title("impact", y=1.0, pad=-20)

    plt.savefig(folder+plot_folder+sampling_algo+"_distanceBoxplot.png", bbox_inches='tight')
    

def plot_statistics_basefeatures(folder,plot_folder,df,sampling_algo,val="stat"):
    axesV2 = {'metricV2.accessVector':[0,0],
    'metricV2.accessComplexity':[0,1],
    'metricV2.authentication':[0,2],
    'metricV2.confidentiality':[0,3],
    'metricV2.integrity':[0,4],
    'metricV2.availability':[1,0],
    'metricV2.severity':[1,1],
    'metricV2.score':[1,2],
    'metricV2.impact':[1,3],
    'metricV2.exploitability':[1,4]
    }

    axesV3 = {'metricV3.attackVector':[0,0],
    'metricV3.attackComplexity':[0,1],
    'metricV3.privilegeRequired':[0,2],
    'metricV3.confidentiality':[0,3],
    'metricV3.integrity':[0,4],
    'metricV3.availability':[1,0],
    'metricV3.severity':[1,1],
    'metricV3.score':[1,2],
    'metricV3.impact':[1,3],
    'metricV3.exploitability':[1,4]
    }

    
    for axes_map in [axesV2]:#,axesV3]:
        plt.rcParams.update({'font.size': 16})
        fig, axs = plt.subplots(2, 5)
        fig.set_figwidth(25)
        fig.set_figheight(10)
        
        if axes_map==axesV2: version="v2"
        else: version="v3"

        for parameter in axes_map.keys():
            i,j = axes_map[parameter]
            ax = axs[i][j]
            
            if parameter+"."+val in df.columns:
                samples = df["iteration"]
                values = df[parameter+"."+val]
                
                ax.plot(samples, values)

            label_title = parameter.replace("metricV2.","").replace("metricV3.","").replace(".stat","").replace(".pvalue","")
            ax.set_title(label_title, y=1.0, pad=-20)
            ax.set_ylim(0,1)
            if i == 1: ax.set_xlabel("iteration")
            if j == 0:
                if val == "stat": ax.set_ylabel("K-S distance")
                elif val == "pvalue": ax.set_ylabel("p-value")
                else: ax.set_ylabel("collision rate")

        plt.savefig(folder+plot_folder+sampling_algo+"_base_features_"+val+"_"+version+".png", bbox_inches='tight')


def get_color_range(val):
    if val == "Low": return '#1b9e77'
    elif val == "Medium": return '#d95f02'
    else: return '#7570b3'

def plot_by_query(folder,plot_folder,df):
    dfs_by_numf = [
        df.query('query.str.count("#")==0', engine='python'),
        df.query('query.str.count("#")==1', engine='python'),
        df.query('query.str.count("#")==2', engine='python')
    ]

    plt.rcParams.update({'font.size': 22})
    fig, axs = plt.subplots(3, 1)
    fig.set_figwidth(15)
    fig.set_figheight(25)

    figscatter, axscatter = plt.subplots(3, 1)
    figscatter.set_figwidth(15)
    figscatter.set_figheight(25)

    custom_lines = [Line2D([0], [0], color=get_color_range("Low"), lw=3),
        Line2D([0], [0], color=get_color_range("Medium"), lw=3),
        Line2D([0], [0], color=get_color_range("High"), lw=3)]

    for i in range(0,3):
        df_numf = dfs_by_numf[i]
        # if i == 0:
        df_numf['group'] = np.where(df_numf['query'].str.contains("4"), "Low", 
            np.where(df_numf['query'].str.contains("6"), "Medium", "High"))
        
        grouped_by_sample = df_numf.groupby(['experiment'])
        labels_legend = []
        dict_query={}
        query_num=[]
        speed_num=[]
        colors_num=[]
        for exp_num, sample_df in grouped_by_sample:
            tot_paths = max(list(sample_df["num_query_paths"]))
            x_vals = sample_df["iteration"]
            y_vals_0 = sample_df["num_query_paths"]/tot_paths

            group_line = list(sample_df["group"])[0]
            if group_line not in labels_legend: labels_legend.append(group_line)
            
            max_speed=0
            prev_y=0
            for curr_y in list(y_vals_0):
                if abs(curr_y-prev_y)>max_speed: max_speed=abs(curr_y-prev_y)
                prev_y=curr_y
            
            dict_query[exp_num] = {"range":group_line, "speed":1-max_speed}
            query_num.append(exp_num)
            speed_num.append(1-max_speed)
            colors_num.append(get_color_range(group_line))
            
            axs[i].plot(x_vals,y_vals_0,linewidth = '2',color=get_color_range(group_line),label=group_line)
            axs[i].set_xlabel("iteration")
            axs[i].set_ylabel("precision")
            axs[i].set_title("Query on "+str(i+1)+" features")
            axs[i].legend(custom_lines, ['Low', 'Medium', 'High'], title="Query Range")

        axscatter[i].scatter(query_num,speed_num,s=100,c=colors_num)
        axscatter[i].set_xlabel("query")
        axscatter[i].set_ylabel("convergance rate")
        axscatter[i].legend(custom_lines, ['Low', 'Medium', 'High'], title="Query Range")
        print(dict_query)
    
    fig.savefig(folder+plot_folder+"by_query.png", bbox_inches='tight')
    figscatter.savefig(folder+plot_folder+"scatter_query.png", bbox_inches='tight')

def plot_single_query(folder,plot_folder,df):    
    set_queries = list(set(df["query"]))
    
    plt.rcParams.update({'font.size': 22})
    fig, axs = plt.subplots(len(set_queries)+1, 1)
    fig.set_figwidth(15)
    fig.set_figheight(25)


    grouped_by_query = df.groupby(['query'])
    i=0
    for query_id, query_df in grouped_by_query:
        tot_paths = max(list(query_df["num_query_paths"]))
        x_vals = query_df["iteration"]
        y_vals_0 = query_df["num_query_paths"]/tot_paths

        axs[i].plot(x_vals,y_vals_0,linewidth = '3')
        axs[i].set_xlabel("iteration")
        axs[i].set_ylabel("recall")
        axs[i].set_title(query_id)

        i+=1


    # for i in range(0,3):
    #     df_numf = dfs_by_numf[i]
    #     # if i == 0:
    #     df_numf['group'] = np.where(df_numf['query'].str.contains("4"), "Low", 
    #         np.where(df_numf['query'].str.contains("6"), "Medium", "High"))
        
    #     grouped_by_sample = df_numf.groupby(['experiment'])
    #     labels_legend = []
    #     for exp_num, sample_df in grouped_by_sample:
    #         tot_paths = max(list(sample_df["num_query_paths"]))
    #         x_vals = sample_df["iteration"]
    #         y_vals_0 = sample_df["num_query_paths"]/tot_paths

    #         group_line = list(sample_df["group"])[0]
    #         if group_line not in labels_legend: labels_legend.append(group_line)
    #         axs[i].plot(x_vals,y_vals_0,linewidth = '2',color=get_color_range(group_line),label=group_line)
    #         axs[i].set_xlabel("iteration")
    #         axs[i].set_ylabel("precision")
    #         axs[i].set_title("Query on "+str(i+1)+" features")

    #         axs[i].legend(custom_lines, ['Low', 'Medium', 'High'], title="Query Range")
    plt.savefig(folder+plot_folder+"by_SINGLE_query.png", bbox_inches='tight')

if __name__ == "__main__":
    experiment_settings={
        'n': config.nhosts[len(config.nhosts)-1],#10,
        'v': config.nvulns[len(config.nvulns)-1],#10,
        't': config.topologies[len(config.topologies)-1],#"powerlaw",
        'd': config.distro[len(config.distro)-1],#"uniform",
        'u': config.diversity[len(config.diversity)-1],#1,
        's':"random"
    }

    df_steers = {}
    df_samples = {}
    df_stats = {}
    GT_path_file = ""
    num_iteration_sampling = []
    for n in config.nhosts:
        for v in config.nvulns:
            for t in config.topologies:
                for d in config.distro:
                    for u in config.diversity:
                        base_name = str(n)+'_'+str(v)+'_'+t+'_'+d+'_'+str(u)
                        folder_name = config.ROOT_FOLDER+base_name+"/"
                        
                        if os.path.exists(folder_name+config.gt_paths): 
                            GT_path_file = folder_name+config.gt_paths
                            with open(GT_path_file) as f: gt_paths = json.load(f)
                            count_query_paths=0
                            for gtp in gt_paths:
                                if isQuery(config.QUERY,gtp): count_query_paths+=1
                        else:
                            count_query_paths=None
                        
                        for samplingType in os.listdir(folder_name):
                            if samplingType in config.sampling_algorithms:
                                for exp in range(1,config.num_experiments+1):
                                    if isExperiment(n,v,t,d,u,samplingType,experiment_settings):
                                        """
                                        SAMPLING
                                        """
                                        if config.start_with_gt: steer_type="none"
                                        else: steer_type="steering"
                                        
                                        if not config.start_with_gt: steer_type="steering"
                                        filename_sample_other = folder_name+samplingType+\
                                                    "/exp"+str(exp)+config.get_samples_filename(steer_type)
                                        filename_sample_query = folder_name+samplingType+\
                                                    "/exp"+str(exp)+config.get_query_samples_filename(steer_type)
                                        filename_sampling_stats = folder_name+samplingType+\
                                                    "/exp"+str(exp)+"/"+config.stats_sampling
                                        
                                        df_exp_sample = convert_samples_to_df(filename_sample_other, filename_sample_query)
                                        num_iteration_sampling.append(max(list(df_exp_sample["iteration"])))
                                        df_exp_sample["experiment"]=exp

                                        if samplingType not in df_samples.keys(): df_samples[samplingType] = [df_exp_sample]
                                        else: df_samples[samplingType].append(df_exp_sample)

                                        df_base_stats, df_base_samples = normalize_convert_samples(filename_sampling_stats)
                                        if samplingType not in df_stats.keys(): df_stats[samplingType] = [df_base_stats]
                                        else: df_stats[samplingType].append(df_base_stats)
                                        
                                        """
                                        STEERING
                                        """
                                        filename_steering_stats = folder_name+samplingType+\
                                                    "/exp"+str(exp)+"/"+config.stats_steering
                                        df_experiment = pd.read_csv(filename_steering_stats)
                                        df_experiment["experiment"]=exp
                                        if samplingType not in df_steers.keys(): df_steers[samplingType] = [df_experiment]
                                        else: df_steers[samplingType].append(df_experiment)
                            
                        """
                        PLOT FOR EACH EXPERIMENT
                        """
                        current_folder_plot = config.plot_folder+base_name+"/"
                        if not os.path.exists(current_folder_plot): os.makedirs(current_folder_plot)

                        for k in df_stats.keys():
                            df_sampling_base = pd.concat(df_stats[k])
                            averages_base_stats = df_sampling_base.groupby(['iteration']).median().reset_index()
                            # averages_base_stats.to_csv(current_folder_plot+"/avg_base_stats.csv",index=False)
                            plot_statistics_basefeatures("",current_folder_plot,averages_base_stats,k)

                        avg_iteration = sum(num_iteration_sampling)/len(num_iteration_sampling)
                        for k in df_samples.keys():
                            df_sampling_derivative = pd.concat(df_samples[k])
                            plot_delta_distribution_aggr("",current_folder_plot,df_sampling_derivative,k,absoluteScale=True)

                            # averages_samples = df_sampling_derivative.groupby(['iteration']).median().reset_index()
                            # averages_samples.to_csv(current_folder_plot+"/avg_samples.csv",index=False)
                        
                            if GT_path_file!="": 
                                plot_distance_boxplot("",current_folder_plot,df_sampling_derivative,GT_path_file,k)

                        for k in df_steers.keys():
                            df_sampling = pd.concat(df_steers[k])
                            # plot_by_query("",current_folder_plot,df_sampling)
                            # plot_single_query("",current_folder_plot,df_sampling)
                        
                        max_iteration=int(max(list(df_sampling[df_sampling.steering_type == "steering"]["iteration"])))
                        for k in df_steers.keys():
                            list_df_extended = []
                            for df_curr in df_steers[k]:
                                curr_max_iteration = int(max(list(df_curr[df_curr.steering_type == "steering"]["iteration"])))
                                copy_row = df_curr[(df_curr.steering_type == "steering") & (df_curr.iteration == curr_max_iteration)]
                                for i in range(curr_max_iteration,max_iteration):
                                    copy_row["iteration"] = i
                                    df_curr = df_curr.append(copy_row, ignore_index=True)
                                list_df_extended.append(df_curr)
                            df_sampling = pd.concat(list_df_extended)

                            count_query_paths=None
                            averages_stats = df_sampling.groupby(['iteration','num_samples','steering_type']).median().reset_index()
                            # averages_stats.to_csv(current_folder_plot+"/avg_stats.csv",index=False)                        
                            first_quantiles_stats = df_sampling.groupby(['iteration','num_samples','steering_type']).quantile(0.25).reset_index()
                            third_quantiles_stats = df_sampling.groupby(['iteration','num_samples','steering_type']).quantile(0.75).reset_index()
                            plot_lines_steering("",current_folder_plot,averages_stats,first_quantiles_stats,third_quantiles_stats,k,count_query_paths)






# def plot_time_steering(folder,plot_folder,df_experiments,param_time,sampling_algo=""):
#     plt.rcParams.update({'font.size': 24})
#     fig, axs = plt.subplots()
#     fig.set_figwidth(15)
#     fig.set_figheight(10)

#     df_experiments = df_experiments[df_experiments.steering_type == "steering"]

#     if param_time == "time_generation":
#         df_experiments['time_generation'] = df_experiments['time_generation'].diff()
#         x = df_experiments["iteration"][:-1]
#         y = df_experiments["time_generation"][:-1]
#     else:
#         x = df_experiments["iteration"]
#         y = df_experiments["time_steering"]
#     plt.bar(x, y)
#     plt.xlabel("iterations")
#     plt.ylabel(param_time+" (s)")
#     plt.savefig(folder+plot_folder+sampling_algo+"_"+param_time+".png", bbox_inches='tight')

# def plot_lines_steering_all(folder,plot_folder,df_experiments,sampling_algo="",tot_paths=None):
#     plt.rcParams.update({'font.size': 24})
#     fig, axs = plt.subplots()
#     fig.set_figwidth(15)
#     fig.set_figheight(10)

#     if "isSteering" in df_experiments.columns:
#         index_steering = list(df_experiments[df_experiments.isSteering == True]["iteration"])
#         if len(index_steering)>0:
#             print("Iteration where steering started: ", index_steering[0])
    
#     if not tot_paths:
#         tot_paths = max(list(df_experiments["num_query_paths"]))
#     df_experiments = df_experiments[df_experiments.steering_type == "steering"]
#     grouped_by_sample = df_experiments.groupby(['experiment'])
#     labels_legend = []
#     for sample, item in grouped_by_sample:
#         sample_df = grouped_by_sample.get_group(sample)

#         x_vals = sample_df["iteration"]
#         y_vals_0 = sample_df["num_query_paths"]/tot_paths

#         labels_legend.append(sample)
#         axs.plot(x_vals,y_vals_0,linewidth = '3')
    
#     axs.set_xlabel("iterations")
#     axs.set_ylabel("% query paths")
#     axs.legend(title="Experiments", labels=labels_legend)
#     axs.set_title("Percentage of Queried Paths to total")

#     plt.savefig(folder+plot_folder+sampling_algo+"_steering_ALL.png", bbox_inches='tight')


# def plot_delta_variation(folder,plot_folder,df_aggregate,sampling_algo=""):
#     plt.rcParams.update({'font.size': 22})
#     fig, axs = plt.subplots(4, 1)
#     fig.set_figwidth(15)
#     fig.set_figheight(20)
    
#     iteration_ids = list(df_aggregate["iteration"])[:-1]

#     all_lengths = list(df_aggregate["length"])
#     past_len=all_lengths[0]
#     x_vals_len = []

#     all_impacts = list(df_aggregate["impact"])
#     past_imp=all_impacts[0]
#     x_vals_imp = []

#     all_likelihoods = list(df_aggregate["likelihood"])
#     past_lik=all_likelihoods[0]
#     x_vals_lik = []

#     all_scores = list(df_aggregate["score"])
#     past_sco=all_scores[0]
#     x_vals_sco = []
#     for i in range(1,len(all_lengths)):
#         curr_len = all_lengths[i]
#         x_vals_len.append(curr_len-past_len)

#         curr_imp = all_impacts[i]
#         x_vals_imp.append(curr_imp-past_imp)

#         curr_lik = all_likelihoods[i]
#         x_vals_lik.append(curr_lik-past_lik)

#         curr_sco = all_scores[i]
#         x_vals_sco.append(curr_sco-past_sco)

#         past_len=curr_len
#         past_imp=curr_imp
#         past_lik=curr_lik
#         past_sco=curr_sco
        
#     axs[0].plot(iteration_ids, x_vals_len,linewidth = '2')
#     axs[1].plot(iteration_ids, x_vals_imp,linewidth = '2')
#     axs[2].plot(iteration_ids, x_vals_lik,linewidth = '2')
#     axs[3].plot(iteration_ids, x_vals_sco,linewidth = '2')

#     axs[0].set_ylabel("delta variation")
#     axs[0].set_title("length", y=1.0, pad=-20)

#     axs[1].set_ylabel("delta variation")
#     axs[1].set_title("impact", y=1.0, pad=-20)

#     axs[2].set_xlabel("iteration")
#     axs[2].set_ylabel("delta variation")
#     axs[2].set_title("likelihood", y=1.0, pad=-20)

#     axs[3].set_xlabel("iteration")
#     axs[3].set_ylabel("delta variation")
#     axs[3].set_title("score", y=1.0, pad=-20)

#     plt.savefig(folder+plot_folder+sampling_algo+"_deltaVariation.png", bbox_inches='tight')

# def plot_delta_distribution(folder,plot_folder,df_exps,sampling_algo="",absoluteScale=False):
#     plt.rcParams.update({'font.size': 22})
#     fig, axs = plt.subplots(4, 1)
#     fig.set_figwidth(15)
#     fig.set_figheight(20)

#     labels_legend=[]
#     grouped_by_experiment = df_exps.groupby(["experiment"])
#     for sample, item in grouped_by_experiment:
#         y_len=[]
#         y_imp=[]
#         y_lik=[]
#         y_sco=[]
#         x_iterations=[]
#         prev_len_distro=[]
#         prev_imp_distro=[]
#         prev_lik_distro=[]
#         prev_sco_distro=[]
#         for iter in list(set(item["iteration"])):
#             current_len_distro = list(item[item.iteration == iter]["length"])+prev_len_distro
#             current_imp_distro = list(item[item.iteration == iter]["impact"])+prev_imp_distro
#             current_lik_distro = list(item[item.iteration == iter]["likelihood"])+prev_lik_distro
#             current_sco_distro = list(item[item.iteration == iter]["score"])+prev_lik_distro
            
#             if len(prev_len_distro)>1:
#                 res_len = stats.ks_2samp(prev_len_distro,current_len_distro)
#                 res_imp = stats.ks_2samp(prev_imp_distro,current_imp_distro)
#                 res_lik = stats.ks_2samp(prev_lik_distro,current_lik_distro)
#                 res_sco = stats.ks_2samp(prev_sco_distro,current_sco_distro)

#                 y_len.append(res_len.statistic)
#                 y_imp.append(res_imp.statistic)
#                 y_lik.append(res_lik.statistic)
#                 y_sco.append(res_sco.statistic)

#                 x_iterations.append(iter)

#             prev_len_distro=current_len_distro
#             prev_imp_distro=current_imp_distro
#             prev_lik_distro=current_lik_distro
#             prev_sco_distro=current_sco_distro
        
#         axs[0].plot(x_iterations, y_len, linewidth = '2')
#         axs[1].plot(x_iterations, y_imp, linewidth = '2')
#         axs[2].plot(x_iterations, y_lik, linewidth = '2')
#         axs[3].plot(x_iterations, y_sco, linewidth = '2')
#         labels_legend.append(sample)
    
#     axs[0].legend(title="Experiments", labels=labels_legend)
#     axs[0].set_ylabel("KS distance")
#     axs[0].set_title("length", y=1.0, pad=-20)

#     axs[1].set_ylabel("K-S distance (current,previous)")
#     axs[1].set_title("impact", y=1.0, pad=-20)

#     axs[2].set_xlabel("iteration")
#     axs[2].set_ylabel("K-S distance (current,previous)")
#     axs[2].set_title("likelihood", y=1.0, pad=-20)

#     axs[3].set_xlabel("iteration")
#     axs[3].set_ylabel("K-S distance (current,previous)")
#     axs[3].set_title("score", y=1.0, pad=-20)

#     if absoluteScale:
#         axs[0].set_ylim(0,1)
#         axs[1].set_ylim(0,1)
#         axs[2].set_ylim(0,1)
#         axs[3].set_ylim(0,1)

#     plt.savefig(folder+plot_folder+sampling_algo+"_deltaDistro.png", bbox_inches='tight')
