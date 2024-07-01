import json
import pandas as pd
from scipy import stats
from copy import deepcopy

"""
This function put the correct format to the dict of features
"""
def fill_missing_keys(existingDict=None):
    if existingDict: featuresDict = deepcopy(existingDict)
    else: featuresDict={}
        
    if "metricV2" not in featuresDict.keys(): featuresDict["metricV2"] = {}
    if "metricV3" not in featuresDict.keys(): featuresDict["metricV3"] = {}
    
    ### CVSS v2
    if "accessVector" not in featuresDict["metricV2"]: featuresDict["metricV2"]["accessVector"]={}
    if "NETWORK" not in featuresDict["metricV2"]["accessVector"].keys(): featuresDict["metricV2"]["accessVector"]["NETWORK"] = 0
    if "ADJACENT_NETWORK" not in featuresDict["metricV2"]["accessVector"].keys(): featuresDict["metricV2"]["accessVector"]["ADJACENT_NETWORK"] = 0
    if "LOCAL" not in featuresDict["metricV2"]["accessVector"].keys(): featuresDict["metricV2"]["accessVector"]["LOCAL"] = 0

    if "accessComplexity" not in featuresDict["metricV2"].keys(): featuresDict["metricV2"]["accessComplexity"]={}
    if "HIGH" not in featuresDict["metricV2"]["accessComplexity"].keys(): featuresDict["metricV2"]["accessComplexity"]["HIGH"] = 0
    if "MEDIUM" not in featuresDict["metricV2"]["accessComplexity"].keys(): featuresDict["metricV2"]["accessComplexity"]["MEDIUM"] = 0
    if "LOW" not in featuresDict["metricV2"]["accessComplexity"].keys(): featuresDict["metricV2"]["accessComplexity"]["LOW"] = 0

    if "authentication" not in featuresDict["metricV2"].keys(): featuresDict["metricV2"]["authentication"]={}
    if "NONE" not in featuresDict["metricV2"]["authentication"].keys(): featuresDict["metricV2"]["authentication"]["NONE"] = 0
    if "SINGLE" not in featuresDict["metricV2"]["authentication"].keys(): featuresDict["metricV2"]["authentication"]["SINGLE"] = 0
    if "MULTIPLE" not in featuresDict["metricV2"]["authentication"].keys(): featuresDict["metricV2"]["authentication"]["MULTIPLE"] = 0

    if "confidentiality" not in featuresDict["metricV2"].keys(): featuresDict["metricV2"]["confidentiality"]={}
    if "NONE" not in featuresDict["metricV2"]["confidentiality"].keys(): featuresDict["metricV2"]["confidentiality"]["NONE"] = 0
    if "PARTIAL" not in featuresDict["metricV2"]["confidentiality"].keys(): featuresDict["metricV2"]["confidentiality"]["PARTIAL"] = 0
    if "COMPLETE" not in featuresDict["metricV2"]["confidentiality"].keys(): featuresDict["metricV2"]["confidentiality"]["COMPLETE"] = 0

    if "integrity" not in featuresDict["metricV2"].keys(): featuresDict["metricV2"]["integrity"]={}
    if "NONE" not in featuresDict["metricV2"]["integrity"].keys(): featuresDict["metricV2"]["integrity"]["NONE"] = 0
    if "PARTIAL" not in featuresDict["metricV2"]["integrity"].keys(): featuresDict["metricV2"]["integrity"]["PARTIAL"] = 0
    if "COMPLETE" not in featuresDict["metricV2"]["integrity"].keys(): featuresDict["metricV2"]["integrity"]["COMPLETE"] = 0

    if "availability" not in featuresDict["metricV2"].keys(): featuresDict["metricV2"]["availability"]={}
    if "NONE" not in featuresDict["metricV2"]["availability"].keys(): featuresDict["metricV2"]["availability"]["NONE"] = 0
    if "PARTIAL" not in featuresDict["metricV2"]["availability"].keys(): featuresDict["metricV2"]["availability"]["PARTIAL"] = 0
    if "COMPLETE" not in featuresDict["metricV2"]["availability"].keys(): featuresDict["metricV2"]["availability"]["COMPLETE"] = 0

    if "severity" not in featuresDict["metricV2"].keys(): featuresDict["metricV2"]["severity"]={}
    if "LOW" not in featuresDict["metricV2"]["severity"].keys(): featuresDict["metricV2"]["severity"]["LOW"] = 0
    if "MEDIUM" not in featuresDict["metricV2"]["severity"].keys(): featuresDict["metricV2"]["severity"]["MEDIUM"] = 0
    if "HIGH" not in featuresDict["metricV2"]["severity"].keys(): featuresDict["metricV2"]["severity"]["HIGH"] = 0

    if "score" not in featuresDict["metricV2"]: featuresDict["metricV2"]["score"] = []
    if "impact" not in featuresDict["metricV2"]: featuresDict["metricV2"]["impact"] = []
    if "exploitability" not in featuresDict["metricV2"]: featuresDict["metricV2"]["exploitability"] = []

    ### CVSS v3
    if "attackVector" not in featuresDict["metricV3"]: featuresDict["metricV3"]["attackVector"]={}
    if "NETWORK" not in featuresDict["metricV3"]["attackVector"].keys(): featuresDict["metricV3"]["attackVector"]["NETWORK"] = 0
    if "ADJACENT_NETWORK" not in featuresDict["metricV3"]["attackVector"].keys(): featuresDict["metricV3"]["attackVector"]["ADJACENT_NETWORK"] = 0
    if "LOCAL" not in featuresDict["metricV3"]["attackVector"].keys(): featuresDict["metricV3"]["attackVector"]["LOCAL"] = 0
    if "PHYSICAL" not in featuresDict["metricV3"]["attackVector"].keys(): featuresDict["metricV3"]["attackVector"]["PHYSICAL"] = 0

    if "attackComplexity" not in featuresDict["metricV3"].keys(): featuresDict["metricV3"]["attackComplexity"]={}
    if "HIGH" not in featuresDict["metricV3"]["attackComplexity"].keys(): featuresDict["metricV3"]["attackComplexity"]["HIGH"] = 0
    if "MEDIUM" not in featuresDict["metricV3"]["attackComplexity"].keys(): featuresDict["metricV3"]["attackComplexity"]["MEDIUM"] = 0
    if "LOW" not in featuresDict["metricV3"]["attackComplexity"].keys(): featuresDict["metricV3"]["attackComplexity"]["LOW"] = 0

    if "privilegeRequired" not in featuresDict["metricV3"].keys(): featuresDict["metricV3"]["privilegeRequired"]={}
    if "NONE" not in featuresDict["metricV3"]["privilegeRequired"].keys(): featuresDict["metricV3"]["privilegeRequired"]["NONE"] = 0
    if "LOW" not in featuresDict["metricV3"]["privilegeRequired"].keys(): featuresDict["metricV3"]["privilegeRequired"]["LOW"] = 0
    if "MEDIUM" not in featuresDict["metricV3"]["privilegeRequired"].keys(): featuresDict["metricV3"]["privilegeRequired"]["MEDIUM"] = 0
    if "HIGH" not in featuresDict["metricV3"]["privilegeRequired"].keys(): featuresDict["metricV3"]["privilegeRequired"]["HIGH"] = 0
    if "CRITICAL" not in featuresDict["metricV3"]["privilegeRequired"].keys(): featuresDict["metricV3"]["privilegeRequired"]["CRITICAL"] = 0

    if "confidentiality" not in featuresDict["metricV3"].keys(): featuresDict["metricV3"]["confidentiality"]={}
    if "NONE" not in featuresDict["metricV3"]["confidentiality"].keys(): featuresDict["metricV3"]["confidentiality"]["NONE"] = 0
    if "LOW" not in featuresDict["metricV3"]["confidentiality"].keys(): featuresDict["metricV3"]["confidentiality"]["LOW"] = 0
    if "MEDIUM" not in featuresDict["metricV3"]["confidentiality"].keys(): featuresDict["metricV3"]["confidentiality"]["MEDIUM"] = 0
    if "HIGH" not in featuresDict["metricV3"]["confidentiality"].keys(): featuresDict["metricV3"]["confidentiality"]["HIGH"] = 0
    if "CRITICAL" not in featuresDict["metricV3"]["confidentiality"].keys(): featuresDict["metricV3"]["confidentiality"]["CRITICAL"] = 0

    if "integrity" not in featuresDict["metricV3"].keys(): featuresDict["metricV3"]["integrity"]={}
    if "NONE" not in featuresDict["metricV3"]["integrity"].keys(): featuresDict["metricV3"]["integrity"]["NONE"] = 0
    if "LOW" not in featuresDict["metricV3"]["integrity"].keys(): featuresDict["metricV3"]["integrity"]["LOW"] = 0
    if "MEDIUM" not in featuresDict["metricV3"]["integrity"].keys(): featuresDict["metricV3"]["integrity"]["MEDIUM"] = 0
    if "HIGH" not in featuresDict["metricV3"]["integrity"].keys(): featuresDict["metricV3"]["integrity"]["HIGH"] = 0
    if "CRITICAL" not in featuresDict["metricV3"]["integrity"].keys(): featuresDict["metricV3"]["integrity"]["CRITICAL"] = 0

    if "availability" not in featuresDict["metricV3"].keys(): featuresDict["metricV3"]["availability"]={}
    if "NONE" not in featuresDict["metricV3"]["availability"].keys(): featuresDict["metricV3"]["availability"]["NONE"] = 0
    if "LOW" not in featuresDict["metricV3"]["availability"].keys(): featuresDict["metricV3"]["availability"]["LOW"] = 0
    if "MEDIUM" not in featuresDict["metricV3"]["availability"].keys(): featuresDict["metricV3"]["availability"]["MEDIUM"] = 0
    if "HIGH" not in featuresDict["metricV3"]["availability"].keys(): featuresDict["metricV3"]["availability"]["HIGH"] = 0
    if "CRITICAL" not in featuresDict["metricV3"]["availability"].keys(): featuresDict["metricV3"]["availability"]["CRITICAL"] = 0

    if "severity" not in featuresDict["metricV3"].keys(): featuresDict["metricV3"]["severity"]={}
    if "NONE" not in featuresDict["metricV3"]["severity"].keys(): featuresDict["metricV3"]["severity"]["NONE"] = 0
    if "LOW" not in featuresDict["metricV3"]["severity"].keys(): featuresDict["metricV3"]["severity"]["LOW"] = 0
    if "MEDIUM" not in featuresDict["metricV3"]["severity"].keys(): featuresDict["metricV3"]["severity"]["MEDIUM"] = 0
    if "HIGH" not in featuresDict["metricV3"]["severity"].keys(): featuresDict["metricV3"]["severity"]["HIGH"] = 0
    if "CRITICAL" not in featuresDict["metricV3"]["severity"].keys(): featuresDict["metricV3"]["severity"]["CRITICAL"] = 0

    if "score" not in featuresDict["metricV3"]: featuresDict["metricV3"]["score"] = []
    if "impact" not in featuresDict["metricV3"]: featuresDict["metricV3"]["impact"] = []
    if "exploitability" not in featuresDict["metricV3"]: featuresDict["metricV3"]["exploitability"] = []

    return featuresDict

"""
Given as parameter a list of vulnerabilities in a given path, this function
create a dictionary with the base features distribution
"""
def base_features_distro(vulnerabilities):
    dicFeatures = fill_missing_keys()
    scores_m2=[]
    exploitability_m2=[]
    impact_m2=[]
    scores_m3=[]
    exploitability_m3=[]
    impact_m3=[]
    for vuln in vulnerabilities:
        if "cvssMetricV2" in vuln["metrics"]:
            metricV2 = vuln["metrics"]["cvssMetricV2"][0]
            metricCvssV2 = metricV2["cvssData"]

            scores_m2.append(metricCvssV2["baseScore"])
            exploitability_m2.append(metricV2["exploitabilityScore"])
            impact_m2.append(metricV2["impactScore"])
            dicFeatures["metricV2"]["accessVector"][metricCvssV2["accessVector"]]+=1
            dicFeatures["metricV2"]["accessComplexity"][metricCvssV2["accessComplexity"]]+=1
            dicFeatures["metricV2"]["authentication"][metricCvssV2["authentication"]]+=1
            dicFeatures["metricV2"]["confidentiality"][metricCvssV2["confidentialityImpact"]]+=1
            dicFeatures["metricV2"]["integrity"][metricCvssV2["integrityImpact"]]+=1
            dicFeatures["metricV2"]["availability"][metricCvssV2["availabilityImpact"]]+=1
            dicFeatures["metricV2"]["severity"][metricV2["baseSeverity"]]+=1
        
        if "cvssMetricV30" in vuln["metrics"] or "cvssMetricV31" in vuln["metrics"]:
            if "cvssMetricV30" in vuln["metrics"]: metricV3 = vuln["metrics"]["cvssMetricV30"][0]
            else: metricV3 = vuln["metrics"]["cvssMetricV31"][0]
            metricCvssV3 = metricV3["cvssData"]

            scores_m3.append(metricCvssV3["baseScore"])
            exploitability_m3.append(metricV3["exploitabilityScore"])
            impact_m3.append(metricV3["impactScore"])
            dicFeatures["metricV3"]["attackVector"][metricCvssV3["attackVector"]]+=1
            dicFeatures["metricV3"]["attackComplexity"][metricCvssV3["attackComplexity"]]+=1
            dicFeatures["metricV3"]["privilegeRequired"][metricCvssV3["privilegesRequired"]]+=1
            dicFeatures["metricV3"]["confidentiality"][metricCvssV3["confidentialityImpact"]]+=1
            dicFeatures["metricV3"]["integrity"][metricCvssV3["integrityImpact"]]+=1
            dicFeatures["metricV3"]["availability"][metricCvssV3["availabilityImpact"]]+=1
            dicFeatures["metricV3"]["severity"][metricCvssV3["baseSeverity"]]+=1
    
    if len(scores_m2)>0:
        dicFeatures["metricV2"]["score"] = scores_m2
        dicFeatures["metricV2"]["impact"] = impact_m2
        dicFeatures["metricV2"]["exploitability"] = exploitability_m2
    
    if len(scores_m3)>0:
        dicFeatures["metricV3"]["score"] = scores_m3
        dicFeatures["metricV3"]["impact"] = impact_m3
        dicFeatures["metricV3"]["exploitability"] = exploitability_m3
    
    return dicFeatures

"""
Given as parameters two dictionaries of base feature distribution, this function
aggregate all the information in the dictionary passed as first parameter, i.e.
summary_dic
"""
def aggregate_statistics_features(summary_dic, current_dic):
    aggregate_dic = fill_missing_keys()

    ### CVSS v2
    if current_dic["metricV2"]:
        for accessVector in current_dic["metricV2"]["accessVector"].keys():
            aggregate_dic["metricV2"]["accessVector"][accessVector] = summary_dic["metricV2"]["accessVector"][accessVector] + current_dic["metricV2"]["accessVector"][accessVector]
        for accessComplexity in current_dic["metricV2"]["accessComplexity"].keys():
            aggregate_dic["metricV2"]["accessComplexity"][accessComplexity] = summary_dic["metricV2"]["accessComplexity"][accessComplexity] + current_dic["metricV2"]["accessComplexity"][accessComplexity]
        for authentication in current_dic["metricV2"]["authentication"].keys():
            aggregate_dic["metricV2"]["authentication"][authentication] = summary_dic["metricV2"]["authentication"][authentication] + current_dic["metricV2"]["authentication"][authentication]
        for confidentiality in current_dic["metricV2"]["confidentiality"].keys():
            aggregate_dic["metricV2"]["confidentiality"][confidentiality] = summary_dic["metricV2"]["confidentiality"][confidentiality] + current_dic["metricV2"]["confidentiality"][confidentiality]
        for integrity in current_dic["metricV2"]["integrity"].keys():
            aggregate_dic["metricV2"]["integrity"][integrity] = summary_dic["metricV2"]["integrity"][integrity] + current_dic["metricV2"]["integrity"][integrity]
        for availability in current_dic["metricV2"]["availability"].keys():
            aggregate_dic["metricV2"]["availability"][availability] = summary_dic["metricV2"]["availability"][availability] + current_dic["metricV2"]["availability"][availability]
        for severity in current_dic["metricV2"]["severity"].keys():
            aggregate_dic["metricV2"]["severity"][severity] = summary_dic["metricV2"]["severity"][severity] + current_dic["metricV2"]["severity"][severity]
        aggregate_dic["metricV2"]["score"] = summary_dic["metricV2"]["score"] + current_dic["metricV2"]["score"]
        aggregate_dic["metricV2"]["impact"] = summary_dic["metricV2"]["impact"] + current_dic["metricV2"]["impact"]
        aggregate_dic["metricV2"]["exploitability"] = summary_dic["metricV2"]["exploitability"] + current_dic["metricV2"]["exploitability"]

    ### CVSS v3
    if current_dic["metricV3"]:
        for attackVector in current_dic["metricV3"]["attackVector"].keys():
            aggregate_dic["metricV3"]["attackVector"][attackVector] = summary_dic["metricV3"]["attackVector"][attackVector] + current_dic["metricV3"]["attackVector"][attackVector]
        for attackComplexity in current_dic["metricV3"]["attackComplexity"].keys():
            aggregate_dic["metricV3"]["attackComplexity"][attackComplexity] = summary_dic["metricV3"]["attackComplexity"][attackComplexity] + current_dic["metricV3"]["attackComplexity"][attackComplexity]
        for privilegeRequired in current_dic["metricV3"]["privilegeRequired"].keys():
            aggregate_dic["metricV3"]["privilegeRequired"][privilegeRequired] = summary_dic["metricV3"]["privilegeRequired"][privilegeRequired] + current_dic["metricV3"]["privilegeRequired"][privilegeRequired]
        for confidentiality in current_dic["metricV3"]["confidentiality"].keys():
            aggregate_dic["metricV3"]["confidentiality"][confidentiality] = summary_dic["metricV3"]["confidentiality"][confidentiality] + current_dic["metricV3"]["confidentiality"][confidentiality]
        for integrity in current_dic["metricV3"]["integrity"].keys():
            aggregate_dic["metricV3"]["integrity"][integrity] = summary_dic["metricV3"]["integrity"][integrity] + current_dic["metricV3"]["integrity"][integrity]
        for availability in current_dic["metricV3"]["availability"].keys():
            aggregate_dic["metricV3"]["availability"][availability] = summary_dic["metricV3"]["availability"][availability] + current_dic["metricV3"]["availability"][availability]
        for severity in current_dic["metricV3"]["severity"].keys():
            aggregate_dic["metricV3"]["severity"][severity] = summary_dic["metricV3"]["severity"][severity] + current_dic["metricV3"]["severity"][severity]
        aggregate_dic["metricV3"]["score"] = summary_dic["metricV3"]["score"] + current_dic["metricV3"]["score"]
        aggregate_dic["metricV3"]["impact"] = summary_dic["metricV3"]["impact"] + current_dic["metricV3"]["impact"]
        aggregate_dic["metricV3"]["exploitability"] = summary_dic["metricV3"]["exploitability"] + current_dic["metricV3"]["exploitability"]

    return aggregate_dic

"""
Given as parameters two dictionaries with the base features distribution, this
function creates a dictionary with Cramer (for categorical) and KS (for continuous)
tests for each base feature
"""
def compare_stats(allDicGt, sampleDicCurrent):
    allDic = deepcopy(allDicGt)
    sampleDic = deepcopy(sampleDicCurrent)

    statsDic = fill_missing_keys()
    statsV2 = statsDic["metricV2"]
    for k in statsV2.keys():
        if not len(allDic["metricV2"][k])>0: break

        if type(allDic["metricV2"][k]) == dict:
            observed = list(sampleDic["metricV2"][k].values())
            truth = list(allDic["metricV2"][k].values())
            observed.sort()
            truth.sort()
            if len(observed) > 0:
                result = stats.cramervonmises_2samp(observed, truth)
                stat = result.statistic
                pval = result.pvalue
            else:
                stat=None
                pval = None
        else:
            observed = sampleDic["metricV2"][k]
            truth = allDic["metricV2"][k]
            observed.sort()
            truth.sort()
            if len(observed) > 0:
                result = stats.ks_2samp(observed, truth)
                stat = result.statistic
                pval = result.pvalue
            else:
                stat=None
                pval = None
        statsDic["metricV2"][k] = {"stat": stat, "pvalue": pval}
    
    statsV3 = statsDic["metricV3"]
    for k in statsV3.keys():
        if not len(allDic["metricV3"][k])>0: break
        
        if type(allDic["metricV3"][k]) == dict:
            observed = list(sampleDic["metricV3"][k].values())
            truth = list(allDic["metricV3"][k].values())
            observed.sort()
            truth.sort()
            if len(observed) > 0:
                result = stats.cramervonmises_2samp(observed, truth)
                stat = result.statistic
                pval = result.pvalue
            else:
                stat=None
                pval = None
        else:
            observed = sampleDic["metricV3"][k]
            truth = allDic["metricV3"][k]
            observed.sort()
            truth.sort()
            if len(observed) > 0:
                result = stats.ks_2samp(observed, truth)
                stat = result.statistic
                pval = result.pvalue
            else: 
                stat=None
                pval = None
        statsDic["metricV3"][k] = {"stat": stat, "pvalue": pval}
    
    return statsDic


"""
This function retrieve the distribution of the derivative features from the
ground truth
"""
def gt_statistics_path(paths_file, file_derivative_features_gt):
    with open(paths_file) as pf: gt_docs = json.load(pf)
    
    length = []
    impact = []
    likelihood = []
    score=[]
    for doc in gt_docs:
        length.append(doc["length"])
        impact.append(doc["impact"])
        likelihood.append(doc["likelihood"])
        score.append(doc["score"])
    df_GT = pd.DataFrame(columns=["length", "impact", "likelihood","score"])
    df_GT["length"] = length
    df_GT["impact"] = impact
    df_GT["likelihood"] = likelihood
    df_GT["score"] = score
    df_GT.to_csv(file_derivative_features_gt,index=False)
    return length, impact, likelihood, score

"""
This function retrieve the distribution of the derivative features from the
list of (generated) paths
"""
def retrieve_derivative(list_paths):
    length = []
    impact = []
    likelihood = []
    score = []
    for elem in list_paths:
        length.append(elem.length)
        impact.append(elem.impact)
        likelihood.append(elem.likelihood)
        score.append(elem.score)
    return length, impact, likelihood, score

"""
This function writes on file the derivative features of (generated) paths
"""
def compare_derivative_gt(sample, coll, list_paths, file_derivative_features_samples):
    curr_len, curr_imp, curr_lik, curr_score = retrieve_derivative(list_paths)
    df_curr = pd.DataFrame(columns=["sample", "collision_rate", "length", "impact", "likelihood", "score"])
    df_curr["sample"] = [sample]*len(curr_len)
    df_curr["collision_rate"] = [coll]*len(curr_len)
    df_curr["length"] = curr_len
    df_curr["impact"] = curr_imp
    df_curr["likelihood"] = curr_lik
    df_curr["score"] = curr_score
    df_curr.to_csv(file_derivative_features_samples, mode='a', index=False, header=False)