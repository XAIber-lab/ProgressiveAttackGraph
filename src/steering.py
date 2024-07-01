import pandas as pd
import numpy as np
from sklearn.tree import DecisionTreeClassifier

def isQuery(query,attack_path):
    for k in query.keys():
        if k!="id":
            min_v, max_v = query[k]
            if attack_path[k] < min_v or attack_path[k] > max_v: return False
    return True

def extract_cve_trace(traces):
    vulns_by_trace=[]
    for trace in traces:
        vulns=[]
        for step in trace.split("##"):
            for edge_str in step.split("#"):
                if "CVE" in edge_str: vulns.append(edge_str)
        vulns_by_trace.append(vulns)
    return vulns_by_trace

def convert_categorical_to_num(str_val):
    if str_val == "NONE": return 0
    elif str_val == "NETWORK" or str_val=="LOW" or str_val=="SINGLE" or str_val=="PARTIAL": return 1
    elif str_val == "ADJACENT_NETWORK" or str_val=="MEDIUM" or str_val=="MULTIPLE" or str_val=="COMPLETE": return 2
    elif str_val == "LOCAL" or str_val=="HIGH": return 3
    elif str_val == "PHYSICAL" or str_val=="CRITICAL": return 4
    else: return 0
def convert_num_to_categorical(num_val,metric,version):
    if metric == "accessVector" or metric == "attackVector":
        if num_val <= 1: return "NETWORK"
        elif num_val >1 and num_val <=2: return "ADJACENT_NETWORK"
        elif num_val >2 and num_val <=3: return "LOCAL"
        else: return "PHYSICAL"
    elif metric == "accessComplexity" or metric == "baseSeverity" or metric == "privilegesRequired" or metric == "attackComplexity":
        if num_val == 0: return "NONE"
        elif num_val <= 1: return "LOW"
        elif num_val>1 and num_val <=2: return "MEDIUM"
        elif num_val>2 and num_val <=3: return "HIGH"
        else: return "CRITICAL"
    elif metric == "integrityImpact" or metric == "confidentialityImpact" or metric == "availabilityImpact":
        if version == 2:
            if num_val == 0: return "NONE"
            elif num_val <= 1: return "PARTIAL"
            else: return "COMPLETE"
        else:
            if num_val == 0: return "NONE"
            elif num_val <= 1: return "LOW"
            elif num_val>1 and num_val <=2: return "MEDIUM"
            elif num_val>2 and num_val <=3: return "HIGH"
            else: return "CRITICAL"
    elif metric == "authentication":
        if num_val == 0: return "NONE"
        elif num_val <= 1: return "SINGLE"
        else: return "MULTIPLE"
    return

def base_features_vulnID(vuln_id,vulnerabilities):
    for vuln in vulnerabilities:
        if vuln["id"] == vuln_id:
            dicFeatures={}
            if "cvssMetricV2" in vuln["metrics"]:
                metricV2 = vuln["metrics"]["cvssMetricV2"][0]
                metricCvssV2 = metricV2["cvssData"]

                dicFeatures["baseScore"] = metricCvssV2["baseScore"]
                dicFeatures["impactScore"] = metricV2["impactScore"]
                dicFeatures["exploitabilityScore"] = metricV2["exploitabilityScore"]
                dicFeatures["accessVector"]=convert_categorical_to_num(metricCvssV2["accessVector"])
                dicFeatures["accessComplexity"]=convert_categorical_to_num(metricCvssV2["accessComplexity"])
                dicFeatures["authentication"]=convert_categorical_to_num(metricCvssV2["authentication"])
                dicFeatures["confidentialityImpact"]=convert_categorical_to_num(metricCvssV2["confidentialityImpact"])
                dicFeatures["integrityImpact"]=convert_categorical_to_num(metricCvssV2["integrityImpact"])
                dicFeatures["availabilityImpact"]=convert_categorical_to_num(metricCvssV2["availabilityImpact"])
                dicFeatures["baseSeverity"]=convert_categorical_to_num(metricV2["baseSeverity"])

                return dicFeatures
            
            if "cvssMetricV30" in vuln["metrics"] or "cvssMetricV31" in vuln["metrics"]:
                if "cvssMetricV30" in vuln["metrics"]: metricV3 = vuln["metrics"]["cvssMetricV30"][0]
                else: metricV3 = vuln["metrics"]["cvssMetricV31"][0]
                metricCvssV3 = metricV3["cvssData"]

                dicFeatures["baseScore"]=metricCvssV3["baseScore"]
                dicFeatures["impactScore"]=metricV3["impactScore"]
                dicFeatures["exploitabilityScore"]=metricV3["exploitabilityScore"]
                # dicFeatures["attackVector"]=convert_categorical_to_num(metricCvssV3["attackVector"])
                dicFeatures["accessVector"]=convert_categorical_to_num(metricCvssV3["attackVector"])
                # dicFeatures["attackComplexity"]=convert_categorical_to_num(metricCvssV3["attackComplexity"])
                dicFeatures["accessComplexity"]=convert_categorical_to_num(metricCvssV3["attackComplexity"])
                # dicFeatures["privilegesRequired"]=convert_categorical_to_num(metricCvssV3["privilegesRequired"])
                dicFeatures["authentication"]=convert_categorical_to_num(metricCvssV3["privilegesRequired"])
                dicFeatures["confidentialityImpact"]=convert_categorical_to_num(metricCvssV3["confidentialityImpact"])
                dicFeatures["integrityImpact"]=convert_categorical_to_num(metricCvssV3["integrityImpact"])
                dicFeatures["availabilityImpact"]=convert_categorical_to_num(metricCvssV3["availabilityImpact"])
                dicFeatures["baseSeverity"]=convert_categorical_to_num(metricCvssV3["baseSeverity"])
                
                return dicFeatures

            return dicFeatures

def dict_median(dict_list):
    mean_dict = {}
    for key in dict_list[0].keys():
        mean_dict[key] = np.median([d[key] for d in dict_list], axis=0)
    return mean_dict
def embed_function(cves_list,isQuery,vulnerabilities):
    subtraining=[]
    for cvetrace in cves_list:
        embedding = []
        for cve in cvetrace:
            embedding.append(base_features_vulnID(cve,vulnerabilities))
        cve_data_dict = dict_median(embedding)
        cve_data_dict["query"] = isQuery
        subtraining.append(cve_data_dict)
    return subtraining

def build_training_set(qfile,ofile,vulnerabilities):
    df_query = pd.read_json(qfile)
    df_other = pd.read_json(ofile)
    num_data = min(len(df_query),len(df_other))
    df_query=df_query[0:num_data]
    df_other=df_other[0:num_data]

    cves_query = extract_cve_trace(list(df_query["trace"]))
    cves_other = extract_cve_trace(list(df_other["trace"]))

    training_set_query=embed_function(cves_query,True,vulnerabilities)
    training_set_other=embed_function(cves_other,False,vulnerabilities)
    df_training = pd.DataFrame(training_set_query+training_set_other)
    
    return df_training

def _find_path(tree, node_numb, path, x):
    path.append(node_numb)

    children_left = tree.children_left
    children_right = tree.children_right

    if node_numb == x:
        return True

    left = False
    right = False

    if children_left[node_numb] != -1:
        left = _find_path(tree, children_left[node_numb], path, x)
    if children_right[node_numb] != -1:
        right = _find_path(tree, children_right[node_numb], path, x)
    if left or right:
        return True

    path.remove(node_numb)
    return False

def _extract_paths(X, model):
    tree = model.tree_
    paths = {}
    leave_id = model.apply(X)
    for leaf in np.unique(leave_id):
        if model.classes_[np.argmax(model.tree_.value[leaf])] == 1:
            path_leaf = []
            _find_path(tree, 0, path_leaf, leaf)
            paths[leaf] = list(np.unique(np.sort(path_leaf)))

    return paths

def _get_rule(tree, path, column_names, feature, threshold):
    children_left = tree.children_left

    mask = ""
    for index, node in enumerate(path):
        # We check if we are not in the leaf
        if index != len(path) - 1:
            # Do we go under or over the threshold ?
            if children_left[node] == path[index + 1]:
                mask += "(df['{}']<= {}) \t ".format(
                    column_names[feature[node]], threshold[node]
                )
            else:
                mask += "(df['{}']> {}) \t ".format(
                    column_names[feature[node]], threshold[node]
                )
    # We insert the & at the right places
    mask = mask.replace("\t", "&", mask.count("\t") - 1)
    mask = mask.replace("\t", "")
    return mask

def _extract_conjunction(rule, conjunction):
    condition = ""
    listconditions = rule.strip().split("&")
    i = 0
    for s in listconditions:
        listLabel = s.strip().split("'")
        condition = (
            condition + listLabel[1] + " " + listLabel[2][1 : len(listLabel[2]) - 1]
        )

        if i != len(listconditions) - 1:
            condition = condition + " " + conjunction + " "
        i += 1

    return condition

def _generate_expression(sample, tree, paths, feature, threshold):
    rules = {}
    expression = ""
    conjunctor = "and"
    disjunctor = "or"

    j = 0
    for key in paths:
        rules[key] = _get_rule(tree, paths[key], sample.columns, feature, threshold)
        new_conjunction = _extract_conjunction(rules[key], conjunctor)

        if j == 0:
            expression = "(" + new_conjunction + ")"
        else:
            expression = expression + " " + disjunctor + " (" + new_conjunction + ")"
        j += 1

    return expression

def filter_vulnerabilities(conditions,vulnerabilities):
    op = {'<=': lambda x, y: float(x) <= float(y),
      '>': lambda x, y: float(x) > float(y)}

    compliant_vulns=[]
    for vuln in vulnerabilities:
        isCompliant = True
        for condition in conditions:
            condition = condition.replace("(","").replace(")","")
            metric,operator,value = condition.split(" ")
            value = float(value)
            if "cvssMetricV2" in vuln["metrics"]:
                metricV2 = vuln["metrics"]["cvssMetricV2"][0]
                metricCvssV2 = metricV2["cvssData"]

                if metric == "baseScore": #numerical
                    if not op[operator](metricCvssV2["baseScore"],value): isCompliant = False
                elif metric == "baseSeverity": #categorical
                    if not op[operator](convert_categorical_to_num(metricV2["baseSeverity"]),value): isCompliant = False
                elif metric in ["impactScore","exploitabilityScore"]: #numerical
                    if not op[operator](metricV2[metric],value): isCompliant = False
                else: #categorical
                    if not op[operator](convert_categorical_to_num(metricCvssV2[metric]),value): isCompliant = False
                
            if "cvssMetricV30" in vuln["metrics"] or "cvssMetricV31" in vuln["metrics"]:
                if "cvssMetricV30" in vuln["metrics"]: metricV3 = vuln["metrics"]["cvssMetricV30"][0]
                else: metricV3 = vuln["metrics"]["cvssMetricV31"][0]
                metricCvssV3 = metricV3["cvssData"]

                if metric == "baseScore": #numerical
                    if not op[operator](metricCvssV3["baseScore"],value): isCompliant = False
                elif metric in ["impactScore","exploitabilityScore"]: #numerical
                    if not op[operator](metricV3[metric],value): isCompliant = False
                else: #categorical
                    if metric == "accessVector":
                        if not op[operator](convert_categorical_to_num(metricCvssV3["attackVector"]),value): isCompliant = False
                    elif metric == "accessComplexity":
                        if not op[operator](convert_categorical_to_num(metricCvssV3["attackComplexity"]),value): isCompliant = False
                    elif metric == "authentication":
                        if not op[operator](convert_categorical_to_num(metricCvssV3["privilegesRequired"]),value): isCompliant = False
                    else:
                        if not op[operator](convert_categorical_to_num(metricCvssV3[metric]),value): isCompliant = False
        if isCompliant: compliant_vulns.append(vuln["id"])
    return compliant_vulns

def convert_expression_to_vuln(expression,vulnerabilities):
    disjunctions = expression.split(" or ")
    all_vulns_compliant = []
    for sub_expression in disjunctions:
        conjunctions = sub_expression.split (" and ")
        filtered_vuln = filter_vulnerabilities(conjunctions,vulnerabilities)
        all_vulns_compliant+=filtered_vuln
    return list(set(all_vulns_compliant))

def get_steering_vulns(qfile,ofile,vulnerabilities):
    training_set = build_training_set(qfile,ofile,vulnerabilities)
    
    X = training_set.loc[:, training_set.columns != "query"]
    y = training_set["query"]
    dtree = DecisionTreeClassifier(class_weight="balanced")
    dtree = dtree.fit(X, y)
    tree_mod = dtree.tree_
    feature = tree_mod.feature
    threshold = tree_mod.threshold

    paths = _extract_paths(X, dtree)
    expr = _generate_expression(training_set, tree_mod, paths, feature, threshold)

    return convert_expression_to_vuln(expr,vulnerabilities)