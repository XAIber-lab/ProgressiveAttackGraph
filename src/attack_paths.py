import random, hashlib, statistics

def get_vulns_by_hostname(dev_hostname,devices):
    cve_list=[]
    for host in devices:
        if host["hostname"] == dev_hostname:
            for iface in host["network_interfaces"]:
                if "ports" in iface.keys():
                    for port in iface["ports"]:
                        for service in port["services"]:
                            cve_list.append(service["cve_list"])
                if "applications" in iface.keys():
                    for app in iface["applications"]:
                        cve_list.append(app["cve_list"])
            return list(set([item for sublist in cve_list for item in sublist]))
    return []
                
"""
These functions checks the pre-post condition chaining
"""
def get_req_privilege(str_priv):
    if str_priv == "NONE" or str_priv == "LOW":
        return "guest"
    elif str_priv == "SINGLE" or str_priv == "MEDIUM":
        return "user"
    else:
        return "root"
def get_gain_privilege(isroot, isuser, req_privilege):
    if isroot == "UNCHANGED" and isuser == "UNCHANGED":
        return get_req_privilege(req_privilege)
    elif isroot == True:
        return "root"
    elif isuser == True:
        return "user"
    else:
        return "user"
def retrieve_privileges(vulnID,vulnerabilities):
    for vuln in vulnerabilities:
        if vuln["id"] == vulnID:
            if "cvssMetricV2" in vuln["metrics"]:
                metricV2 = vuln["metrics"]["cvssMetricV2"][0]
                metricCvssV2 = metricV2["cvssData"]
                
                priv_required = get_req_privilege(metricCvssV2["authentication"])
                priv_gained = get_gain_privilege(metricV2["obtainAllPrivilege"],metricV2["obtainUserPrivilege"],metricCvssV2["authentication"])
                return vuln,priv_required,priv_gained
            elif "cvssMetricV30" in vuln["metrics"] or "cvssMetricV31" in vuln["metrics"]: 
                if "cvssMetricV30" in vuln["metrics"]: metricV3 = vuln["metrics"]["cvssMetricV30"][0]
                else: metricV3 = vuln["metrics"]["cvssMetricV31"][0]
                metricCvssV3 = metricV3["cvssData"]

                priv_required = get_req_privilege(metricCvssV3["privilegesRequired"])
                priv_gained = get_gain_privilege(metricCvssV3["scope"],metricCvssV3["scope"],metricCvssV3["privilegesRequired"])
                return vuln,priv_required,priv_gained
            else:
                return vuln,"guest","guest"

def get_derivative_features(vuln):
    if "cvssMetricV2" in vuln["metrics"]:
        metricV2 = vuln["metrics"]["cvssMetricV2"][0]
        impact = metricV2["impactScore"]
        likelihood = metricV2["exploitabilityScore"]
        score = metricV2["cvssData"]["baseScore"]
    elif "cvssMetricV30" in vuln["metrics"]:
        metricV3 = vuln["metrics"]["cvssMetricV30"][0]
        impact = metricV3["impactScore"]
        likelihood = metricV3["exploitabilityScore"]
        score = metricV3["cvssData"]["baseScore"]
    elif "cvssMetricV31" in vuln["metrics"]:
        metricV3 = vuln["metrics"]["cvssMetricV31"][0]
        impact = metricV3["impactScore"]
        likelihood = metricV3["exploitabilityScore"]
        score = metricV3["cvssData"]["baseScore"]
    else: #default values
        impact = 5 
        likelihood = 5
        score = 5
    return impact,likelihood,score

def reachability_to_attack(reachability_path,devices,vulnerabilities,steering_vulns):
    processed_targets={}
    trace = ""
    impacts=[]
    likelihoods=[]
    scores=[]
    vulnerabilities_path = []
    for edge in reachability_path:
        target_hostname = edge[1]
        if target_hostname not in processed_targets.keys():
            vulns_edge = get_vulns_by_hostname(target_hostname,devices)
            processed_targets[target_hostname] = vulns_edge
        else:
            vulns_edge = processed_targets[target_hostname]
        if len(vulns_edge)<=0: continue
        
        steering_compliant_vulns = []
        for v_edge in vulns_edge:
            if v_edge in steering_vulns: steering_compliant_vulns.append(v_edge)

        if len(steering_compliant_vulns)>0:
            attack_vuln = random.choice(steering_compliant_vulns)
        else:
            attack_vuln = random.choice(vulns_edge)
        vuln,pre,post = retrieve_privileges(attack_vuln,vulnerabilities)
        src=pre+"@"+str(edge[0])
        dst=post+"@"+str(target_hostname)

        if edge == reachability_path[-1]: trace += src+"#"+attack_vuln+"#"+dst
        else: trace += src+"#"+attack_vuln+"#"+dst+"##"

        vulnerabilities_path.append(vuln)
        impact,likelihood,score=get_derivative_features(vuln)
        impacts.append(impact)
        likelihoods.append(likelihood)
        scores.append(score)

    return {
        "id": hashlib.sha256(str(trace).encode("utf-8")).hexdigest(),
        "trace": trace,
        "length": len(impacts),
        "impact": impacts[len(impacts)-1],
        "likelihood": statistics.mean(likelihoods),
        "score" : statistics.median(scores),
    }, vulnerabilities_path

