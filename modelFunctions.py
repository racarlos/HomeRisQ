from itertools import combinations

def getProbability(vectorList):

    # Exploitability Metrics
    accessVector = 0
    accessComplexity = 0
    authentication = 0

    for metric in vectorList:			
        if metric[0] == 'AV':

            if metric[1] == "L":  	            # Local
                accessVector = 0.4
            elif metric[1] == "A": 	            # Adjacent Network
                accessVector = 0.6
            elif metric[1] == "N":	            # Network
                accessVector = 1
        elif metric[0] == 'AC':	    
            if metric[1] == "H":	            # High
                accessComplexity = 0.5
            elif metric[1] == "M":	            # Medium
                accessComplexity = 0.75
            elif metric[1] == "L":	            # Low
                accessComplexity = 1
        elif metric[0] == 'Au':
            if metric[1] == "M":	            # Multiple
                authentication = 0.5
            elif metric[1] == "S":	            # Single
                authentication = 0.55
            elif metric[1] == "N":	            # None
                authentication = 1
    
    probability = accessVector * accessComplexity * authentication
    return probability

def getImpact(vectorList):

    # Impact Metrics
    confidentiality = 0
    integrity = 0
    availability = 0 

    for metric in vectorList:	
        if metric[0] == 'C':
            if metric[1] == "N":	            # None
                confidentiality = 0
            elif metric[1] == "P":	            # Partial
                confidentiality = 0.5
            elif metric[1] == "C": 	            # Complete
                confidentiality = 1
        elif metric[0] == 'I':
            if metric[1] == "N":	            # None
                integrity = 0 					
            elif metric[1] == "P":	            # Partial
                integrity = 0.5 				
            elif metric[1] == "C": 	            # Complete
                integrity = 1	
        elif metric[0] == 'A': 
            if metric[1] == "N":	            # None
                availability = 0 
            elif metric[1] == "P":	            # Partial
                availability = 0.5 
            elif metric[1] == "C": 	            # Complete
                availability = 1

    impact = ((confidentiality+integrity+availability)*100)/3
    return impact


# Given a CVSS Vector and QOD, calculate and return the CVE's risk factor
def getVulnerabilityRisk(vector,qod):

    # Adjust Report confidence from Quality of Detection
    if qod >= 90:
        qod = 1
    elif qod < 90 and qod >= 80:
        qod = 0.95
    elif qod < 80 and qod >= 70:
        qod = 0.90

    vector = vector.split("/")

    for i in range(len(vector)):
        vector[i] = vector[i].split(":")

    probability = getProbability(vector) * qod
    impact = getImpact(vector)

    risk = probability * impact

    print(f"Probability: {probability}")
    print(f"Impact: {impact}")
    print(f"Risk: {risk}")

    return round(risk,4)

# Returns a 2D array of vulnerabilities per host
def sortVulnsByHost(vulnList):

    ipAddress = ""
    ipList = []					# Contains [[ip0,index0],[ip1,index1],[ip2,index2]] 
    perHost = []

    # For every vulnerability found
    for vuln in vulnList:

        hasAdded = False
        ipAddress =  vuln['ipAddress']				# Extract the ip address of current vulnerability

        if len(ipList) == 0:						# If Empty IP List
            entry = [ipAddress,len(ipList)]			
            ipList.append(entry)					# Add current ip and index 0
            perHost.append([vuln])					# Add current vulnerability in its own row
            hasAdded = True
        
        if hasAdded != True:
            for ip in ipList:						# Check if vulns IP is in IP List
                address = ip[0]
                index = int(ip[1])
                
                if address == ipAddress:			# If IP Address is already in IP List 
                    perHost[index].append(vuln)		# Add entry of vulnerabilibity to its host
                    hasAdded = True
                    break							# Early termination

        # If IP address of current vulnerability has not been added to the list yet
        if hasAdded != True:
            entry = [ipAddress,len(ipList)]		
            ipList.append(entry)					# Make entry in IP List
            perHost.append([vuln])					# Make sub array for that IP address in perHost List 

    return perHost

# Returns a subset of vulnerabilities based on combination 
def getVulnerabilitySubsets(vulnListPerHost):
    vulnSubsetList = []           
    
    for i in range(0,len(vulnListPerHost)+1):

        # combinations() function returns a list of subset given length
        for subset in combinations(vulnListPerHost,i):
            if(len(subset) !=0 ):
                vulnSubsetList.append(list(subset))

    return vulnSubsetList


# Get the consolidated Risk per Host, returns [ipAddress,numHosts,consolidatedRisk]
def getConsolidatedRiskPerHost(perHost):

    for host in perHost:                                            # For every machine in the list

        print(f"Host: {perHost.index(host)} \n ")
        print(host)
        idList = []                                                 # ID list of every vuln in a host
        for vuln in host: idList.append(vuln['id'])
    
        vulnSubsetList = getVulnerabilitySubsets(host)

        consolidatedProbability = 0
        consolidatedImpact = 0
        consolidatedRisk = 0 
        
        for subset in vulnSubsetList:                               # For each vulnerability in the subset

            subsetProbability = 1 
            
            subsetIdList = []
            for vuln in subset: subsetIdList.append(vuln['id'])     # Get their IDs and compare with list of all vulns in the host


            # for i in range(len(idList)):                            # Check if ID of vuln is in subset of exploited CVEs
                
            #     if idList[i] in subsetIdList:                       # IF CVE was exploited in this subset    
            #         #print(f"[{i}+]",end=" ")
            #         subsetProbability *=  

            #     else:                                               # IF CVE was not exploited in this subset 
                    #print(f"[{i}-]",end=" ")

            #print("\n")

        #print("=================")


        
    
        exit(1)



    # product of the probability of all exploited CVEs * product of 1 - probability of all non exploited CVEs











