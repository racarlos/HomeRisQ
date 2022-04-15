from itertools import combinations          # Itertools for producing combinations
from gmpFunctions import getSingleReport


#Converts CVSS Vector to Vector String
def splitVector(vector):

    vectorList = vector.split("/")

    for i in range(len(vectorList)):
        vectorList[i] = vectorList[i].split(":")

    return vectorList

def getProbability(vectorList,qod):

    # Adjust Report confidence from Quality of Detection
    if qod >= 90:
        qod = 1
    elif qod < 90 and qod >= 80:
        qod = 0.95
    elif qod < 80 and qod >= 70:
        qod = 0.90

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
    
    probability = accessVector * accessComplexity * authentication*qod
    return round(probability,4)

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
    return round(impact,4)


# Given a CVSS Vector and QOD, calculate and return the CVE's risk factor
def getVulnerabilityRisk(vector,qod):

    vectorList = splitVector(vector) 
    probability = getProbability(vectorList,qod)
    impact = getImpact(vectorList)

    risk = probability * impact
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

        # Get Risk Value of Vulnerability
        vuln['risk'] = round(getVulnerabilityRisk(vuln['vector'],vuln['qod']),2)

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


# Return probability and impact of a subset given a subset of IDS and all vulnerabilities in a host
def getSubsetProbabilityAndImpact(isExploited,host):

    impactMax = 100 
    subsetImpact = 0
    subsetProbability = 1

    for i in range(len(host)):                                  # Go through all vulnerabilities in the per-host vuln list 

        vectorList = splitVector(host[i]['vector'])
        qod = host[i]['qod']

        vulnProbability = getProbability(vectorList,qod)
        vulnImpact = getImpact(vectorList)
        
        # Disregard LOG intensity and impactless vulnerabilities
        if isExploited[i] is True and vulnImpact > 0:
            subsetProbability *= vulnProbability
            subsetImpact += vulnImpact            
        # Product of the probability of all exploited CVEs * product of 1 - probability of all non exploited CVEs
        elif isExploited[i] is False and vulnImpact > 0:
            subsetProbability *= (1-vulnProbability)
            

    subsetProbability = round(subsetProbability,4)
    subsetImpact = round(subsetImpact,4)

    # Max of 100 impact per subset     
    if(subsetImpact < impactMax):
        return [subsetProbability,subsetImpact]
    else :
        return [subsetProbability,impactMax]

# Get the number of Vulnerabilities whose Impact is greater than 0 per host 
def getImpactfulVulnCount(host):
    
    vulnCount = 0

    for i in range(0,len(host)):
        vulnImpact = host[i]['cvss']

        if(vulnImpact > 0): vulnCount +=1 

    return vulnCount 


# Returns a subset of vulnerabiliy ID based on combination 
def getVulnerabilityIDSubset(vulnIdList):
    vulnSubsetList = []           
    
    for i in range(0,len(vulnIdList)+1):

        # combinations() function returns a list of subset given length
        for subset in combinations(vulnIdList,i):
            if(len(subset) !=0 ):
                vulnSubsetList.append(list(subset))

    return vulnSubsetList

# Get the consolidated Risk per Host, returns [hostName,ipAddress,numVulns,consolidatedRisk]
def getConsolidatedRiskPerHost(hostList):

    # print("=====================================")
    # print(hostList)
    # print("=====================================")
    data = [] 

    for host in hostList:                                              # For every machine in the list
 
        consolidatedRisk = 0
    
        idList = []                                                    # ID list of every vuln in a host
        for vuln in host: idList.append(vuln['id'])

        subsetProbabilityList = []
        subsetImpactList = []

        # Generate ID Subsets
        for i in range(1,len(idList)+1):

            vulnSubsetList = []                                         # List is refilled every iteration to prevent memory overflow

            for subset in combinations(idList,i):                       # refill list with new subset based on length i 
                if(len(subset) != 0 ):
                    vulnSubsetList.append(list(subset))

            #print(f"Subset Length: {len(vulnSubsetList)} Iteration: {i}")


            # For each subset calculate their Probability and Impact 
            for subset in vulnSubsetList:                                
                
                isExploited = []                                           # Determines whether CVE is exploited or not 

                for i in range(len(idList)):                               # For each ID in subset check if ID of vuln is in subset of exploited CVEs
                    
                    if idList[i] in subset:                                # IF CVE was exploited in this subset    
                        isExploited.append(True)
                    else:                                                  # IF CVE was not exploited in this subset 
                        isExploited.append(False)

                subsetResult = getSubsetProbabilityAndImpact(isExploited,host)
                subsetProbabilityList.append(subsetResult[0])
                subsetImpactList.append(subsetResult[1])


        # Calculate for Consolidated Risk here - Possibly move this to thread process
        for i in range(len(subsetImpactList)):

            if(subsetImpactList[i] > 0):
                subsetRisk = subsetProbabilityList[i] * subsetImpactList[i]
                consolidatedRisk += subsetRisk
        
        # Number of impactful vulnerabilty per host
        vulnCount = getImpactfulVulnCount(host)
    
        entry = {
            "ipAddress": host[0]['ipAddress'],
            "hostName": host[0]['hostName'],
            "vulnCount": vulnCount,
            "consolidatedRisk": round(consolidatedRisk,2)
        }
        
        data.append(entry)
    
    return data

# Get the Aggregated Risk Score of the Network given the Consolidated Risk Scores per Host 
def getAggregatedRiskScore(perHostData):
    
    aggregatedScore = 1

    for i in range(len(perHostData)):

        hostScore = perHostData[i]['consolidatedRisk']                  # Extract Score
        hostScore = 1 - (hostScore/100)                                 # Convert score to Value from 0-1

        aggregatedScore *= hostScore                                    # Multiply all converted scores to aggregated score

    aggregatedScore = 100 - (aggregatedScore*100)   
    return round(aggregatedScore,2)


def getHighRiskVulnCount(vulnList):
    count = 0 
    threshold = 5.0
    
    for vuln in vulnList:
        vulnRisk = getVulnerabilityRisk(vuln['vector'],vuln['qod'])

        if(vulnRisk) >= threshold:
            count += 1
    return count

def getMostVulnerableHost(consolidatedRiskPerHost):

    maxRisk = 0 
    ipAddress = ''

    # In case the network is very safe
    if len(consolidatedRiskPerHost) == 0:
        return None

    for hostData in consolidatedRiskPerHost:
        if hostData['consolidatedRisk'] > maxRisk:
            ipAddress = hostData['ipAddress']

    return ipAddress


def startCalculation(reportID):

    print(f"Generating Report for: {reportID}")

    # Computation Variables
    vulnList = []
    totalVulnerabilities = 0
    addresses = []
    hostNames = []
    reportJSON =  getSingleReport(reportID)

    # Store all Vulnerabilities and add their Impact, Probability, and Risk Values
    for vuln in reportJSON:
        
        entry = {
            'id':vuln['@id'],
            'name':vuln['name'],
            'ipAddress':vuln['host']['#text'],
            'hostName':vuln['host']['hostname'],
            'vector': vuln['nvt']['severities']['severity']['value'],
            'threatFamily': vuln['nvt']['family'],
            'cvss': float(vuln['nvt']['cvss_base']),
            'solution': vuln['nvt']['solution'],
            'qod': float(vuln['qod']['value'])
        }
        
        totalVulnerabilities += 1
        
        if entry['cvss'] > 0: 
            entry['solution']['#text'] = entry['solution']['#text'].replace('\n','') 
            vulnList.append(entry)
   
        if entry['ipAddress'] in addresses:
            pass
        else: 
            addresses.append(entry['ipAddress'])
            hostNames.append(entry['hostName'])

    # Phase 0 - Sort Vulnerabilities By host 
    perHostVulnList = sortVulnsByHost(vulnList)
    # print("Finished Sorting Vulns per Host. \n")

    # Phase 2 - Get the Consolidated Risk Per Host
    consolidatedRiskPerHost = getConsolidatedRiskPerHost(perHostVulnList)

    # print("Finished Getting Consolidated Risk Per Host. \n")

    # Phase 3 - Get the Aggregated Risk Score of the Network
    aggregatedRisk = getAggregatedRiskScore(consolidatedRiskPerHost)
    
    # Add safe hosts for GUI View
    for i in range(len(addresses)):
        isStored = False
        for entry in consolidatedRiskPerHost:
            if addresses[i] == entry['ipAddress']:
                isStored = True
                break         

        if(isStored is False):
            hostEntry = {
                'ipAddress': addresses[i],
                'hostName': hostNames[i],
                'vulnCount': 0,
                'consolidatedRisk': 0,
            }       
            consolidatedRiskPerHost.append(hostEntry)

    # Get Additional Metrics
    highRiskVulnCount = getHighRiskVulnCount(vulnList)
    mostVulnerableHost = getMostVulnerableHost(consolidatedRiskPerHost)

    print("++++++++++++++++")
    print(consolidatedRiskPerHost)
    print("++++++++++++++++")

    data = {
        'hostCount': len(hostNames),
        'totalVulnerabilities': totalVulnerabilities,
        'perHostVulnList' : perHostVulnList,
        'consolidatedRiskPerHost' : consolidatedRiskPerHost,
        'aggregatedRisk' : aggregatedRisk,
        'highRiskVulnCount' : highRiskVulnCount,
        'mostVulnerableHost' : mostVulnerableHost
    }

    return data