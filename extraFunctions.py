def printReports(reportsList):
    for report in reportsList:
        print("ID: ",report['id'])
        print("Name: ",report['name'])
        print("Date: ",report['date'])
        print("Host Count: ",report['hostCount'])
        print("Vuln Count: ",report['vulnCount'])
        print("Progress: ",report['progress'])
        print("Severity: ",report['severity'])
        print("==================== \n")

def printVulnerabilities(vulnList):
    for vuln in vulnList:
        print("ID: ",vuln['id'])
        print("Name: ",vuln['name'])
        print("IP Adress: ",vuln['ipAddress'])
        print("Hostname: ",vuln['hostName'])
        print("Vector: ",vuln['vector'])
        print("Threat Family: ",vuln['threatFamily'])
        print("CVSS: ",vuln['cvss'])
        print("Solution: ",vuln['solution'])
        print("QOD: ",vuln['qod'])
        print("Index: ",vulnList.index(vuln))
        print("=================== \n")

def getQualitativeAssessment(aggregatedScore):
    assessment = ''
    if 0 <= aggregatedScore <= 20:
        assessment = "Your network is [b]Safe[/b]"
    elif 0 <= aggregatedScore <= 40:
        assessment = "Your network is at a [b]Minor Risk[/b]"
    elif 0 <= aggregatedScore <= 60:
        assessment = "Your network is at a [b]Moderate Risk[/b]"
    elif 0 <= aggregatedScore <= 80:
        assessment = "Your network is at a [b]High Risk[/b]"
    elif 0 <= aggregatedScore <= 100:
        assessment = "Your network is at an [b]Extreme Risk[/b]"
    return assessment

def getSolutionIcon(solutionType):
    solutionIcon = ''
    if(solutionType == 'Mitigation'):
        solutionIcon = 'security'
    elif(solutionType == 'Workaround'):
        solutionIcon = 'hammer-wrench'
    elif(solutionType == 'VendorFix'):
        solutionIcon = 'store'
    elif(solutionType == 'WillNotFix'):
        solutionType = 'thumb-down'
    else:
        solutionIcon = 'close-circle'
    return solutionIcon
   
