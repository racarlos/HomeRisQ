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


