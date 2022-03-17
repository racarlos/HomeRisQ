
import json,xmltodict

# Imports from GVM Libraries
from gvm.connections import UnixSocketConnection			# Unix Domain Socket Connection 
from gvm.protocols.gmp import Gmp							# Greenbone Management Protocol 
from gvm.transforms import EtreeTransform

# Imports from Own Libraries
from modelFunctions import *

connection = UnixSocketConnection()
transform = EtreeTransform()								# Element Tree transform for storing XML 

# Login Variables
username = 'admin'
password = 'kali'

# Task ID's
networkFullAndFastScanId = 'ad0736a6-ab8d-4e3b-b1f4-410f753cb822'
networkDiscoveryScanId = '7c9f814f-2367-4dbf-9d3b-4589a4f6e0f3'

# Computation Variables
vulnList = []

totalVulnerabilities = 0

def XMLtoJSON(a):
	output = json.loads(json.dumps(xmltodict.parse(a)))
	return output

def XMLtoString(a):
	output = json.dumps(xmltodict.parse(a),indent=4)
	return output

def printXML(a):
	print(json.dumps(xmltodict.parse(a),indent=4))
	

with Gmp(connection) as gmp:

	# Retrieve GMP version supported by the remote daemon
	versionResponse = gmp.get_version()
	version = json.loads(json.dumps(xmltodict.parse(versionResponse)))				# Convert XML to Dictionary and parse to JSON String

	# Login 
	gmp.authenticate(username,password)

	# Get all reports
	reportsListResponse = gmp.get_reports()

	# Convert XML to JSON String
	reportsListResponse = json.dumps(XMLtoJSON(reportsListResponse)['get_reports_response']['report'],indent=4)

	# Convert JSON String to dict
	#reportsJSON = json.loads(reportsListResponse)																

	# Print reports list to a file
	print(reportsListResponse,file=open("reports.txt","w"))
	
	# Get Single Report
	reportResponse = gmp.get_report('84c900e0-400e-4d03-94c5-33946b0cca37')
	reportString = json.dumps(XMLtoJSON(reportResponse)['get_reports_response']['report']['report']['results']['result'],indent=4)

	# Convert report to List of Dictionaries, each dictionary contains vulnerability details
	reportJSON = json.loads(reportString)	
	totalVulnerabilities = len(reportJSON)

	# Print contents of individual report to output file
	print(reportString,file=open("output.txt","w"))


	print(f"Current GVM Version: {version['get_version_response']['version']}")
	print("====================")

	
	print(f"Total Vulnerabilities: {totalVulnerabilities}")					
	print("==================== \n")



	# Store all Vulnerabilities and add their Impact, PRobability, and Risk Values
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
		vulnList.append(entry)


	# Sort Vulnerabilities By host 
	perHostVulnList = sortVulnsByHost(vulnList)
	getConsolidatedRiskPerHost(perHostVulnList)

	# # Sample values for Testing
	# sampleQOD = 90.0
	# sampleVector0 = "AV:A/AC:L/Au:N/C:P/I:P/A:N"				# HTTP Cleartext transmission vector
	# sampleVector1 = "AV:N/AC:M/Au:N/C:C/I:C/A:C"				# Log4j vector
	# sampleVector2  = "AV:N/AC:L/Au:N/C:C/I:C/A:C"				# Bluekeep Denial of Service 
	
	# print(f"Number of Hosts: {len(perHost)}")
	# print("==================== \n")

	# for row in perHost:
	# 	for vuln in row:
	# 		print("ID: ",vuln['id'])
	# 		print("Name: ",vuln['name'])
	# 		print("IP Adress: ",vuln['ipAddress'])
	# 		print("Hostname: ",vuln['hostName'])
	# 		print("Vector: ",vuln['vector'])
	# 		print("Threat Family: ",vuln['threatFamily'])
	# 		print("CVSS: ",vuln['cvss'])
	# 		print("Solution: ",vuln['solution'])
	# 		print("QOD: ",vuln['qod'])
	# 		print('\n')

	# 	print("===================")

    




	# # Stop Task 
	# stopResponse =  gmp.stop_task("7c9f814f-2367-4dbf-9d3b-4589a4f6e0f3")
	# print(stopResponse)

