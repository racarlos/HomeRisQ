import json,xmltodict
from textwrap import indent										# For converting XML data to JSON

from gvm.connections import UnixSocketConnection			# Unix Domain Socket Connection 
from gvm.protocols.gmp import Gmp							# Greenbone Management Protocol 
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print

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

	print(f"Current GVM Version: {version['get_version_response']['version']}")
	print("====================")

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
	
	print(f"Total Vulnerabilities: {totalVulnerabilities}")					
	print("====================")

	# Store all Vulnerabilities 
	for vuln in reportJSON:

		entry = {
			'id':vuln['@id'],
			'name':vuln['name'],
			'hostName':vuln['host']['hostname'],
			'ipAdress':vuln['host']['#text'],
			'vector': vuln['nvt']['severities']['severity']['value'],
			'threatFamily': vuln['nvt']['family'],
			'cvss': float(vuln['nvt']['cvss_base']),
			'solution': vuln['nvt']['solution'],
			'qod': float(vuln['qod']['value'])
		}
		vulnList.append(entry)

	# # Print all Vulnerabilities
	# for vuln in vulnList:
	# 	print("ID: ",vuln['id'])
	# 	print("Name: ",vuln['name'])
	# 	print("Hostname: ",vuln['hostName'])
	# 	print("IP Adress: ",vuln['ipAdress'])
	# 	print("Vector: ",vuln['vector'])
	# 	print("Threat Family: ",vuln['threatFamily'])
	# 	print("CVSS: ",vuln['cvss'])
	# 	print("Solution: ",vuln['solution'])
	# 	print("QOD: ",vuln['qod'])
	# 	print('\n')


	sampleQOD = 90.0
	

	# HTTP Cleartext transmission vector
	sampleVector0 = "AV:A/AC:L/Au:N/C:P/I:P/A:N"

	# Log4j vector
	sampleVector1 = "AV:N/AC:M/Au:N/C:C/I:C/A:C"

	# Bluekeep Denial of Service 
	sampleVector2  = "AV:N/AC:L/Au:N/C:C/I:C/A:C"



	# Given a CVSS Vector and QOD, calculate the vulnerability's risk factor
	def getVulnerabilityRisk(vector,qod):

		probability = 0 
		impact = 0

		# Exploitability Metrics
		accessVector = 0
		accessComplexity = 0
		authentication = 0

		# Impact Metrics
		confidentiality = 0
		integrity = 0
		availability = 0 

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

		for metric in vector:			
			if metric[0] == 'AV':

				if metric[1] == "L":  	# Local
					accessVector = 0.4
				elif metric[1] == "A": 	# Adjacent Network
					accessVector = 0.6
				elif metric[1] == "N":	# Network
					accessVector = 1
			elif metric[0] == 'AC':	
				if metric[1] == "H":	# High
					accessComplexity = 0.5
				elif metric[1] == "M":	# Medium
					accessComplexity = 0.75
				elif metric[1] == "L":	# Low
					accessComplexity = 1
			elif metric[0] == 'Au':
				if metric[1] == "M":	# Multiple
					authentication = 0.5
				elif metric[1] == "S":	# Single
					authentication = 0.55
				elif metric[1] == "N":	# None
					authentication = 1
			elif metric[0] == 'C':
				if metric[1] == "N":	# None
					confidentiality = 0
				elif metric[1] == "P":	# Partial
					confidentiality = 0.5
				elif metric[1] == "C": 	# Complete
					confidentiality = 1
			elif metric[0] == 'I':
				if metric[1] == "N":	# None
					integrity = 0 					
				elif metric[1] == "P":	# Partial
					integrity = 0.5 				
				elif metric[1] == "C": 	# Complete
					integrity = 1	
			elif metric[0] == 'A':
				if metric[1] == "N":	# None
					availability = 0 
				elif metric[1] == "P":	# Partial
					availability = 0.5 
				elif metric[1] == "C": 	# Complete
					availability = 1

		probability = accessVector * accessComplexity * authentication * (qod)
		impact = (confidentiality*100 + integrity*100  + availability*100 )/3

		print(accessVector,accessComplexity,authentication,qod)
		print(confidentiality,integrity,availability)

		risk = probability * impact

		print(f"Probability: {probability}")
		print(f"Impact: {impact}")
		print(f"Risk: {risk}")

		return round(risk,4)


	vulnerabilityRisk = getVulnerabilityRisk(sampleVector2,sampleQOD)







	# # Stop Task 
	# stopResponse =  gmp.stop_task("7c9f814f-2367-4dbf-9d3b-4589a4f6e0f3")
	# print(stopResponse)


