#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

#Report IDs
mediumReport = '6beae7f0-d4da-49f8-a4db-c5765bf9401a'
severeReport = '84c900e0-400e-4d03-94c5-33946b0cca37'
metaSploitable = '56f60645-c515-4739-b88b-2d8717c7a1f9'


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
													
	# Print reports list to a file
	print(reportsListResponse,file=open("reports.txt","w"))
	
	# Get Single Report for actual, ignore pagination to get all vuln entries
	reportResponse = gmp.get_report(severeReport,ignore_pagination=True)
	#reportResponse = gmp.get_report(severeReport)
	reportString = json.dumps(XMLtoJSON(reportResponse)['get_reports_response']['report']['report']['results']['result'],indent=4)

	print(reportString,file=open("output.txt","w"))
	
	# Get Single Report for testing
	# reportString = json.dumps(XMLtoJSON(reportResponse)['get_reports_response']['report']['report'],indent=4)
	# print(reportString,file=open("output.txt","w"))
	

	# Convert report to List of Dictionaries, each dictionary contains vulnerability details
	reportJSON = json.loads(reportString)	
	totalVulnerabilities = len(reportJSON)

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
		
		if entry['cvss'] > 0: vulnList.append(entry)
	

	print(f"Current GVM Version: {version['get_version_response']['version']}")
	print("====================")
	
	print(f"Total Vulnerabilities: {len(vulnList)}")					
	print("==================== \n")

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
		print(vulnList.index(vuln),'\n')

	print("===================")
	
	# Sort Vulnerabilities By host 
	perHostVulnList = sortVulnsByHost(vulnList)
	print("Finished Sorting Vulns per Host")

	# Phase 2 - Get the Consolidated Risk Per Host
	perHostData = getConsolidatedRiskPerHost(perHostVulnList)
	print("Finished Getting Consolidated Risk Per Host")

	# Phase 3 - Get the Aggregated Risk Score of the Network
	aggregatedRisk = getAggregatedRiskScore(perHostData)
	print("Finished Getting Aggregated Risk Score")

	for entry in perHostData:
		print(entry)
		print("================ \n")

	print(f"Aggregated Risk: {aggregatedRisk}")
