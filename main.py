#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Imports from GVM Libraries
from gvm.connections import UnixSocketConnection			# Unix Domain Socket Connection 
from gvm.protocols.gmp import Gmp							# Greenbone Management Protocol 
from gvm.transforms import EtreeTransform

# Imports from Own Libraries
from modelFunctions import *
from gmpFunctions import *

# Kivy Imports
from kivy.lang import Builder
from kivymd.app import MDApp
from kivy.core.window import Window

connection = UnixSocketConnection()
transform = EtreeTransform()								# Element Tree transform for storing XML 


# Task ID's
networkFullAndFastScanId = 'ad0736a6-ab8d-4e3b-b1f4-410f753cb822'
networkDiscoveryScanId = '7c9f814f-2367-4dbf-9d3b-4589a4f6e0f3'

#Report IDs
lowReport = '9cc3359e-cec8-4559-a03f-d7d5cf834dfc'
mediumReport = '6beae7f0-d4da-49f8-a4db-c5765bf9401a'
severeReport = '84c900e0-400e-4d03-94c5-33946b0cca37'
metaSploitable = '56f60645-c515-4739-b88b-2d8717c7a1f9'


# Computation Variables
vulnList = []
reportsList = []

totalVulnerabilities = 0


version = getVersion()
reportsListJSON = getReports()

print(f"Current GVM Version: {version}")
print("====================")

# Store reportsList in 
for report in reportsListJSON:

	entry = {
		'id': report['report']['@id'],
		'name': report['task']['name'],
		'date': report['report']['scan_start'],
		'hostCount': int(report['report']['hosts']['count']),
		'vulnCount': int(report['report']['vulns']['count']),
		'progress' : int(report['report']['task']['progress']),
		'severity' : float(report['report']['severity']['full']),
	}

	# Avoid Discovery Scans 
	if entry['name'] != 'Discovery': reportsList.append(entry)

print(reportsList)				


# getSingleReport(lowReport)
# getSingleReport(mediumReport)
reportJSON =  getSingleReport(severeReport)
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


Window.size = (1280,720)

class MainApp(MDApp):

	# Builder Method
	def build(self):
		self.theme_cls.theme_style = "Dark"
		self.theme_cls.primary_palette = "BlueGray"
		screen = Builder.load_file('main.kv')
		return screen

	# For Opening and closing navigation Rail 
	def openRail(self):
		if self.root.ids.rail.rail_state == "open":
			self.root.ids.rail.rail_state = "close"
		else:
			self.root.ids.rail.rail_state = "open"

	def generateHistoryEntries(self):
		pass

# Run the App
MainApp().run()