#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Imports from GVM Libraries
from os import listdir
from gvm.connections import UnixSocketConnection			# Unix Domain Socket Connection 
from gvm.protocols.gmp import Gmp							# Greenbone Management Protocol 
from gvm.transforms import EtreeTransform

# Imports from Own Libraries
from modelFunctions import *
from gmpFunctions import *
from extraFunctions import *


# Kivy Imports
from kivy.lang import Builder
from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivy.animation import Animation
from kivymd.uix.card import MDCard
from kivymd.uix.label import MDLabel
from kivymd.uix.expansionpanel import MDExpansionPanel, MDExpansionPanelThreeLine
from kivy.properties import DictProperty
from kivy.core.window import Window
from kivymd.uix.list import IconLeftWidget


connection = UnixSocketConnection()
transform = EtreeTransform()								# Element Tree transform for storing XML 

# Main Global Variables
version = getVersion()
scanNameList = []
reportsList = []

# Get Reports and Store them reports in reportsList
reportsListJSON = getReports()
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
	
# GUI Variables
hasGeneratedEntries = False
hasGeneratedReport = False
Window.size = (1280,720)							# Set Window size to 1280x720


# Class for content of safe Hosts
class SafePanel(MDBoxLayout):
	pass

# Class for content
class MyContent(MDBoxLayout):
	pass

# Class for containing contents of Host Panel
class VulnPanel(MDBoxLayout): 
	data = DictProperty({})

# Class for the whole data in Dashboard Screen
class ReportDashboard(MDBoxLayout):
	data = DictProperty({})

# Class for Individual Boxes in History Screen
class HistoryEntry(MDBoxLayout):	

	data = DictProperty({})																# Dictionary Containing Values 

	def panel_open(self, *args):
		Animation(
			height=(self.root.ids.box.height + self.root.ids.content.height)
			- self.theme_cls.standard_increment * 2,
			d=0.2,
		).start(self.root.ids.box)

	def panel_close(self, *args):
		Animation(
			height=(self.root.ids.box.height - self.root.ids.content.height)
			+ self.theme_cls.standard_increment * 2,
			d=0.2,
		).start(self.root.ids.box)

	# Function for generating report to be called by Button 
	def viewReport(self):

		global hasGeneratedReport 	# Use global variable flag

		MainApp.get_running_app().root.ids.screenManager.current = "dashboardScreen"	# Switch to dashboard screen

		# [MINOR FIX] Change highlighted to dashboard
		print(f"Generating Report for: {self.data.id}")
		reportResults = startCalculation(str(self.data.id))
		reportResults['assessment'] = getQualitativeAssessment(reportResults['aggregatedRisk'])
		newReportDashboard = ReportDashboard(data=reportResults)
		
		# Create Host Panels 
		for hostIndex in range(len(reportResults['consolidatedRiskPerHost'])):

			# Make small data structure where perHostData is matched with consolidatedRiskperHost
			ipAddress = str(reportResults['consolidatedRiskPerHost'][hostIndex]['ipAddress'])
			hostName = str(reportResults['consolidatedRiskPerHost'][hostIndex]['hostName'])
			consolidatedRisk = str(reportResults['consolidatedRiskPerHost'][hostIndex]['consolidatedRisk'])
			if hostName is None: hostName = 'Unknown'

			# Container for all vulnerabilities in a single host
			vulnContainer = MyContent()

			# Instantiate Host Panel
			hostPanel = MDExpansionPanel(
				icon= 'laptop',
				on_open=self.panel_open,
                on_close=self.panel_close,
				content=vulnContainer,
				panel_cls=MDExpansionPanelThreeLine(
					text= '[color=#ffffff]IP Address: [b]' + ipAddress + '[/b][/color]',
					secondary_text= '[color=#ffffff]Host Name: [b]' + hostName + '[/b][/color]',
					tertiary_text= '[color=#ffffff]Consolidated Risk Score: [b]' + consolidatedRisk + '[/b][/color]',
				)
			)
			
			# If host has vulnerabilities, create a vuln Panel
			if reportResults['consolidatedRiskPerHost'][hostIndex]['vulnCount'] > 0:										
				# For every vulnerability in the host, create own panel and add to container
				for vulnIndex in range(len(reportResults['perHostVulnList'][hostIndex])):
					vulnData = reportResults['perHostVulnList'][hostIndex][vulnIndex]
					vulnData['solutionIcon'] = getSolutionIcon(vulnData['solution']['@type'])
					vulnPanel = VulnPanel(data=vulnData)
					vulnContainer.add_widget(vulnPanel)
					vulnContainer.height += vulnPanel.height	
			# If host is safe, instantiate a safe Panel
			else: 
				vulnPanel = SafePanel()
				vulnContainer.add_widget(vulnPanel)
				vulnContainer.height += vulnPanel.height

			# Add Host Panel to additional data boxes
			newReportDashboard.ids.additionalData.add_widget(hostPanel)

		print(f"Length of Per Host Vuln List: {len(reportResults['perHostVulnList'])}")
		print(f"Length of Consolidated Risk Per Host: {len(reportResults['consolidatedRiskPerHost'])}")

		# Clear Child Widgets before adding report dashboard
		MainApp.get_running_app().root.ids.reportBox.clear_widgets()
		MainApp.get_running_app().root.ids.reportBox.add_widget(newReportDashboard)

		hasGeneratedReport = True


# Main Application Class
class MainApp(MDApp):

	# Builder Method
	def build(self):

		screen = Builder.load_file('main.kv')
		return screen

	# For Opening and closing navigation Rail 
	def openRail(self):
		if self.root.ids.rail.rail_state == "open":
			self.root.ids.rail.rail_state = "close"
		else:
			self.root.ids.rail.rail_state = "open"
			

	# For Generating History Entries in History Screen
	def generateHistoryEntries(self):

		global scanNameList
		self.root.ids.historyGrid.clear_widgets()		# clear previous entries in UI
		reportsList = []								# clear previous entries in memory
		reportsListJSON = getReports()					# get new entries 

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
			if entry['name'] != 'Discovery': 
				scanNameList.append(entry['name'].lower())					# Append to list of scan Names for avoiding name duplicates
				reportsList.append(entry)									# Append to actual list 

		for i in range(len(reportsList)):
			historyEntry = HistoryEntry(data=reportsList[i])				# Generate New Entry
			self.root.ids.historyGrid.add_widget(historyEntry)				# Add newly created widget


	def startScan(self):

		global scanNameList
		scanName = self.root.ids.scanName.text					# Get the text from text input
		scanName = scanName.strip()								# Remove leading and trailing whitespace
		reportString = ""

		if(len(scanName) == 0 ):								# if scan name is empty give prompt
			reportString = "[b]Warning[/b]: [color=#ffffff]Please Input a Scan Name[color=#ffffff]"
		elif scanName.lower() in scanNameList:
			reportString = "[b]Warning[/b]: [color=#ffffff]That scan name is already taken. Please choose another[color=#ffffff]"
		else:													# if not proceed with scan
			self.root.ids.scanName.text = ""					# clear input text field
			scanNameList.append(scanName.lower())						# add to temporary list of scan name's
			reportString = startScan(scanName)					# proceeed with scan

		# Clear Widgets
		self.root.ids.labelContainer.clear_widgets()

		reportLabel = MDLabel(									# Instantiate Label 
			markup = True,
			padding_y=20,
			text=str(reportString),
			halign="center",
			theme_text_color="Custom",
			text_color=(247/255, 193/255, 76/255),
			font_size=40
		)

		# Display Report ID on a label
		self.root.ids.labelContainer.add_widget(reportLabel)

# Run the App
MainApp().run()