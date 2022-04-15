#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Imports from GVM Libraries
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
from kivymd.uix.expansionpanel import MDExpansionPanel, MDExpansionPanelThreeLine
from kivy.properties import DictProperty
from kivy.core.window import Window
from kivymd.uix.list import IconLeftWidget


connection = UnixSocketConnection()
transform = EtreeTransform()								# Element Tree transform for storing XML 


# Task ID's
networkFullAndFastScanId = 'ad0736a6-ab8d-4e3b-b1f4-410f753cb822'
networkDiscoveryScanId = '7c9f814f-2367-4dbf-9d3b-4589a4f6e0f3'

# Main Global Variables
version = getVersion()
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
			
			if reportResults['consolidatedRiskPerHost'][hostIndex]['vulnCount'] > 0:										# If host has vulnerabilities
				# For every vulnerability in the host, create own panel and add to container
				for vulnIndex in range(len(reportResults['perHostVulnList'][hostIndex])):
					vulnPanel = VulnPanel(data=reportResults['perHostVulnList'][hostIndex][vulnIndex])
					vulnContainer.add_widget(vulnPanel)
					vulnContainer.height += vulnPanel.height	
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
		#self.theme_cls.theme_style = "Dark"
		self.theme_cls.primary_palette = "BlueGray"
		screen = Builder.load_file('frame.kv')

		return screen

	# For Opening and closing navigation Rail 
	def openRail(self):
		if self.root.ids.rail.rail_state == "open":
			self.root.ids.rail.rail_state = "close"
		else:
			self.root.ids.rail.rail_state = "open"
			

	# For Generating History Entries in History Screen
	def generateHistoryEntries(self):

		# Use global variable flag 
		global hasGeneratedEntries
		#print(f"Generating History Entries, Length of Reports: {len(reportsList)}")
		
		# Add entries to History Grid if not Previously generated Entries
		if(hasGeneratedEntries == False):
			for i in range(len(reportsList)):
				historyEntry = HistoryEntry(data=reportsList[i])		# Generate New Entry
				self.root.ids.historyGrid.add_widget(historyEntry)		

			hasGeneratedEntries = True

	# For Removing history Entries once user exited the history screen
	def removeHistoryEntries(self):
		pass

# Run the App
MainApp().run()