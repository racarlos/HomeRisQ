#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Imports from GVM Libraries
from unicodedata import name
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
from kivy.properties import DictProperty
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
	
printReports(reportsList)


# GUI Variables
hasGeneratedEntries = False
Window.size = (1280,720)							# Set Window size to 1280x720


class HistoryEntry(MDBoxLayout):	

	data = DictProperty({})																# Dictionary Containing Values 

	# Function for generating report to be called by Button 
	def viewReport(self):
		MainApp.get_running_app().root.ids.screenManager.current = "dashboardScreen"	# Switch to dashboard screen

		#self.root.ids.screenManager.current = "dashboardScreen"			
																		# Change highlighted to dashboard
		print(f"Generating Report for: {self.data.id}")
		reportResults = startCalculation(str(self.data.id))


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