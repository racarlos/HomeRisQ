import json,xmltodict
import re
import os

# Imports from GVM Libraries
from gvm.connections import UnixSocketConnection			# Unix Domain Socket Connection
from gvm.protocols.gmp import Gmp							# Greenbone Management Protocol
from gvm.transforms import EtreeTransform

connection = UnixSocketConnection()
transform = EtreeTransform()								# Element Tree transform for storing XML

# Login Variables
username = 'admin'
password = 'kali'

# Scan Config IDs
spScanConfigID = "12d783d7-0420-4629-9816-c084564815fd"
fullAndFastConfigID = "daba56c8-73ec-11df-a475-002264764cea"
emptyScanConfigID = "085569ce-73ed-11df-83c3-002264764cea"

# Scanner IDs
openVasScannerID = "08b69003-5fc2-4037-a479-93b440211c73"

# Port List IDs
tcpPorts = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"

def XMLtoJSON(a):
	output = json.loads(json.dumps(xmltodict.parse(a)))
	return output

def XMLtoString(a):
	output = json.dumps(xmltodict.parse(a),indent=4)
	return output

def printXML(a):
	print(json.dumps(xmltodict.parse(a),indent=4))

# Retrieve GMP version supported by the remote daemon
def getVersion():
	with Gmp(connection) as gmp:
		versionResponse = gmp.get_version()
		versionResponse = json.loads(json.dumps(xmltodict.parse(versionResponse)))				# Convert XML to Dictionary and parse to JSON String
		version = versionResponse['get_version_response']['version']
	return version

# Retrieve all reports
def getReports():
	with Gmp(connection) as gmp:
		gmp.authenticate(username,password)
		# Get all reports
		reportsListResponse = gmp.get_reports()

		# Convert XML to JSON String
		reportsListString = json.dumps(XMLtoJSON(reportsListResponse)['get_reports_response']['report'],indent=4)

		# Print reports list to a file
		print(reportsListString,file=open("reports.txt","w"))

		# Extract
		reportsListJSON = json.loads(reportsListString)
	
	return reportsListJSON

# Get Single Report for actual calculation
def getSingleReport(reportID):
	with Gmp(connection) as gmp:
		gmp.authenticate(username,password)

		#ignore pagination to get all vuln entries
		reportResponse = gmp.get_report(reportID,ignore_pagination=True)
		
		# Get Single Report for testing
		reportString = json.dumps(XMLtoJSON(reportResponse)['get_reports_response']['report']['report']['results']['result'],indent=4)

		# Print report contents to a file 
		print(reportString,file=open("output.txt","w"))

		# Convert report to List of Dictionaries, each dictionary contains vulnerability details
		reportJSON = json.loads(reportString)	

	return reportJSON

def startScan(scanName):
	
	ipAddress  = os.popen("hostname -I | awk '{print $1}'").read()      # Get IP address
	ipAddress = ipAddress.split('.')
	addressPattern = "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"					# Match only valid IPv4 addresses 
	networkAddress = ''

	for i in range(len(ipAddress)-1):                                   # Split to remove last octet
		networkAddress += ipAddress[i] + '.'

	networkAddress += '0/24'                                            # add subnet mask

	addresses = os.popen(f"sudo nmap -sn {networkAddress}").read()      # run nmap to get list of hosts
	addresses = re.findall(addressPattern,addresses)                    # get all valid IP addrs
	addresses = list(dict.fromkeys(addresses))                          # remove duplicates

	with Gmp(connection) as gmp:
		gmp.authenticate(username,password)

		#Create Target for the new Scan
		createTargetResponse = gmp.create_target(
			name=str(scanName) + " Targets",
			hosts=addresses,    
			port_list_id=tcpPorts
		)
		targetID = json.dumps(XMLtoJSON(createTargetResponse)['create_target_response']['@id'])[1:-1]   # Remove quotation marks

		# Create Task with indicated target and configuration
		createTaskResponse =  gmp.create_task(
			name=str(scanName),
			config_id= emptyScanConfigID,
			target_id=targetID,
			scanner_id=openVasScannerID,
			preferences={
				"max_checks": 4                         # 8 Concurrent Threads Running
			}
		)
		taskID = json.dumps(XMLtoJSON(createTaskResponse)['create_task_response']['@id'])[1:-1]
		
		# Start Task
		startTaskResponse = gmp.start_task(taskID)
		reportId = json.dumps(XMLtoJSON(startTaskResponse)['start_task_response']['report_id'])[1:-1]
		
		print(f"Target ID: {targetID}")
		print(f"Task ID: {taskID}")
		print(f"Report ID: {reportId}")

		answerString = f"Scan: [b]{scanName}[/b] will start shortly. [b]{len(addresses)}[/b] hosts have been found.\n Report ID: [b]{reportId}[/b]" 
		return answerString
