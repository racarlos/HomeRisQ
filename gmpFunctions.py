import json,xmltodict

# Imports from GVM Libraries
from gvm.connections import UnixSocketConnection			# Unix Domain Socket Connection
from gvm.protocols.gmp import Gmp							# Greenbone Management Protocol
from gvm.transforms import EtreeTransform

connection = UnixSocketConnection()
transform = EtreeTransform()								# Element Tree transform for storing XML

# Login Variables
username = 'admin'
password = 'kali'

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

