import json,xmltodict

# Imports from GVM Libraries
from gvm.connections import UnixSocketConnection			# Unix Domain Socket Connection
from gvm.protocols.gmp import Gmp							# Greenbone Management Protocol
from gvm.transforms import EtreeTransform

connection = UnixSocketConnection()
transform = EtreeTransform()								# Element Tree transform for storing XML


def XMLtoJSON(a):
	output = json.loads(json.dumps(xmltodict.parse(a)))
	return output

def XMLtoString(a):
	output = json.dumps(xmltodict.parse(a),indent=4)
	return output

def printXML(a):
	print(json.dumps(xmltodict.parse(a),indent=4))


with Gmp(connection) as gmp:

	# Login Variables
	username = 'admin'
	password = 'kali'
	
	baseScan = "d21f6c81-2b88-4ac1-b7b4-a2a9f2ad4663"				# 1135 , 195 yes
	emptyScan = "085569ce-73ed-11df-83c3-002264764cea"				# 1135 , 195 yes
	fullAndFastScan = "daba56c8-73ec-11df-a475-002264764cea"		# 1135 , 192 yes
	spScan = "12d783d7-0420-4629-9816-c084564815fd"

	gmp.authenticate(username,password)


	#outputResponse = gmp.get_scan_configs()
	outputResponse = gmp.get_reports()

	#outputResponse = gmp.start_task(baseScan)

	#outputResponse = gmp.get_tasks()
	outputResponseString = json.dumps(XMLtoJSON(outputResponse),indent=4)

	print(outputResponseString,file=open("output.txt","w"))
    




	# # Stop Task 
	# stopResponse =  gmp.stop_task("7c9f814f-2367-4dbf-9d3b-4589a4f6e0f3")
	# print(stopResponse)

