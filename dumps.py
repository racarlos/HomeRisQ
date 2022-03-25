import json,xmltodict
from textwrap import indent										# For converting XML data to JSON

from gvm.connections import UnixSocketConnection			# Unix Domain Socket Connection 
from gvm.protocols.gmp import Gmp							# Greenbone Management Protocol 
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print


## Contains Additional codes that I might have to use later


#Robie Note: USE EMPTY TEMPLATE TASK TO TEST SO NO DELAYS IN GENERATING RESULTS, very quick scan no NVTs



with Gmp(connection) as gmp:

    # Start Task and Get the Report ID of the Task
    scanResponse = gmp.start_task("7c9f814f-2367-4dbf-9d3b-4589a4f6e0f3")
    scanResponse = json.loads(json.dumps(xmltodict.parse(scanResponse)))
    scanReportId = scanResponse['start_task_response']['report_id']
    print(f"Scan Report ID: {scanReportId}")
    print(scanResponse)




    # Retrieve Scanner List
    scannerListResponse = gmp.get_scanners()

    #Retrieve all tasks
    tasksResponse = gmp.get_tasks(filter_string=None)
    tasks = json.loads(json.dumps(xmltodict.parse(tasksResponse)))
    print(json.dumps(xmltodict.parse(tasksResponse),indent=4))
    print(tasks['get_tasks_response'].keys())
    print("====================")


    # # Sample values for Testing
	sampleQOD = 90.0
	sampleVector0 = "AV:A/AC:L/Au:N/C:P/I:P/A:N"				# HTTP Cleartext transmission vector
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

