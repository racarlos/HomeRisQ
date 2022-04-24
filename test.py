# Imports from GVM Libraries
import json,xmltodict
from dataclasses_json import config
from sqlalchemy import delete
from gvm.connections import UnixSocketConnection			# Unix Domain Socket Connection
from gvm.protocols.gmp import Gmp							# Greenbone Management Protocol
from gvm.transforms import EtreeTransform

from dumps import XMLtoJSON

connection = UnixSocketConnection()
transform = EtreeTransform()


def XMLtoJSON(a):
	output = json.loads(json.dumps(xmltodict.parse(a)))
	return output



import ipaddress
import re
import os

# Login Variables
username = 'admin'
password = 'kali'

# Scan Config IDs
spScanConfigID = "12d783d7-0420-4629-9816-c084564815fd"
fullAndFastConfigID = "daba56c8-73ec-11df-a475-002264764cea"
emptyScanConfigID = "085569ce-73ed-11df-83c3-002264764cea"

# Scanner IDs
openVasScannerID = "08b69003-5fc2-4037-a479-93b440211c73"

tcpPorts = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"


ipAddress  = os.popen("hostname -I | awk '{print $1}'").read()      # Get IP address
ipAddress = ipAddress.split('.')
addressPattern = "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
networkAddress = ''

# Port List IDs
for i in range(len(ipAddress)-1):                                   # Split to remove last octet
    networkAddress += ipAddress[i] + '.'

networkAddress += '0/24'                                            # add subnet mask

addresses = os.popen(f"sudo nmap -sn {networkAddress}").read()      # run nmap to get list of hosts
addresses = re.findall(addressPattern,addresses)                    # get all valid IP addrs
addresses = list(dict.fromkeys(addresses))                          # remove duplicates

with Gmp(connection) as gmp:
    gmp.authenticate(username,password)

    # configs = gmp.get_scan_configs()
    # configs = json.dumps(XMLtoJSON(configs),indent=4)
    # print(configs)

    # print("=========================")

    # scanners = gmp.get_scanners()
    # scanners = json.dumps(XMLtoJSON(scanners),indent=4)
    # print(scanners)

    getTargetsResponse = gmp.get_port_lists()
    
    #Create Target for the new Scan
    createTargetResponse = gmp.create_target(
        name="testTarget",
        hosts=addresses,    
        port_list_id=tcpPorts
    )

    targetID = json.dumps(XMLtoJSON(createTargetResponse)['create_target_response']['@id'])[1:-1]   # Remove quotation marks
    print(f"Target ID: {targetID}")
    
    createTaskResponse =  gmp.create_task(
        name="SP2 Task",
        config_id=spScanConfigID,
        target_id=targetID,
        scanner_id=openVasScannerID,
        preferences={
            "max_checks": 8                         # 8 Concurrent Threads Running
        }
    )


    taskID = json.dumps(XMLtoJSON(createTaskResponse)['create_task_response']['@id'])[1:-1]
    print(f"Task ID: {taskID}")

    startTaskResponse = gmp.start_task(taskID)
    reportId = json.dumps(XMLtoJSON(createTaskResponse)['start_task_response']['report_id'])[1:-1]
    print(f"Report ID: {reportId}")




    # Delete Task after it has run

    # # Delete Target after task has finished
    # deleteTarget = gmp.delete_target(target_id=targetID)
    # deleteTargetResponse = json.dumps(XMLtoJSON(deleteTarget))
    # print("Delete target Response: ")
    # print(deleteTargetResponse)