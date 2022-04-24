# Imports from GVM Libraries
import json,xmltodict
from gvm.connections import UnixSocketConnection			# Unix Domain Socket Connection
from gvm.protocols.gmp import Gmp							# Greenbone Management Protocol
from gvm.transforms import EtreeTransform

from dumps import XMLtoJSON

connection = UnixSocketConnection()
transform = EtreeTransform()


def XMLtoJSON(a):
	output = json.loads(json.dumps(xmltodict.parse(a)))
	return output

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


ipAddress  = os.popen("hostname -I | awk '{print $1}'").read()      # Get IP address
ipAddress = ipAddress.split('.')
addressPattern = "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
networkAddress = ''

for i in range(len(ipAddress)-1):                                   # Split to remove last octet
    networkAddress += ipAddress[i] + '.'

networkAddress += '0/24'                                            # add subnet mask

addresses = os.popen(f"sudo nmap -sn {networkAddress}").read()      # run nmap to get list of hosts
addresses = re.findall(addressPattern,addresses)                    # get all valid IP addrs
addresses = list(dict.fromkeys(addresses))                          # remove duplicates

with Gmp(connection) as gmp:
    gmp.authenticate(username,password)

    #ignore pagination to get all vuln entries
    # reportResponse = gmp.get_report("4c7718ec-339f-44ce-ac66-74d99d04554b",ignore_pagination=True)
    # # Get Single Report for testing
    # reportString = json.dumps(XMLtoJSON(reportResponse)['get_reports_response']['report']['report']['results']['result'],indent=4)

    # ===============================

    # Get all reports
    reportsListResponse = gmp.get_reports()
    # Convert XML to JSON String
    reportsListString = json.dumps(XMLtoJSON(reportsListResponse)['get_reports_response']['report'],indent=4)


    # Print report contents to a file 
    print(reportsListString,file=open("output.txt","w"))


