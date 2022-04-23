# Imports from GVM Libraries
from gvm.connections import UnixSocketConnection			# Unix Domain Socket Connection
from gvm.protocols.gmp import Gmp							# Greenbone Management Protocol
from gvm.transforms import EtreeTransform

connection = UnixSocketConnection()
transform = EtreeTransform()		


import ipaddress
import re
import os

# Login Variables
username = 'admin'
password = 'kali'

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

    # getTargetsResponse = gmp.get_port_lists()

    createTargetResponse = gmp.create_target(
        name="testTarget",
        comment="Target for current SP2 scan",
        hosts=addresses,    
       
        port_list_id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
    )

    print(createTargetResponse)