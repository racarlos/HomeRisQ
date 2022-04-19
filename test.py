import ipaddress
import os
import re

ipAddress  = os.popen("hostname -I | awk '{print $1}'").read()      # Get IP address
ipAddress = ipAddress.split('.')
networkAddress = ''

for i in range(len(ipAddress)-1):                                   # Split to remove last octet
    networkAddress += ipAddress[i] + '.'

networkAddress += '0/24'                                            # add subnet mask

addresses = os.popen(f"sudo nmap -sn {networkAddress}").read()

