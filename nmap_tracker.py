import sys
import subprocess
import re
from portscan import *

ip_addr_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.(?!0)\d{1,3})') # Regex to pull IP addresses, exclude the network address
scan_ports_pattern = re.compile(r'(?<=Ports:).*/') # Regex to pull the open ports section from the nmap scan

#
# READ IN THE NAME OF THE KNOWN HOSTS FILE FROM SYS ARGV
#
if(len(sys.argv) != 2):
    print("Usage: python nmap_tracker.py (hosts_file.txt)")
    sys.exit(1)
else:
    file_set = set()

    with open(sys.argv[1], "r") as hosts_file:
        lines = hosts_file.readlines()
        
        for line in lines:
            result = ip_addr_pattern.search(line)
            if result != None:
                file_set.add(result[0])



#
# GET IPs OF ACTIVE HOSTS ON THE SUBNET
#

scan_set = set()
address = input("Enter the IP network and CIDR subnet mask abbreviation (EX: 192.168.0.0/24): ")
print("Scanning " + address)
output = subprocess.check_output(["nmap", "-n", "-sn", address, "-oG", "-"]).decode("UTF-8")

for x in output.splitlines():
    result = ip_addr_pattern.search(x)
    if result != None:
        scan_set.add(result[0])
    

# Hosts not detected by scan
down_hosts = file_set - scan_set
print("Down hosts:")
print(down_hosts)
print()

# Unknown (possibly rogue) hosts on the network
unknown_hosts = scan_set - file_set
print("Unknown hosts:")
print(unknown_hosts)
print()

# Known hosts that are up
up_hosts = file_set & scan_set
print("Up hosts:")
print(up_hosts)
print()

# Scan the good hosts
for host in up_hosts:
    print("Scanning up host: " + host)

    output = subprocess.check_output(["nmap", "-T4", "-A", "-Pn", host, "-oG", "-"]).decode("UTF-8")

    ports_string = scan_ports_pattern.search(output)
    if ports_string != None:
        results = PortScan(ports_string[0])
        print(results)
    else:
        print("No open ports detected")
    
    print()
    



for host in down_hosts:
    print("Scanning possibly down host: " + host)
    output = subprocess.check_output(["nmap", "-T4", "-A", "-Pn", host, "-oG", "-"]).decode("UTF-8")

    ports_string = scan_ports_pattern.search(output)
    if ports_string != None:
        results = PortScan(ports_string[0])
        print(results)
    else:
        print("No open ports detected, host down or unresponsive")
    print()
