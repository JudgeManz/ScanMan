# ScanMan

## Project Description

ScanMan 1.1 last updated on December 10, 2020 by Judge Manzano

The application was developed by Judge Manzano as part of his "Extending a Scanning Tool" output. It was developed using Python and the python3-nmap library to extend nmap scanning capabilities. It allows the user to perform basic ICMP and TCP scanning on the user inputted IP addresses and port. After performing the scans, it then displays the information in an easy to read table format. Additionally, it also records the time that it took to complete a scan.

python3-nmap library: https://pypi.org/project/python3-nmap/

## Installation & Usage Guide

Prerequisites to running the software  
1.) Installed Python 3.6 or higher on machine  
2.) "sudo" access for user to perform scans  

Steps to installing software:  
1.) Navigate to directory where ScanMan.py & requirements.txt are located  
2.) Open terminal and type "sudo pip3 install -r requirements.txt"  
Note: The needed libraries are tabulate and python3-nmap which can be directly installed using the ff commands  
- sudo pip3 install tabulate  
- sudo pip3 install python3-nmap  

Steps to running software:   
1.) Navigate to directory where ScanMan.py is located using the terminal  
2.) Type "sudo python3 ScanMan.py"  

Commands:  
1: Version/about.  
2: Help file/documentation.  
3: The time spent by the tool.  
4: Initiate a scan by inputting the target IP address and port  
    - Users will be prompted to input target IP Address  
        - Format for single IP address is: 192.168.1.1  
        - Format for a range of IP addresses is: 192.168.1.1-10  
    - Users will be prompted to input target port  
        - Format for target port is : 22  
0: Exits the application  
