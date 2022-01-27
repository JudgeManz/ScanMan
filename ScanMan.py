import nmap3
from nmap3.nmapparser import NmapCommandParser 
import json
from tabulate import tabulate
import sys, traceback


def Target_List(target_ip):
    print("Preparing to scan target hosts...")
    nmap = nmap3.NmapHostDiscovery() 
    TL_scan = nmap.nmap_no_portscan(target_ip, args="-sL ") #Executes the scan on the target IP addresses
    TL_result = {} #Results of the scan on each IP address will be stored here

    i = 0
    for host in TL_scan["hosts"]: #Iterates through all the hosts and stores the data in python dictionaries
        host_ipaddress = TL_scan['hosts'][i]["addr"]
        host_state = TL_scan['hosts'][i]["state"]
        TL_result[host_ipaddress] = host_state
        i += 1
    return TL_result 

#Function for performing ICMP Scans
def ICMP(target_ip, target_port):
    print("Performing ICMP scan...")
    nmap = nmap3.NmapHostDiscovery() 
    ICMP_scan = nmap.nmap_no_portscan(target_ip, args="-PE ") #Executes the scan on the target IP addresses
    ICMP_result = {} #Results of the scan on each IP address will be stored here

    i = 0
    for host in ICMP_scan["hosts"]: #Iterates through all the hosts and stores the data in python dictionaries
        host_ipaddress = ICMP_scan['hosts'][i]["addr"]
        host_state = ICMP_scan['hosts'][i]["state"]
        ICMP_result[host_ipaddress] = host_state
        i += 1
    ICMP_time=(ICMP_scan['runtime']["elapsed"]) #Stores the time elapsed for the scan
    return ICMP_result, ICMP_time 

#Function for performing TCP Connect Scans
def CON(target_ip, target_port):
    print("Performing TCP Connect scan...")
    nmap = nmap3.NmapScanTechniques()
    CON_scan = nmap.nmap_tcp_scan(target_ip, args="-sT -p " + target_port +  " -Pn") #Executes the scan on the Target IP Addresses/Ports
    CON_result = {} #Results of the scan on each IP address/Port will be stored here
    CON_keys = list(CON_scan.keys())  

    i = 0
    for host in CON_scan: #Iterates through all the hosts/ports and stores the data in python dictionaries
        if(CON_keys[i] == "runtime"):
            break
        else:
            host_ipaddress = CON_scan[CON_keys[i]][0]["host"]
            host_state = CON_scan[CON_keys[i]][0]["state"]
            CON_result[host_ipaddress] = host_state 
            i += 1

    CON_time=(CON_scan['runtime']["elapsed"]) #Stores the time elapsed for the scan
    return CON_result, CON_time 

#Function for performing SYN Scans
def SYN(target_ip, target_port):
    print("Performing TCP SYN scan...")
    nmap = nmap3.NmapScanTechniques()
    SYN_scan = nmap.nmap_syn_scan(target_ip, args="-sS -p " + target_port +  " -Pn") #Executes the scan on the Target IP Addresses/Ports
    SYN_result = {} #Results of the scan on each IP address/Port will be stored here
    SYN_keys = list(SYN_scan.keys())

    i = 0
    for host in SYN_scan: #Iterates through all the hosts/ports and stores the data in python dictionaries
        if(SYN_keys[i] == "runtime"):
            break
        else:
            host_ipaddress = SYN_scan[SYN_keys[i]][0]["host"]
            host_state = SYN_scan[SYN_keys[i]][0]["state"]
            SYN_result[host_ipaddress] = host_state
            i += 1

    SYN_time=(SYN_scan['runtime']["elapsed"]) #Stores the time elapsed for the scan
    return SYN_result, SYN_time 

#Function for performing Xmas Scans
def Xmas(target_ip, target_port):
    print("Performing TCP Xmas scan...")
    nmap = nmap3.Nmap()
    Xmas_scan_scan = nmap.scan_top_ports(target_ip, args="-sX -p " + target_port +  " -Pn") #Executes the scan on the Target IP Addresses/Ports
    Xmas_scan_result = {} #Results of the scan on each IP address/Port will be stored here
    Xmas_scan_keys = list(Xmas_scan_scan.keys())

    i = 0
    for host in Xmas_scan_scan: #Iterates through all the hosts/ports and stores the data in python dictionaries
        if(Xmas_scan_keys[i] == "runtime"):
            break
        else:
            host_ipaddress = Xmas_scan_scan[Xmas_scan_keys[i]][0]["host"]
            host_state = Xmas_scan_scan[Xmas_scan_keys[i]][0]["state"]
            Xmas_scan_result[host_ipaddress] = host_state
            i += 1

    Xmas_scan_time=(Xmas_scan_scan['runtime']["elapsed"]) #Stores the time elapsed for the scan
    return Xmas_scan_result, Xmas_scan_time

#Function for performing FIN Scans
def FIN(target_ip, target_port):
    print("Performing TCP FIN scan...")
    nmap = nmap3.Nmap()
    FIN_scan = nmap.scan_top_ports(target_ip, args="-sF -p " + target_port +  " -Pn") #Executes the scan on the Target IP Addresses/Ports
    FIN_result = {} #Results of the scan on each IP address/Port will be stored here
    FIN_keys = list(FIN_scan.keys())

    i = 0
    for host in FIN_scan: #Iterates through all the hosts/ports and stores the data in python dictionaries
        if(FIN_keys[i] == "runtime"):
            break
        else:
            host_ipaddress = FIN_scan[FIN_keys[i]][0]["host"]
            host_state = FIN_scan[FIN_keys[i]][0]["state"]
            FIN_result[host_ipaddress] = host_state
            i += 1

    FIN_time=(FIN_scan['runtime']["elapsed"]) #Stores the time elapsed for the scan
    return FIN_result, FIN_time

#Function for performing Null Scans
def NullScan(target_ip, target_port):
    print("Performing TCP Null scan...")
    nmap = nmap3.Nmap()
    NULL_scanscan = nmap.scan_top_ports(target_ip, args="-sN -p " + target_port +  " -Pn") #Executes the scan on the Target IP Addresses/Ports
    NULL_scanresult = {} #Results of the scan on each IP address/Port will be stored here
    NULL_scankeys = list(NULL_scanscan.keys())

    i = 0
    for host in NULL_scanscan: #Iterates through all the hosts/ports and stores the data in python dictionaries
        if(NULL_scankeys[i] == "runtime"):
            break
        else:
            host_ipaddress = NULL_scanscan[NULL_scankeys[i]][0]["host"]
            host_state = NULL_scanscan[NULL_scankeys[i]][0]["state"]
            NULL_scanresult[host_ipaddress] = host_state
            i += 1

    NULL_scantime=(NULL_scanscan['runtime']["elapsed"]) #Stores the time elapsed for the scan
    return NULL_scanresult, NULL_scantime

#Function for performing ACK Scans
def ACK(target_ip, target_port):
    print("Performing TCP Ack scan...")
    nmap = nmap3.Nmap()
    ACK_scan = nmap.scan_top_ports(target_ip, args="-sA -p " + target_port +  " -Pn") #Executes the scan on the Target IP Addresses/Ports
    ACK_result = {} #Results of the scan on each IP address/Port will be stored here
    ACK_keys = list(ACK_scan.keys())

    i = 0
    for host in ACK_scan: #Iterates through all the hosts/ports and stores the data in python dictionaries
        if(ACK_keys[i] == "runtime"):
            break
        else:
            host_ipaddress = ACK_scan[ACK_keys[i]][0]["host"]
            host_state = ACK_scan[ACK_keys[i]][0]["state"]
            ACK_result[host_ipaddress] = host_state
            i += 1

    ACK_time=(ACK_scan['runtime']["elapsed"]) #Stores the time elapsed for the scan
    return ACK_result, ACK_time 

#Function for reading about the software's version
def version():
    
    print ('''
    
    ScanMan 1.1 last updated on December 10, 2020 by Judge Manzano

    The application was developed by Judge Manzano as part of his "Extending a Scanning Tool" output. It was developed using Python and the python3-nmap library to extend nmap scanning capabilities. It allows the user to perform basic ICMP and TCP scanning on the user inputted IP addresses and port. After performing the scans, it then displays the information in an easy to read table format. Additionally, it also records the time that it took to complete a scan.

    python3-nmap library: https://pypi.org/project/python3-nmap/

    For further inquiries and questions, do not hesitate to contact the developer at judge_manzano@dlsu.edu.ph

    ''')

#Function for reading the software's helpfile/documentation
def help_file():
    
    print ('''
    SCANMAN HELPFILE

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

    For further inquiries and questions, do not hesitate to contact the developer at judge_manzano@dlsu.edu.ph
    ''')

#Function that performs all the scans using the user's inputted IP address & port
def scan():

    target_ip = input("Input target IP address range (Ex. 192.168.1.1 or 192.168.1.1-10): ")
    target_port = input("Input target port (Ex. 22): ")

    target_list = Target_List(target_ip)
    ip_addresses=list(target_list.keys())

    #ICMP Scans
    icmp = ICMP(target_ip, target_port)
    icmp_scanresult = icmp[0]
    icmp_scantime = float(icmp[1])

    #TCP Connect Scans
    con = CON(target_ip, target_port)
    con_scanresult = con[0]
    con_scantime = float(con[1])

    #SYN Scans
    syn = SYN(target_ip, target_port)
    syn_scanresult = syn[0]
    syn_scantime = float(syn[1])

    #XMAS Scans
    xmas = Xmas(target_ip, target_port)
    xmas_scanresult = xmas[0]
    xmas_scantime = float(xmas[1])

    #FIN Scans
    fin = FIN(target_ip, target_port)
    fin_scanresult = fin[0]
    fin_scantime = float(fin[1])

    #Null Scans
    nullscan = NullScan(target_ip, target_port)
    null_scanresult = nullscan[0]
    null_scantime = float(nullscan[1])

    #ACK Scans
    ack = ACK(target_ip, target_port)
    ack_scanresult = ack[0]
    ack_scantime = float(ack[1])

    print("\nScanMan Finished!\n")
    print("Target Port: " + target_port + "\n")
    table = []
    j = 0
    for host in ip_addresses: #Populates the table with the result for each IP address scanned
        
        #Replaces the ip address/port state gained from the scans with the appropriate legend in the table
        try: icmp_scanresult[ip_addresses[j]]
        except: icmp_status="_"
        else:
            if(icmp_scanresult[ip_addresses[j]]=="up"): icmp_status="O"
            if(icmp_scanresult[ip_addresses[j]]!="up"): icmp_status="_"

        try: con_scanresult[ip_addresses[j]]
        except: con_status="NR"
        else:
            if(con_scanresult[ip_addresses[j]]=="open"): con_status="O"
            if(con_scanresult[ip_addresses[j]]=="open|filtered"): con_status="OF"
            if(con_scanresult[ip_addresses[j]]=="filtered"): con_status="F"
            if(con_scanresult[ip_addresses[j]]!="open" and con_scanresult[ip_addresses[j]]!="open|filtered" and con_scanresult[ip_addresses[j]]!="filtered"): con_status="_"

        try: syn_scanresult[ip_addresses[j]]
        except: syn_status="NR"
        else:
            if(syn_scanresult[ip_addresses[j]]=="open"): syn_status="O"
            if(syn_scanresult[ip_addresses[j]]=="open|filtered"): syn_status="OF"
            if(syn_scanresult[ip_addresses[j]]=="filtered"): syn_status="F"
            if(syn_scanresult[ip_addresses[j]]!="open" and syn_scanresult[ip_addresses[j]]!="open|filtered" and syn_scanresult[ip_addresses[j]]!="filtered"): syn_status="_"

        try: xmas_scanresult[ip_addresses[j]]
        except: xmas_status="NR"
        else:
            if(xmas_scanresult[ip_addresses[j]]=="open"): xmas_status="O"
            if(xmas_scanresult[ip_addresses[j]]=="open|filtered"): xmas_status="OF"
            if(xmas_scanresult[ip_addresses[j]]=="filtered"): xmas_status="F"
            if(xmas_scanresult[ip_addresses[j]]!="open" and xmas_scanresult[ip_addresses[j]]!="open|filtered" and xmas_scanresult[ip_addresses[j]]!="filtered"): xmas_status="_"

        try: fin_scanresult[ip_addresses[j]]
        except: fin_status="NR"
        else:
            if(fin_scanresult[ip_addresses[j]]=="open"): fin_status="O"
            if(fin_scanresult[ip_addresses[j]]=="open|filtered"): fin_status="OF"
            if(fin_scanresult[ip_addresses[j]]=="filtered"): fin_status="F"
            if(fin_scanresult[ip_addresses[j]]!="open" and fin_scanresult[ip_addresses[j]]!="open|filtered" and fin_scanresult[ip_addresses[j]]!="filtered"): fin_status="_"

        try: null_scanresult[ip_addresses[j]]
        except: null_status="NR"
        else:
            if(null_scanresult[ip_addresses[j]]=="open"): null_status="O"
            if(null_scanresult[ip_addresses[j]]=="open|filtered"): null_status="OF"
            if(null_scanresult[ip_addresses[j]]=="filtered"): null_status="F"
            if(null_scanresult[ip_addresses[j]]!="open" and null_scanresult[ip_addresses[j]]!="open|filtered" and null_scanresult[ip_addresses[j]]!="filtered"): null_status="_"

        try: ack_scanresult[ip_addresses[j]]
        except: ack_status="NR"
        else:
            if(ack_scanresult[ip_addresses[j]]=="filtered"): ack_status="FW"
            if(ack_scanresult[ip_addresses[j]]=="unfiltered"): ack_status="_"
        
        table = table + [[ 
                            ip_addresses[j], 
                            icmp_status,
                            con_status,
                            syn_status,
                            xmas_status,
                            fin_status,
                            null_status,
                            ack_status
                        ]]
        j += 1

    table_headers = ['IP Address','ICMP', 'Connect', 'SYN', 'Xmas', 'Fin', 'Null', 'ACK']
    print(tabulate (table , table_headers, tablefmt="github"))

    print('''
    ICMP:
    O: Responds to Echo Requests
    _: No response

    TCP (Connect Column to Null Column): 
    O: Open
    OF: Open or Filtered
    F: Filtered
    _: Closed
    NR: Not Responding

    TCP ACK:
    FW: Firewall detected 
    _: No Firewall
    NR: Not Responding
    ''')

    total_scantime = icmp_scantime + con_scantime + syn_scantime + xmas_scantime + fin_scantime + null_scantime + ack_scantime
    print("\nElapsed time of scan: " + str(total_scantime) + " seconds\n")
    return total_scantime

def main():
    try:
        print('''
        Welcome to ScanMan 1.0! An application developed by Judge Manzano as an output for ETHIHAC.
        This application makes use of python and the python3-nmap library to extend a scanning tool.

        python3-nmap library: https://pypi.org/project/python3-nmap/
        ''')
        
        menu_option = None
        scan_time = None
        while(menu_option != 0):

            print('''Commands:
            1: Version/about.
            2: Help file/documentation.
            3: The time spent by the tool. 
            4: Initiate a scan by inputting the target IP address and port
            0: Exits the application
            ''')

            user_input = input("Input command: ")
            try:
                menu_option = int(user_input)
            except:
                print("Please input a valid command")
            else:
                if(menu_option==1):
                    version()
                if(menu_option==2):
                    help_file()
                if(menu_option==3):
                    if(scan_time == None):
                        print("\nRun a scan to record the elapsed time\n")
                    else:
                        print("\nTime elapsed for last scan: " + str(scan_time) + " seconds\n")
                if(menu_option==4):
                    scan_time=scan()
                if(menu_option != 1 and menu_option != 2 and menu_option != 3 and menu_option != 4 and menu_option != 0):
                    print("\nPlease input a valid command\n")
                
    except KeyboardInterrupt:
        print ("Shutting down ScanMan...")
    
main()
