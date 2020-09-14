#!/bin/python3
import nmap
import sys
import os
import socket
import time
import itertools
import threading
import requests
from datetime import datetime
from elasticsearch import Elasticsearch
es = Elasticsearch([{'host': 'localhost', 'port': '9200'}])

def loading():
    for c in itertools.cycle(["[■□□□□□□□□□]","[■■□□□□□□□□]", "[■■■□□□□□□□]", "[■■■■□□□□□□]", "[■■■■■□□□□□]", "[■■■■■■□□□□]", "[■■■■■■■□□□]", "[■■■■■■■■□□]", "[■■■■■■■■■□]", "[■■■■■■■■■■]"]):
        if scan_finished:
            break
        sys.stdout.write('\rSCANNING ' + c)
        sys.stdout.flush()
        time.sleep(0.2)
    sys.stdout.flush()
    sys.stdout.write('\r\nSCAN COMPLETE\n')

def get_ip():

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def check_ip(ip):

    iplist = ip.split('.')
    
    if ip == "localhost":
        return True
        
    if len(iplist) != 4: # Checks if theres 4 Octets
        return False
        
    for octet in iplist:
        if not octet.isdigit(): # Checks that the octets are made of digits
            return False
				
        x = int(octet) # Turns octets into 'int' to check for value

    if x < 0 or x > 255:
        return False
        
    return True # If 3 logical conditions are met == legitimate IP

def check_range(low, high):
	try:
	
		if low > high:
			return False
		#if not low.isdigit():  # .isdigit() only for Strings
		#	return False
		#if not high.isdigit():
		#	return False
		return True
	
	except ValueError:
		print('Please enter only digits')
        
print('\nScan Indexer: Tool for pinging or port scanning vulnerable hosts \
to index into your Elastic Stack --- Developed by Cesar Urquidi')
print()
print('-' * 50)

# START OF MAIN CODE (OFFER OPTION TO SEE LOCAL HOSTS UP)
# Check user for ES portion or simply scan ports on a local network
print('\nWould you like to run a simple local port scan (via ping sweep) or full NMap scan? \
	\n\n1: Local Scan \
	\n2: NMap')

try:
    while True:

        scan_type = int(input("\n"))

        if scan_type == 1: #BEGIN DISCOVERY AND SIMPLE SOCKET SCANNER
            
            ip = get_ip()
            octets = ip.split('.')

            print('\nList of Pinged Local Connections')
            print('-' * 50)
            
            for octet in range(254): # Bash script to find responding IPs
                os.system("ping -c 1 -W 1 {}.{}.{}.{} | grep \"64 bytes \" | cut -d \" \" -f 4 | tr -d \":\" &".format( \
                    octets[0], octets[1], octets[2], octet))
            
            
            print('Local System IP Address: {}'.format(get_ip()))    
            time.sleep(3) # Prevents overlapping of code exec due to "&" in bash

            while True: # Start grabbing info to port scan - Local Scan
                    
                    ip_to_scan = input('\nEnter one of the previous IPs (or "localhost") to port scan: \n')
                    
                    if check_ip(ip_to_scan):
                        target = socket.gethostbyname(ip_to_scan)
                        break
                    else:
                        print('\n// Incorrect input //')
                        print('\nProper Syntax: XXX.XXX.XXX.XXX or "localhost"' )
                        continue
                    
            while True: # Grabbing port range to scan - Local Scan
                
                print('\nPlease Enter a RANGE of ports of which you would like to scan: ')
                rangelow = int(input('\nLow Bound: '))
                rangehigh = int(input('\nHigh Bound: '))

                if check_range(rangelow, rangehigh):
                    break
                else:
                    print('\n// Invalid Input //')
                    continue

            print('\n')
            print('-' * 50)
            print('Scanning Address: {}'.format(target))
            time_start = datetime.now()
            print('Time Started: {}'.format(time_start))
            print('-' * 50)

            try: # Actually scanning for ports

                openports = []
                print('Open Ports:')

                for port in range(rangelow, rangehigh):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket.setdefaulttimeout(1)

                    response = s.connect_ex((target, port))

                    if response == 0:
                        print('Port {}'.format(port))
                        openports.append(port)
                    s.close()
            
            except socket.gaierror:
                print('\Hostname could not be resolved')
                sys.exit()
            except socket.error:
                print('\nCould not connect to server')
                sys.exit()
            
            print('-' * 50)
            print('SCAN COMPLETE')
            print('-' * 50)
            time_end = datetime.now()
            time_elapsed = time_start - time_end
            print('Time Elapsed: {} Seconds'.format(abs(time_elapsed.total_seconds())))
            if openports:
                print('Open Ports: {}'.format(str(openports)[1:-1]))
            else:
                print('Open Ports: None')
            sys.exit()



        elif scan_type == 2: #BEGIN NMAP/ES
            
            while True:

                addr = input('\nPlease Enter a Valid IPv4 Address (or "localhost"): ')

                if check_ip(addr):
                    break
                else:
                    print('\n// Invalid input //')
                    print('Proper Syntax: XXX.XXX.XXX.XXX')
                    continue

            while True:
                
                print('\nPlease Enter a RANGE of ports of which you would like to scan: ')
                rangelow = int(input('\nLow Bound: '))
                rangehigh = int(input('\nHigh Bound: '))

                if check_range(rangelow, rangehigh):
                    break
                else:
                    print('\n// Invalid Input //')
                    continue

            scan_finished = False # Setting variable to break from loading loop
            animation = threading.Thread(target=loading)
            animation.daemon=True # Allows interrupt during animation

            print()
            animation.start()

            nm = nmap.PortScanner() # After getting correct inputs, instantiate nmap.PortScanner
            scan = nm.scan(addr, f'{rangelow}-{rangehigh}', '-T4') # Scan given IPaddress and port range

            #time.sleep(5)
            scan_finished = True # Ending loop
            time.sleep(1)

            print('\nCommand Ran: "{}"'.format(nm.command_line()))
            print()
            print("Scan Results")
            print('-' * 50)
            print(scan)
            
            print("\nWould you like to write this information to your Elasticsearch?\
                    \n1: Yes\
                    \n2: End Program")
            goto_ES = int(input('\n'))
            
            if goto_ES == 1: # Check if ES is online then write to index
                
                es_online = requests.get('http://localhost:9200')
                status = es_online.status_code
                print('\nChecking to see if your Elasticsearch is operational- \
                    \nStatus Code: {}.'.format(status))

                if status == 200:
                    
                    print('\nName of index you would like to assign the document too?\
                    \n(Document ID automatically assigned in numerical order)\
                    \n(Index is created if there isn\'t one already)')
                    es_user_index = input('\n')
                    
                    doc_id = 1 # First doc will have ID of 1

                    while es.exists(index= es_user_index, id= doc_id): # If doc exists, +1 to ID
                                                                        # otherwise exit loop and write
                        doc_id += 1

                    es.index(index= es_user_index, id= doc_id, body= scan)
                    print('\nSUCCESS')
                    print('Document contents can be found with the following query:')
                    print('\nGET /{}/_doc/{}'.format(es_user_index, doc_id))
                    
                    print()
                    sys.exit()

                else:

                    print('Elasticsearch is Offline\
                        \nRun the program again when it\'s up')
                    sys.exit()
            else:
                sys.exit()


            sys.exit()
        else:
            print('\n// Enter 1 or 2 //')
            continue

except KeyboardInterrupt:
	print('\nInterrupted Program - Terminating')
	sys.exit()

except ValueError:
    print("\nDon\'t be playing - Terminating")

#except NameError:
#    print('\nYou did something wrong and you know it - Terminating')