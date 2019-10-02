'''
Program: Mind Seeker
Author: Shikata
Version: 0.15
'''

#!usr/bin/python
import os
import stat
import argparse 
import socket
import threading
from netaddr import *

#Global Constants
FILE_STRUCTURE_ROOT_NAME = 'mindSeeker'

#command line arguments
parser = argparse.ArgumentParser()

#Adds a programs description
parser = argparse.ArgumentParser(description="Description HEre")

#Creates a group parser. Only allows one argument inside the group parser to be inputted
group = parser.add_mutually_exclusive_group(required=True)

#Allows the inputting of either an IP Address to scan or a DNS address. Not Both
group.add_argument('--ipAddress', help="Takes the IP Address or range of ip addresses to scan")
group.add_argument('--dns', help="Takes the DNS Address of the server to scan")

#More Arguments 
parser.add_argument('--resume', help="Used to resume a mindSeeker scan. Point it too the directory where mindSeeker is stored.")

args = parser.parse_args()


#Prints the banner for the mindSeeker code
def banner():
    print(" ███▄ ▄███▓ ██▓ ███▄    █ ▓█████▄      ██████ ▓█████ ▓█████  ██ ▄█▀▓█████  ██▀███ \n▓██▒▀█▀ ██▒▓██▒ ██ ▀█   █ ▒██▀ ██▌   ▒██    ▒ ▓█   ▀ ▓█   ▀  ██▄█▒ ▓█   ▀ ▓██ ▒ ██▒\n▓██    ▓██░▒██▒▓██  ▀█ ██▒░██   █▌   ░ ▓██▄   ▒███   ▒███   ▓███▄░ ▒███   ▓██ ░▄█ ▒\n▒██    ▒██ ░██░▓██▒  ▐▌██▒░▓█▄   ▌     ▒   ██▒▒▓█  ▄ ▒▓█  ▄ ▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄  \n▒██▒   ░██▒░██░▒██░   ▓██░░▒████▓    ▒██████▒▒░▒████▒░▒████▒▒██▒ █▄░▒████▒░██▓ ▒██▒\n░ ▒░   ░  ░░▓  ░ ▒░   ▒ ▒  ▒▒▓  ▒    ▒ ▒▓▒ ▒ ░░░ ▒░ ░░░ ▒░ ░▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░\n░  ░      ░ ▒ ░░ ░░   ░ ▒░ ░ ▒  ▒    ░ ░▒  ░ ░ ░ ░  ░ ░ ░  ░░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░\n░      ░    ▒ ░   ░   ░ ░  ░ ░  ░    ░  ░  ░     ░      ░   ░ ░░ ░    ░     ░░   ░ \n       ░    ░           ░    ░             ░     ░  ░   ░  ░░  ░      ░  ░   ░     \n                           ░                                                       \n")

def nmapScans(ipAddress):
    #Create the file for the ip Address we are scanning
    os.mkdir(FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress)
    os.mkdir(FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans")

    os.system("nmap -sS " + ipAddress + " -p- -oN "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/synScan -oG "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/synScan.grep | grep open | cut -d \"/\" -f 1 > "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/hostPorts")
    os.system("nmap -sT -sV --version-intensity 5 -oN "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/Versionscan -oG mindSeeker/"+ipAddress+"/nmapScans/versionScan.grep -p $(tr '\n' , <"+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/hostPorts | sed 's/,*$//g') "+ipAddress+" >/dev/null")
    os.system("nmap -A -oN "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/fingerprintScan -oG "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/fingerprintScan.grep -p $(tr '\\n' , <"+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/hostPorts | sed 's/,*$//g') "+ipAddress+" >/dev/null")

def portVulNEnum(ipAddress):
    with open("mindSeeker/"+ipAddress+"/nmapScans/hostPorts") as portFile:
        line = portFile.readline()
        print(line)



#Threading Function that is used to called by threads. 
def enumHost(ipAddress):
    nmapScans(ipAddress)
    portVulNEnum(ipAddress)

def resume():
    #Resume feature to be implemented
    print("Stuff")

def main():
    banner()
    #Local Variables
    threads = []

    #Checks if the python script was ran as root
    if(os.geteuid() != 0):
        print("Script must be run as sudo")
        exit()

    #If DNS was inputted. Assign the ip address inputted too 
    if(args.dns):
        #performs DNS resolution if DNS was inputted
        args.ipAddress = socket.gethostbyname(args.dns)

    #Ip data object contains all the ip address data
    ipData = IPNetwork(args.ipAddress)

    #Manages and Creates file structure for the program output to use
    if not args.resume:
        if not (os.path.exists(FILE_STRUCTURE_ROOT_NAME)):
            os.mkdir(FILE_STRUCTURE_ROOT_NAME)
        else:
            #If the user forgot to use the resume flag and a previous scan was called. This allows them to use the resume flag anyway
            print("Previous Directory Structure Found. Would you like to resume?('Y', 'N')\n:> ")
            #resume()
    else:
        resume()

    #If a Cidr range is used. Removes the first IP address which is invalid. 

    for i in range(len(ipData)):
        thread = threading.Thread(target=enumHost,args=(str(ipData[i]),))
        threads.append(thread)

    for thread in threads:
        thread.start()
    
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()

'''

'''