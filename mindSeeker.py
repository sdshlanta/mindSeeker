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
import time
import shutil
from netaddr import *
import signal

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
parser.add_argument('--maxThreads', help="Adjusts the max number of threads that can run", default=10)
args = parser.parse_args()

#Global Variables
threadStateDictionary = {}
#Sets the max amount of threads to the inputted max threads
semaphore = threading.BoundedSemaphore(value=int(args.maxThreads))

#Prints the banner for the mindSeeker code
def banner():
    print(" ███▄ ▄███▓ ██▓ ███▄    █ ▓█████▄      ██████ ▓█████ ▓█████  ██ ▄█▀▓█████  ██▀███ \n▓██▒▀█▀ ██▒▓██▒ ██ ▀█   █ ▒██▀ ██▌   ▒██    ▒ ▓█   ▀ ▓█   ▀  ██▄█▒ ▓█   ▀ ▓██ ▒ ██▒\n▓██    ▓██░▒██▒▓██  ▀█ ██▒░██   █▌   ░ ▓██▄   ▒███   ▒███   ▓███▄░ ▒███   ▓██ ░▄█ ▒\n▒██    ▒██ ░██░▓██▒  ▐▌██▒░▓█▄   ▌     ▒   ██▒▒▓█  ▄ ▒▓█  ▄ ▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄  \n▒██▒   ░██▒░██░▒██░   ▓██░░▒████▓    ▒██████▒▒░▒████▒░▒████▒▒██▒ █▄░▒████▒░██▓ ▒██▒\n░ ▒░   ░  ░░▓  ░ ▒░   ▒ ▒  ▒▒▓  ▒    ▒ ▒▓▒ ▒ ░░░ ▒░ ░░░ ▒░ ░▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░\n░  ░      ░ ▒ ░░ ░░   ░ ▒░ ░ ▒  ▒    ░ ░▒  ░ ░ ░ ░  ░ ░ ░  ░░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░\n░      ░    ▒ ░   ░   ░ ░  ░ ░  ░    ░  ░  ░     ░      ░   ░ ░░ ░    ░     ░░   ░ \n       ░    ░           ░    ░             ░     ░  ░   ░  ░░  ░      ░  ░   ░     \n                           ░                                                       \n")

#Used for setting the status of the thread inside the dictionary for printing
def threadStatus(val):
    threadStateDictionary[threading.current_thread().getName()] = val

def nmapScans(ipAddress):

    #Create the file for the ip Address we are scanning
    os.makedirs(FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress, exist_ok=True)
    os.makedirs(FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans", exist_ok=True)
    os.system("nmap -sS " + ipAddress + " -p- -oN "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/synScan -oG "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/synScan.grep | grep open | cut -d \"/\" -f 1 > "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/hostPorts")
    
    #If the file for host ports contains nothing than we know the host is not online so we break the thread for this IP
    if(os.stat(FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/hostPorts").st_size == 0):
        threadStatus("-1")
        #remove the directory tree for the thread
        shutil.rmtree(FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress,ignore_errors=True)
        #Returns are used for deciding or not whether the thread should exit
        return 0 

    
    threadStatus("Running Connect Scan")

    os.system("nmap -sT -sV --version-intensity 5 -oN "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/Versionscan -oG mindSeeker/"+ipAddress+"/nmapScans/versionScan.grep -p $(tr '\n' , <"+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/hostPorts | sed 's/,*$//g') "+ipAddress+" >/dev/null")
    threadStatus("Running Fingerprinting Scan")

    os.system("nmap -A -oN "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/fingerprintScan -oG "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/fingerprintScan.grep -p $(tr '\\n' , <"+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/hostPorts | sed 's/,*$//g') "+ipAddress+" >/dev/null")

    #Returns are used for deciding whether or not the thread shoudl exit
    return 1
    

def portVulNEnum(ipAddress):
    try:
        file = open("mindSeeker/"+ipAddress+"/nmapScans/hostPorts")
        for line in file:
            threadStatus("Assessing Port: " + line.strip())
            if(line.strip() == "20"):
                print("True")
            elif(line.strip() == "20"):
                print("False")
        file.close()
    except:
        print("Error: hostPorts file not found ")


#Threading Function that is used to called by threads. 
def enumHost(ipAddress):

    #Sephamores only allow a certain amount of threads to take control of a process. Only 10 threads will be allowed to run at a time
    semaphore.acquire(blocking=True)

    #Adds the current threads name and state to the dictionary
    threadStatus("Running Syn Scan")

    #If the function doesnt return one we dont run any of the other processes
    if(nmapScans(ipAddress) == 1):
        portVulNEnum(ipAddress)
    
    threadStatus("Finished with Evaluation.")


    semaphore.release()

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
        thread = threading.Thread(name=str(ipData[i]), target=enumHost,args=(str(ipData[i]),))
        threads.append(thread)
        #Handles the creation of values within our dictionarty for printing
        

    print("Here")
    for thread in threads:
        thread.start()
    print("here1")
    
    #This series of lines handles the printing associated with the threads
    while(threading.active_count() > 1):
        printedLines = 0
        for i in range(len(threadStateDictionary)):
            print(threads[i].name + " : " + threadStateDictionary[threads[i].name] + " "*10)
            #print(threads[i].name + " " + threadStateDictionary[threads[i].name])
            printedLines=printedLines + 1

        time.sleep(1)
        #http://tldp.org/HOWTO/Bash-Prompt-HOWTO/x361.html
        print("\033["+str(printedLines+1)+"A")

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
