'''
Program: Mind Seeker
Author: Shikata
Version: 1.0
'''

#!usr/bin/python
import os
import stat
import argparse 
import socket
import threading
import time
import shutil
from ipaddress import ip_network
import signal

#Global Constants
FILE_STRUCTURE_ROOT_NAME = 'mindSeeker'
PORTS_TO_VULN_ENUM = ["20","22","23","80","110","135","137","139","143","389","443","445","631","1133","1134","3124","3128","3306","3389",
"4333","5432","5500","6000","6001","6665","6666","6667","6668","6669","8080"]

#command line arguments
parser = argparse.ArgumentParser()

#Adds a programs description
parser = argparse.ArgumentParser(description="Placeholder")

#Creates a group parser. Only allows one argument inside the group parser to be inputted
group = parser.add_mutually_exclusive_group(required=True)

#Allows the inputting of either an IP Address to scan or a DNS address. Not Both
group.add_argument('--ipAddress', help="Takes the IP Address or range of ip addresses to scan")
group.add_argument('--dns', help="Takes the DNS Address of the server to scan")

#More Arguments 
parser.add_argument('--resume', help="Used to resume a mindSeeker scan. Point it too the directory where mindSeeker is stored. -> Currently not functioning")
parser.add_argument('--maxThreads', help="Adjusts the max number of threads that can run", default=10)
args = parser.parse_args()

#Global Variables
threadStateDictionary = {}
#Sets the max amount of threads to the inputted max threads
semaphore = threading.BoundedSemaphore(value=int(args.maxThreads))

#Prints the banner for the mindSeeker code
def banner():
    print(" ███▄ ▄███▓ ██▓ ███▄    █ ▓█████▄      ██████ ▓█████ ▓█████  ██ ▄█▀▓█████  ██▀███ \n▓██▒▀█▀ ██▒▓██▒ ██ ▀█   █ ▒██▀ ██▌   ▒██    ▒ ▓█   ▀ ▓█   ▀  ██▄█▒ ▓█   ▀ ▓██ ▒ ██▒\n▓██    ▓██░▒██▒▓██  ▀█ ██▒░██   █▌   ░ ▓██▄   ▒███   ▒███   ▓███▄░ ▒███   ▓██ ░▄█ ▒\n▒██    ▒██ ░██░▓██▒  ▐▌██▒░▓█▄   ▌     ▒   ██▒▒▓█  ▄ ▒▓█  ▄ ▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄  \n▒██▒   ░██▒░██░▒██░   ▓██░░▒████▓    ▒██████▒▒░▒████▒░▒████▒▒██▒ █▄░▒████▒░██▓ ▒██▒\n░ ▒░   ░  ░░▓  ░ ▒░   ▒ ▒  ▒▒▓  ▒    ▒ ▒▓▒ ▒ ░░░ ▒░ ░░░ ▒░ ░▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░\n░  ░      ░ ▒ ░░ ░░   ░ ▒░ ░ ▒  ▒    ░ ░▒  ░ ░ ░ ░  ░ ░ ░  ░░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░\n░      ░    ▒ ░   ░   ░ ░  ░ ░  ░    ░  ░  ░     ░      ░   ░ ░░ ░    ░     ░░   ░ \n       ░    ░           ░    ░             ░     ░  ░   ░  ░░  ░      ░  ░   ░     \n                           ░                                                       \n")
    print("\n\nAuthor: Shikata")

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

    os.system("nmap -sT -sV --version-intensity 5 -oN "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/Versionscan -oG mindSeeker/"+ipAddress+"/nmapScans/versionScan.grep -p $(tr '\n' , <"+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/hostPorts | sed 's/,*$//g') "+ipAddress+" 2>/dev/null 1>/dev/null")
    threadStatus("Running Fingerprinting Scan")

    os.system("nmap -A -oN "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/fingerprintScan -oG "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/fingerprintScan.grep -p $(tr '\\n' , <"+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/hostPorts | sed 's/,*$//g') "+ipAddress+" 2>/dev/null 1>/dev/null")

    #Returns are used for deciding whether or not the thread shoudl exit
    return 1
    
#for each port inside the file...see if we can't do a bit of vulnerability enumeration on this port. 
def portVulNEnum(ipAddress):
    os.makedirs(FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/vulnScans", exist_ok=True)
    portsThatCouldNotBeScanned = []
    #Figure out a way to better too check if a port has been scanned....Im just really lazy right now and not creative hur dur 
    httpRan = False
    smbRan = False
    try:
        file = open("mindSeeker/"+ipAddress+"/nmapScans/hostPorts")
        #There has to be a way to make this better beside just mass if statements / switch stuff. 
        for line in file:
            #If the port is in the port we are currently enumerating is in the list of ports we can enumerate in our code
            if(line.strip() in PORTS_TO_VULN_ENUM):
                threadStatus("\033[36;3mAssessing Port:\033[0m\033[31;7m" + line.strip()+"\033[0m")
                #Scans for vulnerabilities on FTP
                if(line.strip() == "20"):
                    os.system("nmap -p "+line.strip()+" -oN "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/vulnScans/ftp -oG "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/vulnScans/ftp.grep --script=ftp-anon.nse "+ipAddress+" 1>/dev/null 2>/dev/null")
                #Scans for vulnerabilities on ssh
                elif(line.strip() == "22"):
                    os.system("nmap -p "+line.strip()+" -oN "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/vulnScans/ssh -oG "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/vulnScans/ssh.grep --script=sshv1.nse "+ipAddress+" 1>/dev/null 2>/dev/null")
                #Scans for telnet vulnerabilities
                elif(line.strip() == "23"):
                     os.system("nmap -p "+line.strip()+" -oN "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/vulnScans/telnet -oG "+ FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/vulnScans/telnet.grep --script=telnet-ntlm-info "+ipAddress+" 1>/dev/null 2>/dev/null")
                #Scans for vulnerabilities on SMTP
                elif(line.strip() == "25"):
                    null = False
                #Scans or vulnerabilities on HTTP or HTTPS
                elif(line.strip() == "80" or line.strip() == "443" and httpRan == False):
                    os.makedirs(FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/niktoScan", exist_ok=True)
                    os.system("nikto -h "+ipAddress+" -p 80,443 -Format htm -output "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/niktoScan/nikto.html > /dev/null")
                    httpRan = True
                #Scans for vulnerability on POP3
                elif(line.strip() == "110"):
                    null = False
                #Scans for SMB and NETBIOS vulnerabilities
                elif(line.strip() == "135" or line.strip() == "137" or line.strip() == "139" or line.strip() == "445" and smbRan == False):
                    os.makedirs(FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/enum4linux", exist_ok=True)
                    os.system("nmap -p 135,137,139,445 -oN "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/vulnScans/smb -oG "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/nmapScans/vulnScans/smb.grep --script=smb-enum-shares.nse,smb-vuln-*,smb-protocols "+ipAddress)
                    os.system("enum4linux -a "+ipAddress+" > "+FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/enum4linux/scan.txt")

                #Scans for vulnerabilities on IMAP4
                elif(line.strip() == "143"):
                    null = False
                #Scans for vulnerabilities on LDAP
                elif(line.strip() == "389"):
                    null = False
                elif(line.strip() == "631"):
                    null = False
                #Scans for vulnerabilities on Microsoft SQL
                elif(line.strip() == "1133" or line.strip() == "1134"):
                    null = False
                #Scans for MySQL Vulnerabilities
                elif(line.strip() == "3306"):
                    null = False
                #Scans for vulnerabilities on RDP
                elif(line.strip() == "3389"):
                    null = False
                #Scans for vulnerabilities on mSQL
                elif(line.strip() == "4333"):
                    null = False
                elif(line.strip() == "5432"):
                    null = False
                #Scans for vulnerabilities on VNC Server
                elif(line.strip() == "5500"):
                    null = False
                elif(line.strip() == "6000" or line.strip() == "6001"):
                    null = False
                #Scans for vulnerabilities on HTTP proxy
                elif(line.strip() == "8080" or line.strip() == "3124" or line.strip() == "3128"):
                    null = False
                #Scans for vulnerabilities inside IRC relates things
                elif(line.strip() == "6665" or line.strip() == "6666" or line.strip() == "6667" or line.strip() == "6668" or line.strip() == "6669"):
                    null = False
            
            else:
                #If the port could not be scanned we add it to the list of ports that could not be scanned. 
                portsThatCouldNotBeScanned.append(line.strip())

        file.close()
        
        #If there are ports we could not scan. We append them to a file.
        if(len(portsThatCouldNotBeScanned) > 0):
            file = open(FILE_STRUCTURE_ROOT_NAME+"/"+ipAddress+"/portsThatWereNotScanned.haha", 'a')
            for port in portsThatCouldNotBeScanned:
                file.write(port.strip() + "\n")

            file.close()
        
    except:
        print("Error: hostPorts file not found ")


#Threading Function that is used to called by threads. 
def enumHost(ipAddress):
    #Wow...this finally works...horay
    #Sephamores only allow a certain amount of threads to take control of a process. Only 10 threads will be allowed to run at a time
    semaphore.acquire(blocking=True)

    #Adds the current threads name and state to the dictionary
    threadStatus("Running Syn Scan")

    #If the function doesnt return one we dont run any of the other processes
    returnVal = nmapScans(ipAddress)
    if(returnVal == 1):
        portVulNEnum(ipAddress)
        threadStatus("Finished with Evaluation.")
    else:
        threadStatus("Host is not online")


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
    ipData = ip_network(args.ipAddress)

    #Yea this stuff isnt gonna be worked on for awhile...get over it
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

    # Loop over valid addresses, map will convert them to strings for us.
    # we could also used [str(host) for host in ipData.hosts()]
    for host in map(str, ipData.hosts()):
        thread = threading.Thread(name=host, target=enumHost, args=(host,))
        threads.append(thread)
        #Handles the creation of values within our dictionarty for printing
    

    print("Here")
    for thread in threads:
        thread.start()
    print("here1")
    
    #This series of lines handles the printing associated with the threads
    while(threading.active_count() > 1):
        offlineHosts = 0
        printedLines = 0
        # We grab the names and states from the threadStateDict
        for threadName, threadState in threadStateDictionary.items():
            #If a host is marked as not online we incremement the offline hosts counter. 
            if(threadState.strip() == "Host is not online"):
                offlineHosts = offlineHosts + 1
            else:
                stateColor = ''
                endPadding = ' ' * 10
                # Depending on your perfrences this could be turned into a dict
                if(threadState == "Running Syn Scan"):
                    stateColor = "\033[33;5m"
                elif(threadState == "Running Connect Scan"):
                    stateColor = "\033[35;5m"
                elif(threadState == "Running Fingerprinting Scan"):
                    stateColor = "\033[31;5m"
                elif(threadState == "Finished with Evaluation."):
                    stateColor = "\033[34;4m"
                # using **locals() will allow us to pore the local namespace
                # dict into this string al'a fStrings in python 3.6 or grater
                # but because IDK what version this will be running on we use
                # this hack.
                print("\033[32;4m{threadName}\033[0m:{stateColor} {threadState}\033[0m{endPadding}".format(**locals()))
                printedLines += 1
            #print(threads[i].name + " " + threadStateDictionary[threads[i].name])
                    

        time.sleep(1)
        #http://tldp.org/HOWTO/Bash-Prompt-HOWTO/x361.html
        #Move the cursor up the amount of lines printed + 3
        print("\033["+str(printedLines+2)+"A") #I cant beleive this works. Holy crap...
        #prints the total amount of offline hosts above everything else.
        print("Offline Hosts: " + str(offlineHosts))

    #Not sure if we need this line...might be obsolete because of the while loop. Further research needed.
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
