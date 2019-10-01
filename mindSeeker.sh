#!/bin/bash


echo -e " ███▄ ▄███▓ ██▓ ███▄    █ ▓█████▄      ██████ ▓█████ ▓█████  ██ ▄█▀▓█████  ██▀███ \n▓██▒▀█▀ ██▒▓██▒ ██ ▀█   █ ▒██▀ ██▌   ▒██    ▒ ▓█   ▀ ▓█   ▀  ██▄█▒ ▓█   ▀ ▓██ ▒ ██▒\n▓██    ▓██░▒██▒▓██  ▀█ ██▒░██   █▌   ░ ▓██▄   ▒███   ▒███   ▓███▄░ ▒███   ▓██ ░▄█ ▒\n▒██    ▒██ ░██░▓██▒  ▐▌██▒░▓█▄   ▌     ▒   ██▒▒▓█  ▄ ▒▓█  ▄ ▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄  \n▒██▒   ░██▒░██░▒██░   ▓██░░▒████▓    ▒██████▒▒░▒████▒░▒████▒▒██▒ █▄░▒████▒░██▓ ▒██▒\n░ ▒░   ░  ░░▓  ░ ▒░   ▒ ▒  ▒▒▓  ▒    ▒ ▒▓▒ ▒ ░░░ ▒░ ░░░ ▒░ ░▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░\n░  ░      ░ ▒ ░░ ░░   ░ ▒░ ░ ▒  ▒    ░ ░▒  ░ ░ ░ ░  ░ ░ ░  ░░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░\n░      ░    ▒ ░   ░   ░ ░  ░ ░  ░    ░  ░  ░     ░      ░   ░ ░░ ░    ░     ░░   ░ \n       ░    ░           ░    ░             ░     ░  ░   ░  ░░  ░      ░  ░   ░     \n                           ░                                                       \n"
echo "Author-> Shikata"


#Checks to see if the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

#Check the number of command line arguments
if [ "$#" -ne 1 ]; then
	echo "Usage: $0 <ipAddress>"
	exit 1
fi
echo -e "\nCheck the mindSeeker directory for your results"

#Create a directory to hold all of the output files that come from this script
mkdir mindSeeker 2>/dev/null
mkdir mindSeeker/$1 2>/dev/null
mkdir mindSeeker/$1/nmapScans 2>/dev/null



echo ____Peforming Syn Scan on Host $1____
echo  -e "-->\033[32;5m Please Wait\033[0m"
#Run a NMAP Syn Scan
sudo nmap -sS $1 -p- -oN mindSeeker/$1/nmapScans/synScan -oG mindSeeker/$1/nmapScans/synScan.grep | grep open | cut -d "/" -f 1 > mindSeeker/$1/nmapScans/hostPorts
echo -e "--> Done\n\n"


echo ____Performing TCP Connect Scan on Host $1____
echo  -e "-->\033[32;5m Please Wait\033[0m"
#Run a nmap connect scan against the target. 
nmap -sT -sV --version-intensity 5 -oN mindSeeker/$1/nmapScans/Versionscan -oG mindSeeker/$1/nmapScans/versionScan.grep -p $(tr '\n' , <mindSeeker/$1/nmapScans/hostPorts | sed 's/,*$//g') $1 >/dev/null
echo -e "--> Done\n\n"


echo ____Running Fingerprint Scan on Host $1____
echo  -e "-->\033[32;5m Please Wait\033[0m"
#Runs a Fingerprint Scan Against the target
nmap -A -oN mindSeeker/$1/nmapScans/fingerprintScan -oG mindSeeker/$1/nmapScans/fingerprintScan.grep -p $(tr '\n' , <mindSeeker/$1/nmapScans/hostPorts | sed 's/,*$//g') $1 >/dev/null
echo -e "--> Done\n\n"


echo ___Starting Vuln Enum on Host____
mkdir mindSeeker/$1/nmapScans/vulnScans 2>/dev/null



#Automatically performs Vuln Enumerations
for openPort in $(cat mindSeeker/$1/nmapScans/hostPorts);
do
        echo  -e "Checking Port: \033[32;5m$openPort\033[0m"

	#Scans for vulns on port 20
        if [ $openPort -eq 20 ]; then
                nmap -p $openPort -oN mindSeeker/$1/nmapScans/vulnScans/port20 -oG mindSeeker/$1/nmapScans/vulnScans/port20.grep --script=ftp-anon.nse $1 > /dev/null
        fi

	
	#Scans for vulns on port 22
	if [ $openPort -eq 22 ]; then
                nmap -p $openPort -oN /mindSeeker/$1/nmapScans/vulnScans/port22 -oG mindSeeker/$1/nmapScans/vulnScans/port22.grep --script=sshv1 $1 > /dev/null
        fi	
	
	#Scans for SMTP Vulns
	if [ $openPort -eq 25 ] || [ $openPort -eq 587 ] || [ $openPort -eq 465 ]; then
                nmap -p $openPort -oN mindSeeker/$1/nmapScans/vulnScans/SMTP -oG mindSeeker/$1/nmapScans/vulnScans/SMTP.grep --script=smtp-vuln*,smtp-enum-users,smtp-ntlm-info,smtp-open-relay $1 > /dev/null
        fi
	

	#Scans for vulns on port 80
	if [ $openPort -eq 80 ] || [ $openPort -eq 443 ]; then
                mkdir mindSeeker/$1/niktoScans 2>/dev/null
                
		nikto -h $1 -p 80,443 -Format htm -output mindSeeker/$1/niktoScans/nikto.html > /dev/null 
	fi
	
	#Scans for SMB vulns
 	if [ $openPort -eq 135  ] || [ $openPort -eq 139  ] || [ $openPort -eq 445  ] ; then
                mkdir mindSeeker/$1/enum4Linux 2> /dev/null
                nmap -p $openPort -oN mindSeeker/$1/nmapScans/vulnScans/smb -oG mindSeeker/$1/nmapScans/vulnScans/smb.grep --script=smb-enum-shares.nse,smb-vuln-*,smb-protocols $1
                enum4linux -a $ip > mindSeeker/$1/enum4linux/scan.txt
       fi


done
