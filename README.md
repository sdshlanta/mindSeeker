# mindSeeker
A Recon automation tool that simplifies the recon process for your needs by running different tools on a host based on the ports that are initially open and reporting the findings in a simplified and effective manner. 

# Usage
 - sudo ./mindSeeker.sh <IPADDRESS>
   - CIDR Ranges not supported at this time. Future planning and implementations

# Features
 - Automatically runs full scope NMAP scans on a target and outputs the results to a organized file structure
 - Prevents in-efficient scanning by only targeting found open ports with further enumeration
 - Based on certain open ports on a system. mindSeeker will try to use known tools to enumerate the common service that is usually on that.
 - 
 - 

# To Do List
 - [ ] Allow for the use of CIDR notation inside IP address specifications.
 - [ ] Add the ability to use previously established file structures or files to tell if the scan had already run against a host or series of hosts. This way scans can be resumed if the are aborted mistakenly.
   - [ ] Add a optional argument that can be used to point to a mindSeeker file structure
 - [ ] Implement options to allow the user to run passive recon tools automatically on a domain. 
 - [ ] Add the command for XML output in all nmap commands.
 - [ ] Stop blinking text after a process is complete.
 - [ ] Add support for UDP Scanning and UDP port vuln enum scanning
 - [ ] Allow the ability for processing of filtered ports
 - [ ] Ports to add specialized scanning for
   - [ ] Web Services: 80, 443
     - [ ] Directory Enumeration
       - [ ] Add the ability to fuzz web directories
       - [ ] Output the results to a file 
   - [ ] SQL