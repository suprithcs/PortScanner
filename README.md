Project 4: Port Scanner.

IMPLEMENTED BY : Puneet Loya(username: ploya) and Suprith Chandrashekharachar(username: suprchan)

The project is implemented in C++11.

The code is modularized into five modules.

portScanner.cpp  - The main file which file which initiates the program and sets up the variables based on the given command line arguments.

CommonUtilitites.cpp - The file which performs common functions to both TCP and UDP scans.
TCPUtilities.cpp - File which handles the TCP packet creation and response parsing functions.
UDPUtilities.cpp - File which handles the UDP packet creation and response parsing functions.
optionsManager.cpp : options Manager reads all the command line arguments and fills an option dictionary which stores all the options and their values as key-value pairs.
Jobs.cpp: File which maintains job status and job queues.

Required Files:

CommonUtilitites.cpp CommonUtilitites.h
portScanner.cpp  
TCPUtilities.cpp TCPUtilities.h
UDPUtilities.cpp UDPUtilities.h
optionsManager.cpp optionsManager.h
makefile

Tasks Accomplished:

- Create a TCP/UDP packet with flag bits set according to the type of a scan.
- Send the packet using raw socket.
- Parse the response packets(Either TCP/UDP and ICMP packet).
- Infer the state of the port.
- Get service name information
- Get service version information for set of standard services such as HTTP, WHOIS, POP, IMAP, SMTP, SSH
- Repeat the previous five steps for all the scans,ports and ips requested by the user.
- Provide an option for the user to increase concurrency.

System Requirements:

C++ Compiler : g++/4.7.2 OR g++/4.8

Operating System : Ubuntu14.04/Redhat

Compiling:

If executing on a silo.cs.indiana.edu machine, please make sure you execute the below command at the shell prompt:

	module load gcc/4.7.2

A makefile is provided to compile the program. 

Just cd to the directory containing all files related to the project. Please refer the above section to find which all files are required.

Execute by typing in "make" at the shell prompt.

Refer the makefile for more details.

Usage:

./portScanner [option1, ..., optionN]
--help. Example: “./portScanner --help”.
--ports <ports to scan>. Example: “./portScanner --ports 1,2,3-5”.
--ip <IP address to scan>. Example: “./portScanner --ip 127.0.0.1”.
--prefix <IP prefix to scan>. Example: “./portScanner --prefix 127.143.151.123/24”.
--file <file name containing IP addresses to scan>. Example: “./portScanner --file filename.txt”.
--speedup <parallel threads to use>. Example: “./portScanner --speedup 10”.
--scan <one or more scans>. Example: “./portScanner --scan SYN NULL FIN XMAS”.


Examples to run the program: 

To start the port scanner: -ip 74.207.244.221 --scan SYN ACK NULL UDP FIN XMAS --speedup 100

Output:
[suprchan@silo without_valgrind]$ -ip 74.207.244.221 --scan SYN ACK NULL UDP FIN XMAS --speedup 100 

Sample Output:
-----------------------------------------------------------------Port Scan Stats---------------------------------------------------------------

IP Address: 129.79.247.87


Open Ports: 
Port                Service Name        Results                                           Version                  Conclusion
-----------------------------------------------------------------------------------------------------------------------------------------------
22                  ssh                 SYN(Open) UDP(Closed)                                                      Open      
24                  NA                  SYN(Open) UDP(Closed)                                                      Open      


Closed/Filtered/Unfiltered Ports: 
Port                Service Name        Results                                           Version                  Conclusion
-----------------------------------------------------------------------------------------------------------------------------------------------
20                  ftp-data            SYN(Closed) UDP(Closed)                           NA                       Closed    
21                  ftp                 SYN(Closed) UDP(Closed)                           NA                       Closed    
23                  telnet              SYN(Filtered) UDP(Closed)                         NA                       Filtered  
25                  smtp                SYN(Filtered) UDP(Closed)                         NA                       Filtered  
26                  NA                  SYN(Closed) UDP(Closed)                           NA                       Closed    
27                  NA                  SYN(Closed) UDP(Closed)                           NA                       Closed    
