# Initial-Enumeration
A initial enumeration script for pentesting

Performs an Nmap scan on the provided IP and further Wfuzz and Nikto scans on discovered webservers (http and https are treated as seperate entities (one could have vulns/dirs and the other one doesnt)

example Usage:

sudo ./enum.sh 192.168.1.1
or 
sudo ./enum.sh 192.168.1.0/24

