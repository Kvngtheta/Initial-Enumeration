#!/usr/bin/bash

#Automation of part of the first step of enumeration- information gathering.
#Script performs nmap vulners scan, dirb based on the results of nmap and nikto based on the same
#Also performs a quick check for the existence of anonymous ftp access if relevant
#May add to this as time passes and I learn more

# Just some fancy banner stuff 
figlet "NoB@ckSappi" ; figlet "Initial Enum" ; echo "Services and Web Servers"
ip=$1 && echo -e "Target: ${ip}\nCommencing with nmap vulners scan..."

# perform Nmap scan on all ports using NSE script vulners
nmap -oN ./nmap-scan-results.txt --script vulners.nse -sV -p- ${ip} > /dev/null 2>&1 && zenity --info --text="Nmap Scan On ${ip} Complete. Results saved to nmap-scan-results.txt."
cat ./nmap-scan-results.txt 

# collect relevant ports and place into variables for use later
http_p=$(grep "http" ./nmap-scan-results.txt | grep -v "ssl" | cut -d'/' -f1)
https_p=$(grep "ssl/http" ./nmap-scan-results.txt | cut -d'/' -f1)
ssh_p=$(grep "ssh" ./nmap-scan-results.txt | cut -d'/' -f1)
ftp_p=$(grep "ftp" ./nmap-scan-results.txt | cut -d'/' -f1)

# run enum4linux against target if target is linux
if [[ $(grep "smb" nmap-scan-results.txt) ]]; then
    echo -e "\nRunning enum4linux..."
    enum4linux "${ip}" > linux-enum.txt &
    wait
    cat linux-enum.txt
fi

# perform wfuzz scans (HTTP and HTTPS)
if [[ -n "$http_p" || -n "$https_p" ]]; then
    echo "Found HTTP/HTTPS, commencing with wfuzz..."
    for i in $http_p; do
        wfuzz -w /usr/share/wordlists/dirb/common.txt -u "http://${ip}:${i}/FUZZ.FUZ2Z" --hc 404 -z list,.php,.txt,.log,.html >> ./http-wfuzz.txt &
    done
    for i in $https_p; do
        wfuzz -w /usr/share/wordlists/dirb/common.txt -u "https://${ip}:${i}/FUZZ.FUZ2Z" --hc 404 -z list,.php,.txt,.log,.html >> ./https-wfuzz.txt &
    done
    wait
    cat http-wfuzz.txt https-wfuzz.txt > wfuzz.txt
else
    echo "Did not find a web server..." && exit 1
fi

# curl found results
cat wfuzz.txt | grep -v "404" | grep -o '".*"' | tr -d '"' | uniq > curl.txt

if [[ $(wc -l < curl.txt) -lt 1000 ]]; then
    xargs -I {} -P 5 curl "http://${ip}/{}" < curl.txt >> ./http-curl.txt &
    wait
else
    echo "1000+ pages found, skipping cURL (check wfuzz.txt manually)."
fi

# nikto scans run in parallel
echo -e "\nCommencing with Nikto Scans..."
for i in $http_p; do 
    nikto -h "${ip}:${i}" -nointeractive -maxtime 360 >> nikto-results.txt &
done
for i in $https_p; do 
    nikto -h "${ip}:${i}" -nointeractive -maxtime 360 >> nikto-results.txt &
done
wait

cat ./nikto-results.txt 
if grep -E -- "wordpress|WordPress|Wordpress" ./nikto-results.txt > /dev/null 2>&1; then
    echo "WordPress discovered, you should run WPScan."
fi
echo "Initial enumeration complete" && ls -al 

open_ps=$(grep "open" ./nmap-scan-results.txt)
resp=$(grep "  200" ./wfuzz.txt)

echo -e "\e[33m\e[1mRESULTS:\e[0m\e[33m\e[0m"
echo -e "Open Ports:\n${open_ps}" 
echo -e "\nFiles returning 200 response (see wfuzz.txt if unsure on site.):\n${resp}\n"

if grep "ftp" <<< "${open_ps}"; then
    echo -e "FTPs present, anonymous login could be a thing...\n"
fi
if grep "smbd" <<< "${open_ps}"; then
    echo -e "Samba File Share present...\n"
fi
if grep "doom" <<< "${open_ps}"; then
    echo -e "\nUnknown service is present, check this with telnet..."
fi
if grep -E -- "login|admin|portal|robots" ./curl.txt; then
    echo -e "Interesting Files:\n$(grep -E -- 'login|admin|portal|robots' ./curl.txt)\nSee wfuzz.txt for location of file."
fi
if grep -E -- "smb|windows" ./nmap-scan-results.txt; then
    users=$(grep "(Local User)" linux-enum.txt)
    echo -e "\nLocal users discovered by enum4linux:\n${users}" 
    echo "Discovered shares:" 
    grep "Mapping: OK, Listing: OK" linux-enum.txt
fi

exit 0
