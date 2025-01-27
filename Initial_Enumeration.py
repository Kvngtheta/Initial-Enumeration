import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor

def run_command(command):
    """Run a system command and return the output."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        result.check_returncode()
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}\n{e.stderr}")
        return ""

def write_to_file(filename, data):
    """Write data to a file."""
    with open(filename, "a") as f:
        f.write(data + "\n")

def live_update(message):
    """Print live updates to the console."""
    print(f"[+] {message}")

def nmap_scan(ip):
    """Run nmap and return results."""
    live_update(f"Starting Nmap scan on {ip}...")
    command = f"nmap -oN nmap-scan-results.txt --script vulners.nse -sV -p- {ip}"
    run_command(command)
    live_update("Nmap scan complete. Results saved to nmap-scan-results.txt.")
    with open("nmap-scan-results.txt", "r") as f:
        return f.read()

def parse_ports(output, service):
    """Parse open ports for a specific service."""
    return re.findall(rf"(\d+)/tcp.*{service}", output)

def wfuzz_scan(ip, ports, protocol="http"):
    """Run wfuzz scans for given ports."""
    results_file = f"wfuzz-{protocol}-results.txt"
    for port in ports:
        url = f"{protocol}://{ip}:{port}/FUZZ.FUZ2Z"
        live_update(f"Scanning {url} with wfuzz...")
        command = f"wfuzz -w /usr/share/wordlists/dirb/common.txt -u '{url}' --hc 404 -z list,.php,.txt,.log,.html"
        output = run_command(command)
        write_to_file(results_file, output)
    live_update(f"Wfuzz scan complete. Results saved to {results_file}.")

def nikto_scan(ip, ports, protocol="http"):
    """Run nikto scans for given ports."""
    for port in ports:
        url = f"{protocol}://{ip}:{port}"
        live_update(f"Running Nikto on {url}...")
        command = f"nikto -h {url} -nointeractive -maxtime 360"
        output = run_command(command)
        write_to_file(f"nikto-{protocol}-results.txt", output)
        live_update(f"Nikto scan for {url} complete. Results saved.")

def enum4linux_scan(ip):
    """Run enum4linux against the target IP."""
    live_update(f"Running enum4linux on {ip}...")
    command = f"enum4linux {ip} > linux-enum.txt"
    run_command(command)
    live_update("Enum4linux scan complete. Results saved to linux-enum.txt.")

def perform_curl(ip, file):
    """Use curl to fetch discovered files."""
    live_update("Running curl on discovered URLs...")
    with open(file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]
    if len(urls) > 1000:
        live_update("1000+ pages found. Skipping curl (check wfuzz results manually).")
        return

    results_file = "curl-results.txt"
    with ThreadPoolExecutor(max_workers=5) as executor:
        def fetch(url):
            return run_command(f"curl {url}")

        results = executor.map(fetch, urls)
        for result in results:
            write_to_file(results_file, result)

    live_update(f"Curl fetch complete. Results saved to {results_file}.")

def main():
    ip = input("Enter target IP: ")
    if not ip:
        print("IP address is required.")
        return

    # Run Nmap scan
    nmap_results = nmap_scan(ip)

    # Parse ports from Nmap results
    http_ports = parse_ports(nmap_results, "http")
    https_ports = parse_ports(nmap_results, "ssl/http")
    smb_detected = "smb" in nmap_results

    # Run wfuzz scans
    if http_ports:
        wfuzz_scan(ip, http_ports, "http")
    if https_ports:
        wfuzz_scan(ip, https_ports, "https")

    # Run Nikto scans
    if http_ports:
        nikto_scan(ip, http_ports, "http")
    if https_ports:
        nikto_scan(ip, https_ports, "https")

    # Run enum4linux if SMB is detected
    if smb_detected:
        enum4linux_scan(ip)

    live_update("Enumeration complete. Check results for details.")

if __name__ == "__main__":
    main()
