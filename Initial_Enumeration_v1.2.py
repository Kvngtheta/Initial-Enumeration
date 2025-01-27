import os
import re
import subprocess
import asyncio
import ipaddress
import logging
from tqdm import tqdm
from signal import signal, SIGINT
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(filename="enumeration.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Centralized configuration
CONFIG = {
    "wordlist": "/usr/share/wordlists/dirb/common.txt",
    "max_threads": 5,
    "output_directory": "results",
    "interesting_keywords": ["login", "admin", "portal", "password"],
}

# Graceful exit handler
def handle_exit(signal_received, frame):
    print("\n[!] Ctrl+C detected. Exiting gracefully...")
    exit(0)

signal(SIGINT, handle_exit)

def validate_ip(ip):
    """Validate the user-provided IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def run_command(command):
    """Run a system command and return the output."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        result.check_returncode()
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running command: {command}\n{e.stderr}")
        return ""

def write_to_file(filename, data):
    """Write data to a file."""
    os.makedirs(CONFIG["output_directory"], exist_ok=True)
    filepath = os.path.join(CONFIG["output_directory"], filename)
    with open(filepath, "a") as f:
        f.write(data + "\n")

def live_update(message, highlight=False):
    """Print live updates to the console."""
    if highlight:
        print(f"\033[91m[+] {message}\033[0m")  # Red font for highlights
    else:
        print(f"[+] {message}")

def parse_ports(output):
    """Parse open ports by service type."""
    services = {"http": [], "https": [], "smb": [], "ftp": []}
    for line in output.splitlines():
        if "http" in line and not "ssl" in line:
            services["http"].append(re.search(r"(\d+)/tcp", line).group(1))
        elif "ssl/http" in line:
            services["https"].append(re.search(r"(\d+)/tcp", line).group(1))
        elif "smb" in line:
            services["smb"].append(re.search(r"(\d+)/tcp", line).group(1))
        elif "ftp" in line:
            services["ftp"].append(re.search(r"(\d+)/tcp", line).group(1))
    return services

async def nmap_scan(ip):
    """Run nmap and return results."""
    live_update(f"Starting Nmap scan on {ip}...")
    command = f"nmap -Pn {CONFIG['output_directory']}/nmap-scan-results.txt --script vulners.nse -sV -p- {ip}"
    output = run_command(command)
    live_update("Nmap scan complete. Results saved.")
    return output

async def wfuzz_scan(ip, ports, protocol="http"):
    """Run wfuzz scans for given ports."""
    results_file = f"wfuzz-{protocol}-results.txt"
    for port in ports:
        url = f"{protocol}://{ip}:{port}/FUZZ.FUZ2Z"
        live_update(f"Scanning {url} with wfuzz...")
        command = f"wfuzz -w {CONFIG['wordlist']} -u '{url}' --hc 404 -z list,.php,.txt,.log,.html"
        output = run_command(command)
        write_to_file(results_file, output)
        if any(keyword in output for keyword in CONFIG["interesting_keywords"]):
            live_update(f"Interesting findings in {url}!", highlight=True)
    live_update(f"Wfuzz scan complete. Results saved to {results_file}.")

async def nikto_scan(ip, ports, protocol="http"):
    """Run nikto scans for given ports."""
    results_file = f"nikto-{protocol}-results.txt"
    for port in ports:
        url = f"{protocol}://{ip}:{port}"
        live_update(f"Running Nikto on {url}...")
        command = f"nikto -h {url} -nointeractive -maxtime 360"
        output = run_command(command)
        write_to_file(results_file, output)
        live_update(f"Nikto scan for {url} complete.")

async def enum4linux_scan(ip):
    """Run enum4linux against the target IP."""
    live_update(f"Running enum4linux on {ip}...")
    command = f"enum4linux {ip} > {CONFIG['output_directory']}/linux-enum.txt"
    run_command(command)
    live_update("Enum4linux scan complete. Results saved.")

async def perform_curl(ip, file):
    """Use curl to fetch discovered files."""
    live_update("Running curl on discovered URLs...")
    with open(file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]
    if len(urls) > 1000:
        live_update("1000+ pages found. Skipping curl (check wfuzz results manually).")
        return

    results_file = "curl-results.txt"
    async def fetch(url):
        return run_command(f"curl {url}")

    tasks = [fetch(url) for url in urls]
    results = await asyncio.gather(*tasks)
    for result in results:
        write_to_file(results_file, result)
    live_update(f"Curl fetch complete. Results saved to {results_file}.")

async def main():
    ip = input("Enter target IP: ")
    if not validate_ip(ip):
        print("Invalid IP address. Exiting.")
        return

    # Run Nmap scan
    nmap_results = await nmap_scan(ip)

    # Parse ports from Nmap results
    services = parse_ports(nmap_results)

    # Run wfuzz scans
    wfuzz_tasks = []
    if services["http"]:
        wfuzz_tasks.append(wfuzz_scan(ip, services["http"], "http"))
    if services["https"]:
        wfuzz_tasks.append(wfuzz_scan(ip, services["https"], "https"))

    # Run Nikto scans
    nikto_tasks = []
    if services["http"]:
        nikto_tasks.append(nikto_scan(ip, services["http"], "http"))
    if services["https"]:
        nikto_tasks.append(nikto_scan(ip, services["https"], "https"))

    # Run enum4linux if SMB is detected
    enum4linux_task = None
    if services["smb"]:
        enum4linux_task = enum4linux_scan(ip)

    # Await all tasks
    await asyncio.gather(*wfuzz_tasks, *nikto_tasks, enum4linux_task)

    live_update("Enumeration complete. Check results for details.")

if __name__ == "__main__":
    asyncio.run(main())
