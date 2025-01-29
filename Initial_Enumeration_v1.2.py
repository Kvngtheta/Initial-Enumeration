import os
import re
import json
import asyncio
import logging
import ipaddress
import subprocess
from signal import signal, SIGINT
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(filename="enumeration.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Configuration
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

async def run_command(command):
    """Run a system command asynchronously."""
    proc = await asyncio.create_subprocess_shell(
        command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        logging.error(f"Error running command: {command}\n{stderr.decode().strip()}")
    return stdout.decode().strip()

def write_to_file(filename, data):
    """Write data to a JSON file."""
    os.makedirs(CONFIG["output_directory"], exist_ok=True)
    filepath = os.path.join(CONFIG["output_directory"], filename)
    with open(filepath, "a") as f:
        json.dump(data, f, indent=4)
        f.write("\n")

def parse_ports(output):
    """Parse open ports by service type."""
    services = {"http": [], "https": [], "smb": [], "ftp": []}
    for line in output.splitlines():
        match = re.search(r"(\d+)/tcp", line)
        if match:
            port = match.group(1)
            if "http" in line and "ssl" not in line:
                services["http"].append(port)
            elif "ssl/http" in line:
                services["https"].append(port)
            elif "smb" in line:
                services["smb"].append(port)
            elif "ftp" in line:
                services["ftp"].append(port)
    return services

async def nmap_scan(ip):
    """Run Nmap scan and return results."""
    command = f"nmap -Pn -sV -p- --script vulners {ip} -oN {CONFIG['output_directory']}/nmap-scan-results.txt"
    return await run_command(command)

async def wfuzz_scan(ip, ports, protocol="http"):
    """Run wfuzz scans."""
    results_file = f"wfuzz-{protocol}-results.json"
    results = []
    for port in ports:
        url = f"{protocol}://{ip}:{port}/FUZZ.FUZ2Z"
        command = f"wfuzz -w {CONFIG['wordlist']} -u '{url}' --hc 404 -z list,.php,.txt,.log,.html"
        output = await run_command(command)
        results.append({"url": url, "output": output})
    write_to_file(results_file, results)

async def nikto_scan(ip, ports, protocol="http"):
    """Run Nikto scans."""
    results_file = f"nikto-{protocol}-results.json"
    results = []
    for port in ports:
        url = f"{protocol}://{ip}:{port}"
        command = f"nikto -h {url} -nointeractive -maxtime 360"
        output = await run_command(command)
        results.append({"url": url, "output": output})
    write_to_file(results_file, results)

async def enum4linux_scan(ip):
    """Run enum4linux against the target IP."""
    command = f"enum4linux {ip} > {CONFIG['output_directory']}/linux-enum.txt"
    await run_command(command)

async def perform_curl(ip, file):
    """Use curl to fetch discovered files."""
    semaphore = asyncio.Semaphore(10)  # Limit concurrency
    results = []
    async def fetch(url):
        async with semaphore:
            return await run_command(f"curl {url}")
    
    with open(file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]
    
    if len(urls) > 1000:
        return  # Skip to avoid overload

    tasks = [fetch(url) for url in urls]
    responses = await asyncio.gather(*tasks)
    
    for url, response in zip(urls, responses):
        results.append({"url": url, "content": response})
    write_to_file("curl-results.json", results)

async def main():
    ip = input("Enter target IP: ")
    if not validate_ip(ip):
        print("Invalid IP address. Exiting.")
        return

    # Run Nmap scan
    nmap_results = await nmap_scan(ip)
    services = parse_ports(nmap_results)

    # Run scans concurrently
    tasks = []
    if services["http"]:
        tasks.append(wfuzz_scan(ip, services["http"], "http"))
        tasks.append(nikto_scan(ip, services["http"], "http"))
    if services["https"]:
        tasks.append(wfuzz_scan(ip, services["https"], "https"))
        tasks.append(nikto_scan(ip, services["https"], "https"))
    if services["smb"]:
        tasks.append(enum4linux_scan(ip))
    
    await asyncio.gather(*tasks)
    print("Enumeration complete. Check results for details.")

if __name__ == "__main__":
    with ThreadPoolExecutor(max_workers=CONFIG["max_threads"]) as executor:
        executor.submit(asyncio.run, main())
