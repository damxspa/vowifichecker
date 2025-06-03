import subprocess
import random
import requests
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# List of DNS servers
dns_servers = ["8.8.8.8", "9.9.9.9", "1.1.1.1", "9.9.9.11"]

# Function to generate the range of MNC codes
def generate_mnc_ranges():
    ranges = []
    # First range: mnc000 to mnc100
    for i in range(0, 101):
        ranges.append(f"epdg.epc.mnc{i:03d}.mcc214.pub.3gppnetwork.org")
    # Second range: mnc0700 to mnc720
    for i in range(700, 721):
        ranges.append(f"epdg.epc.mnc{i:04d}.mcc214.pub.3gppnetwork.org")
    return ranges

# Function to perform nslookup
def perform_nslookup(domain, dns_server):
    try:
        result = subprocess.run(
            ["nslookup", domain, dns_server],
            capture_output=True,
            text=True,
            timeout=10
        )
        return domain, result.stdout
    except subprocess.TimeoutExpired:
        return domain, "Timeout"
    except Exception as e:
        return domain, f"Error: {str(e)}"

# Function to extract IPs from nslookup output
def extract_ips(nslookup_output):
    ips = []
    lines = nslookup_output.splitlines()
    capture_ips = False
    for line in lines:
        if "Addresses:" in line or "Address:" in line:
            capture_ips = True
            continue
        if capture_ips and line.strip() and not line.startswith(("Name:", "Aliases:")):
            ip = line.strip()
            if ip.count('.') == 3 and ip != "127.0.0.1":  # Basic IPv4 validation, exclude 127.0.0.1
                ips.append(ip)
        elif capture_ips and not line.strip():
            capture_ips = False
    return ips

# Function to get IP info from ipinfo.io
def get_ip_info(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                "ip": ip,
                "org": data.get("org", "Unknown"),
                "city": data.get("city", "Unknown"),
                "country": data.get("country", "Unknown")
            }
        return {"ip": ip, "org": "Unknown", "city": "Unknown", "country": "Unknown"}
    except Exception as e:
        return {"ip": ip, "org": f"Error: {str(e)}", "city": "Unknown", "country": "Unknown"}

# Main function
def main():
    domains = generate_mnc_ranges()
    results = []
    
    # Perform nslookup with random DNS server
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_domain = {
            executor.submit(perform_nslookup, domain, random.choice(dns_servers)): domain 
            for domain in domains
        }
        for future in future_to_domain:
            domain, output = future.result()
            ips = extract_ips(output)
            if ips:  # Only include domains with valid IPs (excludes 127.0.0.1 and no IPs)
                results.append((domain, ips, output))

    # Process IP information
    ip_info_results = []
    unique_ips = set()
    for domain, ips, _ in results:
        for ip in ips:
            if ip not in unique_ips:
                unique_ips.add(ip)
                ip_info = get_ip_info(ip)
                ip_info_results.append((domain, ip, ip_info))

    # Write results to file
    output_file = Path("resultado.txt")
    with output_file.open("w", encoding="utf-8") as f:
        f.write("=== NSLOOKUP SCAN RESULTS ===\n\n")
        for domain, ips, output in results:
            f.write(f"Domain: {domain}\n")
            f.write(f"IPs found: {', '.join(ips)}\n")
            f.write("Full nslookup output:\n")
            f.write(f"{output}\n")
            f.write("-" * 50 + "\n")

        f.write("\n=== IP INFO ===\n\n")
        for domain, ip, info in ip_info_results:
            f.write(f"Domain: {domain}\n")
            f.write(f"IP: {ip}\n")
            f.write(f"Organization: {info['org']}\n")
            f.write(f"City: {info['city']}\n")
            f.write(f"Country: {info['country']}\n")
            f.write("-" * 50 + "\n")

    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()
