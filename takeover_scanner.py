#!/usr/bin/env python3

import subprocess
import os
import argparse
import csv
import sys
from constants import CNAME_FINGERPRINTS
from constants import TAKEOVER_MAP
import re

NUCLEI_TEMPLATE_DIR = os.path.expanduser("~/nuclei-templates/http/takeovers")
OUTPUT_DIR = "takeover_output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        print(f"[!] Error executing: {cmd}\n{e}")
        return ""

def read_domains(file_path):
    with open(file_path, "r") as f:
        return [line.strip() for line in f.readlines() if line.strip()]

def enum_subdomains(domain_list_file):
    print("[*] Subdomain enumeration...")
    output_file = os.path.join(OUTPUT_DIR, "subs.txt")
    cmd = f"subfinder -dL {domain_list_file} | anew"
    subs = run_cmd(cmd)
    if subs:
        with open(output_file, "w") as f:
            f.write(subs)
    print(f"[DEBUG] Found {len(subs.splitlines())} subdomains.")
    return output_file

def dns_enum(subdomains_file):
    print("[*] CNAMEs and TXTs enumeration...")
    output_file = os.path.join(OUTPUT_DIR, "dns_records.txt")
    cmd = f"dnsx -cname -txt -silent -re -l {subdomains_file} -o {output_file}"
    run_cmd(cmd)
    return output_file

def get_hosts_with_cname(dns_file):
    print("[*] Filtering candidates...")
    cname_hosts_pairs_file = os.path.join(OUTPUT_DIR, "cname_hosts_pairs.txt")
    host_cname_pairs = []
    try:
        with open(dns_file, 'r') as f:
            for line in f:
                if 'CNAME' in line:
                    clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line)
                    clean_line = re.sub(r'[\[\]]', '', clean_line)
                    
                    parts = clean_line.strip().split()
                    if len(parts) >= 3: 
                        host = parts[0]
                        cname = parts[-1]
                        if host and cname and '.' in cname:
                            host_cname_pairs.append(f"{host} -> {cname}")
        unique_pairs = sorted(set(host_cname_pairs))
        if unique_pairs:
            with open(cname_hosts_pairs_file, "w") as f:
                for pair in unique_pairs:
                    f.write(f"{pair}\n")
            print(f"[DEBUG] Found {len(unique_pairs)} unique Host -> CNAME pairs")
        else:
            print("[!] No CNAME candidates found")
            with open(cname_hosts_pairs_file, "w") as f:
                f.write("")
    except Exception as e:
        print(f"[!] Error processing DNS file: {e}")
    return cname_hosts_pairs_file

def get_hosts_with_cname_list(cname_hosts_pairs_file):
    cname_hosts = []
    cname_hosts_file = os.path.join(OUTPUT_DIR, "cname_hosts.txt")
    try:
        with open(cname_hosts_pairs_file, "r") as f:
            for line in f:
                if '->' in line:
                    host = line.split('->')[0].strip()
                    cname_hosts.append(host)
    except Exception as e:
        print(f"[!] Error loading takeover candidates: {e}")
    with open(cname_hosts_file, "w") as f:
        for host in cname_hosts:
            f.write(f"{host}\n")
    print(f"[DEBUG] Extracted {len(cname_hosts)} cname hosts.")
    return cname_hosts_file

def get_grepped_cname_hosts_pairs(cname_hosts_pairs_file):
    print("[*] Performing massive grep filtering on CNAME targets based on master list...")
    grepped_cname_hosts_pairs_file = os.path.join(OUTPUT_DIR, "grepped_cname_hosts_pairs_file.txt")
    all_cname_keywords = []
    for cname_list in CNAME_FINGERPRINTS.values():
        all_cname_keywords.extend(cname_list)
    unique_cname_keywords = sorted(list(set(all_cname_keywords)))
    regex_pattern = '|'.join(unique_cname_keywords)
    cmd = (
        f"grep -iE \"({regex_pattern})\" {cname_hosts_pairs_file} | sort -u > {grepped_cname_hosts_pairs_file}"
    )
    run_cmd(cmd)
    print(f"[DEBUG] Grepped {len(grepped_cname_hosts_pairs_file.splitlines())} candidates.")
    return grepped_cname_hosts_pairs_file

def get_grepped_cname_hosts(grepped_cname_hosts_pairs_file):
    grepped_cname_hosts_file = os.path.join(OUTPUT_DIR, "grepped_takeover_cname_hosts.txt")
    grepped_cname_hosts = []
    try:
        with open(grepped_cname_hosts_pairs_file, "r") as f:
            for line in f:
                if '->' in line:
                    host = line.split('->')[0].strip()
                    grepped_cname_hosts.append(host)
    except Exception as e:
        print(f"[!] Error loading grepped takeover candidates: {e}")
    with open(grepped_cname_hosts_file, "w") as f:
        for host in grepped_cname_hosts:
            f.write(f"{host}\n")
    return grepped_cname_hosts_file

def check_online_hosts(grepped_cname_hosts_file):
    print("[*] Checking online hosts...")
    online_file = os.path.join(OUTPUT_DIR, "online_candidates.txt")
    cmd = f"httpx -silent -l {grepped_cname_hosts_file}"
    output = run_cmd(cmd)
    if output:
        with open(online_file, "w") as f:
            f.write(output)
    print(f"[DEBUG] Found {len(output.splitlines())} online hosts.")
    return online_file

def run_nuclei_scan(online_hosts_file, cname_hosts_pairs_file):
    print("[*] Executing targeted nuclei scan...")
    csv_file = os.path.join(OUTPUT_DIR, "final_results.csv")
    results = []
    host_to_cname = {}
    try:
        with open(cname_hosts_pairs_file, 'r') as f:
            for line in f:
                if '->' in line:
                    host, cname = [p.strip() for p in line.split('->', 1)]
                    host_to_cname[host] = cname
    except Exception as e:
        print(f"[!] Erro ao carregar pares Host -> CNAME: {e}")
        return
    for host_url in read_domains(online_hosts_file):
        host = host_url.split('//')[-1].split('/')[0]
        cname_target = host_to_cname.get(host)
        nuclei_template = None
        provider_name = "Unknown"
        if cname_target:
            for provider, cnames in CNAME_FINGERPRINTS.items():
                for cname_regex in cnames:
                    if re.search(cname_regex, cname_target, re.IGNORECASE):
                        provider_name = provider
                        nuclei_template = TAKEOVER_MAP.get(provider_name)
                        break
                if nuclei_template:
                    break
        if nuclei_template:
            template_path = os.path.join(NUCLEI_TEMPLATE_DIR, nuclei_template) 
            cmd = f"nuclei -u {host} -t {template_path}"
            print(f"[*] Testing {host} against {provider_name} template: {nuclei_template}")
            try:
                result = run_cmd(cmd)
                vulnerable = "NOT Vulnerable"
                if result:
                    vulnerable = f"VULNERABLE ({provider_name})"
                    output_path = os.path.join(OUTPUT_DIR, f"{host.split(':')[0]}_vulnerable_{provider_name}.txt")
                    with open(output_path, "w") as f:
                        f.write(result)
                    print(f"  [!!!] VULNERABLE! Result saved in: {output_path}")
                results.append([host, cname_target, provider_name, template_path, vulnerable])
            except Exception as e:
                print(f"[!] Error running nuclei for {host}: {e}")
                results.append([host, cname_target, provider_name, template_path, f"Error: {str(e)}"])
        else:
            print(f"[*] Skipped {host} (CNAME: {cname_target}) - No specific nuclei template found for provider: {provider_name}")
            results.append([host, cname_target if cname_target else "N/A", provider_name, "N/A", "Skipped (No Template)"])

    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Subdomain", "CNAME Target", "Provider", "Nuclei Template", "Vulnerability Status"])
        writer.writerows(results)

    print(f"[+] CSV report saved in: {csv_file}")

def main(domains_file):
    print("[+] Starting automated Subdomain Takeover scanner...")

    subs_file = enum_subdomains(domains_file)
    dns_file = dns_enum(subs_file)
    cname_hosts_pairs_file = get_hosts_with_cname(dns_file)
    get_hosts_with_cname_list(cname_hosts_pairs_file)
    grepped_cname_hosts_pairs_file = get_grepped_cname_hosts_pairs(cname_hosts_pairs_file)
    grepped_cname_hosts_file = get_grepped_cname_hosts(grepped_cname_hosts_pairs_file)
    online_file = check_online_hosts(grepped_cname_hosts_file)
    run_nuclei_scan(online_file, grepped_cname_hosts_pairs_file)

    print("[+] Process completed. Check the 'takeover_output' directory for results.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated Subdomain Takeover Scanner")
    parser.add_argument("-f", "--file", required=True, help="File containing list of domains")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[!] File {args.file} not found.")
        sys.exit(1)

    main(args.file)