#!/usr/bin/env python3

import subprocess
import os
import argparse
import csv
import sys


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
    return output_file

def dns_enum(subdomains_file):
    print("[*] CNAMEs and TXTs enumeration...")
    output_file = os.path.join(OUTPUT_DIR, "dns_records.txt")
    cmd = f"dnsx -cname -txt -silent -re -l {subdomains_file} -o {output_file}"
    dns_output = run_cmd(cmd)
    return output_file

def filter_takeover_candidates_step(dns_file):
    print("[*] Filtering candidates...")
    candidates_file = os.path.join(OUTPUT_DIR, "takeover_candidates.txt")
    cmd = f"grep 'CNAME' {dns_file} | sed 's/\\[[0-9;]*m//g' | awk '{{print $1 ' -> ' $NF}}' | sed 's/\\]//' | sort -u"
    output = run_cmd(cmd)
    if output:
        with open(candidates_file, "w") as f:
            f.write(output)
    return candidates_file

def get_takeover_candidates_hosts(candidates_file):
    candidates_hosts = []
    try:
        with open(candidates_file, "r") as f:
            for line in f:
                if '->' in line:
                    host = line.split('->')[0].strip()
                    candidates_hosts.append(host)
    except Exception as e:
        print(f"[!] Error loading takeover candidates: {e}")
    candidadtes_hosts_file = os.path.join(OUTPUT_DIR, "takeover_candidates_hosts.txt")
    with open(candidadtes_hosts_file, "w") as f:
        for host in candidates_hosts:
            f.write(f"{host}\n")
    return candidadtes_hosts_file

def get_takeover_candidates_targets(candidates_file):
    candidates_targets = []
    try:
        with open(candidates_file, "r") as f:
            for line in f:
                if '->' in line:
                    target = line.split('->')[1].strip()
                    candidates_targets.append(target)
    except Exception as e:
        print(f"[!] Error loading takeover candidates: {e}")
    candidadtes_targets_file = os.path.join(OUTPUT_DIR, "takeover_candidates_targets.txt")
    with open(candidadtes_targets_file, "w") as f:
        for target in candidates_targets:
            f.write(f"{target}\n")
    return candidadtes_targets_file

def check_online_hosts(candidadtes_hosts_file):
    print("[*] Checking online hosts...")
    online_file = os.path.join(OUTPUT_DIR, "online_candidates.txt")
    cmd = f"httpx -silent -l {candidadtes_hosts_file}"
    output = run_cmd(cmd)
    if output:
        with open(online_file, "w") as f:
            f.write(output)
    return online_file


def run_nuclei_scan(candidadtes_hosts_file):
    print("[*] Executing nuclei scan...")
    csv_file = os.path.join(OUTPUT_DIR, "final_results.csv")
    results = []

    for host in candidadtes_hosts_file:
        vulnerable = "not vulnerable"
        cmd = f"nuclei -u {host} -t {NUCLEI_TEMPLATE_DIR} -silent"
        result = run_cmd(cmd)
        if result:
            vulnerable = "vulnerable"
            output_path = os.path.join(OUTPUT_DIR, f"{host.replace('http://','').replace('https://','').replace('/','_')}_takeover.txt")
            with open(output_path, "w") as f:
                f.write(result)
            print(f"[!] Result saved in: {output_path}")
        results.append([host, vulnerable, ""])

    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Subdomain", "Nuclei Result", "Manual Verification"])
        writer.writerows(results)

    print(f"[+] CSV report saved in: {csv_file}")

def main(domains_file):
    print("[+] Starting automated Subdomain Takeover scanner...")

    subs_file = enum_subdomains(domains_file)
    dns_file = dns_enum(subs_file)
    candidates_file = filter_takeover_candidates_step(dns_file)
    online_file = check_online_hosts(candidates_file)
    online_candidates = load_online_candidates(online_file)
    mapped_candidates = map_candidates_to_templates(online_candidates)
    run_nuclei_scan(mapped_candidates)

    print("[+] Process completed. Check the 'takeover_output' directory for results.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated Subdomain Takeover Scanner")
    parser.add_argument("-f", "--file", required=True, help="File containing list of domains")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[!] File {args.file} not found.")
        sys.exit(1)

    main(args.file)