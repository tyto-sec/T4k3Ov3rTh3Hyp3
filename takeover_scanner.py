#!/usr/bin/env python3

import subprocess
import os
import argparse
import csv
import sys

TAKEOVER_MAP = {
    "amazonaws": "takeovers/amazon-bucket-takeover.yaml",
    "s3.amazonaws": "takeovers/amazon-bucket-takeover.yaml",
    "heroku": "takeovers/heroku-takeover.yaml",
    "github": "takeovers/github-takeover.yaml",
    "cloudfront": "takeovers/cloudfront-takeover.yaml",
    "fastly": "takeovers/fastly-takeover.yaml",
    "azurewebsites": "takeovers/azure-takeover.yaml",
    "cloudapp": "takeovers/azure-takeover.yaml",
    "netlify": "takeovers/netlify-takeover.yaml",
    "zendesk": "takeovers/zendesk-takeover.yaml",
    "unbounce": "takeovers/unbounce-takeover.yaml",
    "stripe": "takeovers/stripe-takeover.yaml",
}

NUCLEI_TEMPLATE_DIR = os.path.expanduser("~/nuclei-templates/")
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
    cmd = f"cat {domain_list_file} | subfinder -dL -silent | anew"
    subs = run_cmd(cmd)
    if subs:
        with open(output_file, "w") as f:
            f.write(subs)
    return output_file

def dns_enum(subdomains_file):
    print("[*] CNAMEs and TXTs enumeration...")
    output_file = os.path.join(OUTPUT_DIR, "dns_records.txt")
    cmd = f"cat {subdomains_file} | dnsx -cname -txt -silent"
    dns_output = run_cmd(cmd)
    if dns_output:
        with open(output_file, "w") as f:
            f.write(dns_output)
    return output_file

def filter_takeover_candidates_step(dns_file):
    print("[*] Filtering candidates...")
    candidates_file = os.path.join(OUTPUT_DIR, "takeover_candidates.txt")
    cmd = (
        f"cat {dns_file} | grep -iE "
        "'(azure|aws|s3\\.amazonaws|github|amazonaws|heroku|cloudfront|fastly|cloudapp|"
        "azurewebsites|netlify|pageserve|unbounce|wordpress|zendesk|desk\\.com|stripe)'"
    )
    output = run_cmd(cmd)
    if output:
        with open(candidates_file, "w") as f:
            f.write(output)
    return candidates_file

def check_online_hosts(candidates_file):
    print("[*] Checking online hosts...")
    online_file = os.path.join(OUTPUT_DIR, "online_candidates.txt")
    cmd = f"cat {candidates_file} | httpx -silent"
    output = run_cmd(cmd)
    if output:
        with open(online_file, "w") as f:
            f.write(output)
    return online_file

def load_online_candidates(online_file):
    try:
        with open(online_file, "r") as f:
            return [line.strip().split()[0] for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error loading online subdomains: {e}")
        return []

def map_candidates_to_templates(candidates_subdomains):
    print("[*] Mapping candidates to Nuclei templates...")
    mapped = {}
    with open(os.path.join(OUTPUT_DIR, "dns_records.txt")) as f:
        lines = [line.strip() for line in f.readlines()]
    dns_map = {line.split()[0]: line for line in lines if line}

    for sub in candidates_subdomains:
        dns_line = dns_map.get(sub, "")
        for keyword, template in TAKEOVER_MAP.items():
            if keyword in dns_line.lower():
                if sub not in mapped:
                    mapped[sub] = []
                mapped[sub].append(template)
    return mapped

def run_nuclei_scan(candidates_map):
    print("[*] Executing nuclei scan...")
    csv_file = os.path.join(OUTPUT_DIR, "final_results.csv")
    results = []

    for host, templates in candidates_map.items():
        vulnerable = "not vulnerable"
        for tpl in templates:
            tpl_path = os.path.join(NUCLEI_TEMPLATE_DIR, tpl)
            print(f"[+] Scanning {host} with template {tpl}...")
            cmd = f"nuclei -u {host} -t {tpl_path} -silent"
            result = run_cmd(cmd)
            if result:
                vulnerable = "vulnerable"
                output_path = os.path.join(OUTPUT_DIR, f"{host.replace('http://','').replace('https://','').replace('/','_')}_takeover.txt")
                with open(output_path, "w") as f:
                    f.write(result)
                print(f"[!] Result saved in: {output_path}")
                break
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