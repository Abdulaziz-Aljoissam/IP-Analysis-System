import os
import sys
import subprocess
import re
import csv
import json
import time
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

def setup_env():
    packages = ['requests', 'tqdm', 'colorama']
    for p in packages:
        try:
            __import__(p)
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", p])

setup_env()
import requests
from tqdm import tqdm
from colorama import init, Fore

init(autoreset=True)

BASE_PATH = r"C:\Users\aziz\Desktop\IP_Analysis_System"
PATHS = {
    "blacklist": os.path.join(BASE_PATH, "IP_Blacklist"),
    "whitelist": os.path.join(BASE_PATH, "IP_Whitelist"),
    "projects": os.path.join(BASE_PATH, "Projects"),
    "logs": os.path.join(BASE_PATH, "Logs"),
    "cache": os.path.join(BASE_PATH, "Core_Cache")
}

for p in PATHS.values(): os.makedirs(p, exist_ok=True)

C, G, W, R, Y, GL = Fore.CYAN, Fore.LIGHTBLACK_EX, Fore.WHITE, Fore.RED, Fore.YELLOW, Fore.GREEN
SAFE_PROVIDERS = ["google", "aws", "amazon", "azure", "microsoft", "cloudflare", "oracle", "ibm"]

class IPAnalysisEngine:
    def __init__(self, use_api=False):
        self.use_api = use_api
        self.cache_path = os.path.join(PATHS["cache"], "intel_cache.json")
        self.cache = self._load_cache()
        self.singles = {"blacklist": {}, "whitelist": {}}
        self.cidr_v4_index = {"blacklist": {}, "whitelist": {}}
        self.cidr_v6_list = {"blacklist": [], "whitelist": []}
        self.stats = {"rules": 0, "files": 0, "ipv6_rules": 0}
        self._load_database()

    def _load_cache(self):
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path, 'r', encoding='utf-8') as f: return json.load(f)
            except: pass
        return {}

    def _extract_all_ips(self, text):
        clean_text = text.replace(',', ' ').replace('"', ' ').replace(';', ' ').replace('\'', ' ')
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:3[0-2]|[12]?[0-9]))?\b'
        ipv6_pattern = r'\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*(?:/(?:12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9]))?'
        ips_v4 = re.findall(ipv4_pattern, clean_text)
        ips_v6 = [x[0].strip() for x in re.findall(ipv6_pattern, clean_text)]
        return ips_v4, ips_v6

    def _load_database(self):
        for folder_type in ["blacklist", "whitelist"]:
            folder = PATHS[folder_type]
            if not os.path.exists(folder): continue
            for file in os.listdir(folder):
                file_path = os.path.join(folder, file)
                self.stats["files"] += 1
                final_cat = folder_type
                for provider in SAFE_PROVIDERS:
                    if provider in file.lower():
                        final_cat = "whitelist"
                        break
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    v4_list, v6_list = self._extract_all_ips(content)
                    for item in v4_list:
                        self.stats["rules"] += 1
                        if '/' in item:
                            try:
                                net = ipaddress.ip_network(item, strict=False)
                                octet = str(item.split('.')[0])
                                if octet not in self.cidr_v4_index[final_cat]:
                                    self.cidr_v4_index[final_cat][octet] = []
                                self.cidr_v4_index[final_cat][octet].append((net, file))
                            except: pass
                        else:
                            self.singles[final_cat][item] = file
                    for item in v6_list:
                        self.stats["ipv6_rules"] += 1
                        try:
                            net = ipaddress.ip_network(item.strip(), strict=False)
                            self.cidr_v6_list[final_cat].append((net, file))
                        except: pass
                except Exception: pass

    def check_local(self, target_ip):
        try:
            ip_obj = ipaddress.ip_address(target_ip)
            is_v6 = (ip_obj.version == 6)
            if not is_v6:
                for cat in ["whitelist", "blacklist"]:
                    if target_ip in self.singles[cat]:
                        return ("Safe" if cat == "whitelist" else "Malicious"), cat.capitalize(), self.singles[cat][target_ip], target_ip
            cats_order = ["whitelist", "blacklist"]
            if not is_v6:
                first_octet = target_ip.split('.')[0]
                for cat in cats_order:
                    if first_octet in self.cidr_v4_index[cat]:
                        for net, filename in self.cidr_v4_index[cat][first_octet]:
                            if ip_obj in net:
                                return ("Safe" if cat == "whitelist" else "Malicious"), cat.capitalize(), filename, str(net)
            else:
                for cat in cats_order:
                    for net, filename in self.cidr_v6_list[cat]:
                        if ip_obj in net:
                            return ("Safe" if cat == "whitelist" else "Malicious"), cat.capitalize(), filename, str(net)
            return "Unknown", "External Intel", "N/A", "N/A"
        except: return "Error", "Invalid Format", "N/A", "N/A"

    def fetch_api(self, ip):
        if ip in self.cache: return self.cache[ip]
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,org", timeout=2)
            if r.status_code == 200 and r.json().get('status') == 'success':
                self.cache[ip] = r.json()
                return r.json()
        except: pass
        return None

def show_header():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"\n{C}  {'─'*65}")
    print(f"{C}    IP-ANALYSIS-SYSTEM {W}v2.0")
    print(f"{Y}    Project by: Abdulaziz Aljoissam")
    print(f"{G}    IPv6 Support | Cloud Safe-Guard | CSV Unpacker")
    print(f"{C}  {'─'*65}\n")

def process_offline(target, engine):
    try:
        clean_target = target.strip().replace('"', '').replace(',', '')
        try:
            ip_obj = ipaddress.ip_address(clean_target)
            ip = str(ip_obj)
        except:
            found = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', target)
            if found: ip = found[0]
            else: return None

        ver_cat, ver_src, ver_file, ver_rule = engine.check_local(ip)
        
        sheet_cat = "UNCATEGORIZED"
        if ver_cat == "Malicious": sheet_cat = "MALICIOUS_THREAT"
        elif ver_cat == "Safe": sheet_cat = "SAFE_WHITELIST"

        verdict_fmt = f"{ver_cat} (Match: {ver_rule})" if ver_rule != "N/A" else ver_cat

        return {
            "Classification": sheet_cat, "IP": ip, "Target": target.strip(),
            "Verdict": verdict_fmt, "Matched_File": ver_file, 
            "Organization": ver_file if ver_file != "N/A" else "Local DB", 
            "Country": "Local Match" if ver_file != "N/A" else "N/A", 
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    except: return None

def process_online(res, engine):
    if res["Classification"] == "UNCATEGORIZED":
        intel = engine.fetch_api(res["IP"])
        if intel:
            res["Classification"] = "EXTERNAL_INTEL"
            res["Organization"] = intel.get('org', 'Unknown')
            res["Country"] = intel.get('country', 'N/A')
            res["Verdict"] = "Checked Online"
    return res

def run_bulk_scan(use_api=False):
    show_header()
    f_path = input(f"    {C}Source File Path > {W}").strip().replace('"', '')
    if not os.path.exists(f_path): return
    p_name = input(f"    {C}Project Name > {W}").strip() or f"Scan_{datetime.now().strftime('%H%M%S')}"
    project_file = os.path.join(PATHS["projects"], f"{p_name}_Final_Report.csv")

    with open(f_path, 'r', encoding='utf-8', errors='ignore') as f:
        targets = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', f.read())))

    print(f"\n{Y}    [*] Phase 1: Offline Local Analysis...")
    engine = IPAnalysisEngine(use_api=use_api)
    results = []
    with ThreadPoolExecutor(max_workers=60) as executor:
        futures = {executor.submit(process_offline, t, engine): t for t in targets}
        for future in tqdm(as_completed(futures), total=len(targets), desc="    Local Scanning", bar_format="{l_bar}{bar:20}{r_bar}"):
            res = future.result()
            if res: results.append(res)

    if use_api:
        unknowns = [r for r in results if r["Classification"] == "UNCATEGORIZED"]
        if unknowns:
            print(f"\n{Y}    [*] Phase 2: Processing {len(unknowns)} Unknown IPs via API...")
            with ThreadPoolExecutor(max_workers=20) as executor:
                list(tqdm(executor.map(lambda r: process_online(r, engine), unknowns), total=len(unknowns), desc="    API Processing", bar_format="{l_bar}{bar:20}{r_bar}"))

    with open(project_file, 'w', newline='', encoding='utf-8') as f:
        fields = ["Classification", "IP", "Target", "Verdict", "Matched_File", "Organization", "Country", "Timestamp"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)
    
    if use_api:
        with open(engine.cache_path, 'w', encoding='utf-8') as f: json.dump(engine.cache, f)

    print(f"\n{GL}    [✔] Success: Report Generated.")
    print(f"    {W}File: {project_file}")
    input(f"\n{Y}    [PRESS ENTER TO RETURN...]")

if __name__ == "__main__":
    while True:
        show_header()
        print(f"    {C}[1] {W}FAST ANALYSIS  {G}│ Local-only scan (Smart CSV/IPv6)")
        print(f"    {C}[2] {W}DEEP ANALYSIS  {G}│ Local scan + API for Unknown IPs")
        print(f"    {C}[3] {W}QUICK SEARCH   {G}│ Individual lookup & hierarchy check")
        print(f"    {C}[4] {W}STATISTICS     {G}│ Database health & rules count")
        print(f"    {C}[5] {W}REPOSITORIES   {G}│ Access projects & generated logs")
        print(f"    {C}[H] {Y}HELP SYSTEM    {G}│ Detailed guide for users")
        print(f"    {C}[0] {W}EXIT           {G}│ Securely terminate session")
        
        c = input(f"\n    Selection > ").upper()
        if c == "1": run_bulk_scan(use_api=False)
        elif c == "2": run_bulk_scan(use_api=True)
        elif c == "3":
            show_header()
            t = input(f"    Target > ").strip()
            e = IPAnalysisEngine(use_api=True)
            res = process_offline(t, e)
            if res:
                if res["Classification"] == "UNCATEGORIZED": res = process_online(res, e)
                print(f"\n    {G}IP: {W}{res['IP']}\n    {G}Verdict: {W}{res['Verdict']}\n    {G}File: {W}{res['Matched_File']}")
            input("\n    Enter...")
        elif c == "4":
            show_header()
            e = IPAnalysisEngine()
            print(f"\n    {C}DATABASE INTEGRITY REPORT\n    {G}─────────────────────────────────")
            print(f"    {W}Files: {GL}{e.stats['files']}\n    {W}IPv4:  {GL}{e.stats['rules']:,}\n    {W}IPv6:  {GL}{e.stats['ipv6_rules']:,}")
            input("\n    Enter...")
        elif c == "5": os.startfile(PATHS["projects"]) if os.name == 'nt' else print(PATHS["projects"])
        elif c == "H":
            show_header()
            print(f"    {Y}HELP GUIDE:\n    - Local scan runs first.\n    - Only Unknown IPs go to API.\n    - Supports IPv6 & CSV.")
            input("\n    Enter...")
        elif c == "0": break