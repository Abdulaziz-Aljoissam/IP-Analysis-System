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
        
        # إحصائيات مفصلة
        self.stats = {
            "blacklist": {"rules": 0, "files": 0, "ipv6": 0},
            "whitelist": {"rules": 0, "files": 0, "ipv6": 0}
        }
        
        print(f"{Y}    [*] Loading Database Rules... (Please Wait)")
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
        ips_v4 = re.findall(ipv4_pattern, clean_text)
        
        ips_v6 = []
        potential_v6 = [word for word in clean_text.split() if ':' in word]
        for p in potential_v6:
            p_clean = p.strip("[](),'\"")
            try:
                ipaddress.ip_network(p_clean, strict=False)
                ips_v6.append(p_clean)
            except ValueError:
                continue
        return ips_v4, ips_v6

    def _load_database(self):
        for folder_type in ["blacklist", "whitelist"]:
            folder = PATHS[folder_type]
            if not os.path.exists(folder): continue
            
            files = os.listdir(folder)
            for file in files:
                file_path = os.path.join(folder, file)
                final_cat = folder_type
                
                # التحقق من كلمات الموفرين الآمنين في اسم الملف
                for provider in SAFE_PROVIDERS:
                    if provider in file.lower():
                        final_cat = "whitelist"
                        break
                
                self.stats[final_cat]["files"] += 1
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    v4_list, v6_list = self._extract_all_ips(content)
                    for item in v4_list:
                        self.stats[final_cat]["rules"] += 1
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
                        self.stats[final_cat]["ipv6"] += 1
                        try:
                            net = ipaddress.ip_network(item.strip(), strict=False)
                            self.cidr_v6_list[final_cat].append((net, file))
                        except: pass
                except Exception: pass

    def check_local(self, target_ip):
        try:
            ip_obj = ipaddress.ip_address(target_ip)
            is_v6 = (ip_obj.version == 6)
            cats = ["whitelist", "blacklist"]
            matches = []

            if not is_v6:
                for cat in cats:
                    if target_ip in self.singles[cat]:
                        matches.append({"cat": cat, "file": self.singles[cat][target_ip]})

                first_octet = target_ip.split('.')[0]
                for cat in cats:
                    if first_octet in self.cidr_v4_index[cat]:
                        for net, filename in self.cidr_v4_index[cat][first_octet]:
                            if ip_obj in net:
                                matches.append({"cat": cat, "file": filename})
            else:
                for cat in cats:
                    for net, filename in self.cidr_v6_list[cat]:
                        if ip_obj in net:
                            matches.append({"cat": cat, "file": filename})
            
            if not matches:
                return "Unknown", "", ""

            white_files = sorted(list(set(m['file'] for m in matches if m['cat'] == 'whitelist')))
            black_files = sorted(list(set(m['file'] for m in matches if m['cat'] == 'blacklist')))
            
            is_malicious = len(black_files) > 0
            final_verdict = "Malicious" if is_malicious else "Safe"
            if (len(white_files) + len(black_files)) > 1:
                final_verdict += " (Multi-Match)"
            
            return final_verdict, " | ".join(white_files), " | ".join(black_files)
        except: return "Error", "N/A", "N/A"

    def fetch_api(self, ip):
        if ip in self.cache: return self.cache[ip]
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,org", timeout=3)
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
    print(f"{G}    Status: Multi-Match | Split Columns | Enhanced Stats")
    print(f"{C}  {'─'*65}\n")

def process_offline(target, engine):
    try:
        clean_target = target.strip().replace('"', '').replace(',', '')
        ip = None
        try:
            ip_obj = ipaddress.ip_address(clean_target)
            ip = str(ip_obj)
        except ValueError:
            found = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', target)
            if found: ip = found[0]
        
        if not ip: return None

        verdict, white_matches, black_matches = engine.check_local(ip)
        sheet_cat = "UNCATEGORIZED"
        if "Malicious" in verdict: sheet_cat = "MALICIOUS_THREAT"
        elif "Safe" in verdict: sheet_cat = "SAFE_WHITELIST"

        return {
            "Classification": sheet_cat, "IP": ip, "Target": target.strip(),
            "Verdict": verdict, "Matched_Whitelist": white_matches, 
            "Matched_Blacklist": black_matches, "Organization": "Local DB", 
            "Country": "Local Match", "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
    if not os.path.exists(f_path): 
        print(f"    {R}Error: File Not Found!"); time.sleep(2); return

    p_name = input(f"    {C}Project Name > {W}").strip() or f"Scan_{datetime.now().strftime('%H%M%S')}"
    project_file = os.path.join(PATHS["projects"], f"{p_name}_Final_Report.csv")

    try:
        with open(f_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            targets = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)))
    except Exception as e:
        print(f"    {R}Error reading file: {e}"); return

    print(f"\n{Y}    [*] Phase 1: Offline Local Analysis...")
    engine = IPAnalysisEngine(use_api=use_api)
    results = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(process_offline, t, engine): t for t in targets}
        for future in tqdm(as_completed(futures), total=len(targets), desc="    Analyzing", bar_format="{l_bar}{bar:20}{r_bar}", colour='green'):
            res = future.result()
            if res: results.append(res)

    if use_api:
        unknowns = [r for r in results if r["Classification"] == "UNCATEGORIZED"]
        if unknowns:
            print(f"\n{Y}    [*] Phase 2: Online API Intelligence...")
            with ThreadPoolExecutor(max_workers=10) as executor:
                list(tqdm(executor.map(lambda r: process_online(r, engine), unknowns), total=len(unknowns), desc="    API Checking", bar_format="{l_bar}{bar:20}{r_bar}", colour='cyan'))

    try:
        with open(project_file, 'w', newline='', encoding='utf-8') as f:
            fields = ["Classification", "IP", "Target", "Verdict", "Matched_Whitelist", "Matched_Blacklist", "Organization", "Country", "Timestamp"]
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(results)
        if use_api:
            with open(engine.cache_path, 'w', encoding='utf-8') as f: json.dump(engine.cache, f)
        print(f"\n{GL}    [✔] Success: Report Generated.")
        print(f"    {W}Path: {project_file}")
    except PermissionError:
        print(f"\n{R}    [X] Error: Close the CSV file if it's open!")

    input(f"\n    [PRESS ENTER TO RETURN]")

if __name__ == "__main__":
    while True:
        show_header()
        print(f"    {C}[1] {W}FAST ANALYSIS  {G}│ Local Analysis (White vs Black)")
        print(f"    {C}[2] {W}DEEP ANALYSIS  {G}│ Local Analysis + Online API")
        print(f"    {C}[3] {W}QUICK SEARCH   {G}│ Single IP Lookup")
        print(f"    {C}[4] {W}STATISTICS     {G}│ Database Health Check")
        print(f"    {C}[5] {W}OPEN PROJECTS  {G}│ Access projects folder")
        print(f"    {C}[H] {Y}HELP SYSTEM    {G}│ User Instructions")
        print(f"    {C}[0] {W}EXIT           {G}│ Securely Terminate")
        
        c = input(f"\n    Selection > ").upper()
        if c == "1": run_bulk_scan(False)
        elif c == "2": run_bulk_scan(True)
        elif c == "3":
            show_header()
            t = input(f"    Target IP > ").strip()
            print(f"{Y}    Loading engine...")
            e = IPAnalysisEngine(use_api=True)
            res = process_offline(t, e)
            if res:
                if res["Classification"] == "UNCATEGORIZED": res = process_online(res, e)
                print(f"\n    {G}IP: {W}{res['IP']}\n    {G}Verdict: {W}{res['Verdict']}")
                print(f"    {G}Whitelist: {W}{res['Matched_Whitelist'] or 'None'}")
                print(f"    {G}Blacklist: {W}{res['Matched_Blacklist'] or 'None'}")
                print(f"    {G}Org: {W}{res['Organization']}")
            else:
                print(f"\n    {R}Invalid format.")
            input("\n    Enter...")
        elif c == "4":
            show_header()
            e = IPAnalysisEngine()
            print(f"\n    {C}DATABASE INTEGRITY REPORT")
            print(f"    {G}─────────────────────────────────────────")
            print(f"    {W}TOTAL BLACKLIST (Malicious):")
            print(f"    - Files: {R}{e.stats['blacklist']['files']}")
            print(f"    - IPv4:  {R}{e.stats['blacklist']['rules']:,}")
            print(f"    - IPv6:  {R}{e.stats['blacklist']['ipv6']:,}")
            print(f"\n    {W}TOTAL WHITELIST (Safe):")
            print(f"    - Files: {GL}{e.stats['whitelist']['files']}")
            print(f"    - IPv4:  {GL}{e.stats['whitelist']['rules']:,}")
            print(f"    - IPv6:  {GL}{e.stats['whitelist']['ipv6']:,}")
            print(f"    {G}─────────────────────────────────────────")
            input("\n    Enter...")
        elif c == "5": os.startfile(PATHS["projects"]) if os.name == 'nt' else print(PATHS["projects"])
        elif c == "H":
            show_header()
            print(f"    {Y}HELP GUIDE:")
            print(f"    - Data split into Matched_Whitelist & Matched_Blacklist columns.")
            print(f"    - Supports IPv6 without system freezing.")
            print(f"    - Multi-match detection identifies IPs in multiple sources.")
            input("\n    Enter...")
        elif c == "0": break
