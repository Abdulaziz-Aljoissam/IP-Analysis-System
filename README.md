<img width="1115" height="628" alt="image" src="https://github.com/user-attachments/assets/16317641-b747-4ff2-964f-1a760c08151a" />

# IP ANALYSIS SYSTEM

Documentation : https://github.com/Abdulaziz-Aljoissam/IP_Analysis_System


---

## Description

IP Analysis System is a professional pentest and SOC intelligence tool. 
The purpose of this project is to provide security researchers with a high-speed environment to analyze IP addresses against local databases and external threat intelligence. It is designed to handle thousands of IPs using multi-threaded processing, supporting both IPv4 and IPv6 protocols.

## Caution

This system is built for security analysis and pentest practice. Do not use this tool for unauthorized activities. The automatic cloud safe-guard is designed to prevent false positives against major providers, but users should always verify results manually before taking action. Use it at your own risk.

---

## Licenses

This project uses an open-source framework. You can modify the code, add new threat feeds to the blacklist folders, or rebuild the local database as needed for your specific security requirements.

---

## Available Modules

| Module Name | Type | Description |
| :--- | :--- | :--- |
| FAST ANALYSIS | Local | High-speed scan using local blacklists and whitelists only. |
| DEEP ANALYSIS | Hybrid | Full local scan combined with API lookups for unknown IPs. |
| QUICK SEARCH | Single | Instant individual lookup and hierarchy network check. |
| STATISTICS | Audit | Generates a health report of the database and rules count. |
| REPOSITORIES | Storage | Direct access to projects, generated reports, and logs. |

---

## Key Features
<img width="1293" height="398" alt="image" src="https://github.com/user-attachments/assets/02e516c1-cba8-449a-ab1f-3d73d3778b43" />

* **IPv6 Ready**: Full support for extracting and analyzing IPv6 addresses and networks.
* **Cloud Safe-Guard**: Automatic whitelisting for major providers like AWS, Google, and Azure.
* **Multi-Threaded**: High-performance scanning with 60 parallel workers for local analysis.
* **Automatic Setup**: Self-configuring environment that builds the necessary folder structure on launch.
* **CIDR Support**: Advanced matching for network ranges using optimized first-octet indexing.

---

## Installation

1. **Clone the repository**:
   `git clone https://github.com/Abdulaziz-Aljoissam/IP_Analysis_System.git`

2. **Run the system**:
   `python ip_analyzer.py`

3. **Analyze**:
   Place your IP lists in the IP_Blacklist or IP_Whitelist folders and start the scan.

---

**Project by: Abdulaziz Aljoissam**
*IP-ANALYSIS-SYSTEM v2.0 - Security Intelligence Framework*
