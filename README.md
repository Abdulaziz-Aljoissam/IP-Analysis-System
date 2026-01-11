# IP ANALYSIS SYSTEM v2.0

<p align="center">
  <img width="1115" height="628" alt="Main Interface" src="https://github.com/user-attachments/assets/16317641-b747-4ff2-964f-1a760c08151a" />
</p>
 
**Author** : Abdulaziz Aljoissam

---

## 📝 Description

**IP Analysis System** is a professional pentest and SOC intelligence tool. The purpose of this project is to provide security researchers with a high-speed environment to analyze IP addresses against local databases and external threat intelligence. It is designed to handle thousands of IPs using multi-threaded processing, supporting both IPv4 and IPv6 protocols.

## ⚠️ Caution

This system is built for security analysis and pentest practice. Do not use this tool for unauthorized activities. The automatic cloud safe-guard is designed to prevent false positives against major providers like AWS, Google, and Azure, but users should always verify results manually before taking action. Use it at your own risk.

---

## 🚀 Available Modules

| Module Name | Type | Description |
| :--- | :--- | :--- |
| **FAST ANALYSIS** | Local | High-speed scan using local blacklists and whitelists only. |
| **DEEP ANALYSIS** | Hybrid | Full local scan combined with API lookups for unknown IPs. |
| **QUICK SEARCH** | Single | Instant individual lookup and hierarchy network check. |
| **STATISTICS** | Audit | Generates a health report of the database and rules count. |
| **REPOSITORIES** | Storage | Direct access to projects, generated reports, and logs. |

---

## ✨ Key Features

<p align="center">
  <img width="1293" height="398" alt="Features Overview" src="https://github.com/user-attachments/assets/02e516c1-cba8-449a-ab1f-3d73d3778b43" />
</p>

* **IPv6 Ready**: Full support for extracting and analyzing IPv6 addresses and networks.
* **Cloud Safe-Guard**: Automatic whitelisting for major providers like Google, AWS, Azure, and Cloudflare.
* **Multi-Threaded**: High-performance scanning with up to 60 parallel workers for local analysis.
* **Automatic Setup**: Self-configuring environment that builds the necessary folder structure on launch.
* **CIDR Support**: Advanced matching for network ranges using optimized first-octet indexing.

---

## 📂 Directory Structure

Upon the first run, the system automatically creates the following architecture:

```text
IP_Analysis_System/
├── IP_Blacklist/   # Drop your malicious IP .txt or .csv files here
├── IP_Whitelist/   # Drop your trusted IP/Cloud provider lists here
├── Projects/       # Final CSV reports are saved here
├── Logs/           # System activity logs
└── Core_Cache/     # API intelligence cache (intel_cache.json)
