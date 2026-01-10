high-performance PowerShell-based security tool designed for the analysis and classification of IPv4 addresses. Developed by Abdulaziz Aljoissam, the system enables security professionals to process large IP lists by cross-referencing them against local intelligence and automated online databases.

The tool is specifically engineered for speed, utilizing a specialized Two-Stage Verification algorithm to handle datasets exceeding 600,000 records efficiently.

How It Works
The system follows a structured pipeline to classify IP addresses accurately:

Extraction: The tool reads input files such as logs, CSVs, or plain text and extracts valid IPv4 addresses.

Indexing: During the loading phase, it builds a prefix-based index to facilitate rapid searching.

Two-Stage Verification:

Stage 1 (Trigger): Performs a lightning-fast match using IP prefixes (e.g., /8, /16, /24) to identify a small group of potential candidates.

Stage 2 (Confirm): Conducts precise CIDR validation and bitwise matching only on the candidates identified in the first stage.

Auto-Classification: For addresses not found in local lists, the system can perform a WHOIS lookup via ip-api.com to classify them based on organization reputation or geographic risk.

Reporting: Results are organized into specific project folders containing detailed CSV files and a summary report.

Directory Structure
The system uses a organized folder hierarchy to manage data:

IP_Blacklist/: Store local threat intelligence and known malicious ranges here.

IP_Whitelist/: Store trusted sources, internal networks, or authorized IPs here.

Projects/: Automatically stores all analysis results and categorized reports.

Logs/: Contains technical logs for auditing the analysis process.

Building Your Rules
The tool's effectiveness depends on the intelligence files you provide in the IP_Blacklist/ and IP_Whitelist/ folders.

Format: You can use .txt or .csv files containing one IP per line or CIDR notation.

CIDR Notation: Using CIDR (e.g., 192.168.0.0/16) is highly recommended for large ranges as it maximizes the performance of the Two-Stage Verification logic.

No Spaces: Ensure CIDR notation is written without spaces (e.g., 10.0.0.0/8) to ensure proper parsing.

Quick Start
Run_Analyzer.bat: The easiest method to start the program; it handles execution policy bypass automatically.

Manual Start: Run .\IP_Analyzer.ps1 directly from a PowerShell terminal.

CLI Parameters: Use parameters for automation, such as .\IP_Analyzer.ps1 -InputFile "external_ips.txt" -ProjectName "SecurityAudit".