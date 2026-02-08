# Cybersecurity Internship Projects - Raj Bharti

This repository contains four automated security tools developed to mitigate endpoint risks and enhance threat visibility.

## 📂 Project Overview

### 1. Secure File Transfer & DLP Toolkit
* **Goal:** Detect unauthorized movement of sensitive data.
* **Tech:** Python, Watchdog API, SHA-256 Hashing.
* **Key Feature:** Real-time file integrity monitoring and keyword-based DLP.

### 2. USB Device Control & Firewall
* **Goal:** Block unauthorized USB storage devices.
* **Tech:** Python, Pyudev (Linux).
* **Key Feature:** Automated port-blocking based on hardware serial number whitelisting.

### 3. Windows Registry HIDS
* **Goal:** Detect malware persistence in the Windows Registry.
* **Tech:** Python, Winreg.
* **Key Feature:** Monitors "Run" keys and alerts on unauthorized autostart changes.

### 4. Threat Intelligence Aggregator
* **Goal:** Automate the collection of malicious IOCs.
* **Tech:** Python, Requests, URLHaus API.
* **Key Feature:** Generates a standardized blocklist (CSV) for firewall integration.
