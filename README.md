# 🔐 Wazuh Threat Detection & CTI Lab

## 📌 Project Overview
This project demonstrates how to build a **Threat Detection & Monitoring Lab** using **Wazuh SIEM**, Windows 11 endpoint, and ParrotOS attacker machine.  
The goal is to simulate attacks, integrate threat intelligence, and detect malicious activity in real time.

---

## ⚙️ Lab Architecture
- **Wazuh Manager (OVA)** – running on VMware
- **Windows 11 VM (Agent Installed)** – monitored endpoint
- **ParrotOS VM (Attacker Machine)** – used for brute force & malware simulation
- **Host Machine** – running Wazuh Dashboard

![Architecture](docs/architecture.png)

---

## 🔎 Use Cases Implemented

### 1. File Integrity Monitoring (FIM)
- Monitored `C:\Windows\System32\drivers\etc\hosts` on Windows 11
- Detected changes and generated alerts

![FIM Example](docs/fim-example.png)

---

### 2. Sysmon + Wazuh Integration
- Installed **Sysmon** on Windows
- Forwarded process creation & PowerShell logs to Wazuh
- Detected suspicious PowerShell execution

![Sysmon Alert](docs/sysmon-alert.png)

---

### 3. Threat Intelligence Integration
- Integrated **AlienVault OTX** with Wazuh
- Any connection to known malicious IP triggered alerts

![TI Example](docs/ti-integration.png)

---

### 4. Attack Simulation
- Used **Hydra** from ParrotOS to brute-force SSH login
- Wazuh generated **Brute Force Detection Alert**
- Tested with **EICAR test malware** for malware detection

![Brute Force Example](docs/brute-force.png)

---

## 📂 Repository Structure
```bash
wazuh-cti-lab/
│
├── docs/               # Screenshots & diagrams
├── wazuh-configs/      # Configurations & custom rules
└── reports/            # Final project report
