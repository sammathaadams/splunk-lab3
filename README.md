# Lab 3 — Splunk SIEM & Log Analysis

**Splunk Free · Azure VM · SOC Skills · Security Monitoring**

| Field | Value |
|---|---|
| Certification Alignment | CompTIA Security+ · CySA+ · Splunk Core Certified User |
| Tools Used | Splunk Enterprise (free) · Azure Ubuntu VM · Universal Forwarder |
| Time to Complete | 4–6 hours across multiple sessions |
| Estimated Cost | $0 — Splunk Free licence (500 MB/day) covers everything |
| Career Relevance | SOC Analyst (Tier 1–3) · Security Engineer · Incident Responder |

---

## The Business Problem This Lab Solves

A medium-sized organization generates millions of log events every day — Windows Event Logs from workstations, authentication logs from Active Directory, firewall logs from network equipment, and cloud resource logs. Without a SIEM, those logs sit in separate systems with no way to search across them, correlate events, or identify patterns that indicate an attack.

The SIEM is the SOC's primary tool. When an alert fires, the analyst opens the SIEM and searches logs to understand what happened, when, from where, and what was affected. Splunk is the most widely deployed commercial SIEM. Demonstrating hands-on Splunk experience in a lab environment is concrete, verifiable evidence of SOC readiness — this skill appears on job descriptions for almost every security operations role.

| Role | How This Lab Applies |
|---|---|
| SOC Analyst Tier 1 | Monitoring dashboards, searching logs for suspicious activity, escalating findings |
| SOC Analyst Tier 2–3 | Building detection rules, correlating events across data sources, threat hunting |
| Cloud Security Engineer | Microsoft Sentinel and AWS Security Hub use the same SIEM concepts — this lab teaches the mental model |
| Incident Responder | Searching logs during an active incident, building a timeline, identifying scope of compromise |

---

## Architecture

![Architecture Diagram](screenshots/architecture.svg)

This lab uses two Azure VMs in the same virtual network. The Windows Server DC01 from Lab 1 runs the Splunk Universal Forwarder, which ships Windows Event Logs to a second Ubuntu VM running Splunk Enterprise. Splunk indexes the logs into the `windows_logs` index, making them searchable through the web UI at port 8000.

**Data flow:** DC01 Windows Event Logs → Universal Forwarder (port 9997, encrypted) → Splunk Indexer (Ubuntu 22.04) → `windows_logs` index → SPL searches → Dashboards & Alerts

**DC01 Region:** US West 2 · **Architecture:** x64 · **Security:** Trusted Launch

### Infrastructure

| Component | Detail |
|---|---|
| Log Source | DC01 — Windows Server 2025 Datacenter x64 Gen2 (Lab 1 VM), Standard_D2s_v3 |
| Splunk VM | Ubuntu 22.04 LTS, Standard_B2s (2 vCPU · 4 GB RAM), 30 GB disk |
| Splunk Version | Enterprise 10.x — 60-day trial, then permanently free at 500 MB/day |
| NSG Rules | Port 22 (SSH) — your IP only · Port 8000 (Web UI) — your IP only · Port 9997 (forwarder) — VNet only |
| Resource Group | rg-lab03-0626 |

---

## Screenshots

> Add your screenshots here as you complete each step.

### Architecture Diagram
![Architecture](screenshots/architecture.svg)

### Splunk Web UI — Search & Reporting
![Splunk Search](screenshots/splunk-search-ui.png)

### Failed Logins Dashboard Panel (EventCode 4625)
![Failed Logins](screenshots/dashboard-failed-logins.png)

### Account Lockout Events (EventCode 4740)
![Account Lockouts](screenshots/dashboard-account-lockouts.png)

### Windows Security Overview Dashboard
![Dashboard](screenshots/dashboard-security-overview.png)

### Automated Alert — Brute Force Detection
![Alert Config](screenshots/alert-brute-force-config.png)

### Universal Forwarder Connected (Data Flowing)
![Forwarder Connected](screenshots/forwarder-data-flowing.png)

---

## Key Concepts

### What is a SIEM?
SIEM (Security Information and Event Management) collects log data from across your entire environment and makes it searchable in one place. Its two core jobs: (1) **correlation** — connecting events across systems to reveal patterns no single source would show, and (2) **alerting** — automatically notifying analysts when suspicious conditions are met.

### What is SPL?
Splunk Processing Language (SPL) is the query language used to ask Splunk questions. It works as a pipeline — start with a search, then pipe results through commands that filter, transform, and visualize data. Example:

```
index=windows_logs EventCode=4625 | stats count by Account_Name | sort -count
```

### What is a Splunk Index?
An index is a named storage bucket where events are kept. When logs arrive, they are stored in the specified index. This lab uses one index: `windows_logs`.

### What is the Universal Forwarder?
A lightweight agent installed on any machine whose logs you want to send to Splunk. It monitors Windows Event Logs, compresses and encrypts the data, and forwards it over port 9997. Designed to run invisibly in the background on production servers.

### Key Windows Event IDs

| Event Code | Meaning | SOC Significance |
|---|---|---|
| 4624 | Successful logon | Baseline for normal activity; look for off-hours or unusual logon types |
| 4625 | Failed logon | Spike for one account = brute force; spread across many accounts = password spray |
| 4740 | Account locked out | Trail of lockouts = password spray attack in progress |

---

## What You Will Build

- **Splunk Enterprise** deployed on Azure Ubuntu VM
- **Universal Forwarder** on DC01 (Lab 1 Windows Server) shipping Security/System/Application logs
- **`inputs.conf`** configuring which Windows Event Logs to collect
- **5 SPL searches** covering failed logins, successful logins, lockouts, threat hunting, and after-hours detection
- **"Windows Security Overview" dashboard** with 4 panels
- **Automated alert** — fires every 15 minutes when any account has >10 failed logins

---

## What Gets Installed Where

| Location | What | Why |
|---|---|---|
| **Your local machine** | Nothing (Splunk-related) | You access everything through your browser and PowerShell SSH |
| **Ubuntu VM** (new this lab) | Splunk Enterprise | This is the SIEM — logs are indexed, searched, and alerted here |
| **DC01 Windows Server VM** | Splunk Universal Forwarder only | Lightweight agent that ships Windows Event Logs to the Ubuntu VM |

---

## Step 0 — Deploy Both VMs with Azure CLI

> VMs are torn down after each lab. Run these commands to rebuild everything from scratch.

```powershell
# Set variables — edit before running
$RG       = "rg-lab03-0626"
$LOCATION = "westus2"
$VNET     = "splunk-lab3-vnet"
$SUBNET   = "lab3-subnet"
$ADMIN    = "labadmin"
$PASSWORD = "LabPass123!"   # change this

# Resource group + VNet
az group create --name $RG --location $LOCATION

az network vnet create `
  --resource-group $RG --name $VNET `
  --address-prefix 10.0.0.0/16 `
  --subnet-name $SUBNET --subnet-prefix 10.0.1.0/24
```

### Deploy DC01 (Windows Server 2025)

```powershell
# NSG — RDP from your IP only (replace YOUR_PUBLIC_IP)
az network nsg create --resource-group $RG --name dc01-nsg

az network nsg rule create --resource-group $RG --nsg-name dc01-nsg `
  --name Allow-RDP --priority 1000 --protocol Tcp `
  --destination-port-ranges 3389 `
  --source-address-prefixes YOUR_PUBLIC_IP --access Allow

# DC01 VM
az vm create `
  --resource-group $RG --name DC01 `
  --image Win2025Datacenter --size Standard_D2s_v3 `
  --vnet-name $VNET --subnet $SUBNET --nsg dc01-nsg `
  --admin-username $ADMIN --admin-password $PASSWORD `
  --location $LOCATION --security-type TrustedLaunch `
  --public-ip-sku Standard

# Save this private IP — needed for forwarder config
az vm list-ip-addresses --resource-group $RG --name DC01 `
  --query "[].virtualMachine.network.privateIpAddresses[0]" --output tsv
```

### Deploy Splunk VM (Ubuntu 22.04)

```powershell
# NSG — SSH and Splunk UI from your IP; port 9997 from VNet only
az network nsg create --resource-group $RG --name splunk-nsg

az network nsg rule create --resource-group $RG --nsg-name splunk-nsg `
  --name Allow-SSH --priority 1000 --protocol Tcp `
  --destination-port-ranges 22 --source-address-prefixes YOUR_PUBLIC_IP --access Allow

az network nsg rule create --resource-group $RG --nsg-name splunk-nsg `
  --name Allow-SplunkUI --priority 1010 --protocol Tcp `
  --destination-port-ranges 8000 --source-address-prefixes YOUR_PUBLIC_IP --access Allow

az network nsg rule create --resource-group $RG --nsg-name splunk-nsg `
  --name Allow-Forwarder-VNet --priority 1020 --protocol Tcp `
  --destination-port-ranges 9997 --source-address-prefixes 10.0.0.0/16 --access Allow

# Splunk Ubuntu VM
az vm create `
  --resource-group $RG --name splunk-vm `
  --image Ubuntu2204 --size Standard_B2s `
  --vnet-name $VNET --subnet $SUBNET --nsg splunk-nsg `
  --admin-username $ADMIN --admin-password $PASSWORD `
  --location $LOCATION --public-ip-sku Standard

# Save both IPs
az vm list-ip-addresses --resource-group $RG --name splunk-vm `
  --query "[].virtualMachine.network.{Public:publicIpAddresses[0].ipAddress,Private:privateIpAddresses[0]}" `
  --output table
```

> **Public IP** → browser (`http://<IP>:8000`) and PowerShell SSH SSH  
> **Private IP** → Universal Forwarder installer on DC01 (port 9997)

### Teardown when done

```powershell
az group delete --name $RG --yes --no-wait
```

---

## Step 1 — Get Splunk Free

1. Go to [splunk.com/en_us/download/splunk-enterprise.html](https://splunk.com/en_us/download/splunk-enterprise.html)
2. Create a free account using a temporary email from [temp-mail.org](https://temp-mail.org/en/)
3. Download **Splunk Enterprise for Linux** (.deb package)
4. Follow steps in Step 2 below to install

> **Important:** You want **Splunk Enterprise** — not Splunk Cloud (hosted SaaS) and not Splunk SOAR.

---

## Step 2 — Deploy Splunk on Azure Ubuntu VM

### Create the VM

| Setting | Value |
|---|---|
| OS | Ubuntu 22.04 LTS |
| Size | Standard_D2s_v3 (2 vCPU · 8 GiB RAM) |
| Disk | 30 GB |
| NSG Inbound Ports | 8000 (Web UI) · 9997 (forwarder input) · 22 (SSH) |

```bash
# SSH into your Ubuntu VM, then run:

# Download Splunk Enterprise (current version as of April 2026)
wget -O splunk-10.2.2-linux-amd64.deb \
  "https://download.splunk.com/products/splunk/releases/10.2.2/linux/splunk-10.2.2-80b90d638de6-linux-amd64.deb"

# NOTE: If this 404s, log into splunk.com → Free Trials and Downloads → Linux .deb
# and copy the wget command shown on the download page.

# Install
sudo dpkg -i splunk-10.2.2-linux-amd64.deb

# Start Splunk and set admin credentials when prompted
sudo /opt/splunk/bin/splunk start --accept-license

# Enable auto-start on reboot
sudo /opt/splunk/bin/splunk enable boot-start

# Access the web UI:
# http://<YOUR_VM_PUBLIC_IP>:8000
```

### Configure Receiving & Create Index

1. Log into the Splunk web UI at `http://<your-vm-ip>:8000`
2. **Settings → Forwarding and Receiving → Configure Receiving → New Receiving Port → `9997` → Save**
3. **Settings → Indexes → Create New Index → name it `windows_logs` → Save**

---

## Step 3 — Install Universal Forwarder on DC01

> Do this on your **Windows Server VM from Lab 1** — not on the Splunk Ubuntu VM.

1. On DC01, go to [splunk.com/en_us/download/universal-forwarder.html](https://splunk.com/en_us/download/universal-forwarder.html)
2. Download the **Windows 64-bit installer**
3. Run installer — when asked for Deployment Server: enter Splunk VM's **private IP** and port `8089`
4. When asked for Receiving Indexer: Splunk VM's **private IP** and port `9997`
5. Complete with default settings

### Configure inputs.conf

Create/edit this file on DC01:
`C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

See full file contents in [`scripts/inputs.conf`](scripts/inputs.conf).

```powershell
# Restart the forwarder to apply changes (run as Administrator on DC01)
Restart-Service SplunkForwarder
```

---

## Step 4 — Essential SPL Searches

See [`scripts/spl-searches.md`](scripts/spl-searches.md) for all searches with explanations.

| Search | Purpose |
|---|---|
| `index=windows_logs \| head 100` | Confirm data is flowing |
| `EventCode=4625 \| stats count by Account_Name` | Failed login attempts |
| `EventCode=4624 \| stats count by Account_Name, Logon_Type` | Successful logins by type |
| `EventCode=4740 \| table _time, Account_Name, Caller_Computer_Name` | Account lockouts |
| `EventCode=4625 earliest=-24h \| stats count as failures \| head 10` | Top 10 failed usernames |
| After-hours filter with `eval hour` | Logins outside 7am–7pm |

---

## Step 5 — Build the Security Dashboard

1. **Dashboards → Create New Dashboard**
2. Name: `Windows Security Overview` → Create Dashboard
3. Add 4 panels:

| Panel | SPL | Visualization |
|---|---|---|
| Failed Logins — Last 24h | EventCode=4625 · stats count by Account_Name | Bar chart |
| Account Lockouts — Last 7d | EventCode=4740 · table output | Events list |
| Login Activity Over Time | EventCode=4624 · timechart count | Line chart |
| Top Source IPs — After Hours | After-hours search · stats count by Workstation_Name | Column chart |

---

## Step 6 — Create an Automated Alert

Search to save as alert:
```
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625
| stats count as failures by Account_Name
| where failures > 10
```

Alert settings:
- **Name:** Potential Brute Force — High Failure Count
- **Type:** Scheduled
- **Schedule:** Every 15 minutes
- **Trigger:** Number of Results > 0
- **Action:** Add to Triggered Alerts

---

## Verification Checklist

| Check | How to Verify |
|---|---|
| Data flowing | `index=windows_logs \| head 10` returns recent events |
| Failed login search | EventCode=4625 search returns results (type wrong password on DC01 to generate events) |
| Dashboard populated | Windows Security Overview shows all 4 panels with data |
| Alert active | Settings → Searches, Reports, and Alerts → alert shows Enabled |

---

## Portfolio Notes

Take screenshots of:
- Your populated "Windows Security Overview" dashboard
- The alert configuration page
- An SPL search returning results (4625, 4624, 4740)
- The Universal Forwarder connected status in Splunk

These screenshots are direct evidence of SIEM hands-on experience for SOC Analyst and Security Engineer applications.

---

## Files in This Repo

```
splunk-lab3/
├── README.md                          ← this file
├── screenshots/
│   ├── architecture.svg               ← infrastructure diagram
│   ├── splunk-search-ui.png           ← add your screenshot
│   ├── dashboard-failed-logins.png    ← add your screenshot
│   ├── dashboard-account-lockouts.png ← add your screenshot
│   ├── dashboard-security-overview.png← add your screenshot
│   ├── alert-brute-force-config.png   ← add your screenshot
│   └── forwarder-data-flowing.png     ← add your screenshot
├── scripts/
│   ├── inputs.conf                    ← Universal Forwarder config
│   └── spl-searches.md               ← all SPL queries with explanations
└── splunk-siem-sop.txt               ← step-by-step runbook
```
