# SOP — Lab 3: Splunk SIEM & Log Analysis

| Field | Value |
| :---- | :---- |
| **Author** | Sammatha Adams |
| **Lab Series** | Home Lab 5-Series — Lab 3 of 5 |
| **Environment** | macOS (local) · Azure (Ubuntu 22.04 VM · Windows Server VM — both deployed fresh in this lab) |
| **Certifications** | CompTIA Security+ · CySA+ · Splunk Core Certified User |
| **Date** | 2026-07-06 |

---

## PURPOSE

This lab deploys two Azure VMs from scratch — an Ubuntu VM running Splunk Enterprise as a SIEM (Security Information and Event Management) platform, and a Windows Server VM (`dc01`) that forwards its Windows Event Logs to Splunk. It demonstrates core SOC analyst skills: log ingestion, SPL searching, dashboard building, and automated alerting.

**Note on the Windows Server VM:** Earlier revisions of this SOP reused the Windows Server VM built in Lab 1\. That VM no longer exists, so this revision deploys a brand-new Windows Server VM as part of Section 2 below instead of assuming one is already running. If you want Active Directory Domain Services configured on this VM (as Lab 1 covered), follow the Lab 1 SOP separately — it is not required for the Splunk/log-forwarding work in this lab, since a plain Windows Server VM already generates the Security Event Log entries (successful/failed logons, lockouts) this lab searches on.

Completing this lab gives you demonstrable, hands-on Splunk experience that appears on job descriptions for SOC Analyst, Security Engineer, and Incident Responder roles.

---

## NOTE — What Gets Installed Where

This lab spans two machines. Do not confuse them.

| Machine | What you do here |
| :---- | :---- |
| **Your Mac (local)** | Run Azure CLI commands, SSH into the Ubuntu VM, RDP into the Windows Server VM, manage the Git repo |
| **Ubuntu VM (new — Splunk server)** | Install Splunk Enterprise, receive and index logs |
| **Windows Server VM (new — `dc01`)** | Install Splunk Universal Forwarder, configure inputs.conf, send logs |

---

## PREREQUISITES

Before starting, confirm you have:

- [ ] Azure CLI installed on your Mac (`az --version` should return output)  
- [ ] GitHub CLI installed on your Mac (`gh --version` should return output)  
- [ ] An active Azure subscription (`az account show --output table` returns the right one)  
- [ ] Splunk Enterprise downloaded for Linux (`.deb` file) — see Section 3 below  
- [ ] Your Mac Terminal open and ready

**Both VMs in this lab are created from scratch** — there is no dependency on any VM from a previous lab. If you also want Active Directory running on the Windows Server VM, complete the Lab 1 SOP against the new VM after this lab; it is a separate, optional step.

**Mac users:** You do not need PuTTY or any additional SSH tool. macOS has SSH built in. You will run all remote commands directly from your Terminal app. For the Windows Server VM, use Microsoft Remote Desktop (free on the Mac App Store) to RDP in.

---

## SECTION 0 — INSTALL PREREQUISITES (MAC)

All commands in this section run in Terminal on your local Mac. This is a one-time setup — once installed, these tools persist and you do not need to repeat this section for future labs in this series.

### 0.1 Verify what is already installed

Run these four checks first. If all four return version output without errors, skip straight to SECTION 1 — you are already set up.

git \--version az \--version gh \--version az account show \--output table

If any command returns "command not found" or an error, install that tool using the matching step below before continuing.

---

### 0.2 Install Homebrew — the Mac package manager

Homebrew is the standard package manager for macOS. It lets you install command-line tools (like Azure CLI and GitHub CLI) with a single command. Almost everything in this lab series installs through Homebrew.

**Check if it's already installed:**

brew \--version

If this returns a version (e.g., `Homebrew 4.x.x`), skip to 0.3.

**Install Homebrew:**

/bin/bash \-c "$(curl \-fsSL [https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh](https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh))"

**What this does:** Downloads and runs the official Homebrew installer script directly from GitHub. The script installs Homebrew to `/opt/homebrew/` on Apple Silicon Macs or `/usr/local/` on Intel Macs.

- `curl -fsSL` — downloads the script silently (`-s`), following redirects (`-L`), and failing on errors (`-f`)  
- The installer will ask for your Mac password and may prompt you to install Xcode Command Line Tools — accept both

**After installation**, if your terminal shows a message like "Add Homebrew to your PATH", run the two commands it provides (they start with `echo` and `source`). Then close and reopen Terminal.

**Verify:**

brew \--version

* Homebrew has no PowerShell/winget equivalent step in the Windows version of this SOP — it exists here because macOS does not ship with a package manager the way Windows ships with winget.

---

### 0.3 Install Git

Git is the version control system used to track your lab files and push them to GitHub. All git commands and the GitHub CLI depend on Git being installed first.

**Check if it's already installed:**

git \--version

If this returns a version (e.g., `git version 2.x.x`), skip to 0.4.

**Install Git:**

brew install git

**What this does:** Uses Homebrew to download and install Git. Homebrew handles the download, extraction, and PATH configuration automatically.

**Verify:**

git \--version

Expected output: `git version 2.x.x`

---

### 0.4 Install Azure CLI

The Azure CLI (`az`) lets you create and manage Azure resources directly from your Mac Terminal without clicking through the portal. The `az` command is used to deploy and manage every resource in this lab series — VMs, network ports, and resource groups — from the terminal.

**Check if it's already installed:**

az \--version

If this returns version info, skip to 0.5.

**Install Azure CLI:**

brew update && brew install azure-cli

**What this does:**

- `brew update` — refreshes Homebrew's list of available packages to make sure you get the latest version  
- `brew install azure-cli` — installs the `az` command-line tool

This takes 2–5 minutes. When it finishes, `az` is available in any new terminal window.

**Verify:**

az \--version

Expected output: `azure-cli x.x.x` on the first line with no errors.

---

### 0.5 Authenticate with Azure CLI

az login

**What this does:** Opens a browser window where you sign in with your Azure account credentials. Once authenticated, your terminal session is authorized to create and manage Azure resources. Your login session persists — you won't need to run this again unless the session expires (usually after a few hours or days).

Confirm the correct subscription is active:

az account show \--query "{Name:name, SubscriptionId:id, State:state}" \--output table

If you have multiple subscriptions and need to switch:

az account list \--output table az account set \--subscription ""

**Why check the subscription:** With multiple Azure accounts (personal, work, school), `az login` may default to the wrong one. Confirming the active subscription before deploying resources prevents VMs from being created in the wrong account — resources created in the wrong subscription are invisible from the right one and still incur charges.

---

### 0.6 Install GitHub CLI

The GitHub CLI (`gh`) lets you create GitHub repositories and manage your code directly from the terminal — no browser required. `gh repo create` in Section 1 creates the lab repo in a single command.

**Check if it's already installed:**

gh \--version

If this returns a version, skip to 0.7.

**Install GitHub CLI:**

brew install gh

**Verify:**

gh \--version

Expected output: `gh version x.x.x (YYYY-MM-DD)`

---

### 0.7 Authenticate with GitHub CLI

gh auth login

**What this does:** Walks you through an interactive setup:

1. Select **GitHub.com** (not GitHub Enterprise)  
2. Select **HTTPS** as the preferred protocol  
3. Select **Login with a web browser**  
4. Copy the one-time code shown in the terminal, press Enter — a browser window opens  
5. Paste the code on the GitHub device authorization page and click Authorize

Once complete, `gh` is authenticated and can create repos on your behalf. This login persists indefinitely until you explicitly log out.

**Verify:**

gh auth status

Should show `Logged in to github.com account YOUR_USERNAME (oauth_token)`.

---

### 0.8 Final verification

Run all four checks in one block to confirm the environment is ready:

brew \--version && git \--version && az \--version && gh \--version && az account show \--output table

All must return output without errors before proceeding to SECTION 1\.

---

## SECTION 1 — LOCAL REPOSITORY SETUP

**Why do this first?** Setting up your Git repo before any cloud work means every config file, script, and screenshot you create during the lab is version-controlled from the start. This is professional practice — it gives you a timestamped record of your work.

### 1.1 Create the project folder and initialize Git

Open Terminal on your Mac and run each command in order:

cd \~/Documents/Repos

**What this does:** Changes your working directory to your Repos folder — the folder you've been using for this lab series. All project files will live inside a subfolder here.

mkdir lab3-splunk-siem

**What this does:** Creates a new folder called `lab3-splunk-siem`. The name is descriptive and follows the same naming pattern as your previous labs. Consistent naming makes your portfolio easier to navigate.

cd lab3-splunk-siem

**What this does:** Moves you into the folder you just created. Every command from here on runs inside this project folder.

git init

**What this does:** Initializes an empty Git repository in the current folder. Git will now track every change you make to files in this folder. You'll see a message like `Initialized empty Git repository in .../lab3-splunk-siem/.git/`.

### 1.2 Create the project scaffold

echo "\# Lab 3 — Splunk SIEM & Log Analysis" \> README.md

mkdir scripts screenshots

**What this does:** Creates a `README.md` file with a title heading, and two folders — `scripts` (for any PowerShell or bash scripts from this lab) and `screenshots` (for your portfolio screenshots). The `echo` command writes the text directly into the file without opening an editor.

git add .

**What this does:** Stages all new files for your first commit. The `.` means "everything in the current directory." Git is now tracking README.md and the two folders.

git commit \-m "initial commit: lab3-splunk-siem project structure"

**What this does:** Creates your first commit — a permanent snapshot of the project structure. The `-m` flag lets you write the commit message inline. Commit messages are written in the imperative tense ("add", "create", "fix") and describe what was done.

### 1.3 Create the GitHub repository and push

gh repo create lab3-splunk-siem \--public \--source=. \--remote=origin \--push

**What this does — broken down:**

- `gh repo create lab3-splunk-siem` — creates a new repository on GitHub.com named `lab3-splunk-siem`  
- `--public` — makes it publicly visible (important for your portfolio — recruiters need to see it)  
- `--source=.` — tells GitHub CLI that the current folder is the source  
- `--remote=origin` — sets up a remote connection named `origin` pointing to the new GitHub repo  
- `--push` — immediately pushes your initial commit to GitHub

After this runs, your repo is live on GitHub. You can visit `github.com/YOUR_USERNAME/lab3-splunk-siem` to confirm.

---

## SECTION 2 — DEPLOY BOTH VMs IN AZURE

Since the Windows Server VM from Lab 1 no longer exists, this lab deploys **both** VMs it needs — the Splunk Ubuntu VM and a Windows Server VM (`dc01`) — from scratch. Both VMs are placed in the same Virtual Network (VNet) so they can communicate privately over port 9997 without exposing that traffic to the internet. Each VM gets its own Network Security Group (NSG) — a firewall — locked down so only your IP can RDP into `dc01`, only your IP can SSH or reach the Splunk UI, and only other VMs inside the VNet can send log data to Splunk on port 9997\.

### 2.1 Log in to Azure from your Mac Terminal

az login

**What this does:** Opens a browser window where you authenticate with your Azure account. Once authenticated, your terminal session is authorized to create and manage Azure resources. If you already authenticated in Section 0.5, this completes immediately.

### 2.2 Set variables for this lab

Run all commands in this section from the same Terminal tab. Set these variables once — every command below references them.

export RG="rg-splunk-lab3" export LOCATION="eastus" export VNET="splunk-lab3-vnet" export SUBNET="lab3-subnet" export ADMIN="azureuser" export PASSWORD="YourStrongPassword123\!"

**Change `PASSWORD`** to a real strong password before running anything — Azure requires 12+ characters with uppercase, lowercase, a number, and a symbol.

**IMPORTANT:** Exported variables only exist in the Terminal tab/session where you set them. If you close Terminal or open a new tab, re-run this block before continuing — otherwise the commands below will run with blank values and your VMs will be created with empty or wrong settings.

If SSH or RDP ever fails with "Permission denied" after deployment, you can reset the password with:

az vm user update \--resource-group $RG \--name splunk-vm \--username $ADMIN \--password $PASSWORD

(swap `splunk-vm` for `dc01` to reset the other VM's password)

### 2.3 Create the resource group and virtual network

az group create   
\--name $RG   
\--location $LOCATION

**What this does:** Creates a logical container in Azure called a resource group named `rg-splunk-lab3`. All resources you create for this lab (both VMs, NSGs, the VNet, disks, public IPs) go inside this group. Keeping Lab 3 resources in their own group makes cleanup easy — you delete the group and everything inside it disappears.

az network vnet create   
\--resource-group $RG   
\--name $VNET   
\--address-prefix 10.0.0.0/16   
\--subnet-name $SUBNET   
\--subnet-prefix 10.0.1.0/24

**What this does:** A Virtual Network (VNet) is a private network in Azure. VMs inside the same VNet can reach each other using private IP addresses without going through the public internet — this is how `dc01` will send logs to the Splunk VM securely.

- `--address-prefix 10.0.0.0/16` — reserves the 10.0.0.0/16 address space (65,536 IPs) for the VNet. Both VMs get private IPs from this range.  
- `--subnet-prefix 10.0.1.0/24` — carves a /24 subnet (256 IPs) from the VNet for the VMs to sit in.

### 2.4 Get your public IP

The NSG rules below restrict SSH, RDP, and the Splunk Web UI to your own IP address only. Look it up and save it as a variable:

export MY\_IP=$(curl \-s [https://ifconfig.me](https://ifconfig.me)) echo $MY\_IP

**What this does:** `curl -s https://ifconfig.me` asks a public service what IP address your request came from, and saves it to `MY_IP`. Confirm the `echo` prints a real IPv4 address before continuing. If your home or coffee-shop IP changes later (common on many ISPs), the NSG rules below will need updating — see the Troubleshooting section.

### 2.5 Deploy `dc01` — Windows Server VM

**Create the NSG and RDP rule:**

az network nsg create   
\--resource-group $RG   
\--name dc01-nsg

az network nsg rule create   
\--resource-group $RG   
\--nsg-name dc01-nsg   
\--name Allow-RDP   
\--priority 1000   
\--protocol Tcp   
\--destination-port-ranges 3389   
\--source-address-prefixes $MY\_IP   
\--access Allow

**What this does:** Port 3389 is the RDP port. Restricting the source to your IP only means that even if someone scans the internet for open RDP ports, they cannot connect — only requests from your specific IP are allowed through the NSG.

**Deploy the VM:**

az vm create   
\--resource-group $RG   
\--name dc01   
\--image Win2022Datacenter   
\--size Standard\_D2s\_v3   
\--vnet-name $VNET   
\--subnet $SUBNET   
\--nsg dc01-nsg   
\--admin-username $ADMIN   
\--admin-password $PASSWORD   
\--public-ip-sku Standard

**What each flag does:**

- `--name dc01` — the name of the VM inside Azure. This is the log source for the lab — its Security Event Log records logons, logon failures, and lockouts.  
- `--image Win2022Datacenter` — Windows Server 2022 Datacenter  
- `--size Standard_D2s_v3` — 2 vCPUs and 8GB RAM, enough headroom to run the Universal Forwarder alongside normal Windows Server services  
- `--vnet-name` / `--subnet` / `--nsg` — places `dc01` inside the VNet you created in 2.3, protected by the `dc01-nsg` firewall rules from this step  
- `--admin-username` / `--admin-password` — the Windows login you'll use to RDP in  
- `--public-ip-sku Standard` — assigns a static public IP so you can always reach the VM

**Get `dc01`'s IPs** — save both, you'll need them later:

az vm show \-d \-g $RG \-n dc01 \--query publicIps \-o tsv

az vm list-ip-addresses \-g $RG \-n dc01 \--query "\[\].virtualMachine.network.privateIpAddresses\[0\]" \-o tsv

The public IP is what you RDP to from your Mac in Section 5\. The private IP is only needed if you ever want to reference `dc01` from the Splunk VM's side.

### 2.6 Deploy the Splunk Ubuntu VM

**Create the NSG and rules:**

az network nsg create   
\--resource-group $RG   
\--name splunk-nsg

# Port 22 — SSH from your IP only

az network nsg rule create   
\--resource-group $RG   
\--nsg-name splunk-nsg   
\--name Allow-SSH   
\--priority 1000   
\--protocol Tcp   
\--destination-port-ranges 22   
\--source-address-prefixes $MY\_IP   
\--access Allow

# Port 8000 — Splunk Web UI from your IP only

az network nsg rule create   
\--resource-group $RG   
\--nsg-name splunk-nsg   
\--name Allow-SplunkUI   
\--priority 1010   
\--protocol Tcp   
\--destination-port-ranges 8000   
\--source-address-prefixes $MY\_IP   
\--access Allow

# Port 9997 — forwarder input from the VNet only (NEVER open to the internet)

az network nsg rule create   
\--resource-group $RG   
\--nsg-name splunk-nsg   
\--name Allow-SplunkForwarder-VNet   
\--priority 1020   
\--protocol Tcp   
\--destination-port-ranges 9997   
\--source-address-prefixes 10.0.0.0/16   
\--access Allow

**What each rule does:**

- **Allow-SSH (22):** SSH is how you connect to and control the Ubuntu VM from your Mac. Restricting it to your IP prevents brute-force SSH attempts from the internet — a common attack vector on cloud VMs.  
- **Allow-SplunkUI (8000):** This is where the Splunk web interface runs — you open it in your browser to search logs, build dashboards, and configure alerts. Restricting to your IP keeps the dashboard from being publicly reachable.  
- **Allow-SplunkForwarder-VNet (9997):** This is the port Splunk listens on for incoming log data. Restricting it to `10.0.0.0/16` (the VNet CIDR) means only other VMs inside this VNet — i.e., `dc01` — can send data to Splunk. If this port were open to `0.0.0.0/0`, anyone on the internet could flood your Splunk instance with junk data and exhaust the 500MB/day free licence.

**Deploy the VM:**

az vm create   
\--resource-group $RG   
\--name splunk-vm   
\--image Ubuntu2204   
\--size Standard\_B2s   
\--vnet-name $VNET   
\--subnet $SUBNET   
\--nsg splunk-nsg   
\--admin-username $ADMIN   
\--authentication-type password   
\--admin-password $PASSWORD   
\--public-ip-sku Standard

**What each flag does:**

- `--name splunk-vm` — the name of your VM inside Azure  
- `--image Ubuntu2204` — Ubuntu 22.04 LTS, the OS Splunk officially supports on Linux  
- `--size Standard_B2s` — 2 vCPUs and 4GB RAM. Splunk requires **at least 4GB RAM** — do not go smaller  
- `--vnet-name` / `--subnet` / `--nsg` — places the VM inside the same VNet as `dc01`, protected by the `splunk-nsg` rules from this step  
- `--admin-username` — the Linux username you'll use to log in via SSH  
- `--authentication-type password` — use password auth (simpler for a lab environment)  
- `--public-ip-sku Standard` — assigns a static public IP address so you can always reach the VM

**Get `splunk-vm`'s IPs:**

az vm show \-d \-g $RG \-n splunk-vm \--query publicIps \-o tsv

az vm list-ip-addresses \-g $RG \-n splunk-vm \--query "\[\].virtualMachine.network.privateIpAddresses\[0\]" \-o tsv

- **Public IP** → your browser: `http://<PUBLIC_IP>:8000`; your Mac's SSH: `ssh azureuser@<PUBLIC_IP>`  
- **Private IP** → the Universal Forwarder installer on `dc01` uses this in Section 5 to know where to send logs (port 9997\)

### 2.7 Verify both VMs are running

az vm list \-g $RG \--show-details \--query "\[\].{Name:name, State:powerState, IP:publicIps}" \--output table

Expected output shows both `dc01` and `splunk-vm` with state `VM running` and their public IPs.

---

## SECTION 3 — GET SPLUNK ENTERPRISE

Splunk Enterprise is free. You get a 60-day full-featured trial, after which it automatically converts to the free licence, which allows 500MB of data indexing per day — more than enough for a home lab.

**Important:** You want **Splunk Enterprise** (the on-premises version you install yourself). Do not download Splunk Cloud (a hosted SaaS product) or Splunk SOAR (a different product entirely).

### 3.1 Create a Splunk account using a temporary email

Splunk requires a free account before you can download. Use a temporary email — you don't need to give real personal details.

1. Open your browser and go to [**https://temp-mail.org/en/**](https://temp-mail.org/en/)  
     
   - A temporary email address is automatically generated when the page loads. No sign-up needed.  
   - Copy the email address shown on screen.

   

2. In a new tab, go to: [**https://splunk.com/en\_us/download/splunk-enterprise.html**](https://splunk.com/en_us/download/splunk-enterprise.html)  
     
3. Fill in the registration form:  
     
   - **Email:** paste the temp-mail address  
   - **First Name / Last Name:** any dummy values (e.g., John Smith)  
   - **Company:** Home Lab  
   - **Job Title:** Student  
   - **Phone:** 555-0100  
   - These fields are not verified.

   

4. Go back to the temp-mail.org tab — a confirmation email from Splunk will appear within a minute. Click the confirmation link.  
     
5. You are now logged in. Select **Linux → .deb (64-bit)** and download the file.

**Note on the download URL:** Splunk updates the download URL with every new release. The current version as of this writing is 10.2.2. If any `wget` command in this SOP returns a 404 error, log into splunk.com, go to Free Trials and Downloads → Splunk Enterprise → Linux .deb, and copy the fresh `wget` command from that page.

---

## SECTION 4 — INSTALL SPLUNK ON THE UBUNTU VM

### 4.1 SSH into the Ubuntu VM from your Mac

ssh azureuser@YOUR\_SPLUNK\_VM\_PUBLIC\_IP

**What this does:** Opens an encrypted SSH (Secure Shell) connection from your Mac Terminal to the Ubuntu VM running in Azure. Replace `YOUR_SPLUNK_VM_PUBLIC_IP` with the IP you copied in Section 2.5.

- The first time you connect, you'll see a message asking you to confirm the server's fingerprint. Type `yes` and press Enter — this saves the server identity so you're not asked again.  
- Type your password when prompted. **Nothing will appear on screen as you type** — no dots, no asterisks. This is normal Linux behavior. Type your password and press Enter anyway.

Once connected, your terminal prompt changes to show `azureuser@splunk-vm:~$` — you are now running commands on the remote Ubuntu VM, not your Mac.

### 4.2 Download Splunk Enterprise onto the Ubuntu VM

Run these commands inside your SSH session (on the Ubuntu VM):

wget \-O splunk-10.2.2-linux-amd64.deb \\

"[https://download.splunk.com/products/splunk/releases/10.2.2/linux/splunk-10.2.2-80b90d638de6-linux-amd64.deb](https://download.splunk.com/products/splunk/releases/10.2.2/linux/splunk-10.2.2-80b90d638de6-linux-amd64.deb)"

**What this does:**

- `wget` is a Linux command-line tool for downloading files from the internet  
- `-O splunk-10.2.2-linux-amd64.deb` — the `-O` flag names the output file. Without this, wget uses the filename from the URL, which may be unwieldy  
- The URL in quotes is the direct download link for Splunk Enterprise 10.2.2 for Linux

You'll see a progress bar. The file is about 300MB — it takes a minute or two depending on Azure's bandwidth.

**If you get a 404 error:** The URL has changed because Splunk released a new version. Log into splunk.com → Free Trials and Downloads → Splunk Enterprise → Linux .deb → copy the wget command shown on screen.

### 4.3 Install Splunk

sudo dpkg \-i splunk-10.2.2-linux-amd64.deb

**What this does:**

- `sudo` — runs the command with administrator (root) privileges. Installing software on Linux requires root.  
- `dpkg` — the Debian/Ubuntu package manager. It installs `.deb` packages (similar to `.pkg` files on Mac).  
- `-i` — the install flag  
- The filename at the end is the file you just downloaded

Splunk installs to `/opt/splunk/`. You'll see output listing files being unpacked. This takes about 30 seconds.

### 4.4 Start Splunk and accept the licence

sudo /opt/splunk/bin/splunk start \--accept-license \--answer-yes \--run-as-root

**What this does:**

- `/opt/splunk/bin/splunk` — this is the Splunk binary (the program itself). It lives at this path after installation.  
- `start` — tells Splunk to start up  
- `--accept-license` — automatically accepts the Splunk licence agreement, skipping the interactive prompt  
- `--answer-yes` — answers yes to all remaining prompts automatically  
- `--run-as-root` — **required in Splunk 9.x and later** when starting via `sudo`. Without this flag, Splunk will silently fail to start and report `splunkd is not running` even though the command appeared to complete successfully.

**Credential behaviour:** Splunk may prompt you to create an admin username and password during this command, during the `enable boot-start` command in Step 4.5, or not at all from the terminal (this varies by version). Wherever the prompt appears, set your Splunk admin username and password and write them down — they are your Splunk login credentials, completely separate from your Ubuntu VM login. If no terminal prompt appears at either step, credentials are set via the web UI on first login (see Step 4.6).

Splunk takes 30–60 seconds to fully start. When you see `Splunk is now available at http://splunk-vm:8000`, the server is ready.

### 4.5 Enable Splunk to auto-start on reboot

sudo /opt/splunk/bin/splunk enable boot-start

**What this does:** Registers Splunk as a system service so it starts automatically if the VM ever reboots. Without this, you'd have to manually SSH in and start Splunk every time the VM restarts. The command creates a systemd service entry for Splunk.

**Note:** If you were not prompted to set admin credentials in Step 4.4, the prompt may appear here instead — this is normal. Set your credentials if prompted.

### 4.6 Open the Splunk Web UI and set admin credentials

Leave your SSH terminal open. On your Mac, open a browser and navigate to:

http://YOUR\_SPLUNK\_VM\_PUBLIC\_IP:8000

What you see depends on your Splunk version:

- **First-run setup page:** Create your admin username and password here. Save these — they are your Splunk credentials for all future logins.  
- **Login page directly:** Use `admin` / `changeme` (Splunk's built-in default). Splunk will immediately prompt you to change the password. Do so.

If neither works, reset the admin password from your SSH session:

sudo /opt/splunk/bin/splunk edit user admin \-password 'SplunkAdmin123\!' \-auth admin:changeme

**Splunk credentials are completely separate from your Ubuntu VM credentials.** The Linux password (`azureuser` / whatever you set in Section 2.5) is for SSH only. The Splunk admin password is for the web UI and Splunk CLI only. If the page doesn't load at all, wait another 30 seconds — Splunk can take a moment to fully initialize.

### 4.7 Configure Splunk to receive data (in the Web UI)

You must tell Splunk to listen on port 9997 before the forwarder can connect.

1. In the Splunk Web UI, click **Settings** (top navigation bar)  
2. Click **Forwarding and Receiving**  
3. Under "Receive Data", click **Configure Receiving**  
4. Click **New Receiving Port**  
5. Enter **9997** → click **Save**

**Why port 9997?** This is Splunk's default forwarder-to-indexer port. Every Universal Forwarder in the world defaults to sending on 9997\. By opening this receiving port, Splunk is now listening for incoming log data on that port.

### 4.8 Create the windows\_logs index (in the Web UI)

An index is Splunk's named storage bucket — like a database table for your logs. Creating a dedicated index for Windows logs keeps them separate from other data sources you might add later.

1. Click **Settings → Indexes**  
2. Click **New Index**  
3. Set **Index Name** to `windows_logs`  
4. Leave all other settings at defaults  
5. Click **Save**

**Why a separate index?** When you search, you specify `index=windows_logs` to search only Windows data. If all your logs went into the default index, searches would be slower and harder to scope. Separate indexes also let you set different retention periods per data source.

### 4.9 Close the SSH session

You are done with the Ubuntu VM for now. Close the SSH session:

exit

**What this does:** All remaining steps (Section 5 onward) are performed on `dc01` via RDP, not on the Ubuntu VM. You can always SSH back in later if needed.

---

## SECTION 5 — CONFIGURE THE UNIVERSAL FORWARDER ON DC01

**Switch to your `dc01` Windows Server VM now.** Everything in this section happens on `dc01`, not the Ubuntu Splunk VM. RDP into it from your Mac using Microsoft Remote Desktop (free on the Mac App Store) and the public IP you saved in Section 2.3.

### 5.1 Install the Universal Forwarder on `dc01`

On your Windows Server VM:

1. Open a browser and go to: `https://splunk.com/en_us/download/universal-forwarder.html`  
2. Download the **Windows 64-bit** installer (`.msi` file)  
3. Run the installer  
   - When asked for a **Deployment Server**: enter your Splunk VM's **private IP address** (the 10.x.x.x address from your Azure VNet) and port **8089**  
   - When asked for a **Receiving Indexer**: enter your Splunk VM's **private IP address** and port **9997**  
   - Complete the installation with default settings

**Why the private IP and not the public IP?** Both your VMs are in the same Azure Virtual Network (VNet) since they were created in the same resource group. Traffic between them stays on Azure's internal network — it's faster and doesn't cost egress fees. The private IP is shown in the Azure portal under your Splunk VM's "Overview" → "Private IP address", or from the `az vm list-ip-addresses` command in Section 2.5.

**What is a Deployment Server?** The Deployment Server (port 8089\) is a Splunk management port that lets you remotely push configuration updates to forwarders. You're pointing the forwarder at your Splunk instance so it can receive those updates centrally.

### 5.2 Configure inputs.conf — tell the forwarder what to collect

`inputs.conf` is a text configuration file that tells the Universal Forwarder exactly which Windows Event Logs to collect and forward. You create or edit this file on `dc01`.

On `dc01`, open Notepad **as Administrator** (right-click Notepad → Run as Administrator) and create this file:

**File path:** `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

**Why Notepad as Administrator?** The `C:\Program Files\` directory is protected. Without admin rights, Notepad will silently fail to save the file there.

**If the `local` folder doesn't exist:** Create it manually — right-click inside the `system` folder → New → Folder → name it `local`.

\[WinEventLog://Security\]

disabled \= 0

start\_from \= oldest

current\_only \= 0

evt\_resolve\_ad\_obj \= 1

\[WinEventLog://System\]

disabled \= 0

\[WinEventLog://Application\]

disabled \= 0

**Line-by-line explanation:**

| Line | What it does |
| :---- | :---- |
| `[WinEventLog://Security]` | Defines a data input source — the Windows Security Event Log. The bracket format is Splunk's stanza syntax. |
| `disabled = 0` | `0` means **enabled** (active). Setting this to `1` would turn off this log source without deleting the config. |
| `start_from = oldest` | Collect historical events from the beginning of the log, not just new events going forward. You want historical data for your searches. |
| `current_only = 0` | Paired with `start_from = oldest` — confirms you want both old and new events. |
| `evt_resolve_ad_obj = 1` | Resolve Active Directory objects — this makes usernames appear as readable names (e.g., `jsmith`) instead of cryptic Security Identifiers (SIDs like `S-1-5-21-...`). |
| `[WinEventLog://System]` | Collect the Windows System log (OS-level events: service starts/stops, driver failures, hardware issues). |
| `[WinEventLog://Application]` | Collect the Windows Application log (events from installed applications). |

### 5.3 Restart the Universal Forwarder to apply inputs.conf

On `dc01`, open **PowerShell as Administrator** and run:

Restart-Service SplunkForwarder

**What this does:** Stops and restarts the SplunkForwarder Windows service. The forwarder reads `inputs.conf` at startup — restarting it applies your new configuration. Without this restart, the forwarder won't know to collect the logs you just configured.

You won't see any output on success. To confirm it's running:

Get-Service SplunkForwarder

The Status column should show `Running`. Give it 1–2 minutes after the restart before searching in Splunk — there is a brief delay while the first batch of events is transmitted and indexed.

---

## SECTION 6 — ESSENTIAL SPL SEARCHES

Switch back to your Mac. All searches are typed into the search bar in the **Search & Reporting** app in the Splunk Web UI (`http://YOUR_SPLUNK_VM_IP:8000`). Set the time range using the time picker on the right side of the search bar.

**SPL pipeline pattern:** Every SPL search works as a pipeline. You start by finding events, then pipe (`|`) the results through commands that filter, reshape, or visualize the data. Read it left to right: "find these events, then do this, then do that."

### 6.1 Confirm data is flowing

index=windows\_logs | head 100

| Part | What it does |
| :---- | :---- |
| `index=windows_logs` | Search only inside the `windows_logs` index you created. Always specify the index — it makes searches faster and more precise. |
| \` | head 100\` |

**If this returns results:** Your forwarder is working. You'll see Windows Event Log entries with timestamps, event codes, and source machine info.

**If this returns nothing:** Check that the SplunkForwarder service is running on `dc01` (`Get-Service SplunkForwarder`). Also verify the private IP and port 9997 are correct in the forwarder's configuration.

### 6.2 Find failed login attempts — EventCode 4625

index=windows\_logs sourcetype=WinEventLog:Security EventCode=4625

| stats count by Account\_Name, Workstation\_Name

| sort \-count

| Part | What it does |
| :---- | :---- |
| `sourcetype=WinEventLog:Security` | Filter to only the Security Event Log (vs System or Application logs that are also in this index). |
| `EventCode=4625` | Filter to only failed logon events. EventCode 4625 \= "An account failed to log on." |
| \` | stats count by Account\_Name, Workstation\_Name\` |
| \` | sort \-count\` |

**What to look for:** A single account with 5+ failures in a short time window is a possible brute force attack. Multiple accounts each with 1–2 failures could indicate a password spray attack (an attacker trying one password against many accounts).

### 6.3 Find successful logins — EventCode 4624

index=windows\_logs sourcetype=WinEventLog:Security EventCode=4624

| stats count by Account\_Name, Logon\_Type

| sort \-count

| Part | What it does |
| :---- | :---- |
| `EventCode=4624` | Filter to successful logon events. "An account was successfully logged on." |
| \` | stats count by Account\_Name, Logon\_Type\` |

**Logon Type reference:**

| Logon\_Type | Meaning | Normal? |
| :---- | :---- | :---- |
| 2 | Interactive (physically at the keyboard) | Yes |
| 3 | Network (accessing a file share, network resource) | Yes |
| 5 | Service account (automated, background process) | Yes — usually |
| 10 | Remote Interactive (RDP session) | Investigate if unexpected |

### 6.4 Find account lockouts — EventCode 4740

index=windows\_logs sourcetype=WinEventLog:Security EventCode=4740

| table \_time, Account\_Name, Caller\_Computer\_Name

| sort \-\_time

| Part | What it does |
| :---- | :---- |
| `EventCode=4740` | Filter to account lockout events — triggered when an account hits the lockout threshold (e.g., 5 failed attempts). |
| \` | table \_time, Account\_Name, Caller\_Computer\_Name\` |
| \` | sort \-\_time\` |

**What to look for:** Multiple lockouts for the same account in rapid succession \= likely brute force. Lockouts spread across multiple different accounts in a short window \= possible password spray attack.

### 6.5 Top 10 failed login usernames — threat hunting

index=windows\_logs sourcetype=WinEventLog:Security EventCode=4625 earliest=-24h

| stats count as failures by Account\_Name

| sort \-failures

| head 10

| Part | What it does |
| :---- | :---- |
| `earliest=-24h` | Restrict the search to only the last 24 hours. Splunk time modifiers use `-Nh` (hours), `-Nd` (days), `-Nw` (weeks). |
| `count as failures` | The `as failures` renames the count column to `failures` instead of the generic word `count` — makes the output easier to read. |
| \` | head 10\` |

**Thresholds to know:** 20+ failures for one account in 24 hours warrants investigation. Usernames that don't exist in Active Directory indicate an **account enumeration attack** — the attacker is guessing usernames.

### 6.6 Detect after-hours logins

index=windows\_logs sourcetype=WinEventLog:Security EventCode=4624

| eval hour=strftime(\_time, "%H")

| where hour \< 7 OR hour \> 19

| table \_time, Account\_Name, Workstation\_Name, Logon\_Type

| sort \-\_time

| Part | What it does |
| :---- | :---- |
| \` | eval hour=strftime(\_time, "%H")\` |
| \` | where hour \< 7 OR hour \> 19\` |
| \` | table ...\` |

**What to look for:** After-hours Logon\_Type 5 (service accounts) \= normal and expected. After-hours Logon\_Type 2 or 10 (interactive or RDP) from regular user accounts \= warrants a closer look.

---

## SECTION 7 — BUILD A SECURITY DASHBOARD

Dashboards save your searches as permanent panels that refresh automatically. Instead of running searches manually each shift, a SOC analyst opens the dashboard and sees current status at a glance.

1. In Splunk, click **Dashboards** in the top navigation  
2. Click **Create New Dashboard**  
3. Name it: `Windows Security Overview`  
4. Click **Create Dashboard**  
5. Click **Add Panel** for each panel below

For each panel:

- Select **New Search**  
- Paste the corresponding search  
- Choose the visualisation type listed  
- Click **Add to Dashboard**

| Panel Name | Search | Visualisation |
| :---- | :---- | :---- |
| Failed Logins — Last 24h | \`index=windows\_logs EventCode=4625 | stats count by Account\_Name\` |
| Account Lockouts — Last 7d | \`index=windows\_logs EventCode=4740 | table \_time, Account\_Name, Caller\_Computer\_Name\` |
| Login Activity Over Time | \`index=windows\_logs EventCode=4624 | timechart count\` |
| Top Source IPs — After Hours | After-hours search from 6.6 with \` | stats count by Workstation\_Name\` |

**What `timechart` does:** The `timechart count` command is a special Splunk command that automatically buckets events into time intervals (minutes, hours, days) and counts them. It powers line charts and column charts that show trends over time — the visual pattern that makes a spike in failed logins obvious.

6. Click **Save** when all panels are added

---

## SECTION 8 — CREATE AN AUTOMATED ALERT

Alerts make Splunk proactive. Instead of relying on a human to notice a problem on a dashboard, Splunk runs a search on a schedule and notifies you when a threshold is crossed. This is how real SOC detection works.

### 8.1 Run the alert search first to confirm it works

index=windows\_logs sourcetype=WinEventLog:Security EventCode=4625

| stats count as failures by Account\_Name

| where failures \> 10

**What this does:** Finds any account that has more than 10 failed login attempts in the selected time window. In a real environment, 10 failures in a 15-minute window is a reliable brute force indicator. Run this first to make sure it executes without errors before saving it as an alert.

### 8.2 Save as an alert

1. Click **Save As → Alert**  
2. **Name:** `Potential Brute Force — High Failure Count`  
3. **Alert type:** Scheduled  
4. **Run every:** 15 minutes  
5. **Trigger condition:** Number of Results is greater than 0  
6. **Trigger actions:** Add to Triggered Alerts  
7. Click **Save**

**Why "Number of Results \> 0"?** The search already applies the `where failures > 10` filter — so results only appear when an account has crossed the threshold. If results exist (\>0), that means the alert condition is met and Splunk should fire.

**Alert fatigue note:** Setting the threshold too low causes the alert to fire constantly on normal activity. Analysts start ignoring it. Setting it too high means real attacks slip through. In production, you'd tune this threshold based on weeks of baseline observation.

---

## SECTION 9 — GIT COMMIT AND PUSH TO GITHUB

Back on your Mac Terminal, save all your work to the portfolio repo.

cd \~/Documents/Repos/lab3-splunk-siem

Add any scripts you created during the lab to the `scripts/` folder, and any screenshots to `screenshots/`. Then:

git add .

**What this does:** Stages all new and modified files for the next commit. The `.` captures everything — scripts, screenshots, and the README.

git commit \-m "feat: splunk lab3 — siem deployment, spl searches, dashboard, brute force alert"

**What this does:** Creates a permanent commit snapshot with a descriptive message. The `feat:` prefix is conventional commit format (feature work). The summary after the dash describes everything you built in this lab.

git push

**What this does:** Uploads your local commits to GitHub. After this completes, your lab work is publicly visible in your portfolio repo.

**Expected files in this commit:**

- `README.md` — lab documentation  
- `SOP_Lab3_Splunk_SIEM.md` — this file  
- `scripts/` — any PowerShell or bash scripts used  
- `screenshots/` — dashboard screenshots, alert config screenshots

---

## VERIFICATION CHECKLIST

Run each check to confirm the lab is working end to end.

| Check | How to verify | Expected result |
| :---- | :---- | :---- |
| Both VMs are running | `az vm list -g rg-splunk-lab3 --show-details --query "[].{Name:name, State:powerState}" -o table` | Both `dc01` and `splunk-vm` show `VM running` |
| Splunk is running | SSH into Ubuntu VM: `sudo /opt/splunk/bin/splunk status` | Output shows `splunkd is running` |
| Data is flowing | In Splunk search bar: \`index=windows\_logs | head 10\` |
| Failed login search | Run EventCode=4625 search | Returns results (generate test failures by typing a wrong password on `dc01`) |
| Dashboard loads | Open Dashboards → Windows Security Overview | All four panels show populated charts |
| Alert is active | Settings → Searches, Reports, and Alerts | Your alert appears with status Enabled |

---

## TROUBLESHOOTING

**`index=windows_logs | head 10` returns no results** The forwarder is not sending data. On `dc01`:

1. Check the service is running: `Get-Service SplunkForwarder` → should show `Running`  
2. If stopped: `Start-Service SplunkForwarder`  
3. Verify the private IP in the forwarder config matches your Splunk VM's actual private IP  
4. Confirm the `Allow-SplunkForwarder-VNet` rule exists on `splunk-nsg` and allows `10.0.0.0/16`: `az network nsg rule list -g rg-splunk-lab3 --nsg-name splunk-nsg -o table`

**Splunk Web UI at port 8000 doesn't load**

1. Confirm the `Allow-SplunkUI` rule exists and lists your current IP: `az network nsg rule list -g rg-splunk-lab3 --nsg-name splunk-nsg -o table`  
2. SSH into the Ubuntu VM and check if Splunk is running: `sudo /opt/splunk/bin/splunk status`  
3. If not running: `sudo /opt/splunk/bin/splunk start`

**`wget` returns a 404 error when downloading Splunk** The download URL has changed because Splunk released a new version. Log into splunk.com → Free Trials and Downloads → Splunk Enterprise → Linux .deb → copy the current `wget` command.

**SSH connection refused or times out (or RDP to `dc01` refused/times out)**

Because the NSG rules in Section 2 restrict SSH (22), RDP (3389), and the Splunk UI (8000) to the IP you had when you ran Section 2.4, this is usually caused by your public IP changing — common if you've switched wifi networks or your ISP reassigned your address.

1. Get your current public IP: `curl -s https://ifconfig.me`  
     
2. Update the relevant NSG rule with the new IP:  
     
   az network nsg rule update \--resource-group rg-splunk-lab3 \--nsg-name splunk-nsg \--name Allow-SSH \--source-address-prefixes YOUR\_NEW\_IP  
     
   az network nsg rule update \--resource-group rg-splunk-lab3 \--nsg-name splunk-nsg \--name Allow-SplunkUI \--source-address-prefixes YOUR\_NEW\_IP  
     
   az network nsg rule update \--resource-group rg-splunk-lab3 \--nsg-name dc01-nsg \--name Allow-RDP \--source-address-prefixes YOUR\_NEW\_IP  
     
3. Confirm the VM itself is running: `az vm show -g rg-splunk-lab3 -n splunk-vm --query "powerState" -o tsv` (swap `splunk-vm` for `dc01` as needed)  
     
4. If the VM is deallocated: `az vm start -g rg-splunk-lab3 -n splunk-vm` (or `-n dc01`)

**Universal Forwarder installer doesn't ask for Deployment Server / Receiving Indexer** Click "Customize Options" during the installer wizard — the default "Quick Install" skips the server configuration screens.

---

## CLEANUP

**When you are done with the lab** and have taken all screenshots and pushed to GitHub, delete the Azure resources to avoid charges.

az group delete \--name rg-splunk-lab3 \--yes \--no-wait

**What this does:**

- `az group delete --name rg-splunk-lab3` — deletes the entire resource group and everything inside it (both VMs, disks, network cards, public IPs, the VNet, and both NSGs)  
- `--yes` — skips the "are you sure?" confirmation prompt  
- `--no-wait` — returns your terminal prompt immediately without waiting for the deletion to complete (it runs in the background in Azure)

**Both VMs (`dc01` and `splunk-vm`) live in this one resource group**, so this single command tears down everything created in this lab. There is no other-lab VM to worry about preserving.

---

## NOTES

- The Splunk free licence (post-60-day trial) limits indexing to **500MB/day**. A home lab with one Windows Server will typically generate well under 100MB/day — the limit will not be an issue.  
- All SPL searches in this lab use the `sourcetype=WinEventLog:Security` filter. If you add other data sources in future labs, always specify the sourcetype to keep searches accurate.  
- Splunk stores its data in `/opt/splunk/var/lib/splunk/`. If you ever need to free disk space on the Ubuntu VM, this is where the indexed data lives.  
- The Windows Event Log Security audit policy on `dc01` must have "Logon Events" auditing enabled for EventCode 4624/4625/4740 to appear. Check **Local Security Policy → Security Settings → Local Policies → Audit Policy → Audit logon events** and confirm Success and Failure are both checked; since this is a freshly deployed VM (no longer inherited from Lab 1), don't assume this is already configured — verify it directly.

