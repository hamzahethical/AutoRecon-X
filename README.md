<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

<h1 align="center">⚔️ AutoRecon-X</h1>
<h3 align="center">Automated Bug Bounty Reconnaissance Framework</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.7+-3572A5?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Bug%20Bounty-Recon%20Tool-red?style=for-the-badge&logo=bugcrowd&logoColor=white"/>
  <img src="https://img.shields.io/badge/Subdomains-crt.sh%20%2B%20DNS%20Brute-orange?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Report-HTML%20%2B%20JSON-blue?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
</p>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=18&pause=1000&color=00FF66&center=true&vCenter=true&width=700&lines=Enumerate+Subdomains+via+crt.sh+%2B+DNS+BruteForce;Probe+live+HTTP%2FHTTPS+services+%26+fingerprint+tech;Port+scan+%2B+service+detection+on+live+hosts;Generate+a+beautiful+HTML+pentest+report" alt="Typing SVG"/>
</p>

---

## 🔍 What is AutoRecon-X?

**AutoRecon-X** is a fully automated, zero-dependency reconnaissance framework built for **bug bounty hunters** and **penetration testers**. Point it at a domain and it runs a full 5-phase recon pipeline — from subdomain discovery to a professional HTML report.

---

## ⚙️ Pipeline Architecture

```
Target Domain
     │
     ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 1: Subdomain Enumeration                             │
│  ├─ crt.sh Certificate Transparency Log mining              │
│  └─ DNS Brute-Force (100-word wordlist)                     │
├─────────────────────────────────────────────────────────────┤
│  Phase 2: DNS Resolution                                    │
│  └─ Multi-threaded A-record resolution (60 threads)         │
├─────────────────────────────────────────────────────────────┤
│  Phase 3: HTTP/HTTPS Probing                                │
│  ├─ Live host detection (HTTP + HTTPS fallback)             │
│  ├─ Page title extraction                                   │
│  ├─ Redirect chain tracking                                 │
│  └─ Tech stack fingerprinting (16+ signatures)             │
├─────────────────────────────────────────────────────────────┤
│  Phase 4: Port Scanning                                     │
│  └─ Top 18 critical ports with service detection           │
├─────────────────────────────────────────────────────────────┤
│  Phase 5: HTML Report Generation                            │
│  └─ Professional dark-theme pentest report                  │
└─────────────────────────────────────────────────────────────┘
     │
     ▼
  report.html + terminal output
```

---

## 🛠️ Installation

```bash
# Clone the repo
git clone https://github.com/hamzahethical/AutoRecon-X.git
cd AutoRecon-X

# Install optional rich library for colorful terminal output
pip install rich
```

**Zero required dependencies** — uses only Python 3.7+ standard library. `rich` is optional.

---

## 🚀 Usage

```bash
# Basic scan — saves report as domain_autorecon_report.html
python autorecon.py -d example.com

# Custom output file
python autorecon.py -d example.com -o my_report.html

# Skip port scanning (faster)
python autorecon.py -d example.com --no-ports

# Use custom DNS wordlist
python autorecon.py -d example.com --wordlist wordlists/large.txt

# Scan more hosts during port scanning phase
python autorecon.py -d example.com --max-port-hosts 25
```

---

## 📊 Sample Terminal Output

```
╭────────────────────────────────────────────────────╮
│            AutoRecon-X — example.com              │
╰────────────────────────────────────────────────────╯

─────── Phase 1: Subdomain Enumeration ─────────────
00:01:03  [INFO]   Fetching subdomains from crt.sh...
00:01:08  [OK]     crt.sh: 47 subdomains found
00:01:08  [INFO]   DNS brute-force with 100 wordlist...
00:01:14  [OK]     DNS brute: 12 resolved hosts
00:01:14  [FIND]   Total unique subdomains: 59

─────── Phase 3: HTTP/HTTPS Probing ────────────────
00:01:30  [OK]     Live web hosts: 23

─────── Phase 4: Port Scanning ─────────────────────
00:01:35  [FIND]   api.example.com  →  80/HTTP, 443/HTTPS, 8443/HTTPS-Alt
00:01:36  [FIND]   dev.example.com  →  22/SSH, 80/HTTP, 3306/MySQL

╭──────────────────────────────────────────╮
│            ✓ Scan Complete               │
├────────────────────────┬─────────────────┤
│ Subdomains Found       │  59             │
│ Live DNS Hosts         │  31             │
│ Live Web Services      │  23             │
│ Total Open Ports       │  18             │
│ Time Elapsed           │  87.4s          │
│ Report Saved To        │  report.html    │
╰────────────────────────┴─────────────────╯
```

---

## 📋 Detected Technologies

AutoRecon-X fingerprints **16+ technologies** from HTTP headers and HTML body:

| Category | Signatures Detected |
| :--- | :--- |
| **CMS** | WordPress, Drupal, Joomla, Shopify |
| **Frameworks** | Laravel, Django, React, Angular, Vue.js |
| **Frontend** | jQuery, Bootstrap |
| **Servers** | Apache, Nginx, IIS |
| **Cloud/CDN** | Cloudflare, AWS S3 |
| **Languages** | PHP, ASP.NET, Node.js |

---

## 🗂️ Output Files

| File | Description |
| :--- | :--- |
| `<domain>_autorecon_report.html` | Professional dark-theme HTML report with all findings |

---

## ⚠️ Disclaimer

**AutoRecon-X** is built for **educational purposes** and **authorized security testing only**. Only use this tool against targets you have explicit written permission to test. Unauthorized scanning is illegal.

---

## 👨‍💻 Author

**Md Hamzah** | [@hamzahethical](https://github.com/hamzahethical)  
Cybersecurity Specialist | Bug Bounty Hunter | Security Researcher  
📍 Kolkata, India 🇮🇳

---

> *"Reconnaissance is the foundation of every successful penetration test."*
