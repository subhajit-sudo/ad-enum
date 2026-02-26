![AD-ENUM Banner](ad_enum_banner_1772130719450.png)

# 🛡️ AD-ENUM v5.0
### *The Ultimate Active Directory Enumerator & Hash Extractor*

[![Maintained](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/subhajit-sudo/ad-enum/graphs/commit-activity)
[![Kali](https://img.shields.io/badge/Platform-Kali%20Linux-blue.svg)](https://www.kali.org/)
[![Bash](https://img.shields.io/badge/Language-Bash-4EAA25.svg)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

**AD-ENUM** is a high-performance, automated enumeration script designed for security professionals and red teamers. It streamlines the discovery of vulnerabilities and credentials in Active Directory environments by consolidating techniques from top Hack The Box and VulnNyx labs into a single, cohesive workflow.

---

## 🚀 Key Features

- **⚡ High-Speed Discovery**: Uses optimized AD wordlists and timeouts to prevent hangs.
- **🔍 Deep Enumeration**: 
  - Kerberos (krb5-enum-users)
  - LDAP (LAPS, gMSA, Delegation, Shadow Credentials)
  - SMB (Shares, RID Bruting, GPP password hunting)
  - RPC & SNMP/SMTP discovery
- **💥 Advanced Attacks**: 
  - Automated AS-REP Roasting & Kerberoasting
  - Intelligent Password Spraying with mutation support
  - DCSync & NTDS Dumping (requires admin)
  - ADCS / Certificate Services analysis
- **📄 Clean Reporting**: Organized output directory with categorized results and a summary report.

---

## 🛠️ Installation

```bash
git clone https://github.com/subhajit-sudo/ad-enum.git
cd ad-enum
chmod +x ad-enum.sh
sudo ./ad-enum.sh -i  # Install all dependencies automatically
```

---

## 📖 Usage

```bash
sudo ./ad-enum.sh -t <TARGET_IP> [options]
```

### Options:
| Flag | Description |
|------|-------------|
| `-t` | **Target IP** address (Required) |
| `-u` | **Username** for authenticated enumeration |
| `-p` | **Password** for authenticated enumeration |
| `-H` | **NTLM Hash** for Pass-the-Hash |
| `-w` | Custom **Username** wordlist |
| `-W` | Custom **Password** wordlist |
| `-i` | **Install** missing dependencies |

---

## 📂 Output Structure

Results are saved in `./ad-enum-results/TARGET_DATE/`:
- `nmap/` - Port scan results
- `kerberos/` - Valid usernames & tickets
- `hashes/` - Extracted NTDS, SAM, and Roasted hashes
- `smb/` - Share listings and RID brutes
- `ldap/` - Deep domain object data
- `report.txt` - High-level summary

---

## 🧪 Techniques Included
AD-ENUM automates techniques observed in labs like:
- **Active** (GPP Mining)
- **Forest & Absolute** (AS-REP Roasting)
- **Sauna** (Kerberoasting)
- **Resolute** (LDAP Description Mining)
- **Cascade** (Base64 Attribute Extraction)

---

## ⚖️ Disclaimer
This tool is for educational and authorized penetration testing only. Usage on unauthorized targets is illegal.

---
Created by [subhajit-sudo](https://github.com/subhajit-sudo)
