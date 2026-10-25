#!/bin/bash
# =============================================================
# Hardening Audit - quick and read-only security check for
# Ubuntu / Debian servers.
#
# It checks the most common weak settings, shows PASS / WARN /
# FAIL for each one, gives a fix, and ends with a score.
# It never changes anything on the system.
# =============================================================

# ---------- Colors (only when the output is a terminal) ----------
if [ -t 1 ]; then
    GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"
    GREY="\033[90m";  RESET="\033[0m"
else
    GREEN=""; YELLOW=""; RED=""; GREY=""; RESET=""
fi

# ---------- Counters used for the final score ----------
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# ---------- Help message ----------
usage() {
    cat << EOF
Hardening Audit - quick security check for Ubuntu/Debian

Usage:
  ./tool.sh          Run the audit
  sudo ./tool.sh     Run the audit with all checks (recommended)
  ./tool.sh -h       Show this help

Checks:
  - SSH root login and password authentication
  - Firewall (ufw) and open ports
  - Pending security updates
  - Accounts with empty password or UID 0
  - Permissions of /etc/shadow and world-writable files in /etc
  - Risky services installed (telnet, ftp, ...)

Result of each check: PASS (ok), WARN (to review), FAIL (insecure),
SKIP (could not be checked, usually needs sudo).
The tool only reads the system, it never modifies it.
EOF
}

# ---------- Small helpers ----------

# True if the script is run as root (sudo)
is_root() {
    [ "$EUID" -eq 0 ]
}

# Print one result line and update the counters.
# Usage: result STATUS "check name" "details" ["how to fix"]
result() {
    local status="$1" name="$2" details="$3" advice="$4"
    local color

    case "$status" in
        PASS) color=$GREEN;  PASS_COUNT=$((PASS_COUNT + 1)) ;;
        WARN) color=$YELLOW; WARN_COUNT=$((WARN_COUNT + 1)) ;;
        FAIL) color=$RED;    FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        SKIP) color=$GREY;   SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    esac

    printf "%b[%-4s]%b %-22s %s\n" "$color" "$status" "$RESET" "$name" "$details"

    # Show the fix only when something is not fine
    if [ -n "$advice" ] && [ "$status" != "PASS" ]; then
        printf "         -> Fix: %s\n" "$advice"
    fi
}

# Read the value of an SSH option (ex: PermitRootLogin).
# sshd uses the first value it finds, so the .d folder is read first.
get_ssh_option() {
    grep -rhiE "^\s*$1\s+" /etc/ssh/sshd_config.d/ /etc/ssh/sshd_config 2>/dev/null \
        | head -n 1 | awk '{print tolower($2)}'
}

# ---------- The checks (one function per check) ----------

# 1. Can root log in directly through SSH?
check_ssh_root() {
    local name="SSH root login" value

    if [ ! -f /etc/ssh/sshd_config ]; then
        result SKIP "$name" "SSH server not installed"
        return
    fi

    value=$(get_ssh_option PermitRootLogin)
    case "$value" in
        no|prohibit-password|without-password)
            result PASS "$name" "root cannot log in with a password ($value)" ;;
        yes)
            result FAIL "$name" "root can log in directly" \
                "set 'PermitRootLogin no' in /etc/ssh/sshd_config" ;;
        "")
            result WARN "$name" "not set explicitly (default value applies)" \
                "set 'PermitRootLogin no' in /etc/ssh/sshd_config" ;;
        *)
            result WARN "$name" "unexpected value: $value" \
                "set 'PermitRootLogin no' in /etc/ssh/sshd_config" ;;
    esac
}

# 2. Is password login allowed on SSH? (keys are safer)
check_ssh_password() {
    local name="SSH password login" value

    if [ ! -f /etc/ssh/sshd_config ]; then
        result SKIP "$name" "SSH server not installed"
        return
    fi

    value=$(get_ssh_option PasswordAuthentication)
    if [ "$value" = "no" ]; then
        result PASS "$name" "disabled, only SSH keys are accepted"
    else
        result WARN "$name" "passwords are accepted (brute-force risk)" \
            "use SSH keys, then set 'PasswordAuthentication no'"
    fi
}

# 3. Is the firewall running?
check_firewall() {
    local name="Firewall (ufw)"

    if ! command -v ufw > /dev/null; then
        result FAIL "$name" "ufw is not installed" "sudo apt install ufw"
    elif systemctl is-active --quiet ufw; then
        result PASS "$name" "active"
    else
        result FAIL "$name" "installed but not active" "sudo ufw enable"
    fi
}

# 4. Which ports listen on the network? (127.0.0.1 / ::1 are ignored)
check_open_ports() {
    local name="Open ports" ports count

    if ! command -v ss > /dev/null; then
        result SKIP "$name" "'ss' command not found"
        return
    fi

    # 5th column of 'ss' = local address:port -> keep only the port number
    ports=$(ss -tuln | awk 'NR>1 {print $5}' \
            | grep -vE '^(127\.|\[::1\]|::1)' \
            | sed 's/.*://' | sort -un | tr '\n' ' ')
    count=$(echo "$ports" | wc -w)

    if [ "$count" -le 3 ]; then
        result PASS "$name" "$count port(s) exposed: ${ports:-none}"
    else
        result WARN "$name" "$count ports exposed: $ports" \
            "close the services you do not need"
    fi
}

# 5. Are security updates waiting to be installed?
check_updates() {
    local name="Security updates" count

    if ! command -v apt > /dev/null; then
        result SKIP "$name" "apt not found (not Debian/Ubuntu)"
        return
    fi

    # Lines of the upgradable list that come from a "-security" repository
    count=$(apt list --upgradable 2>/dev/null | grep -c -- "-security")

    if [ "$count" -eq 0 ]; then
        result PASS "$name" "no pending security update"
    else
        result WARN "$name" "$count security update(s) pending" \
            "sudo apt update && sudo apt upgrade"
    fi
}

# 6. Accounts with an empty password (needs root to read /etc/shadow)
check_empty_passwords() {
    local name="Empty passwords" users

    if ! is_root; then
        result SKIP "$name" "needs sudo to read /etc/shadow"
        return
    fi

    # Field 2 of /etc/shadow is the password hash: empty = no password
    users=$(awk -F: '($2 == "") {print $1}' /etc/shadow | tr '\n' ' ')

    if [ -z "$users" ]; then
        result PASS "$name" "no account without password"
    else
        result FAIL "$name" "accounts without password: $users" \
            "sudo passwd -l <user>  (lock the account)"
    fi
}

# 7. Only root should have UID 0
check_uid_zero() {
    local name="Extra UID 0 accounts" users

    users=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd | tr '\n' ' ')

    if [ -z "$users" ]; then
        result PASS "$name" "only root has UID 0"
    else
        result FAIL "$name" "other accounts with root rights: $users" \
            "remove or fix these accounts"
    fi
}

# 8. /etc/shadow holds the password hashes, it must not be readable by all
check_shadow_perms() {
    local name="/etc/shadow perms" perms

    perms=$(stat -c %a /etc/shadow 2>/dev/null)

    case "$perms" in
        640|600|400|000) result PASS "$name" "permissions are $perms" ;;
        "")              result SKIP "$name" "file not found" ;;
        *)               result FAIL "$name" "permissions are $perms (too open)" \
                             "sudo chmod 640 /etc/shadow" ;;
    esac
}

# 9. Config files that any user can modify
check_world_writable() {
    local name="World-writable in /etc" count

    # -xdev: stay on one filesystem, -perm -0002: writable by "others"
    count=$(find /etc -xdev -type f -perm -0002 2>/dev/null | wc -l)

    if [ "$count" -eq 0 ]; then
        result PASS "$name" "no file writable by everyone"
    else
        result FAIL "$name" "$count file(s) writable by everyone" \
            "find /etc -xdev -type f -perm -0002  then  chmod o-w <file>"
    fi
}

# 10. Old or insecure services still installed
check_risky_services() {
    local name="Risky services" found="" pkg

    if ! command -v dpkg-query > /dev/null; then
        result SKIP "$name" "dpkg not found"
        return
    fi

    for pkg in telnetd rsh-server vsftpd tftpd-hpa; do
        if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
            found="$found$pkg "
        fi
    done

    if [ -z "$found" ]; then
        result PASS "$name" "no insecure service installed"
    else
        result FAIL "$name" "installed: $found" \
            "sudo apt remove $found"
    fi
}

# ---------- Final summary and score ----------
summary() {
    local checked score rating

    checked=$((PASS_COUNT + WARN_COUNT + FAIL_COUNT))

    echo
    echo "-------------------------------------------------------------"
    echo "PASS: $PASS_COUNT   WARN: $WARN_COUNT   FAIL: $FAIL_COUNT   SKIP: $SKIP_COUNT"

    if [ "$checked" -eq 0 ]; then
        echo "No check could be done."
        return
    fi

    # PASS = 2 points, WARN = 1 point, FAIL = 0 -> percentage
    score=$(( (PASS_COUNT * 2 + WARN_COUNT) * 100 / (checked * 2) ))

    if   [ "$score" -ge 80 ]; then rating="Good"
    elif [ "$score" -ge 50 ]; then rating="Needs improvement"
    else                           rating="Poor"
    fi

    echo "Hardening score: $score% ($rating)"
    if [ "$SKIP_COUNT" -gt 0 ]; then
        echo "Note: $SKIP_COUNT check(s) skipped, run with sudo for a full audit."
    fi
}

# ---------- Main ----------
main() {
    # Arguments
    case "$1" in
        -h|--help) usage; exit 0 ;;
        "")        ;;
        *)         echo "Error: unknown option '$1'"; echo; usage; exit 1 ;;
    esac

    # The tool only makes sense on Linux
    if [ "$(uname -s)" != "Linux" ]; then
        echo "Error: this tool works on Linux only."
        exit 1
    fi

    echo "=== Hardening Audit - $(hostname) - $(date '+%Y-%m-%d %H:%M') ==="
    if ! is_root; then
        echo "Note: not running as root, some checks will be skipped."
    fi
    echo

    check_ssh_root
    check_ssh_password
    check_firewall
    check_open_ports
    check_updates
    check_empty_passwords
    check_uid_zero
    check_shadow_perms
    check_world_writable
    check_risky_services

    summary

    # Exit code 1 if something is insecure (useful for automation)
    if [ "$FAIL_COUNT" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
