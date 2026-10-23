#!/usr/bin/env bash
#
# linux_baseline_check.sh
# ---------------------------------------------------------------------------
# Linux Security Baseline & Persistence/Reverse-Shell Backdoor Inspection
#
# This script integrates the "Routine Security Check" chapter of the NOP Team
# Linux Emergency Response Manual (v2.0.2) into a single, dependency-light
# baseline collector. It is designed to run FIRST during an incident response,
# so that later specialized hunting (mining, C2 backdoor, ransomware, brute
# force, etc.) has enough seed information to work on.
#
# Design goals / consensus with common international security practice:
#   * All output and comments are in English to avoid locale / encoding issues.
#   * Only standard coreutils + a few widely pre-installed tools (awk, sed,
#     grep, find, ps, netstat/ss, systemctl, ip, last, lsattr, getcap, etc.)
#     are used. Optional tools (rpm, dpkg, debsums, chkrootkit, clamav,
#     unhide, rkhunter, locate) are probed and skipped gracefully if missing.
#   * It is READ-ONLY by default: it collects and reports, but never modifies
#     the system. Remediation is left to the analyst.
#   * It records IOC seeds (listening ports, external connections, process
#     command lines, timestamps) that later manual hunting relies on.
#
# Usage:
#   ./linux_baseline_check.sh [--output DIR] [--skip-integrity] [--skip-recent]
#                             [--quiet] [--help]
#
#   --output DIR        write the full report into DIR (default: ./baseline_report)
#   --skip-integrity    skip md5sum/rpm/dpkg/debsums integrity checks (slow)
#   --skip-recent       skip scanning the last-7-day recent files/artifacts
#   --quiet             print only the final summary, not per-section headers
#   --help              show this help
#
# Changelog:
#   v1.1.0  (2026-10-23)
#     - FIX: cron/service/profile.d/motd entries that are DIRECTORIES are now
#       enumerated instead of being silently dropped by cat(1).
#     - FIX: /etc/motd (a file) is now checked (was previously skipped due to
#       a [ -d ] test).
#     - FIX: lastb failure is now reported instead of being silently swallowed.
#     - FIX: --output without a value now errors cleanly instead of tripping
#       'set -u'.
#     - FIX: 0x34 recent-artifacts no longer truncates the report to 30 lines
#       per location; the full list is written to the report.
#     - FIX: 0x19 comments now match implementation (sha256, not md5sum), with
#       a usrmerge-aware fallback for binary path resolution.
#     - NEW: process-level LD_PRELOAD scan (/proc/*/environ).
#     - NEW: SSH directory / key file permission checks + per-user ssh config.
#     - NEW: ExecStart lines of enabled systemd services.
#     - NEW: writable cron file scan (privilege escalation).
#     - NEW: IPv6 external connection section.
#     - CHG: removed bash-builtin name collision check (high false-positive
#       rate, e.g. coreutils /usr/bin/echo); PATH writability is covered in 0x30.
# ---------------------------------------------------------------------------

set -u

# ===================== Configuration =====================
SCRIPT_VERSION="1.1.0"
OUTPUT_DIR="./baseline_report"
SKIP_INTEGRITY=0
SKIP_RECENT=0
QUIET=0

# Set of known-good directories that should not contain unowned executables.
# (Used only as advisory context, not a hard rule.)
SENSITIVE_DIRS=("/tmp" "/dev/shm" "/var/tmp" "/var/www" "/srv" "/home")

# Find the "real" ps/netstat in case they were replaced (rootkit defense).
BUSYBOX="$(command -v busybox 2>/dev/null || true)"

# ===================== Helper functions =====================

# Print a section banner to both stdout and the report file.
section() {
    local title="$1"
    echo "" | tee -a "$REPORT"
    echo "================================================================" | tee -a "$REPORT"
    echo "  $title" | tee -a "$REPORT"
    echo "================================================================" | tee -a "$REPORT"
}

# Print a subsection marker.
subsection() {
    echo "" | tee -a "$REPORT"
    echo "--- $1 ---" | tee -a "$REPORT"
}

# Run a command and append its (cleaned) output to the report. If the command
# is missing, print a notice instead of failing.
run() {
    local desc="$1"; shift
    subsection "$desc"
    if command -v "$1" >/dev/null 2>&1; then
        # Execute the command; redirect stderr to stdout so errors are captured.
        "$@" 2>&1 | sed 's/\r$//' | tee -a "$REPORT"
    else
        echo "  [SKIP] command not found: $1" | tee -a "$REPORT"
    fi
}

# Print a FINDING line to the findings summary (and echo to stdout).
finding() {
    local level="$1"; shift
    local line="[$level] $*"
    echo "$line" >> "$FINDINGS"
    [ "$QUIET" -eq 0 ] && echo "  >>> $line"
}

usage() {
    grep -E '^#' "$0" | sed 's/^#\{1,2\} //' | sed '/^$/d'
    exit 0
}

# ===================== Parse arguments =====================
while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            if [ $# -lt 2 ]; then
                echo "Error: --output requires a directory argument" >&2
                exit 2
            fi
            OUTPUT_DIR="$2"; shift 2 ;;
        --skip-integrity) SKIP_INTEGRITY=1; shift ;;
        --skip-recent)   SKIP_RECENT=1; shift ;;
        --quiet)         QUIET=1; shift ;;
        --help|-h)       usage ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

# ===================== Prepare output =====================
mkdir -p "$OUTPUT_DIR" 2>/dev/null || { echo "Cannot create output dir: $OUTPUT_DIR"; exit 1; }
TS="$(date +%Y%m%d_%H%M%S)"
HOST="$(hostname 2>/dev/null || echo unknown)"
REPORT="$OUTPUT_DIR/baseline_${HOST}_${TS}.txt"
FINDINGS="$OUTPUT_DIR/findings_${HOST}_${TS}.txt"
: > "$REPORT"
: > "$FINDINGS"

# ===================== Report header =====================
{
    echo "Linux Security Baseline Check Report"
    echo "Generated : $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "Hostname  : $HOST"
    echo "Script    : linux_baseline_check.sh v$SCRIPT_VERSION"
    echo "User      : $(id -un 2>/dev/null) (uid=$(id -u 2>/dev/null))"
    echo "Kernel    : $(uname -a 2>/dev/null)"
} | tee -a "$REPORT"

# ===================== 0x01 Host / environment snapshot =====================
section "0x01 Host & Environment Snapshot"
run "OS release" cat /etc/os-release
run "Current date/time (UTC)" date -u
run "Uptime" uptime
run "Loaded kernel modules count" bash -c 'echo $(ls /proc/modules 2>/dev/null | wc -l) modules loaded (see lsmod section)'
run "Current environment (sanitized, no secrets)" bash -c 'env | grep -viE "key|token|secret|pass|pwd|password" | sort'
run "PATH variable" bash -c 'echo "$PATH"'
run "umask" umask

# ===================== 0x02 Process & network baseline (IOC seeds) =====================
section "0x02 Process & Network Baseline (IOC seeds for later hunting)"
subsection "Listening ports (netstat -tulnp)"
if [ -n "$(command -v netstat 2>/dev/null)" ]; then
    netstat -tulnp 2>/dev/null | tee -a "$REPORT"
else
    echo "  [SKIP] netstat not found, trying ss" | tee -a "$REPORT"
    ss -tulnp 2>/dev/null | tee -a "$REPORT"
fi

subsection "All established/external connections (netstat -anp)"
if [ -n "$(command -v netstat 2>/dev/null)" ]; then
    netstat -anp 2>/dev/null | grep -iE "ESTABLISHED|LISTEN" | tee -a "$REPORT"
else
    ss -anp 2>/dev/null | grep -iE "ESTAB|LISTEN" | tee -a "$REPORT"
fi

subsection "External (non-private) IPv4 connections -- potential C2 beacon"
# Flag connections whose remote IPv4 is not in RFC1918 / loopback / link-local.
if [ -n "$(command -v netstat 2>/dev/null)" ]; then
    net_cmd="netstat -anp"
else
    net_cmd="ss -anp"
fi
$net_cmd 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+' \
    | awk -F: '{print $1}' | sort -u | while read -r ip; do
    case "$ip" in
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|127.*|0.0.0.0|169.254.*) ;;
        *) echo "  [EXTERNAL IPv4] $ip" ;;
    esac
done | tee -a "$REPORT"

subsection "IPv6 established connections (manual review; IPv6 NAT is rare, so global peers are notable)"
$net_cmd 2>/dev/null | grep -iE "ESTAB" | grep -E '(\[|::)' | tee -a "$REPORT"

subsection "Full process list (ps aux) -- baseline command lines"
if [ -n "${BUSYBOX:-}" ]; then
    BUSYBOX_PS="$BUSYBOX ps aux"
else
    BUSYBOX_PS="ps aux"
fi
$BUSYBOX_PS 2>/dev/null | tee -a "$REPORT"

# ===================== 0x03 Antivirus / rootkit scanners =====================
section "0x03 Antivirus & Rootkit Scanners (optional, skip if absent)"
for tool in chkrootkit rkhunter clamscan unhide; do
    if command -v "$tool" >/dev/null 2>&1; then
        finding "INFO" "Scanner present: $tool"
        subsection "Quick presence check for $tool (run manually for full scan)"
        case "$tool" in
            clamscan) echo "  clamav available: run 'clamscan -r / --exclude-dir=/sys' for full scan" | tee -a "$REPORT" ;;
            *) echo "  $tool available: run 'sudo $tool' for a full scan" | tee -a "$REPORT" ;;
        esac
    else
        echo "  [SKIP] $tool not installed" | tee -a "$REPORT"
    fi
done

# ===================== 0x04 Shell history =====================
section "0x04 Shell History Inspection"
subsection "Bash history files found"
find /home /root -maxdepth 2 \( -name ".bash_history" -o -name ".zsh_history" \) 2>/dev/null | tee -a "$REPORT"
subsection "Global history config (HISTFILE/HISTSIZE) in profile files"
grep -rniE "HISTFILE|HISTSIZE|HISTFILESIZE|HISTTIMEFORMAT" /etc/profile /etc/bash.bashrc /etc/profile.d/ /root/.bashrc /home/*/.bashrc 2>/dev/null | tee -a "$REPORT"
subsection "Recent suspicious history entries (curl/wget/base64/nc/socat/ssh tunnel)"
grep -rniE "(curl|wget|base64|/dev/tcp/|nc |ncat|socat|mkfifo|/bin/sh -i|reverse|ssh -[DRNf]|crontab|chmod \+x|pty\.spawn|pkill|kill -9)" /root/.bash_history /home/*/.bash_history 2>/dev/null | tee -a "$REPORT"

# ===================== 0x05 Cron / scheduled tasks =====================
section "0x05 Scheduled Tasks (Persistence)"
for f in /etc/crontab /etc/anacrontab /var/spool/cron /var/spool/cron/crontabs /var/spool/at /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    if [ -e "$f" ]; then
        subsection "$f"
        if [ -d "$f" ]; then
            # Directory entry: list the dir itself (so even unreadable entries
            # are visible) and cat every regular file inside it.
            ls -la "$f" 2>/dev/null | tee -a "$REPORT"
            find "$f" -maxdepth 1 -type f 2>/dev/null | sort | while read -r cf; do
                echo "### $cf" | tee -a "$REPORT"
                if [ -r "$cf" ]; then
                    cat "$cf" 2>/dev/null | tee -a "$REPORT"
                else
                    echo "  [PERM] not readable (try with sudo): $cf" | tee -a "$REPORT"
                fi
            done
        else
            if [ -r "$f" ]; then
                cat "$f" 2>/dev/null | tee -a "$REPORT"
            else
                echo "  [PERM] not readable (try with sudo): $f" | tee -a "$REPORT"
            fi
        fi
    fi
done
subsection "Writable cron spool / cron.d files (non-root writable = privilege escalation)"
find /var/spool/cron /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/crontab /etc/anacrontab -type f \( -perm -002 -o -perm -020 \) 2>/dev/null | while read -r cf; do
    if [ -n "$cf" ]; then
        finding "HIGH" "Writable cron file: $cf"
        echo "  $cf" | tee -a "$REPORT"
    fi
done
subsection "Systemd timers (alternative persistence)"
run "systemd timers" bash -c 'systemctl list-timers --all 2>/dev/null | head -50'

# ===================== 0x06 Accounts =====================
section "0x06 Account Information"
run "All accounts (/etc/passwd)" cat /etc/passwd
subsection "Shadow password flags (perm-sensitive)"
if [ -r /etc/shadow ]; then
    awk -F: '($2=="" || $2=="!") {print $1": no/disabled password"}' /etc/shadow 2>/dev/null | tee -a "$REPORT"
else
    echo "  [PERM] /etc/shadow not readable (run with sudo for full check)" | tee -a "$REPORT"
fi
subsection "Accounts with UID 0 (privileged)"
awk -F: '$3==0 {print $1" (uid=0)"}' /etc/passwd | tee -a "$REPORT"
[ "$(awk -F: '$3==0' /etc/passwd | wc -l)" -gt 1 ] && finding "HIGH" "Multiple UID-0 accounts detected (expect only root)"
subsection "Accounts with a writable password field (password padding backdoor)"
# Manual 0x22: if /etc/passwd password field is not 'x', it may be padded.
awk -F: '$2 != "x" && $2 != "*" && $2 != "!" {print $1": password field not x -> "$2}' /etc/passwd 2>/dev/null | tee -a "$REPORT"
subsection "Recently created/modified accounts (passwd mtime)"
run "passwd file timestamps" bash -c 'ls -la /etc/passwd /etc/shadow /etc/group 2>/dev/null'

# ===================== 0x07 Login information =====================
section "0x07 Login Information"
run "Currently logged-in users (w)" w
run "Last logins (last -awF)" bash -c 'last -awF 2>/dev/null | head -40'
run "Lastlog" lastlog 2>/dev/null | head -40
run "Failed login attempts (lastb)" bash -c 'if lastb 2>/dev/null | grep -q .; then lastb 2>/dev/null | head -30; else echo "[SKIP] lastb failed (needs privileges or no btmp)"; fi'
run "Reboot history" bash -c 'last reboot 2>/dev/null | head -20'

# ===================== 0x08 SUID / SGID / world-writable =====================
section "0x08 Special Permission Files (SUID/SGID, world-writable)"
subsection "SUID files (find / -perm -4000)"
find / -xdev -perm -4000 -type f 2>/dev/null | tee -a "$REPORT"
subsection "SGID files (find / -perm -2000)"
find / -xdev -perm -2000 -type f 2>/dev/null | tee -a "$REPORT"
subsection "World-writable files owned by root (excluding /proc /sys)"
find / -xdev -type f -perm -0002 -uid 0 2>/dev/null | grep -vE '^/proc|^/sys' | tee -a "$REPORT" | head -50
subsection ".so / script files with SUID (unusual)"
find / -xdev \( -perm -4000 \) \( -name "*.so" -o -name "*.py" -o -name "*.sh" \) 2>/dev/null | tee -a "$REPORT"

# ===================== 0x09 Dynamic linker hijacking =====================
section "0x09 Dynamic Linker Hijacking (LD_PRELOAD / ld.so)"
subsection "LD_PRELOAD environment"
echo "LD_PRELOAD=$LD_PRELOAD" | tee -a "$REPORT"
[ -n "${LD_PRELOAD:-}" ] && finding "HIGH" "LD_PRELOAD is set in current env: $LD_PRELOAD"
subsection "LD_PRELOAD in running process environments (/proc/*/environ)"
found=0
for ef in /proc/[0-9]*/environ; do
    [ -r "$ef" ] || continue
    if tr '\0' '\n' < "$ef" 2>/dev/null | grep -q '^LD_PRELOAD='; then
        pid="${ef#/proc/}"; pid="${pid%/environ}"
        preload=$(tr '\0' '\n' < "$ef" 2>/dev/null | grep '^LD_PRELOAD=' | head -1)
        comm=$(cat /proc/$pid/comm 2>/dev/null)
        finding "HIGH" "LD_PRELOAD set in PID $pid ($comm): $preload"
        echo "  $pid $comm $preload" | tee -a "$REPORT"
        found=1
    fi
done
[ "$found" -eq 0 ] && echo "  No LD_PRELOAD found in running process environments." | tee -a "$REPORT"
subsection "/etc/ld.so.preload"
if [ -s /etc/ld.so.preload ]; then
    finding "HIGH" "/etc/ld.so.preload is not empty (library preloading backdoor)"
    cat /etc/ld.so.preload | tee -a "$REPORT"
else
    echo "  (empty/none)" | tee -a "$REPORT"
fi
subsection "LD_LIBRARY_PATH"
echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" | tee -a "$REPORT"
subsection "/etc/ld.so.conf and included dirs"
run "ld.so.conf" bash -c 'cat /etc/ld.so.conf 2>/dev/null; echo "--- included ---"; for d in /etc/ld.so.conf.d/*; do [ -r "$d" ] && cat "$d"; done 2>/dev/null'

# ===================== 0x10 Bash builtins / functions =====================
section "0x10 Bash Builtins, Functions & Aliases (command-hijack vectors)"
subsection "Bash functions (declare -f)"
declare -f 2>/dev/null | tee -a "$REPORT"
subsection "Aliases (alias)"
alias 2>/dev/null | tee -a "$REPORT"
# Note: the old "builtin-name collision in /usr/bin" check was removed in v1.1.0:
# it produced a high false-positive rate (e.g. coreutils /usr/bin/echo is a
# legitimate file). PATH-writability is covered in 0x30 instead.

# ===================== 0x11 Startup items / config scripts =====================
section "0x11 Startup Items & Configuration Scripts"
subsection "Enabled systemd services (systemctl list-unit-files --type=service | grep enabled)"
run "enabled services" bash -c 'systemctl list-unit-files --type=service 2>/dev/null | grep -i enabled | head -80'
subsection "Running services"
run "running services" bash -c 'systemctl list-units --type=service --state=running 2>/dev/null | head -80'
subsection "ExecStart of enabled services (look for /tmp /dev/shm /var/tmp paths)"
systemctl list-unit-files --type=service 2>/dev/null | grep -i enabled | awk '{print $1}' | head -80 | while read -r svc; do
    [ -z "$svc" ] && continue
    sp=$(systemctl show -p FragmentPath --value "$svc" 2>/dev/null)
    if [ -n "$sp" ] && [ -r "$sp" ]; then
        grep -E "^(ExecStart|ExecStartPre|ExecStartPost)=" "$sp" 2>/dev/null | sed "s|^|  $svc: |" | tee -a "$REPORT"
    fi
done
for f in /etc/rc.local /etc/rc.d/rc.local /etc/profile /etc/profile.d /etc/bash.bashrc /etc/bashrc; do
    if [ -e "$f" ]; then
        subsection "$f"
        if [ -d "$f" ]; then
            find "$f" -maxdepth 1 -type f 2>/dev/null | sort | while read -r cf; do
                echo "### $cf" | tee -a "$REPORT"
                cat "$cf" 2>/dev/null | tee -a "$REPORT"
            done
        else
            cat "$f" 2>/dev/null | tee -a "$REPORT"
        fi
    fi
done
subsection "Per-user profile/rc scripts"
find /home /root -maxdepth 2 \( -name ".bashrc" -o -name ".bash_profile" -o -name ".profile" -o -name ".bash_logout" -o -name ".bash_aliases" \) 2>/dev/null | while read -r uf; do
    echo "### $uf" | tee -a "$REPORT"
    cat "$uf" 2>/dev/null | tee -a "$REPORT"
done

# ===================== 0x12 SSH keys & config =====================
section "0x12 SSH Keys & Client Config (backdoor / key injection)"
subsection "authorized_keys files (look for 'command=' forced command)"
find /home /root -name "authorized_keys*" -type f 2>/dev/null | while read -r kf; do
    echo "### $kf" | tee -a "$REPORT"
    if grep -q "command=" "$kf" 2>/dev/null; then
        finding "HIGH" "SSH forced command in $kf"
    fi
    cat "$kf" 2>/dev/null | tee -a "$REPORT"
done
subsection "ssh config files (LocalCommand / ProxyCommand backdoor)"
for cf in /etc/ssh/ssh_config /etc/ssh/sshd_config /root/.ssh/config /home/*/.ssh/config; do
    if [ -e "$cf" ]; then
        echo "### $cf" | tee -a "$REPORT"
        grep -niE "LocalCommand|ProxyCommand|AuthorizedKeysCommand|PermitRootLogin|PubkeyAuthentication|PasswordAuthentication" "$cf" 2>/dev/null | tee -a "$REPORT"
    fi
done
subsection "SSH directory & key file permissions (expect 700 dirs, <=600 private keys)"
find /home /root \( -name ".ssh" -o -name "authorized_keys" -o -name "authorized_keys2" -o -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "id_dsa" \) 2>/dev/null | while read -r p; do
    perm=$(stat -c '%a' "$p" 2>/dev/null)
    owner=$(stat -c '%U' "$p" 2>/dev/null)
    echo "  $perm $owner $p" | tee -a "$REPORT"
    case "$p" in
        */.ssh)
            [ "$perm" != "700" ] && [ "$perm" != "750" ] && finding "MED" "SSH dir permission $perm (expect 700): $p" ;;
        */authorized_keys*)
            case "$perm" in 600|640|644) ;; *) finding "MED" "authorized_keys unusual permission $perm: $p" ;; esac ;;
        *id_*.pub) ;;   # public keys may stay world-readable
        *)
            [ "${perm:-0}" -gt 600 ] && finding "MED" "Private SSH key too permissive ($perm, expect <=600): $p" ;;
    esac
done
subsection "ssh public-key fingerprints (for login attribution)"
find /home /root -name "authorized_keys*" -type f 2>/dev/null | while read -r kf; do
    ssh-keygen -lf "$kf" 2>/dev/null | sed "s|^|  $kf: |" | tee -a "$REPORT"
done

# ===================== 0x13 DNS resolution config =====================
section "0x13 DNS Resolution Configuration"
run "/etc/resolv.conf" cat /etc/resolv.conf
run "/etc/hosts" cat /etc/hosts
subsection "nsswitch.conf (hosts line, potential hijack)"
grep -i "hosts:" /etc/nsswitch.conf 2>/dev/null | tee -a "$REPORT"

# ===================== 0x14 Logs =====================
section "0x14 Log Inspection"
run "/var/log listing" bash -c 'ls -la /var/log 2>/dev/null | head -60'
subsection "SSH auth log (recent failed/accepted)"
for lf in /var/log/auth.log /var/log/secure /var/log/messages; do
    if [ -r "$lf" ]; then
        echo "### $lf (last 40 auth lines)" | tee -a "$REPORT"
        tail -n 40 "$lf" 2>/dev/null | grep -iE "ssh|auth|fail|accept|invalid|session" | tee -a "$REPORT"
    fi
done
subsection "sudo usage (last sudo)"
run "sudo log" bash -c 'journalctl -u sudo 2>/dev/null | tail -20 || grep -i sudo /var/log/auth.log 2>/dev/null | tail -20 || echo "[SKIP] no sudo log available"'

# ===================== 0x15 Kernel hardening =====================
section "0x15 Kernel Hardening (ptrace_scope / ASLR)"
subsection "ptrace_scope (yama)"
if [ -r /proc/sys/kernel/yama/ptrace_scope ]; then
    v=$(cat /proc/sys/kernel/yama/ptrace_scope); echo "ptrace_scope=$v" | tee -a "$REPORT"
    [ "$v" -eq 0 ] && finding "MED" "ptrace_scope=0 (debugger attach to any process allowed)"
else
    echo "  [N/A] /proc/sys/kernel/yama/ptrace_scope not present" | tee -a "$REPORT"
fi
subsection "ASLR (randomize_va_space)"
if [ -r /proc/sys/kernel/randomize_va_space ]; then
    v=$(cat /proc/sys/kernel/randomize_va_space); echo "randomize_va_space=$v" | tee -a "$REPORT"
    [ "$v" -eq 0 ] && finding "HIGH" "ASLR disabled (randomize_va_space=0)"
else
    echo "  [N/A]" | tee -a "$REPORT"
fi

# ===================== 0x16 Capabilities =====================
section "0x16 File Capabilities"
if command -v getcap >/dev/null 2>&1; then
    getcap -r / 2>/dev/null | tee -a "$REPORT"
    getcap -r / 2>/dev/null | grep -iE "cap_setuid|cap_setgid|cap_sys_admin|cap_dac_override|cap_dac_read_search|ep" | grep -vE "/usr/|/sbin/|/bin/" && finding "MED" "Unusual file capabilities found outside system paths"
else
    echo "  [SKIP] getcap not installed" | tee -a "$REPORT"
fi

# ===================== 0x17 iptables =====================
section "0x17 Firewall / iptables (port multiplexing backdoor)"
if command -v iptables >/dev/null 2>&1; then
    run "iptables -L -n -v" bash -c 'iptables -L -n -v 2>/dev/null | head -60'
    run "iptables -t nat -L -n -v" bash -c 'iptables -t nat -L -n -v 2>/dev/null | head -40'
else
    echo "  [SKIP] iptables not present (nftables?)" | tee -a "$REPORT"
    run "nft list ruleset" bash -c 'nft list ruleset 2>/dev/null | head -60'
fi

# ===================== 0x18 Deleted-but-running files =====================
section "0x18 Deleted Files Still Held by Processes"
subsection "/proc/*/exe deleted (process started from a deleted binary)"
if [ -r /proc/1/exe ]; then
    ls -al /proc/*/exe 2>/dev/null | grep -i deleted | tee -a "$REPORT"
else
    echo "  [PERM] /proc not fully readable, try with sudo" | tee -a "$REPORT"
fi
subsection "lsof deleted (memfd / deleted executables)"
if command -v lsof >/dev/null 2>&1; then
    lsof +L1 2>/dev/null | grep -i deleted | tee -a "$REPORT" | head -40
else
    echo "  [SKIP] lsof not installed" | tee -a "$REPORT"
fi

# ===================== 0x19 Software / config integrity =====================
section "0x19 Software & Configuration Integrity"
if [ "$SKIP_INTEGRITY" -eq 1 ]; then
    echo "  [SKIP] integrity checks disabled via --skip-integrity" | tee -a "$REPORT"
else
    if command -v rpm >/dev/null 2>&1; then
        subsection "rpm -Va (modified files vs packaged; first 60 lines shown)"
        rpm -Va 2>/dev/null | grep -vE '^\.\.\.\.\.\.\.U' | head -60 | tee -a "$REPORT"
    fi
    if command -v dpkg >/dev/null 2>&1; then
        subsection "debsums -a -c (modified packaged files; first 60 lines shown)"
        if command -v debsums >/dev/null 2>&1; then
            debsums -a -c 2>/dev/null | head -60 | tee -a "$REPORT"
        else
            echo "  [SKIP] debsums not installed (apt install debsums)" | tee -a "$REPORT"
        fi
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        subsection "Checksums of critical binaries (sha256, deduplicated)"
        {
            for b in /bin/ps /bin/netstat /usr/bin/ls /bin/login /usr/bin/passwd /usr/bin/ssh /usr/sbin/sshd; do
                [ -e "$b" ] && sha256sum "$b" 2>/dev/null
            done
            # usrmerge / custom-path fallback: also hash whatever these resolve to.
            for b in ps netstat ls login passwd ssh sshd; do
                p=$(command -v "$b" 2>/dev/null)
                [ -n "$p" ] && sha256sum "$p" 2>/dev/null
            done
        } 2>/dev/null | sort -u | tee -a "$REPORT"
    else
        echo "  [SKIP] sha256sum not available" | tee -a "$REPORT"
    fi
fi

# ===================== 0x20 sudo configuration =====================
section "0x20 Sudo Configuration"
run "/etc/sudoers (with includes)" bash -c 'cat /etc/sudoers 2>/dev/null; for f in /etc/sudoers.d/*; do [ -r "$f" ] && echo "### $f" && cat "$f"; done 2>/dev/null'
subsection "NOPASSWD / ALL rules (privilege escalation risk)"
grep -rniE "NOPASSWD|ALL=.*ALL|\(ALL\)" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -viE "^#" | tee -a "$REPORT"

# ===================== 0x21 Third-party repo GPG keys =====================
section "0x21 Third-Party Repository GPG Keys"
subsection "RPM repo keys"
if command -v rpm >/dev/null 2>&1; then
    rpm -qa --qf '%{NAME}-%{VERSION}\n' gpg-pubkey-* 2>/dev/null | tee -a "$REPORT"
fi
subsection "APT trusted keys (/etc/apt/trusted.gpg.d, /etc/apt/keyrings)"
run "apt-key list (legacy)" bash -c 'apt-key list 2>/dev/null | head -40 || echo "[SKIP] apt-key deprecated"'
run "trusted.gpg.d listing" bash -c 'ls -la /etc/apt/trusted.gpg.d/ /etc/apt/keyrings/ 2>/dev/null'

# ===================== 0x22 Cron logs =====================
section "0x22 Scheduled Task Logs"
run "cron service log" bash -c 'journalctl -u cron 2>/dev/null | tail -20; journalctl -u crond 2>/dev/null | tail -20'

# ===================== 0x23 Kernel module signing =====================
section "0x23 Kernel Module Signing"
subsection "Kernel module signature config"
if [ -r "/boot/config-$(uname -r)" ]; then
    zgrep CONFIG_MODULE_SIG "/boot/config-$(uname -r)" 2>/dev/null | grep -v "^#" | tee -a "$REPORT"
else
    echo "  [SKIP] /boot/config-$(uname -r) not readable" | tee -a "$REPORT"
fi
subsection "Modules tainted / unsigned in dmesg & logs"
dmesg 2>/dev/null | grep -i "taint" | tee -a "$REPORT"
for lf in /var/log/kern.log /var/log/syslog; do
    [ -r "$lf" ] && grep -i "taint" "$lf" 2>/dev/null | tail -20 | tee -a "$REPORT"
done

# ===================== 0x24 Loaded kernel modules =====================
section "0x24 Loaded Kernel Modules"
run "lsmod (loaded modules)" bash -c 'lsmod 2>/dev/null | head -80'
subsection "Modules lacking a signed/known vermagic (manual review)"
ls /sys/module 2>/dev/null | tee -a "$REPORT" | head -80

# ===================== 0x25 PAM =====================
section "0x25 PAM (Pluggable Authentication Modules)"
subsection "/etc/pam.d listing"
run "pam.d files" bash -c 'ls -la /etc/pam.d/ 2>/dev/null'
subsection "Suspicious PAM directives (pam_exec / pam_permit / odd module paths)"
grep -rniE "pam_exec|pam_permit|pam_unix.so nullok|pam_.*\.so.*->|/tmp/|/dev/shm/" /etc/pam.d/ 2>/dev/null | tee -a "$REPORT"
subsection "PAM shared objects present"
run "pam security modules" bash -c 'ls -la /usr/lib/x86_64-linux-gnu/security/ /usr/lib64/security/ 2>/dev/null | head -80'
subsection "PAM integrity (debsums/rpm, if available)"
if command -v debsums >/dev/null 2>&1; then
    debsums -a -c 2>/dev/null | grep -i pam | tee -a "$REPORT"
fi

# ===================== 0x26 proc vs ps hidden-process detection =====================
section "0x26 Hidden Process Detection (proc vs ps)"
subsection "PIDs present in /proc but missing from ps (possible hidden/rootkit process)"
# Build a space-prefixed, space-suffixed list so we match whole PIDs only.
ps_pids=" $(ps -e -o pid= 2>/dev/null | tr -d ' ' | tr '\n' ' ') "
if [ "${ps_pids// /}" = "" ]; then
    echo "  [SKIP] ps produced no output, cannot cross-check /proc" | tee -a "$REPORT"
else
    hidden=0
    for p in /proc/[0-9]*; do
        pid="${p#/proc/}"
        case "$ps_pids" in
            *" $pid "*) ;;
            *) echo "  [HIDDEN?] PID $pid in /proc but not in ps: $(cat /proc/$pid/comm 2>/dev/null)" | tee -a "$REPORT"; hidden=1 ;;
        esac
    done
    [ "$hidden" -eq 0 ] && echo "  No /proc-vs-ps discrepancies found." | tee -a "$REPORT"
fi

# ===================== 0x27 trap / shell hooks =====================
section "0x27 Shell Trap Hooks"
subsection "Active trap handlers in current shell (trap -p)"
trap -p 2>/dev/null | tee -a "$REPORT"

# ===================== 0x28 User skeleton templates =====================
section "0x28 User Skeleton Templates (/etc/skel poisoning)"
run "/etc/skel contents" bash -c 'ls -la /etc/skel/ 2>/dev/null; find /etc/skel -type f -exec echo "### {}" \; -exec cat {} \; 2>/dev/null'

# ===================== 0x29 TCP Wrappers =====================
section "0x29 TCP Wrappers (hosts.allow / hosts.deny)"
for f in /etc/hosts.allow /etc/hosts.deny; do
    if [ -e "$f" ]; then
        subsection "$f"
        cat "$f" 2>/dev/null | tee -a "$REPORT"
        if grep -qiE "spawn|twist" "$f" 2>/dev/null; then
            finding "HIGH" "TCP Wrappers $f uses spawn/twist (can execute commands)"
        fi
    fi
done

# ===================== 0x30 Sensitive directories =====================
section "0x30 Sensitive Directories (dropper / payload stash)"
for d in "${SENSITIVE_DIRS[@]}"; do
    if [ -d "$d" ]; then
        subsection "$d : recently modified executables/scripts (last 7 days unless --skip-recent)"
        if [ "$SKIP_RECENT" -eq 1 ]; then
            echo "  [SKIP] recent scan disabled" | tee -a "$REPORT"
        else
            find "$d" -xdev -type f \( -perm -100 -o -name "*.sh" -o -name "*.py" -o -name "*.pl" \) -mtime -7 2>/dev/null | tee -a "$REPORT" | head -40
        fi
    fi
done
subsection "PATH directories writable by non-root (privilege escalation path)"
echo "$PATH" | tr ':' '\n' | while read -r p; do
    if [ -d "$p" ] && [ -w "$p" ] && [ "$(stat -c '%u' "$p" 2>/dev/null)" != "0" ]; then
        finding "HIGH" "Writable PATH directory owned by non-root: $p"
    fi
done

# ===================== 0x31 udev rules =====================
section "0x31 udev Rules (RUN/PROGRAM/IMPORT backdoor)"
for d in /etc/udev/rules.d /usr/lib/udev/rules.d /run/udev/rules.d /lib/udev/rules.d; do
    if [ -d "$d" ]; then
        echo "### $d" | tee -a "$REPORT"
        grep -riI -E 'RUN|PROGRAM|IMPORT' "$d" 2>/dev/null | tee -a "$REPORT"
    fi
done

# ===================== 0x32 Python .pth backdoor =====================
section "0x32 Python .pth Backdoor"
echo "PYTHONPATH=$PYTHONPATH" | tee -a "$REPORT"
[ -n "${PYTHONPATH:-}" ] && finding "MED" "PYTHONPATH is set: $PYTHONPATH (could inject malicious modules)"
subsection "*.pth files containing 'import' (auto-executed on python startup)"
if command -v locate >/dev/null 2>&1; then
    locate '*.pth' 2>/dev/null
else
    find / -xdev -name '*.pth' 2>/dev/null
fi | while read -r pf; do
    if grep -q "^import" "$pf" 2>/dev/null; then
        finding "HIGH" "Python .pth with top-level import: $pf"
        grep -n "^import" "$pf" 2>/dev/null | sed "s|^|    |" | tee -a "$REPORT"
    fi
done

# ===================== 0x33 motd =====================
section "0x33 MOTD (Message Of The Day) Backdoor"
for d in /etc/update-motd.d /etc/motd /etc/profile.d; do
    if [ -e "$d" ]; then
        echo "### $d" | tee -a "$REPORT"
        if [ -d "$d" ]; then
            find "$d" -type f 2>/dev/null | while read -r mf; do
                echo "--- $mf ---" | tee -a "$REPORT"
                cat "$mf" 2>/dev/null | tee -a "$REPORT"
            done
        else
            cat "$d" 2>/dev/null | tee -a "$REPORT"
        fi
    fi
done

# ===================== 0x34 Recent artifacts summary (IOC time window) =====================
if [ "$SKIP_RECENT" -eq 0 ]; then
    section "0x34 Recent Artifacts (last 7 days) -- IOC time window"
    subsection "Files modified in last 7 days under key locations (full list written to report)"
    for loc in /etc /usr/bin /usr/sbin /bin /sbin /tmp /dev/shm /var/tmp /home; do
        if [ -d "$loc" ]; then
            echo "### $loc" | tee -a "$REPORT"
            find "$loc" -xdev -mtime -7 -type f 2>/dev/null | sort -u | tee -a "$REPORT"
        fi
    done
fi

# ===================== Final summary =====================
section "Summary"
{
    echo "Full report : $REPORT"
    echo "Findings    : $FINDINGS"
    echo ""
    echo "Findings by level:"
    for lvl in HIGH MED INFO; do
        c=$(grep -c "^\[$lvl\]" "$FINDINGS" 2>/dev/null || echo 0)
        echo "  $lvl : $c"
    done
    echo ""
    echo "Top findings (HIGH first):"
} | tee -a "$REPORT"

if [ -s "$FINDINGS" ]; then
    grep -E '^\[(HIGH|MED)\]' "$FINDINGS" | tee -a "$REPORT"
    echo "" | tee -a "$REPORT"
    echo "All findings also saved to: $FINDINGS" | tee -a "$REPORT"
else
    echo "  No explicit findings flagged (manual review of full report recommended)." | tee -a "$REPORT"
fi

echo ""
echo "Baseline check complete. Report: $REPORT"
echo "Findings : $FINDINGS"
exit 0
