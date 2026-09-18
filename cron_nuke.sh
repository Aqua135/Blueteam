#!/usr/bin/env bash
#
# nuke_cron.sh — Remove all cron jobs on a Linux host.
# Run as root. Intended for blue-team incident cleanup (e.g. RVB competition).
#
# Clears:
#   - Every user's crontab (via `crontab -r`)
#   - /etc/crontab
#   - /etc/cron.d/*
#   - /etc/cron.{hourly,daily,weekly,monthly}/* (job files, dirs left intact)
#   - /var/spool/cron/crontabs/* (raw spool, belt-and-suspenders)
#   - Pending `at` jobs
#
# Usage: sudo ./nuke_cron.sh [--dry-run]

set -euo pipefail

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

run() {
    if $DRY_RUN; then
        echo "[dry-run] $*"
    else
        eval "$@"
    fi
}

echo "=== Nuking all user crontabs ==="
# Every local user (from /etc/passwd), not just ones with existing spool files,
# in case a crontab was hidden/aliased in a way `ls` on the spool dir would miss.
while IFS=: read -r username _ _ _ _ _ _; do
    if crontab -u "$username" -l >/dev/null 2>&1; then
        echo "Removing crontab for: $username"
        run "crontab -u '$username' -r"
    fi
done < /etc/passwd

echo "=== Clearing system-wide cron files ==="
run "truncate -s 0 /etc/crontab 2>/dev/null || true"
run "rm -f /etc/cron.d/* 2>/dev/null || true"
run "rm -f /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* 2>/dev/null || true"

echo "=== Clearing raw cron spool ==="
run "rm -f /var/spool/cron/crontabs/* 2>/dev/null || true"
run "rm -f /var/spool/cron/*/* 2>/dev/null || true"   # some distros use /var/spool/cron/<user>

echo "=== Clearing pending 'at' jobs ==="
if command -v atq >/dev/null 2>&1; then
    atq | awk '{print $1}' | while read -r job; do
        echo "Removing at job: $job"
        run "atrm '$job'"
    done
fi

echo "=== Restarting cron service ==="
for svc in cron crond; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
        run "systemctl restart '$svc'"
    fi
done

echo "Done. Note: this does not touch systemd timers (systemctl list-timers)"
echo "or persistence in init scripts/rc.local — check those separately if in scope."
