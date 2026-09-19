#!/usr/bin/env bash
#
# reset_all_passwords.sh — Set every local user's password to a given value.
# Run as root. Intended for blue-team lockout after a compromise (e.g. RVB competition).
#
# By default only touches "real" accounts (UID >= 1000, has a login shell,
# excludes 'nobody'), so you don't break system/service accounts.
# Pass --all to include every account in /etc/passwd instead.
#
# Usage:
#   sudo ./reset_all_passwords.sh                 # prompts for password (hidden input)
#   sudo ./reset_all_passwords.sh 'NewP@ssw0rd!'   # password on CLI (visible in shell history!)
#   sudo ./reset_all_passwords.sh --all 'NewP@ssw0rd!'

set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

ALL_ACCOUNTS=false
if [[ "${1:-}" == "--all" ]]; then
    ALL_ACCOUNTS=true
    shift
fi

PASSWORD="${1:-}"
if [[ -z "$PASSWORD" ]]; then
    read -r -s -p "Enter new password for all users: " PASSWORD
    echo
    read -r -s -p "Confirm password: " PASSWORD_CONFIRM
    echo
    if [[ "$PASSWORD" != "$PASSWORD_CONFIRM" ]]; then
        echo "Passwords did not match." >&2
        exit 1
    fi
fi

MIN_UID=$(awk -F= '/^UID_MIN/{print $2}' /etc/login.defs 2>/dev/null | tr -d ' \t' || echo 1000)
MIN_UID=${MIN_UID:-1000}

users=()
while IFS=: read -r username _ uid _ _ _ shell; do
    if $ALL_ACCOUNTS; then
        users+=("$username")
        continue
    fi
    # Skip nologin/false shells and anything below the "real user" UID floor.
    if [[ "$uid" -ge "$MIN_UID" && "$shell" != *nologin && "$shell" != */false ]]; then
        users+=("$username")
    fi
done < /etc/passwd

if [[ ${#users[@]} -eq 0 ]]; then
    echo "No matching users found."
    exit 0
fi

echo "=== Resetting password for ${#users[@]} account(s) ==="
for u in "${users[@]}"; do
    if echo "${u}:${PASSWORD}" | chpasswd; then
        echo "Reset: $u"
    else
        echo "FAILED: $u" >&2
    fi
done

echo "Done. Consider also: 'passwd -e <user>' to force a change at next login,"
echo "and rotating root's password separately if root wasn't in scope above."
