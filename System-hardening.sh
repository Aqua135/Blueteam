#!/bin/bash

# System Hardening Script for Security Competitions
# Requires root privileges
# Run this BEFORE the firewall script

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BLUE_TEAM_USER="blueteam"
BLUE_TEAM_PASSWORD="Bl00T3@m!2024#Secure"
BACKUP_DIR="/root/security_backups"
LOG_DIR="/var/log/blueteam"
ALLOWED_USERS=("root" "$BLUE_TEAM_USER") # Add users you want to keep

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        exit 1
    fi
}

# Create necessary directories
create_directories() {
    echo -e "${BLUE}[*] Creating necessary directories...${NC}"
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$LOG_DIR"
    chmod 700 "$BACKUP_DIR"
    chmod 700 "$LOG_DIR"
    echo -e "${GREEN}[+] Directories created${NC}"
}

# Get system information
get_system_info() {
    echo -e "${BLUE}[*] Gathering system information...${NC}"
    
    INFO_FILE="$BACKUP_DIR/system_info_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "====== System Information ======"
        echo "Date: $(date)"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
        echo ""
        echo "====== Network Interfaces ======"
        ip addr show
        echo ""
        echo "====== Listening Services ======"
        ss -tulpn
        echo ""
        echo "====== Running Processes ======"
        ps aux --sort=-%mem | head -20
        echo ""
        echo "====== Current Users ======"
        cat /etc/passwd
        echo ""
        echo "====== Sudo Users ======"
        grep -Po '^sudo.+:\K.*$' /etc/group
        echo ""
        echo "====== Installed Packages ======"
        if command -v dpkg &> /dev/null; then
            dpkg -l
        elif command -v rpm &> /dev/null; then
            rpm -qa
        fi
        echo ""
        echo "====== Cron Jobs ======"
        for user in $(cut -f1 -d: /etc/passwd); do
            echo "--- Cron for $user ---"
            crontab -u "$user" -l 2>/dev/null
        done
        echo ""
        echo "====== System Crontab ======"
        cat /etc/crontab 2>/dev/null
        ls -la /etc/cron.* 2>/dev/null
    } > "$INFO_FILE"
    
    echo -e "${GREEN}[+] System info saved to: $INFO_FILE${NC}"
}

# Create blue team user
create_blue_team_user() {
    echo -e "${BLUE}[*] Creating blue team user...${NC}"
    
    if id "$BLUE_TEAM_USER" &>/dev/null; then
        echo -e "${YELLOW}[!] User $BLUE_TEAM_USER already exists${NC}"
    else
        useradd -m -s /bin/bash "$BLUE_TEAM_USER"
        echo -e "${GREEN}[+] User $BLUE_TEAM_USER created${NC}"
    fi
    
    # Set password
    echo "$BLUE_TEAM_USER:$BLUE_TEAM_PASSWORD" | chpasswd
    
    # Add to sudo group
    usermod -aG sudo "$BLUE_TEAM_USER" 2>/dev/null || usermod -aG wheel "$BLUE_TEAM_USER" 2>/dev/null
    
    echo -e "${GREEN}[+] Blue team user configured${NC}"
    echo -e "${YELLOW}[!] Username: $BLUE_TEAM_USER${NC}"
    echo -e "${YELLOW}[!] Password: $BLUE_TEAM_PASSWORD${NC}"
}

# Delete unauthorized users
delete_unauthorized_users() {
    echo -e "${BLUE}[*] Removing unauthorized users...${NC}"
    
    # Backup /etc/passwd and /etc/shadow
    cp /etc/passwd "$BACKUP_DIR/passwd.backup"
    cp /etc/shadow "$BACKUP_DIR/shadow.backup"
    
    # Get all users with UID >= 1000 (regular users)
    USERS=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd)
    
    for user in $USERS; do
        # Check if user is in allowed list
        if [[ ! " ${ALLOWED_USERS[@]} " =~ " ${user} " ]]; then
            echo -e "${YELLOW}[!] Removing user: $user${NC}"
            userdel -r "$user" 2>/dev/null
        fi
    done
    
    echo -e "${GREEN}[+] Unauthorized users removed${NC}"
}

# Change passwords for remaining users
change_passwords() {
    echo -e "${BLUE}[*] Changing passwords for authorized users...${NC}"
    
    for user in "${ALLOWED_USERS[@]}"; do
        if id "$user" &>/dev/null; then
            # Generate a strong random password
            NEW_PASS=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-20)"!@#"
            echo "$user:$NEW_PASS" | chpasswd
            echo "$user:$NEW_PASS" >> "$BACKUP_DIR/passwords.txt"
            echo -e "${GREEN}[+] Password changed for: $user${NC}"
        fi
    done
    
    chmod 600 "$BACKUP_DIR/passwords.txt"
    echo -e "${YELLOW}[!] Passwords saved to: $BACKUP_DIR/passwords.txt${NC}"
}

# Create backups
create_backups() {
    echo -e "${BLUE}[*] Creating system backups...${NC}"
    
    # Backup important configuration files
    cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.backup" 2>/dev/null
    cp /etc/sudoers "$BACKUP_DIR/sudoers.backup" 2>/dev/null
    cp -r /etc/pam.d "$BACKUP_DIR/pam.d.backup" 2>/dev/null
    cp /etc/login.defs "$BACKUP_DIR/login.defs.backup" 2>/dev/null
    
    # Backup web directories if they exist
    if [ -d /var/www ]; then
        tar -czf "$BACKUP_DIR/var_www_backup.tar.gz" /var/www 2>/dev/null
    fi
    
    if [ -d /srv/www ]; then
        tar -czf "$BACKUP_DIR/srv_www_backup.tar.gz" /srv/www 2>/dev/null
    fi
    
    echo -e "${GREEN}[+] Backups created in: $BACKUP_DIR${NC}"
}

# Install security tools
install_tools() {
    echo -e "${BLUE}[*] Installing security tools...${NC}"
    
    # Detect package manager
    if command -v apt-get &> /dev/null; then
        apt-get update -qq
        apt-get install -y fail2ban auditd rkhunter chkrootkit aide ufw logwatch 2>/dev/null
    elif command -v yum &> /dev/null; then
        yum install -y fail2ban audit rkhunter aide firewalld logwatch 2>/dev/null
    elif command -v dnf &> /dev/null; then
        dnf install -y fail2ban audit rkhunter aide firewalld logwatch 2>/dev/null
    else
        echo -e "${RED}[-] Unknown package manager${NC}"
    fi
    
    echo -e "${GREEN}[+] Security tools installed${NC}"
}

# Make initial configuration changes
configure_system() {
    echo -e "${BLUE}[*] Applying initial hardening configurations...${NC}"
    
    # SSH Hardening
    if [ -f /etc/ssh/sshd_config ]; then
        sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
        sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
        sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
        sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
        echo -e "${GREEN}[+] SSH hardened${NC}"
    fi
    
    # Disable unnecessary services
    for service in avahi-daemon cups bluetooth; do
        systemctl stop "$service" 2>/dev/null
        systemctl disable "$service" 2>/dev/null
    done
    
    # Set password policies
    if [ -f /etc/login.defs ]; then
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
        sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    14/' /etc/login.defs
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
    fi
    
    # Secure shared memory
    if ! grep -q "tmpfs /run/shm" /etc/fstab; then
        echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
    fi
    
    echo -e "${GREEN}[+] System configurations applied${NC}"
}

# Set directory permissions
set_directory_permissions() {
    echo -e "${BLUE}[*] Setting directory permissions...${NC}"
    
    # Important system directories
    IMPORTANT_DIRS=(
        "/etc"
        "/boot"
        "/usr/bin"
        "/usr/sbin"
        "/sbin"
        "/bin"
    )
    
    for dir in "${IMPORTANT_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            # Set ownership to root:root
            chown -R root:root "$dir"
            # Remove write permissions for group and others on executables
            find "$dir" -type f -executable -exec chmod go-w {} \; 2>/dev/null
            echo -e "${GREEN}[+] Secured: $dir${NC}"
        fi
    done
    
    # Secure sensitive files
    chmod 600 /etc/shadow 2>/dev/null
    chmod 600 /etc/gshadow 2>/dev/null
    chmod 644 /etc/passwd 2>/dev/null
    chmod 644 /etc/group 2>/dev/null
    
    # Give blueteam user ownership of log directory
    chown -R "$BLUE_TEAM_USER:$BLUE_TEAM_USER" "$LOG_DIR"
    
    echo -e "${GREEN}[+] Directory permissions configured${NC}"
}

# Enable comprehensive logging
enable_logging() {
    echo -e "${BLUE}[*] Enabling comprehensive logging...${NC}"
    
    # Enable auditd
    systemctl enable auditd 2>/dev/null
    systemctl start auditd 2>/dev/null
    
    # Add audit rules
    if command -v auditctl &> /dev/null; then
        auditctl -w /etc/passwd -p wa -k user_modification
        auditctl -w /etc/shadow -p wa -k user_modification
        auditctl -w /etc/group -p wa -k group_modification
        auditctl -w /etc/sudoers -p wa -k sudoers_modification
        auditctl -w /var/log/auth.log -p wa -k auth_log
        auditctl -w /var/log/secure -p wa -k secure_log
    fi
    
    # Configure rsyslog for better logging
    if [ -f /etc/rsyslog.conf ]; then
        # Ensure auth logs are being captured
        if ! grep -q "auth,authpriv.*" /etc/rsyslog.conf; then
            echo "auth,authpriv.* /var/log/auth.log" >> /etc/rsyslog.conf
        fi
        systemctl restart rsyslog 2>/dev/null
    fi
    
    # Set up logrotate for blueteam logs
    cat > /etc/logrotate.d/blueteam <<EOF
$LOG_DIR/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 $BLUE_TEAM_USER $BLUE_TEAM_USER
}
EOF
    
    echo -e "${GREEN}[+] Logging enabled and configured${NC}"
}

# Print summary
print_summary() {
    echo -e "\n${GREEN}=====================================${NC}"
    echo -e "${GREEN}  System Hardening Complete${NC}"
    echo -e "${GREEN}=====================================${NC}"
    echo -e "${YELLOW}Blue Team User: $BLUE_TEAM_USER${NC}"
    echo -e "${YELLOW}Password saved in: $BACKUP_DIR/passwords.txt${NC}"
    echo -e "${YELLOW}Backups location: $BACKUP_DIR${NC}"
    echo -e "${YELLOW}Logs location: $LOG_DIR${NC}"
    echo -e "${GREEN}=====================================${NC}"
    echo -e "${BLUE}Next steps:${NC}"
    echo -e "1. Review system info: cat $BACKUP_DIR/system_info_*.txt"
    echo -e "2. Run the firewall script to configure iptables"
    echo -e "3. Monitor logs in $LOG_DIR"
    echo -e "${GREEN}=====================================${NC}\n"
}

# Main execution
main() {
    clear
    echo -e "${GREEN}=====================================${NC}"
    echo -e "${GREEN}  System Hardening Script${NC}"
    echo -e "${GREEN}=====================================${NC}\n"
    
    check_root
    create_directories
    get_system_info
    create_blue_team_user
    delete_unauthorized_users
    change_passwords
    create_backups
    install_tools
    configure_system
    set_directory_permissions
    enable_logging
    print_summary
    
    echo -e "${GREEN}[+] System hardening completed successfully!${NC}"
}

main
