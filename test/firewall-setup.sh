#!/bin/bash

# IPTables Firewall Manager
# Requires root privileges

BACKUP_DIR="/etc/iptables"
BACKUP_FILE="$BACKUP_DIR/iptables.backup"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        exit 1
    fi
}

# Create backup directory if it doesn't exist
create_backup_dir() {
    if [[ ! -d "$BACKUP_DIR" ]]; then
        mkdir -p "$BACKUP_DIR"
        echo -e "${GREEN}Created backup directory: $BACKUP_DIR${NC}"
    fi
}

# Display current rules
show_current_rules() {
    echo -e "\n${YELLOW}Current IPTables Rules:${NC}"
    iptables -L -v -n --line-numbers
}

# Block all ports except SSH (22) and loopback
block_all_ports() {
    echo -e "${YELLOW}Blocking all ports except SSH (22) and loopback...${NC}"
    
    # Flush existing rules
    iptables -F
    iptables -X
    
    # Set default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    
    # Allow established and related connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH (to prevent lockout)
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    echo -e "${GREEN}All ports blocked except SSH (22)${NC}"
    show_current_rules
}

# Block specific ports
block_specific_ports() {
    echo -e "${YELLOW}Enter ports to block (space-separated, e.g., 80 443 8080):${NC}"
    read -r ports
    
    if [[ -z "$ports" ]]; then
        echo -e "${RED}No ports specified${NC}"
        return
    fi
    
    # Initialize if rules are empty
    if ! iptables -L INPUT -n | grep -q "Chain INPUT"; then
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
    fi
    
    for port in $ports; do
        if [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 ]] && [[ "$port" -le 65535 ]]; then
            iptables -A INPUT -p tcp --dport "$port" -j DROP
            iptables -A INPUT -p udp --dport "$port" -j DROP
            echo -e "${GREEN}Blocked port: $port${NC}"
        else
            echo -e "${RED}Invalid port: $port${NC}"
        fi
    done
    
    show_current_rules
}

# Allow specific ports
allow_specific_ports() {
    echo -e "${YELLOW}Enter ports to allow (space-separated, e.g., 80 443 8080):${NC}"
    read -r ports
    
    if [[ -z "$ports" ]]; then
        echo -e "${RED}No ports specified${NC}"
        return
    fi
    
    for port in $ports; do
        if [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 ]] && [[ "$port" -le 65535 ]]; then
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
            iptables -A INPUT -p udp --dport "$port" -j ACCEPT
            echo -e "${GREEN}Allowed port: $port${NC}"
        else
            echo -e "${RED}Invalid port: $port${NC}"
        fi
    done
    
    show_current_rules
}

# Create backup
create_backup() {
    create_backup_dir
    
    echo -e "${YELLOW}Creating backup of current IPTables rules...${NC}"
    iptables-save > "$BACKUP_FILE"
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}Backup created successfully: $BACKUP_FILE${NC}"
        echo -e "${GREEN}Backup date: $(date)${NC}"
    else
        echo -e "${RED}Failed to create backup${NC}"
    fi
}

# Restore backup
restore_backup() {
    if [[ ! -f "$BACKUP_FILE" ]]; then
        echo -e "${RED}Backup file not found: $BACKUP_FILE${NC}"
        return
    fi
    
    echo -e "${YELLOW}Restoring IPTables rules from backup...${NC}"
    iptables-restore < "$BACKUP_FILE"
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}Backup restored successfully${NC}"
        show_current_rules
    else
        echo -e "${RED}Failed to restore backup${NC}"
    fi
}

# Flush all rules (reset to defaults)
flush_rules() {
    echo -e "${YELLOW}Flushing all IPTables rules...${NC}"
    iptables -F
    iptables -X
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    echo -e "${GREEN}All rules flushed. Firewall is now open.${NC}"
    show_current_rules
}

# Main menu
show_menu() {
    echo -e "\n${GREEN}================================${NC}"
    echo -e "${GREEN}  IPTables Firewall Manager${NC}"
    echo -e "${GREEN}================================${NC}"
    echo "1) Block all ports (except SSH)"
    echo "2) Block specific ports"
    echo "3) Allow specific ports"
    echo "4) Show current rules"
    echo "5) Create backup"
    echo "6) Restore backup"
    echo "7) Flush all rules (reset)"
    echo "8) Exit"
    echo -e "${GREEN}================================${NC}"
    echo -n "Select an option: "
}

# Main program
main() {
    check_root
    
    while true; do
        show_menu
        read -r choice
        
        case $choice in
            1) block_all_ports ;;
            2) block_specific_ports ;;
            3) allow_specific_ports ;;
            4) show_current_rules ;;
            5) create_backup ;;
            6) restore_backup ;;
            7) flush_rules ;;
            8) echo -e "${GREEN}Exiting...${NC}"; exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}" ;;
        esac
        
        echo -e "\nPress Enter to continue..."
        read -r
    done
}

main
