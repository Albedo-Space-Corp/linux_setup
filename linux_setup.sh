#!/bin/bash

# Linux Setup Script for Albedo
# Usage: sudo ./linux-setup.sh [general|FSW|EE]
# 
# This script automates the setup process for different user types:
# - general: Basic compliance setup (Intune, Edge, ClamAV)
# - FSW: Flight Software development environment  
# - EE: Electrical Engineering development environment

set -e  # Exit on error for critical failures
set -o pipefail  # Fail on pipe errors

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/linux-setup-$(date +%Y%m%d-%H%M%S).log"
FAILED_PACKAGES=()
MANUAL_STEPS=()
RESET_ADMIN_PASSWORD=false
SKIP_PROMPTS=false

# Utility functions
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to generate a secure random password
generate_password() {
    local length=${1:-24}
    # Use /dev/urandom for cryptographic randomness, filtered to printable chars
    { LC_ALL=C tr -dc 'A-Za-z0-9!@#$%^&*()_+-=' < /dev/urandom || true; } | head -c "$length"
}

# Function to prompt for admin password or auto-generate one
# Sets ADMIN_PASSWORD and ADMIN_PASSWORD_GENERATED (true if auto-generated)
prompt_admin_password() {
    ADMIN_PASSWORD_GENERATED=false

    if [[ "$SKIP_PROMPTS" == "true" ]] || ! [[ -t 0 ]]; then
        # Non-interactive: auto-generate
        ADMIN_PASSWORD=$(generate_password 24)
        ADMIN_PASSWORD_GENERATED=true
        return 0
    fi

    echo ""
    echo -e "${YELLOW}Set the password for the albedo_admin account.${NC}"
    echo -e "${YELLOW}Press Enter to auto-generate a secure password instead.${NC}"
    echo ""

    while true; do
        read -s -r -p "Enter password (or Enter to auto-generate): " user_pw
        echo ""

        if [[ -z "$user_pw" ]]; then
            ADMIN_PASSWORD=$(generate_password 24)
            ADMIN_PASSWORD_GENERATED=true
            return 0
        fi

        local pw_errors=()
        if [[ ${#user_pw} -lt 12 ]]; then
            pw_errors+=("at least 12 characters")
        fi
        if ! [[ "$user_pw" =~ [A-Z] ]]; then
            pw_errors+=("an uppercase letter")
        fi
        if ! [[ "$user_pw" =~ [a-z] ]]; then
            pw_errors+=("a lowercase letter")
        fi
        if ! [[ "$user_pw" =~ [0-9] ]]; then
            pw_errors+=("a number")
        fi
        if ! [[ "$user_pw" =~ [^a-zA-Z0-9] ]]; then
            pw_errors+=("a special character")
        fi
        if [[ ${#pw_errors[@]} -gt 0 ]]; then
            echo -e "${RED}Password must contain: $(IFS=', '; echo "${pw_errors[*]}"). Try again.${NC}"
            continue
        fi

        read -s -r -p "Confirm password: " user_pw_confirm
        echo ""

        if [[ "$user_pw" != "$user_pw_confirm" ]]; then
            echo -e "${RED}Passwords do not match. Try again.${NC}"
            continue
        fi

        ADMIN_PASSWORD="$user_pw"
        unset user_pw user_pw_confirm
        return 0
    done
}

# Function to check if script is running interactively
is_interactive() {
    [[ $- == *i* ]] && [[ -t 0 ]] && [[ -t 1 ]]
}

log_success() {
    echo -e "${GREEN}✓ $1${NC}" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}✗ $1${NC}" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}⚠ $1${NC}" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}ℹ $1${NC}" | tee -a "$LOG_FILE"
}

# Function to attempt package installation with error handling
install_package() {
    local package=$1
    local description=${2:-$package}
    
    log_info "Installing $description..."
    
    if dpkg -l | grep -q "^ii  $package "; then
        local version=$(dpkg -l | grep "^ii  $package " | awk '{print $3}' | head -1)
        log_success "$description already installed (version $version)"
        return 0
    fi
    
    if sudo apt-get install -y "$package" >> "$LOG_FILE" 2>&1; then
        local version=$(dpkg -l | grep "^ii  $package " | awk '{print $3}' | head -1)
        log_success "$description installed successfully (version $version)"
        return 0
    else
        log_error "Failed to install $description"
        FAILED_PACKAGES+=("$package - $description")
        return 1
    fi
}

# Special Git installation to avoid 3.x breaking changes
install_git() {
    log_info "Installing Git (pinned to 2.x series)..."
    
    if command -v git &> /dev/null; then
        local git_version=$(git --version | cut -d' ' -f3)
        log_success "Git already installed (version $git_version)"
        return 0
    fi
    
    # Check what Git versions are available
    local available_git=$(apt list git 2>/dev/null | grep -v WARNING | tail -n +2 | head -1)
    if echo "$available_git" | grep -q "git/.*2\." >> "$LOG_FILE" 2>&1; then
        if sudo apt-get install -y git >> "$LOG_FILE" 2>&1; then
            local git_version=$(git --version | cut -d' ' -f3)
            log_success "Git installed successfully (version $git_version)"
            return 0
        else
            log_error "Failed to install Git"
            FAILED_PACKAGES+=("git - Git (2.x series)")
            return 1
        fi
    else
        log_warning "Git 3.x detected in repositories - investigating alternatives..."
        # Try to install from specific repository or use fallback
        if sudo apt-get install -y git=2* >> "$LOG_FILE" 2>&1; then
            local git_version=$(git --version | cut -d' ' -f3)
            log_success "Git installed successfully (version $git_version)"
            return 0
        else
            log_error "Could not install safe Git version - manual intervention required"
            FAILED_PACKAGES+=("git - Git (version constraint failed)")
            return 1
        fi
    fi
}

# Function to download and install .deb packages
install_deb_package() {
    local url=$1
    local filename=$2
    local description=$3
    
    log_info "Downloading and installing $description..."
    
    # Try to detect if already installed using common package names
    local package_check=""
    case "$description" in
        *"Visual Studio Code"*) package_check="code" ;;
        *"SonicWall"*) package_check="netextender" ;;
        *) package_check="${description,,}" ;;
    esac
    
    if command -v "$package_check" &> /dev/null || dpkg -l | grep -q "$package_check"; then
        if command -v "$package_check" &> /dev/null; then
            local version=$($package_check --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            if [ -n "$version" ]; then
                log_success "$description already installed (version $version)"
            else
                log_success "$description already installed"
            fi
        else
            local version=$(dpkg -l | grep "$package_check" | awk '{print $3}' | head -1)
            log_success "$description already installed (version $version)"
        fi
        return 0
    fi
    
    if curl -L "$url" -o "/tmp/$filename" >> "$LOG_FILE" 2>&1; then
        if sudo DEBIAN_FRONTEND=noninteractive apt install -y "/tmp/$filename" >> "$LOG_FILE" 2>&1; then
            rm -f "/tmp/$filename"
            # Try to get version after installation
            if command -v "$package_check" &> /dev/null; then
                local version=$($package_check --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
                if [ -n "$version" ]; then
                    log_success "$description installed successfully (version $version)"
                else
                    log_success "$description installed successfully"
                fi
            else
                log_success "$description installed successfully"
            fi
            return 0
        else
            log_error "Failed to install $description"
            FAILED_PACKAGES+=("$filename - $description")
            rm -f "/tmp/$filename"
            return 1
        fi
    else
        log_error "Failed to download $description"
        FAILED_PACKAGES+=("$filename - $description (download failed)")
        return 1
    fi
}

# TPM2 auto-unlock setup via Clevis
# Binds LUKS encryption to the TPM2 chip so the drive auto-unlocks at boot
# PCR 7 = Secure Boot state (detects tampering, stable across kernel updates)
setup_tpm2_autounlock() {
    log_info "Setting up TPM2 LUKS auto-unlock..."

    # Check for TPM2 device — /dev/tpmrm0 is TPM2-specific (doesn't exist on TPM 1.2)
    if [ -e /dev/tpmrm0 ]; then
        log_info "TPM2 resource manager device found (/dev/tpmrm0)"
    elif [ -e /dev/tpm0 ]; then
        # /dev/tpm0 exists on both TPM 1.2 and 2.0 — verify version if tools are available
        if command -v tpm2_getcap &>/dev/null && tpm2_getcap properties-fixed 2>/dev/null | grep -q 'TPM_PT_FAMILY_INDICATOR.*2.0'; then
            log_info "TPM2 device confirmed via tpm2_getcap"
        else
            log_warning "TPM device found but cannot confirm TPM2 - skipping auto-unlock setup"
            MANUAL_STEPS+=("TPM2: Found /dev/tpm0 but could not confirm TPM2. Verify BIOS settings and re-run.")
            return 0
        fi
    else
        log_warning "No TPM device found - skipping auto-unlock setup"
        MANUAL_STEPS+=("TPM2: No TPM device detected. Enable TPM in BIOS and re-run to enable auto-unlock.")
        return 0
    fi

    # Auto-detect LUKS partition
    LUKS_DEV=$(lsblk -rno NAME,FSTYPE | awk '$2=="crypto_LUKS"{print "/dev/"$1}' | head -1)
    if [ -z "$LUKS_DEV" ]; then
        log_warning "No LUKS partition detected - skipping auto-unlock setup"
        return 0
    fi

    log_info "Detected LUKS partition: $LUKS_DEV"

    # Check if Clevis is already bound to TPM2 on this device
    if command -v clevis &>/dev/null && clevis luks list -d "$LUKS_DEV" 2>/dev/null | grep -q tpm2; then
        log_success "TPM2 auto-unlock already configured for $LUKS_DEV"
        return 0
    fi

    # TPM2 binding requires the LUKS passphrase — skip in non-interactive mode
    if [[ "$SKIP_PROMPTS" == "true" ]] || ! [[ -t 0 ]]; then
        log_warning "TPM2 auto-unlock requires LUKS passphrase - skipping in non-interactive mode"
        MANUAL_STEPS+=("TPM2 AUTO-UNLOCK: Run setup interactively to enable (requires LUKS passphrase)")
        return 0
    fi

    # Prompt for LUKS passphrase
    echo ""
    echo -e "${YELLOW}TPM2 Auto-Unlock Setup${NC}"
    echo -e "${YELLOW}Enter your LUKS disk encryption passphrase to enable auto-unlock at boot.${NC}"
    echo -e "${YELLOW}Your original passphrase will still work as a fallback.${NC}"
    echo ""
    # Prompt twice and require a match — hidden input has no typo feedback
    while :; do
        read -s -r -p "Enter LUKS passphrase: " LUKS_PASSPHRASE
        echo ""
        read -s -r -p "Confirm LUKS passphrase: " LUKS_PASSPHRASE_CONFIRM
        echo ""
        if [ "$LUKS_PASSPHRASE" = "$LUKS_PASSPHRASE_CONFIRM" ]; then
            unset LUKS_PASSPHRASE_CONFIRM
            break
        fi
        unset LUKS_PASSPHRASE_CONFIRM
        echo -e "${YELLOW}Passphrases do not match. Try again.${NC}"
    done

    # Verify the passphrase is correct before proceeding
    if ! echo -n "$LUKS_PASSPHRASE" | cryptsetup luksOpen --test-passphrase --key-file - "$LUKS_DEV" 2>/dev/null; then
        log_error "Invalid LUKS passphrase - skipping TPM2 auto-unlock"
        unset LUKS_PASSPHRASE
        return 1
    fi

    # Install Clevis packages
    install_package "clevis" "Clevis"
    install_package "clevis-tpm2" "Clevis TPM2"
    install_package "clevis-luks" "Clevis LUKS"
    install_package "clevis-initramfs" "Clevis Initramfs"

    # Create secure temp files for keyfile-based operations
    LUKS_KEYFILE=$(mktemp /tmp/luks_key.XXXXXX)
    TEMP_KEYFILE=$(mktemp /tmp/luks_tmp.XXXXXX)
    chmod 600 "$LUKS_KEYFILE" "$TEMP_KEYFILE"

    # Ensure keyfiles are always cleaned up, even on unexpected exit (set -e)
    trap 'shred -u "$LUKS_KEYFILE" "$TEMP_KEYFILE" 2>/dev/null; trap - RETURN EXIT' RETURN EXIT

    echo -n "$LUKS_PASSPHRASE" > "$LUKS_KEYFILE"
    unset LUKS_PASSPHRASE

    # Generate a cryptographically random temp key — Clevis can't authorize against
    # argon2id (Ubuntu's default LUKS2 KDF), so we add a pbkdf2 key, bind with it, then remove it
    dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 -w0 > "$TEMP_KEYFILE"

    # Find two free LUKS key slots (one for temp key, one for Clevis).
    # LUKS2 luksDump only lists ALLOCATED slots under "Keyslots:", so we
    # enumerate used slots and take the complement from the valid range.
    # LUKS1 lists all 8 slots explicitly as "Key Slot N: ENABLED|DISABLED".
    declare -A USED_SLOTS=()
    LUKS_VERSION=$(cryptsetup luksDump "$LUKS_DEV" | awk '/^Version:/{print $2+0; exit}')
    if [ "$LUKS_VERSION" = "1" ]; then
        MAX_SLOT=7
    else
        MAX_SLOT=31
    fi
    while read -r slot; do
        [ -n "$slot" ] && USED_SLOTS[$slot]=1
    done < <(cryptsetup luksDump "$LUKS_DEV" | awk '
        /^Keyslots:/                    { in_ks=1; next }
        /^[^[:space:]]/                 { in_ks=0 }
        in_ks && /^[[:space:]]+[0-9]+:/ { gsub(/:/, "", $1); print $1+0 }
        /^Key Slot [0-9]+: ENABLED/     { print $3+0 }
    ')
    FREE_SLOTS=()
    for slot in $(seq 0 "$MAX_SLOT"); do
        if [ -z "${USED_SLOTS[$slot]:-}" ]; then
            FREE_SLOTS+=("$slot")
        fi
    done
    if [ "${#FREE_SLOTS[@]}" -lt 2 ]; then
        log_error "Need at least 2 free LUKS key slots (found ${#FREE_SLOTS[@]} of $((MAX_SLOT+1)))"
        return 1
    fi
    TEMP_SLOT="${FREE_SLOTS[0]}"
    CLEVIS_SLOT="${FREE_SLOTS[1]}"
    log_info "Using LUKS slot $TEMP_SLOT for temp key, slot $CLEVIS_SLOT for Clevis"

    # Add temporary pbkdf2 key
    log_info "Adding temporary LUKS key for Clevis binding..."
    if cryptsetup luksAddKey --key-slot "$TEMP_SLOT" --pbkdf pbkdf2 --key-file "$LUKS_KEYFILE" "$LUKS_DEV" "$TEMP_KEYFILE" >> "$LOG_FILE" 2>&1; then
        log_success "Temporary key added to LUKS slot $TEMP_SLOT"
    else
        log_error "Failed to add temporary LUKS key"
        return 1
    fi

    # Bind Clevis to TPM2 (PCR 7 = Secure Boot state)
    log_info "Binding Clevis to TPM2 (this may take a moment)..."
    if clevis luks bind -d "$LUKS_DEV" -s "$CLEVIS_SLOT" -k "$TEMP_KEYFILE" tpm2 '{"pcr_bank":"sha256","pcr_ids":"7"}' >> "$LOG_FILE" 2>&1; then
        log_success "Clevis bound to TPM2 on slot $CLEVIS_SLOT (PCR 7)"
    else
        log_error "Failed to bind Clevis to TPM2 - cleaning up temporary key"
        cryptsetup luksKillSlot --key-file "$LUKS_KEYFILE" "$LUKS_DEV" "$TEMP_SLOT" >> "$LOG_FILE" 2>&1
        return 1
    fi

    # Remove temporary key
    log_info "Removing temporary key from slot $TEMP_SLOT..."
    if cryptsetup luksKillSlot --key-file "$LUKS_KEYFILE" "$LUKS_DEV" "$TEMP_SLOT" >> "$LOG_FILE" 2>&1; then
        log_success "Temporary key removed from slot $TEMP_SLOT"
    else
        log_warning "Could not remove temporary key from slot $TEMP_SLOT - remove manually: sudo cryptsetup luksKillSlot $LUKS_DEV $TEMP_SLOT"
    fi

    # Rebuild initramfs so auto-unlock happens early enough in boot
    log_info "Rebuilding initramfs (this may take a moment)..."
    if update-initramfs -u -k all >> "$LOG_FILE" 2>&1; then
        log_success "Initramfs rebuilt successfully"
    else
        log_error "Failed to rebuild initramfs - auto-unlock may not work until initramfs is rebuilt"
        return 1
    fi

    log_success "TPM2 auto-unlock configured - drive will auto-unlock at boot"
    log_info "Note: Changing Secure Boot settings will break auto-unlock. Re-run setup to rebind."
}

# Usage function
usage() {
    echo "Usage: $0 [general|FSW|EE] [--reset-admin-password] [--yes]"
    echo ""
    echo "Setup types:"
    echo "  general - Basic Albedo compliance setup (Intune, Edge, ClamAV)"
    echo "  FSW     - Flight Software development environment (includes general)"
    echo "  EE      - Electrical Engineering environment (includes general + extensive tools)"
    echo ""
    echo "Options:"
    echo "  --reset-admin-password  Force password reset for existing albedo_admin user"
    echo "  --yes, -y               Skip confirmation prompts (for automation)"
    echo ""
    echo "The script must be run with sudo privileges."
    echo ""
    echo "Examples:"
    echo "  sudo ./linux-setup.sh general"
    echo "  curl -fsSL <URL> | sudo bash -s -- FSW --yes"
    exit 1
}

# Check if running as root/sudo
check_sudo() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script requires root privileges"
        log_info "Please run: sudo ./linux-setup.sh [general|FSW|EE]"
        exit 1
    fi
    
    if [[ -z "$SUDO_USER" ]]; then
        log_error "This script should be run with sudo, not as root directly"
        log_info "Please run: sudo ./linux-setup.sh [general|FSW|EE]"
        exit 1
    fi
}

# Update system packages
update_system() {
    log_info "Updating system packages..."
    if sudo apt-get update >> "$LOG_FILE" 2>&1; then
        log_success "System package lists updated"
    else
        log_error "Failed to update package lists"
        exit 1
    fi
}

# General setup function (Albedo compliance requirements)
setup_general() {
    log_info "Starting General (Compliance) Setup..."
    
    # Install basic requirements
    install_package "curl" "cURL"
    install_package "gpg" "GPG"
    install_package "build-essential" "Build Essential"
    
    # Attach to Ubuntu Pro
    log_info "Configuring Ubuntu Pro subscription..."
    if sudo pro status 2>/dev/null | grep -q "Subscription: Ubuntu Pro"; then
        log_success "Already attached to Ubuntu Pro"
    else
        if sudo pro attach C13PjYQrKneqABjpyAHjXhgkXDsH8x >> "$LOG_FILE" 2>&1; then
            log_success "Successfully attached to Ubuntu Pro"
        else
            log_error "Failed to attach to Ubuntu Pro"
            FAILED_PACKAGES+=("ubuntu-pro - Ubuntu Pro subscription")
        fi
    fi
    
    # Create albedo_admin user account with full access
    log_info "Setting up albedo_admin user account..."
    
    # Check if we're currently running as albedo_admin
    CURRENT_USER="${SUDO_USER:-$(whoami)}"
    if [[ "$CURRENT_USER" == "albedo_admin" ]]; then
        log_success "Already running as albedo_admin user - skipping account setup"
        return 0
    fi
    
    USER_EXISTS=false
    if id "albedo_admin" &>/dev/null; then
        USER_EXISTS=true
        log_info "albedo_admin user already exists"
        
        # Check if user has sudo access
        if groups albedo_admin | grep -q sudo; then
            log_success "albedo_admin already has sudo access"
        else
            log_info "Adding albedo_admin to sudo group..."
            if sudo usermod -aG sudo albedo_admin >> "$LOG_FILE" 2>&1; then
                log_success "Added albedo_admin to sudo group"
            else
                log_error "Failed to add albedo_admin to sudo group"
                FAILED_PACKAGES+=("albedo_admin - Sudo access")
            fi
        fi
        
        # Determine if we should reset the password
        SHOULD_RESET_PASSWORD=false

        if [[ "$RESET_ADMIN_PASSWORD" == "true" ]]; then
            SHOULD_RESET_PASSWORD=true
            log_info "Password reset forced via command line flag"
        elif [[ "$SKIP_PROMPTS" == "true" ]]; then
            log_info "Skipping password reset (--yes flag provided)"
        elif is_interactive; then
            echo -e "${YELLOW}albedo_admin user already exists.${NC}"
            echo -e "${YELLOW}Do you want to reset the password? [y/N]: ${NC}\c"
            read -r response
            if [[ "$response" =~ ^[Yy]$ ]]; then
                SHOULD_RESET_PASSWORD=true
            fi
        else
            log_info "Non-interactive mode: skipping password reset"
        fi
        
        if [[ "$SHOULD_RESET_PASSWORD" == "true" ]]; then
            log_info "Resetting albedo_admin password..."
            prompt_admin_password
            if echo "albedo_admin:$ADMIN_PASSWORD" | sudo chpasswd >> "$LOG_FILE" 2>&1; then
                log_success "albedo_admin password reset successfully"
            else
                log_error "Failed to reset albedo_admin password"
                FAILED_PACKAGES+=("albedo_admin - Password reset")
                unset ADMIN_PASSWORD
            fi
        fi
    else
        log_info "Creating new albedo_admin user..."
        prompt_admin_password
        
        # Create the user with home directory
        if sudo useradd -m -s /bin/bash albedo_admin >> "$LOG_FILE" 2>&1; then
            # Set the password
            if echo "albedo_admin:$ADMIN_PASSWORD" | sudo chpasswd >> "$LOG_FILE" 2>&1; then
                # Add user to sudo group for full access
                if sudo usermod -aG sudo albedo_admin >> "$LOG_FILE" 2>&1; then
                    log_success "albedo_admin user created successfully"
                else
                    log_error "Failed to add albedo_admin to sudo group"
                    FAILED_PACKAGES+=("albedo_admin - User sudo access")
                fi
            else
                log_error "Failed to set password for albedo_admin"
                FAILED_PACKAGES+=("albedo_admin - User password")
                unset ADMIN_PASSWORD
            fi
        else
            log_error "Failed to create albedo_admin user"
            FAILED_PACKAGES+=("albedo_admin - User creation")
            unset ADMIN_PASSWORD
        fi
    fi
    
    # Display password info (only show the actual password if it was auto-generated)
    if [[ -n "$ADMIN_PASSWORD" ]]; then
        echo ""
        echo -e "${RED}=================================${NC}"
        if [[ "$USER_EXISTS" == "true" ]]; then
            echo -e "${RED}  ALBEDO_ADMIN PASSWORD RESET   ${NC}"
        else
            echo -e "${RED}  ALBEDO_ADMIN ACCOUNT CREATED  ${NC}"
        fi
        echo -e "${RED}=================================${NC}"
        echo -e "${YELLOW}Username: ${GREEN}albedo_admin${NC}"
        if [[ "$ADMIN_PASSWORD_GENERATED" == "true" ]]; then
            echo -e "${YELLOW}Password: ${GREEN}$ADMIN_PASSWORD${NC}"
            echo -e "${RED}=================================${NC}"
            echo -e "${RED}SAVE THIS PASSWORD TO YOUR ${NC}"
            echo -e "${RED}PASSWORD MANAGER IMMEDIATELY!${NC}"
        else
            echo -e "${YELLOW}Password: ${GREEN}(set to your provided password)${NC}"
        fi
        echo -e "${RED}=================================${NC}"
        echo ""

        # Clear the password variable for security
        unset ADMIN_PASSWORD
    fi
    
    # Install Microsoft Edge
    log_info "Setting up Microsoft Edge repository..."
    if curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | sudo tee /usr/share/keyrings/microsoft-edge.gpg > /dev/null 2>> "$LOG_FILE"; then
        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-edge.gpg] https://packages.microsoft.com/repos/edge stable main" | sudo tee /etc/apt/sources.list.d/microsoft-edge.list >> "$LOG_FILE"
        sudo apt-get update >> "$LOG_FILE" 2>&1
        install_package "microsoft-edge-stable" "Microsoft Edge"
    else
        log_error "Failed to add Microsoft Edge repository"
        FAILED_PACKAGES+=("microsoft-edge-stable - Microsoft Edge (repo setup failed)")
    fi
    
    # Install ClamAV
    install_package "clamav" "ClamAV Antivirus"
    install_package "clamav-daemon" "ClamAV Daemon"
    
    # Install Microsoft Package Signing Key and Intune
    log_info "Setting up Microsoft package repository..."
    if curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /tmp/microsoft.gpg 2>> "$LOG_FILE"; then
        sudo install -o root -g root -m 644 /tmp/microsoft.gpg /usr/share/keyrings/ >> "$LOG_FILE" 2>&1
        rm -f /tmp/microsoft.gpg
        sudo sh -c 'echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/ubuntu/$(lsb_release -rs)/prod $(lsb_release -cs) main" > /etc/apt/sources.list.d/microsoft-ubuntu-$(lsb_release -cs)-prod.list' >> "$LOG_FILE" 2>&1
        sudo apt-get update >> "$LOG_FILE" 2>&1
        install_package "intune-portal" "Microsoft Intune Portal"
    else
        log_error "Failed to setup Microsoft package repository"
        FAILED_PACKAGES+=("intune-portal - Microsoft Intune (repo setup failed)")
    fi
    
    # Install Git and VSCode (essential tools)
    install_git
    
    # Install VSCode
    install_deb_package "https://code.visualstudio.com/sha/download?build=stable&os=linux-deb-x64" "vscode.deb" "Visual Studio Code"
    
    # Install Slack
    log_info "Installing Slack..."
    if command -v snap &> /dev/null; then
        if ! snap list | grep -q "slack"; then
            if sudo snap install slack >> "$LOG_FILE" 2>&1; then
                local version=$(snap list slack 2>/dev/null | tail -n +2 | awk '{print $2}' | head -1)
                log_success "Slack installed successfully (version $version)"
            else
                log_error "Failed to install Slack"
                FAILED_PACKAGES+=("slack - Slack")
            fi
        else
            local version=$(snap list slack | tail -n +2 | awk '{print $2}' | head -1)
            log_success "Slack already installed (version $version)"
        fi
    else
        log_warning "Snap not available, skipping Slack installation"
        FAILED_PACKAGES+=("slack - Slack (snap not available)")
    fi
    
    # Install 1Password
    # Reference: https://support.1password.com/install-linux/#debian-or-ubuntu
    log_info "Installing 1Password..."
    if dpkg -l | grep -q "^ii  1password "; then
        local version=$(dpkg -l | grep "^ii  1password " | awk '{print $3}' | head -1)
        log_success "1Password already installed (version $version)"
    else
        if curl -sS https://downloads.1password.com/linux/keys/1password.asc | sudo gpg --yes --dearmor --output /usr/share/keyrings/1password-archive-keyring.gpg 2>> "$LOG_FILE"; then
            echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/1password-archive-keyring.gpg] https://downloads.1password.com/linux/debian/amd64 stable main' | sudo tee /etc/apt/sources.list.d/1password.list >> "$LOG_FILE"
            sudo mkdir -p /etc/debsig/policies/AC2D62742012EA22/ >> "$LOG_FILE" 2>&1
            curl -sS https://downloads.1password.com/linux/debian/debsig/1password.pol | sudo tee /etc/debsig/policies/AC2D62742012EA22/1password.pol >> "$LOG_FILE" 2>&1
            sudo mkdir -p /usr/share/debsig/keyrings/AC2D62742012EA22 >> "$LOG_FILE" 2>&1
            curl -sS https://downloads.1password.com/linux/keys/1password.asc | sudo gpg --yes --dearmor --output /usr/share/debsig/keyrings/AC2D62742012EA22/debsig.gpg 2>> "$LOG_FILE"
            sudo apt-get update >> "$LOG_FILE" 2>&1
            install_package "1password" "1Password"
            # The 1password .deb postinst drops /etc/apt/sources.list.d/1password.sources
            # (deb822 format). Our .list file becomes redundant and produces
            # "configured multiple times" warnings on every apt update.
            if [ -f /etc/apt/sources.list.d/1password.sources ]; then
                sudo rm -f /etc/apt/sources.list.d/1password.list
            fi
        else
            log_error "Failed to setup 1Password repository"
            FAILED_PACKAGES+=("1password - 1Password (repo setup failed)")
        fi
    fi

    # Install Claude Code with Bedrock support.
    # setup_ccb.sh is designed to be run by a normal user — it runs `sudo`
    # internally for package installs. We run it as root with HOME pointed at
    # the invoking user so its ~/.aws, ~/.claude, and shell RC edits land in
    # the right place. Running via `sudo -u $SUDO_USER` would force a second
    # password prompt because the nested sudo doesn't share our root session.
    # Afterwards we chown anything it created back to the user.
    log_info "Setting up Claude Code with AWS Bedrock..."
    log_info "Running Claude Code Bedrock setup script (setup_ccb.sh)..."
    CCB_SCRIPT=$(mktemp /tmp/setup_ccb.XXXXXX.sh)
    if curl -fsSL "https://raw.githubusercontent.com/Albedo-Space-Corp/claude_code/refs/heads/main/setup_ccb.sh" -o "$CCB_SCRIPT" >> "$LOG_FILE" 2>&1; then
        USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        if HOME="$USER_HOME" USER="$SUDO_USER" LOGNAME="$SUDO_USER" bash "$CCB_SCRIPT" 2>> "$LOG_FILE"; then
            log_success "Claude Code Bedrock setup completed successfully"
        else
            log_error "Claude Code Bedrock setup failed"
            FAILED_PACKAGES+=("claude - Claude Code Bedrock setup")
        fi
        # Reclaim ownership of anything setup_ccb.sh created under the user's home
        for path in .aws .claude .local/bin/jq .bashrc .zshrc; do
            [ -e "$USER_HOME/$path" ] && chown -R "$SUDO_USER:" "$USER_HOME/$path" 2>/dev/null
        done
        rm -f "$CCB_SCRIPT"
    else
        log_error "Failed to download Claude Code Bedrock setup script"
        FAILED_PACKAGES+=("claude - Claude Code Bedrock setup (download failed)")
    fi
    
    # Install System76 drivers if this is a System76 machine
    log_info "Checking for System76 hardware..."
    if [ -f /sys/class/dmi/id/sys_vendor ]; then
        SYS_VENDOR=$(cat /sys/class/dmi/id/sys_vendor)
        if [[ "$SYS_VENDOR" == *"System76"* ]]; then
            log_info "System76 hardware detected - installing System76 drivers..."
            if sudo apt-add-repository -y ppa:system76-dev/stable >> "$LOG_FILE" 2>&1; then
                sudo apt-get update >> "$LOG_FILE" 2>&1
                
                # Pre-configure Secure Boot MOK enrollment for DKMS modules
                # Password "system76" will be needed at reboot to complete MOK enrollment
                MOK_PASSWORD="system76"
                log_info "Pre-configuring Secure Boot MOK enrollment..."
                echo "shim-signed shim/mok_password password $MOK_PASSWORD" | sudo debconf-set-selections
                echo "shim-signed shim/mok_password_again password $MOK_PASSWORD" | sudo debconf-set-selections
                
                log_info "Installing System76 Driver (this may take a while for DKMS modules)..."
                if sudo apt-get install -y system76-driver >> "$LOG_FILE" 2>&1; then
                    log_success "System76 Driver installed successfully"
                    MANUAL_STEPS+=("SECURE BOOT (System76) - Only if you need Secure Boot enabled:")
                    MANUAL_STEPS+=("  Note: System76 drivers may have issues with Secure Boot.")
                    MANUAL_STEPS+=("  If Secure Boot is required, see SECURE_BOOT_FIX.md for steps.")
                    MANUAL_STEPS+=("  Otherwise, leave Secure Boot disabled - everything works fine.")
                    MANUAL_STEPS+=("")
                else
                    log_error "Failed to install System76 Driver"
                    FAILED_PACKAGES+=("system76-driver - System76 Driver")
                fi
            else
                log_error "Failed to add System76 PPA"
                FAILED_PACKAGES+=("system76-driver - System76 Driver (PPA setup failed)")
            fi
        else
            log_info "Not a System76 machine (vendor: $SYS_VENDOR) - skipping System76 drivers"
        fi
    else
        log_warning "Cannot determine system vendor - skipping System76 drivers"
    fi
    
    # Install and configure Landscape client
    log_info "Setting up Landscape client..."
    install_package "landscape-client" "Landscape Client"
    
    # Check if Landscape is already configured
    if [ -f /etc/landscape/client.conf ] && grep -q "account_name" /etc/landscape/client.conf 2>/dev/null; then
        log_success "Landscape client already configured"
    else
        HOSTNAME=$(cat /etc/hostname)
        log_info "Configuring Landscape client for host: $HOSTNAME..."
        
        # Create config directory if it doesn't exist
        sudo mkdir -p /etc/landscape >> "$LOG_FILE" 2>&1
        
        # Write the Landscape config file directly (non-interactive)
        sudo tee /etc/landscape/client.conf > /dev/null << EOF
[client]
account_name = albedo
computer_title = $HOSTNAME
url = https://landscape.canonical.com/message-system
ping_url = http://landscape.canonical.com/ping
EOF
        
        if [ -f /etc/landscape/client.conf ]; then
            log_success "Landscape client configuration file created"
            
            # Enable and start the landscape-client service
            if sudo systemctl enable landscape-client >> "$LOG_FILE" 2>&1; then
                log_success "Landscape client service enabled"
            else
                log_warning "Could not enable Landscape client service"
            fi
            
            if sudo systemctl restart landscape-client >> "$LOG_FILE" 2>&1; then
                log_success "Landscape client service started"
            else
                log_warning "Could not start Landscape client service - may need reboot"
            fi
        else
            log_error "Failed to create Landscape configuration"
            FAILED_PACKAGES+=("landscape-client - Landscape Client configuration")
        fi
    fi
    
    # Setup Intune Portal to run on startup via systemd user service
    log_info "Setting up Intune Portal to run on startup..."
    INTUNE_SERVICE_DIR="/home/$SUDO_USER/.config/systemd/user"
    sudo -u $SUDO_USER mkdir -p "$INTUNE_SERVICE_DIR" >> "$LOG_FILE" 2>&1
    
    # Create the systemd user service file
    cat > "$INTUNE_SERVICE_DIR/intune-portal.service" << 'EOF'
[Unit]
Description=Microsoft Intune Portal
After=graphical-session.target
PartOf=graphical-session.target

[Service]
Type=simple
ExecStart=/usr/bin/intune-portal
Restart=on-failure
RestartSec=10

[Install]
WantedBy=graphical-session.target
EOF
    
    # Set proper ownership
    sudo chown $SUDO_USER:$SUDO_USER "$INTUNE_SERVICE_DIR/intune-portal.service" >> "$LOG_FILE" 2>&1
    
    # Enable linger so user services can run without active session
    if sudo loginctl enable-linger $SUDO_USER >> "$LOG_FILE" 2>&1; then
        log_success "User linger enabled for $SUDO_USER"
    else
        log_warning "Could not enable linger for $SUDO_USER"
    fi
    
    # Enable the service for the user (requires user's runtime environment)
    USER_ID=$(id -u $SUDO_USER)
    if [ -d "/run/user/$USER_ID" ]; then
        if sudo -u $SUDO_USER XDG_RUNTIME_DIR="/run/user/$USER_ID" systemctl --user daemon-reload >> "$LOG_FILE" 2>&1 && \
           sudo -u $SUDO_USER XDG_RUNTIME_DIR="/run/user/$USER_ID" systemctl --user enable intune-portal.service >> "$LOG_FILE" 2>&1; then
            log_success "Intune Portal startup service enabled"
        else
            log_warning "Could not enable Intune Portal service now - will be enabled on first login"
            MANUAL_STEPS+=("Enable Intune startup: systemctl --user enable intune-portal.service")
        fi
    else
        log_info "User runtime directory not available - service will be enabled on first login"
        MANUAL_STEPS+=("Enable Intune startup: systemctl --user daemon-reload && systemctl --user enable intune-portal.service")
    fi
    
    # Setup TPM2 auto-unlock for LUKS encrypted drive
    setup_tpm2_autounlock

    # Add manual setup instructions for general
    MANUAL_STEPS+=("GENERAL SETUP COMPLETION:")
    MANUAL_STEPS+=("1. Reboot your device")
    MANUAL_STEPS+=("2. Ensure @James Folkert has added you to 'INTUNE - U - Linux Users' Entra group")
    MANUAL_STEPS+=("3. Open Intune Portal app and sign in with your Albedo email")
    MANUAL_STEPS+=("4. Click 'Register' → 'Begin' to enroll device")
    MANUAL_STEPS+=("5. Configure Ubuntu appearance (Settings → Appearance → Dark theme)")
    MANUAL_STEPS+=("6. Configure screenshot shortcut (Settings → Keyboard → Custom: Shift+Win+S)")
    MANUAL_STEPS+=("7. Configure task manager shortcut (Custom: gnome-system-monitor, Ctrl+Shift+Esc)")
    MANUAL_STEPS+=("8. Configure Slack workspaces (albedo.enterprise and albedo-enterprise)")
    MANUAL_STEPS+=("9. Open a new terminal (to reload PATH) and run: claude")
    MANUAL_STEPS+=("")
    
    log_success "General setup completed"
}

# FSW setup function (Flight Software development)
setup_fsw() {
    log_info "Starting FSW (Flight Software) Setup..."
    
    # Run general setup first
    setup_general
    
    # Install FSW development tools
    install_package "zsh" "Z Shell"
    install_package "python3-pip" "Python3 pip"
    install_package "python3.12-venv" "Python3 virtual environment"
    install_package "build-essential" "Build Essential"
    install_package "doxygen" "Doxygen"
    install_package "ccache" "CCache"
    install_package "meson" "Meson Build System"
    install_package "python3-dev" "Python3 Development Headers"
    install_package "clang-format" "Clang Format"
    install_package "chromium-browser" "Chromium Browser"
    install_package "gimp" "GIMP"
    
    # Install Oh My Zsh (requires user interaction, so add to manual steps)
    log_info "Oh My Zsh will be installed manually (requires user interaction)..."
    
    # Install Docker
    log_info "Installing Docker..."
    if command -v docker &> /dev/null; then
        local version=$(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        log_success "Docker already installed (version $version)"
    else
        if curl -fsSL https://get.docker.com -o /tmp/get-docker.sh >> "$LOG_FILE" 2>&1; then
            if sudo sh /tmp/get-docker.sh >> "$LOG_FILE" 2>&1; then
                sudo usermod -aG docker $SUDO_USER >> "$LOG_FILE" 2>&1
                rm -f /tmp/get-docker.sh
                local version=$(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
                log_success "Docker installed successfully (version $version)"
            else
                log_error "Failed to install Docker"
                FAILED_PACKAGES+=("docker - Docker Engine")
                rm -f /tmp/get-docker.sh
            fi
        else
            log_error "Failed to download Docker installation script"
            FAILED_PACKAGES+=("docker - Docker Engine (download failed)")
        fi
    fi
    
    # Install SonicWall NetExtender
    install_deb_package "https://software.sonicwall.com/NetExtender/NetExtender-linux-amd64-10.3.0-21.deb" "sonicwall.deb" "SonicWall NetExtender"
    
    # Install AWS CLI v2
    log_info "Installing AWS CLI v2..."
    if command -v aws &> /dev/null; then
        local version=$(aws --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        log_success "AWS CLI already installed (version $version)"
    else
        if curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.0.30.zip" -o /tmp/awscliv2.zip >> "$LOG_FILE" 2>&1; then
            if cd /tmp && unzip -q awscliv2.zip >> "$LOG_FILE" 2>&1; then
                if sudo ./aws/install >> "$LOG_FILE" 2>&1; then
                    rm -rf /tmp/aws/ /tmp/awscliv2.zip
                    local version=$(aws --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
                    log_success "AWS CLI v2 installed successfully (version $version)"
                else
                    log_error "Failed to install AWS CLI v2"
                    FAILED_PACKAGES+=("awscli - AWS CLI v2")
                    rm -rf /tmp/aws/ /tmp/awscliv2.zip
                fi
            else
                log_error "Failed to extract AWS CLI v2"
                FAILED_PACKAGES+=("awscli - AWS CLI v2 (extract failed)")
                rm -f /tmp/awscliv2.zip
            fi
        else
            log_error "Failed to download AWS CLI v2"
            FAILED_PACKAGES+=("awscli - AWS CLI v2 (download failed)")
        fi
    fi
    
    # Install Duplo
    log_info "Installing Duplo JIT..."
    if command -v duplo-jit &> /dev/null; then
        local version=$(duplo-jit --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "installed")
        log_success "Duplo JIT already installed (version $version)"
    else
        if curl -L "https://github.com/duplocloud/duplo-jit/releases/download/v0.5.7/duplo-jit_0.5.7_linux_amd64.zip" -o /tmp/duplo.zip >> "$LOG_FILE" 2>&1; then
            sudo mkdir -p /usr/local/share/duplo >> "$LOG_FILE" 2>&1
            if sudo unzip -q /tmp/duplo.zip -d /usr/local/share/duplo >> "$LOG_FILE" 2>&1; then
                sudo ln -sf /usr/local/share/duplo/duplo-jit /usr/local/bin/duplo-jit >> "$LOG_FILE" 2>&1
                rm -f /tmp/duplo.zip
                local version=$(duplo-jit --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "v0.5.7")
                log_success "Duplo JIT installed successfully (version $version)"
            else
                log_error "Failed to install Duplo JIT"
                FAILED_PACKAGES+=("duplo-jit - Duplo JIT")
                rm -f /tmp/duplo.zip
            fi
        else
            log_error "Failed to download Duplo JIT"
            FAILED_PACKAGES+=("duplo-jit - Duplo JIT (download failed)")
        fi
    fi
    
    # Install FSW specific packages
    install_package "libpq-dev" "PostgreSQL Development Libraries"
    install_package "libsocketcan-dev" "SocketCAN Development Libraries"
    
    # Install CMake v3.25.0
    log_info "Installing CMake v3.25.0..."
    if command -v cmake &> /dev/null; then
        local version=$(cmake --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        log_success "CMake already installed (version $version)"
    else
        if mkdir -p /tmp/cmake-install && cd /tmp/cmake-install >> "$LOG_FILE" 2>&1; then
            if curl -L "https://github.com/Kitware/CMake/releases/download/v3.25.0/cmake-3.25.0-linux-x86_64.tar.gz" -o cmake.tar.gz >> "$LOG_FILE" 2>&1; then
                if tar -zxf cmake.tar.gz >> "$LOG_FILE" 2>&1; then
                    sudo cp cmake-3.25.0-linux-x86_64/bin/* /usr/local/bin >> "$LOG_FILE" 2>&1
                    sudo cp -r cmake-3.25.0-linux-x86_64/doc /usr/local >> "$LOG_FILE" 2>&1
                    sudo cp -r cmake-3.25.0-linux-x86_64/man/man1 /usr/local/share/man >> "$LOG_FILE" 2>&1
                    sudo cp -r cmake-3.25.0-linux-x86_64/man/man7 /usr/local/share/man >> "$LOG_FILE" 2>&1
                    sudo cp -r cmake-3.25.0-linux-x86_64/share/* /usr/local/share >> "$LOG_FILE" 2>&1
                    cd /tmp && rm -rf cmake-install
                    local version=$(cmake --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
                    log_success "CMake v3.25.0 installed successfully (version $version)"
                else
                    log_error "Failed to extract CMake"
                    FAILED_PACKAGES+=("cmake-3.25.0 - CMake v3.25.0 (extract failed)")
                    cd /tmp && rm -rf cmake-install
                fi
            else
                log_error "Failed to download CMake"
                FAILED_PACKAGES+=("cmake-3.25.0 - CMake v3.25.0 (download failed)")
                cd /tmp && rm -rf cmake-install
            fi
        else
            log_error "Failed to create CMake install directory"
            FAILED_PACKAGES+=("cmake-3.25.0 - CMake v3.25.0 (directory creation failed)")
        fi
    fi
    
    # Create necessary directories
    log_info "Creating FSW directories..."
    sudo -u $SUDO_USER mkdir -p /home/$SUDO_USER/.pip >> "$LOG_FILE" 2>&1
    sudo -u $SUDO_USER mkdir -p /home/$SUDO_USER/.cache/cpm >> "$LOG_FILE" 2>&1  
    sudo -u $SUDO_USER mkdir -p /home/$SUDO_USER/.cache/ccache >> "$LOG_FILE" 2>&1
    sudo -u $SUDO_USER touch /home/$SUDO_USER/.pypirc >> "$LOG_FILE" 2>&1
    log_success "FSW directories created"
    
    # Add FSW manual setup instructions
    MANUAL_STEPS+=("FSW SETUP COMPLETION:")
    MANUAL_STEPS+=("1. Install Oh My Zsh: sh -c \"\$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)\"")
    MANUAL_STEPS+=("2. Change default shell: chsh -s \$(which zsh)")
    MANUAL_STEPS+=("3. Setup SSH keys for GitLab (commercial & gov) - generate with ssh-keygen -t ed25519")
    MANUAL_STEPS+=("4. Setup GitLab Personal Access Tokens (PATs)")
    MANUAL_STEPS+=("5. Configure ~/.pip/pip.conf with your GitLab PATs")
    MANUAL_STEPS+=("6. Configure ~/.ssh/config for GitLab access")
    MANUAL_STEPS+=("7. Setup Docker login: docker login registry.gitlab.com")
    MANUAL_STEPS+=("8. Copy AWS credentials to ~/.aws/ if available")
    MANUAL_STEPS+=("9. Logout and login to apply Docker group membership")
    MANUAL_STEPS+=("10. Setup Teams/Outlook as Chromium apps (navigate to URLs and click install)")
    MANUAL_STEPS+=("")
    
    log_success "FSW setup completed"
}

# EE setup function (Electrical Engineering)
setup_ee() {
    log_info "Starting EE (Electrical Engineering) Setup..."
    
    # Run general setup first
    setup_general
    
    # Add i386 architecture
    log_info "Adding i386 architecture..."
    if sudo dpkg --add-architecture i386 >> "$LOG_FILE" 2>&1; then
        log_success "i386 architecture added"
        sudo apt-get update >> "$LOG_FILE" 2>&1
    else
        log_error "Failed to add i386 architecture"
    fi
    
    # Install universe and multiverse repositories
    log_info "Adding universe and multiverse repositories..."
    sudo add-apt-repository -y universe >> "$LOG_FILE" 2>&1
    sudo add-apt-repository -y multiverse >> "$LOG_FILE" 2>&1
    sudo apt-get update >> "$LOG_FILE" 2>&1
    sudo systemctl daemon-reload >> "$LOG_FILE" 2>&1
    
    # Upgrade system
    log_info "Upgrading system packages..."
    sudo apt-get upgrade -y >> "$LOG_FILE" 2>&1
    
    # EE Package installation (Matthew Huff's extensive list)
    log_info "Installing EE packages (this may take a while)..."
    
    # Core development tools
    install_package "software-properties-common" "Software Properties Common"
    install_package "gnome-shell-extension-manager" "GNOME Shell Extension Manager"
    install_package "build-essential" "Build Essential"
    install_package "usbutils" "USB Utilities"
    install_package "libusb-1.0-0-dev" "USB Development Libraries"
    install_package "libflac*" "FLAC Libraries"
    install_package "gdb" "GNU Debugger"
    install_package "gcc" "GNU Compiler Collection"
    install_package "g++" "GNU C++ Compiler"
    install_package "sed" "Stream Editor"
    install_package "make" "Make"
    install_package "curl" "cURL"
    install_package "libstdc++6:i386" "Standard C++ Library (32-bit)"
    install_package "libgtk2.0-0:i386" "GTK2 Libraries (32-bit)"
    install_package "xz-utils" "XZ Utils"
    install_package "binutils" "Binary Utilities"
    install_package "diffutils" "Diff Utilities"
    install_package "patch" "Patch"
    install_package "gzip" "GZip"
    install_package "bzip2" "BZip2"
    install_package "perl" "Perl"
    install_package "tar" "Tar"
    install_package "findutils" "Find Utilities"
    install_package "qt5*" "Qt5 Libraries"
    install_package "glib*" "GLib Libraries"
    install_package "gtk2*" "GTK2 Libraries"
    install_package "mercurial" "Mercurial"
    install_package "subversion" "Subversion"
    install_package "cpio" "CPIO"
    install_package "chrpath" "Chrpath"
    install_package "socat" "Socat"
    install_package "libssl-dev" "SSL Development Libraries"
    install_package "libncurses5*" "NCurses5 Libraries"
    install_package "libncurses6*" "NCurses6 Libraries"
    install_package "libelf-dev" "ELF Development Libraries"
    install_package "unzip" "Unzip"
    install_package "python3" "Python3"
    install_package "python3-pip" "Python3 pip"
    install_package "python3-venv" "Python3 Virtual Environment"
    install_package "locales" "Locales"
    install_package "sudo" "Sudo"
    install_package "nano" "Nano Editor"
    install_package "wget" "Wget"
    install_package "xterm" "XTerm"
    install_package "autoconf" "Autoconf"
    install_package "libtool" "Libtool"
    install_package "rsync" "Rsync"
    install_package "bc" "Basic Calculator"
    install_package "texinfo" "Texinfo"
    install_package "gcc-multilib" "GCC Multilib"
    install_package "lsb-release" "LSB Release"
    install_package "diffstat" "Diffstat"
    install_package "gawk" "GNU Awk"
    install_package "lz4" "LZ4"
    install_package "zstd" "Zstandard"
    install_package "dnsutils" "DNS Utilities"
    install_package "net-tools" "Network Tools"
    install_package "bash" "Bash Shell"
    install_package "util-linux" "Util Linux"
    install_package "parted" "Parted"
    install_package "progress" "Progress"
    install_package "libxslt1-dev" "XSLT Development Libraries"
    
    # X11 and graphics libraries
    install_package "libgraphite2-3" "Graphite2 Library"
    install_package "libxt6" "X Toolkit Library"
    install_package "libxrender1" "X Render Library"
    install_package "libxi6" "X Input Library"
    install_package "libxft2" "X FreeType Library"
    install_package "libxtst6" "X Test Library"
    install_package "libfreetype6" "FreeType Library"
    install_package "libcanberra-gtk-module" "Canberra GTK Module"
    install_package "libsm6" "Session Management Library"
    install_package "libtiff*" "TIFF Libraries"
    install_package "libasyncns0" "Async Name Service Library"
    install_package "libdbus-1-3" "D-Bus Library"
    install_package "libdrm2" "DRM Library"
    install_package "libegl1" "EGL Library"
    install_package "libexpat1" "Expat Library"
    install_package "libflac-dev" "FLAC Development Libraries"
    install_package "libfontconfig1" "Font Configuration Library"
    install_package "libgbm1" "Graphics Buffer Manager"
    install_package "libglib2.0-0" "GLib Library"
    install_package "libgl1" "OpenGL Library"
    install_package "libice6" "X11 ICE Library"
    install_package "libnspr4" "Netscape Portable Runtime"
    install_package "libnss3" "Network Security Services"
    install_package "libogg0" "Ogg Library"
    install_package "libpulse0" "PulseAudio Library"
    install_package "libsndfile1" "Sound File Library"
    install_package "libsqlite3-0" "SQLite3 Library"
    install_package "libvorbisenc2" "Vorbis Encoder Library"
    install_package "libvorbis0a" "Vorbis Library"
    install_package "libwrap0" "TCP Wrapper Library"
    install_package "libx11-xcb1" "X11 XCB Library"
    install_package "libxcb-dri2-0" "XCB DRI2 Library"
    install_package "libxcb-glx0" "XCB GLX Library"
    install_package "libxcb-render0" "XCB Render Library"
    install_package "libxcb-shape0" "XCB Shape Library"
    install_package "libxcb-xfixes0" "XCB XFixes Library"
    install_package "libxcomposite1" "X Composite Library"
    install_package "libxcursor1" "X Cursor Library"
    install_package "libxdamage1" "X Damage Library"
    install_package "libxfixes3" "X Fixes Library"
    install_package "libxslt1.1" "XSLT Library"
    install_package "x11-apps" "X11 Applications"
    
    # Java and fonts
    install_package "openjdk-11-jdk" "OpenJDK 11"
    install_package "xfonts-100dpi" "X11 100dpi Fonts"
    install_package "xfonts-75dpi" "X11 75dpi Fonts"
    install_package "xfonts-base" "X11 Base Fonts"
    install_package "xfonts-intl-asian" "X11 Asian Fonts"
    install_package "xfonts-intl-chinese" "X11 Chinese Fonts"
    install_package "xfonts-intl-chinese-big" "X11 Chinese Big Fonts"
    install_package "xfonts-intl-japanese" "X11 Japanese Fonts"
    install_package "xfonts-intl-japanese-big" "X11 Japanese Big Fonts"
    install_package "xkb-data" "XKB Data"
    install_package "ksh" "Korn Shell"
    install_package "libxft2:i386" "X FreeType Library (32-bit)"
    
    # Additional tools
    install_package "htop" "HTTop Process Monitor"
    install_package "remmina" "Remmina Remote Desktop"
    install_package "gedit" "GEdit Text Editor"
    install_package "libfuse2" "FUSE Library v2"
    install_package "cmake" "CMake"
    install_package "okular" "Okular Document Viewer"
    install_package "genext2fs" "Generate Ext2 Filesystem"
    install_package "samba" "Samba"
    install_package "git-lfs" "Git Large File Storage"
    install_package "nodejs" "Node.js"
    install_package "npm" "NPM"
    install_package "universal-ctags" "Universal CTags"
    install_package "rauc" "RAUC"
    install_package "slang-gsl" "S-Lang GSL"
    install_package "ghdl" "GHDL VHDL Simulator"
    install_package "gtkwave" "GTKWave"
    install_package "deja-dup" "Deja Dup Backup"
    install_package "lm-sensors" "Hardware Monitoring"
    
    # Python packages
    install_package "python3-openpyxl" "Python3 OpenPyXL"
    install_package "python3-tk" "Python3 Tkinter"
    install_package "python3-cocotb" "Python3 Cocotb"
    install_package "python3-cocotb-bus" "Python3 Cocotb Bus"
    install_package "python3-pycryptodome" "Python3 PyCryptoDome"
    install_package "python3-progress" "Python3 Progress"
    
    # Install KSnip screenshot tool via snap
    log_info "Installing KSnip screenshot tool..."
    if command -v snap &> /dev/null; then
        if ! snap list | grep -q "ksnip"; then
            if sudo snap install ksnip >> "$LOG_FILE" 2>&1; then
                local version=$(snap list ksnip 2>/dev/null | tail -n +2 | awk '{print $2}' | head -1)
                log_success "KSnip installed successfully (version $version)"
            else
                log_error "Failed to install KSnip"
                FAILED_PACKAGES+=("ksnip - KSnip")
            fi
        else
            local version=$(snap list ksnip | tail -n +2 | awk '{print $2}' | head -1)
            log_success "KSnip already installed (version $version)"
        fi
    else
        log_warning "Snap not available, skipping KSnip installation"
        FAILED_PACKAGES+=("ksnip - KSnip (snap not available)")
    fi
    
    # Configure Git
    log_info "Configuring Git..."
    sudo -u $SUDO_USER git config --global init.defaultBranch main >> "$LOG_FILE" 2>&1
    
    # Add user to dialout group
    log_info "Adding user to dialout group..."
    sudo usermod -aG dialout $SUDO_USER >> "$LOG_FILE" 2>&1
    
    # Create tools and repo directories
    log_info "Creating EE tool directories..."
    if sudo mkdir -p /tools >> "$LOG_FILE" 2>&1; then
        sudo chown $SUDO_USER:$SUDO_USER /tools >> "$LOG_FILE" 2>&1
        log_success "/tools directory created"
    else
        log_error "Failed to create /tools directory"
    fi
    
    if sudo mkdir -p /repo >> "$LOG_FILE" 2>&1; then
        sudo chown $SUDO_USER:$SUDO_USER /repo >> "$LOG_FILE" 2>&1
        log_success "/repo directory created"
    else
        log_error "Failed to create /repo directory"
    fi
    
    # Create SSL cert links for Libero
    log_info "Creating SSL certificate links for Libero..."
    sudo mkdir -p /etc/pki/tls/certs >> "$LOG_FILE" 2>&1
    sudo ln -sf /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt >> "$LOG_FILE" 2>&1
    log_success "SSL certificate links created"
    
    # Add EE manual setup instructions
    MANUAL_STEPS+=("EE SETUP COMPLETION:")
    MANUAL_STEPS+=("1. Install FPGA Tools manually:")
    MANUAL_STEPS+=("   - Libero SoC v2025.1 → /tools/microchip/Libero_SoC_v2025.1")
    MANUAL_STEPS+=("   - SoftConsole v2022.2 → /tools/microchip/SoftConsole-v2022.2-RISC-V-747")
    MANUAL_STEPS+=("   - Questa 2025p2 → /tools/Siemens/questa2025p2")  
    MANUAL_STEPS+=("   - Xilinx tools → /tools/Xilinx/")
    MANUAL_STEPS+=("2. After installing Libero, run these commands:")
    MANUAL_STEPS+=("   mv /tools/microchip/Libero_SoC_2025.1/Libero_SoC/Designer/lib64/rhel/libstdc++.so.6 \\")
    MANUAL_STEPS+=("      /tools/microchip/Libero_SoC_2025.1/Libero_SoC/Designer/lib64/rhel/libstdc++.so.6.bak")
    MANUAL_STEPS+=("   mv /tools/microchip/Libero_SoC_2025.1/Libero_SoC/Synplify_Pro/linux_a_64/lib/libstdc++.so.6 \\")
    MANUAL_STEPS+=("      /tools/microchip/Libero_SoC_2025.1/Libero_SoC/Synplify_Pro/linux_a_64/lib/libstdc++.so.6.bak")
    MANUAL_STEPS+=("3. For Vivado, create symlink:")
    MANUAL_STEPS+=("   sudo ln -s /lib/x86_64-linux-gnu/libtinfo.so.6 /lib/x86_64-linux-gnu/libtinfo.so.5")
    MANUAL_STEPS+=("4. Add these lines to ~/.bashrc:")
    MANUAL_STEPS+=("   lic_server=\"29000@10.111.0.10\"")
    MANUAL_STEPS+=("   export MGLS_LICENSE_FILE=\$lic_server")
    MANUAL_STEPS+=("   export SALT_LICENSE_SERVER=\$lic_server")
    MANUAL_STEPS+=("   export LM_LICENSE_FILE=\$lic_server")
    MANUAL_STEPS+=("   export XILINXD_LICENSE_FILE=\$lic_server")
    MANUAL_STEPS+=("   alias questa2025p2='export PATH=\"/tools/Siemens/questa2025p2/questasim/linux_x86_64:\$PATH\"'")
    MANUAL_STEPS+=("   alias microchip2025p1='export FPGENPROG=/tools/microchip/Libero_SoC_v2025.1/Libero_SoC/Designer/bin64/fpgenprog && export PATH=\"/tools/microchip/Libero_SoC_v2025.1/Libero_SoC/QuestaSim_Pro/bin:/tools/microchip/Libero_SoC_v2025.1/Libero_SoC/Designer/bin64:/tools/microchip/SoftConsole-v2022.2-RISC-V-747/riscv-unknown-elf-gcc/bin:\$PATH\"'")
    MANUAL_STEPS+=("5. Run: sudo sensors-detect (accept all defaults)")
    MANUAL_STEPS+=("6. Logout and login to apply group memberships")
    MANUAL_STEPS+=("")
    
    log_success "EE setup completed"
}

# Function to print manual setup instructions
print_manual_instructions() {
    if [ ${#MANUAL_STEPS[@]} -gt 0 ]; then
        log_info "Manual setup steps required:"
        echo ""
        for step in "${MANUAL_STEPS[@]}"; do
            echo -e "${YELLOW}$step${NC}"
        done
        echo ""
    fi
}

# Function to print failed packages
print_failed_packages() {
    if [ ${#FAILED_PACKAGES[@]} -gt 0 ]; then
        log_warning "The following packages failed to install:"
        for package in "${FAILED_PACKAGES[@]}"; do
            echo -e "${RED}  ✗ $package${NC}"
        done
        echo ""
        log_info "You can try installing failed packages manually later."
        echo ""
    fi
}

# Main execution
main() {
    # Parse arguments
    SETUP_TYPE=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --reset-admin-password)
                RESET_ADMIN_PASSWORD=true
                shift
                ;;
            --yes|-y)
                SKIP_PROMPTS=true
                shift
                ;;
            general|FSW|EE)
                if [[ -n "$SETUP_TYPE" ]]; then
                    log_error "Multiple setup types specified"
                    usage
                fi
                SETUP_TYPE=$1
                shift
                ;;
            *)
                log_error "Unknown argument: $1"
                usage
                ;;
        esac
    done
    
    # Check if setup type was provided
    if [[ -z "$SETUP_TYPE" ]]; then
        usage
    fi
    
    # Check sudo
    check_sudo
    
    # Print header (first log_info call creates $LOG_FILE). Relax perms so the
    # invoking user can read it later without sudo. Keep root as owner —
    # Ubuntu's fs.protected_regular=2 blocks root from appending to files it
    # doesn't own in world-writable sticky dirs like /tmp, so chown'ing mid-run
    # would break every subsequent tee -a.
    log_info "Starting Albedo Linux Setup - Type: $SETUP_TYPE"
    chmod 644 "$LOG_FILE" 2>/dev/null || true
    log_info "Log file: $LOG_FILE"
    echo ""
    
    # Update system
    update_system
    
    # Run appropriate setup
    case $SETUP_TYPE in
        general)
            setup_general
            ;;
        FSW)
            setup_fsw
            ;;
        EE)
            setup_ee
            ;;
    esac
    
    # Print results
    echo ""
    log_info "Setup completed!"
    echo ""
    
    print_failed_packages
    print_manual_instructions
    
    log_info "Full log available at: $LOG_FILE"
}

# Run main function
main "$@"
