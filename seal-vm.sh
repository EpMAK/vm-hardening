#!/bin/bash
# =============================================================================
# VM Template Seal Script - Debian 13
# Run as root AFTER cis-harden-debian13.sh, BEFORE saving to VCD catalog
# =============================================================================

set -euo pipefail

# Must run as root directly — not via sudo (sudo is child of user session
# and will die when the template user is deleted mid-script)
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run as root directly via 'su -', not sudo"
    exit 1
fi

if [ -n "${SUDO_USER:-}" ]; then
    echo "ERROR: Running under sudo — switch to root via 'su -' first"
    echo "       sudo passwd root  →  su -  →  bash seal-vm.sh"
    exit 1
fi

LOG="/var/log/seal-vm.log"
exec > >(tee -a "$LOG") 2>&1

echo "============================================="
echo " VM Template Seal"
echo " Started: $(date)"
echo "============================================="

# =============================================================================
# PARAMETERS
# =============================================================================

# User that was used during template build — will be deleted
TEMPLATE_USER="template"

# =============================================================================
# STEP 1 - Remove template build user
# =============================================================================
echo "[1] Removing template build user"

if id "$TEMPLATE_USER" &>/dev/null; then
    # Lock first
    passwd -l "$TEMPLATE_USER" 2>/dev/null || true
    # Kill any running processes
    pkill -u "$TEMPLATE_USER" 2>/dev/null || true
    sleep 1
    # Delete user and home directory
    userdel -r "$TEMPLATE_USER" 2>/dev/null || true
    echo "[1] User $TEMPLATE_USER removed"
else
    echo "[1] User $TEMPLATE_USER not found, skipping"
fi

# Remove any leftover sudo rules for template user
if [ -f "/etc/sudoers.d/$TEMPLATE_USER" ]; then
    rm -f "/etc/sudoers.d/$TEMPLATE_USER"
fi

# =============================================================================
# STEP 2 - Clean user artifacts
# =============================================================================
echo "[2] Cleaning user artifacts"

# Clear all shell histories
find /home /root -name ".*history" -exec truncate -s 0 {} \; 2>/dev/null || true
truncate -s 0 /root/.bash_history 2>/dev/null || true
history -c 2>/dev/null || true

# Clear SSH known_hosts
find /home /root -name "known_hosts" -exec truncate -s 0 {} \; 2>/dev/null || true

# Clear root's authorized_keys (VMs should get their own keys)
truncate -s 0 /root/.ssh/authorized_keys 2>/dev/null || true

# =============================================================================
# STEP 3 - Remove SSH host keys (regenerated on first boot)
# =============================================================================
echo "[3] Removing SSH host keys"
rm -f /etc/ssh/ssh_host_*
echo "[3] SSH host keys removed — will regenerate on first boot"

# =============================================================================
# STEP 4 - Clean machine identity
# =============================================================================
echo "[4] Cleaning machine identity"

# Machine ID — blank it so it regenerates uniquely per VM
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -s /etc/machine-id /var/lib/dbus/machine-id

# Hostname — reset to generic
hostnamectl set-hostname "localhost" 2>/dev/null || \
    echo "localhost" > /etc/hostname
truncate -s 0 /etc/hosts
cat > /etc/hosts << 'HOSTSEOF'
127.0.0.1   localhost
127.0.1.1   localhost
::1         localhost ip6-localhost ip6-loopback
HOSTSEOF

# =============================================================================
# STEP 5 - Clean cloud-init remnants (if any slipped through)
# =============================================================================
echo "[5] Cleaning cloud-init remnants"
rm -rf /etc/cloud /var/lib/cloud /run/cloud-init 2>/dev/null || true

# =============================================================================
# STEP 6 - Clean logs
# =============================================================================
echo "[6] Cleaning logs"

# Truncate system logs
find /var/log -type f \( \
    -name "*.log" -o \
    -name "syslog" -o \
    -name "auth.log" -o \
    -name "kern.log" -o \
    -name "mail.log" -o \
    -name "dpkg.log" -o \
    -name "apt.log" \
\) -exec truncate -s 0 {} \; 2>/dev/null || true

# Clear journal logs
journalctl --rotate 2>/dev/null || true
journalctl --vacuum-time=1s 2>/dev/null || true

# Clear audit logs (fresh start per VM)
truncate -s 0 /var/log/audit/audit.log 2>/dev/null || true

# =============================================================================
# STEP 7 - Clean temp files
# =============================================================================
echo "[7] Cleaning temp files"
find /tmp /var/tmp -type f -delete 2>/dev/null || true
find /tmp /var/tmp -type d -mindepth 1 -delete 2>/dev/null || true

# =============================================================================
# STEP 8 - Clean package cache
# =============================================================================
echo "[8] Cleaning package cache"
apt-get clean
apt-get autoremove -y -qq
rm -rf /var/lib/apt/lists/*

# =============================================================================
# STEP 9 - Reset network interfaces config
# =============================================================================
echo "[9] Resetting network config"

# Reset to minimal interfaces file — actual config set by vm-customize.sh
cat > /etc/network/interfaces << 'IFEOF'
# This file is managed by vm-customize.sh on first boot
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
IFEOF

# Unlock resolv.conf if locked
chattr -i /etc/resolv.conf 2>/dev/null || true
cat > /etc/resolv.conf << 'RESOLVEOF'
# Populated by vm-customize.sh on first boot
RESOLVEOF

# =============================================================================
# STEP 10 - Re-initialize AIDE database on clean state
# =============================================================================
echo "[10] Re-initializing AIDE database on sealed state"
aideinit -y -f 2>/dev/null || aide --init 2>/dev/null || true
if [ -f /var/lib/aide/aide.db.new ]; then
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
elif [ -f /var/lib/aide/aide.db.new.gz ]; then
    mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
fi
echo "[10] AIDE database initialized on clean template state"

# =============================================================================
# STEP 11 - Lock root account
# =============================================================================
echo "[11] Locking root account"

# Lock root password — root cannot login directly
# Access is only via sudo from admin user created by vm-customize.sh
passwd -l root

# Expire root password as extra measure
chage -E 0 root 2>/dev/null || true

echo "[11] Root account locked"

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo "============================================="
echo " Seal Complete"
echo " Finished: $(date)"
echo "============================================="
echo ""
echo "VM is ready to be saved as a template in VCD."
echo ""
echo "NEXT STEPS:"
echo "  1. Power off:   shutdown -h now"
echo "  2. In VCD:      vApp → Add to Catalog"
echo "  3. Name it:     debian13-cis-v1.0-$(date +%Y%m%d)"
echo ""
echo "PER-VM AFTER DEPLOY:"
echo "  1. Set IP Pool on NIC in VCD"
echo "  2. Edit HOSTNAME/DNS/NTP in vm-customize.sh"  
echo "  3. Paste into VCD Guest OS Customization Script"
echo "  4. Power on"
echo ""
