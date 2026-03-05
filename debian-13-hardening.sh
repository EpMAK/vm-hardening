#!/bin/bash
# =============================================================================
# CIS Benchmark Hardening Script - Debian 13 (Trixie)
# Level 1 + selected Level 2 controls
# Run as root after base OS install, before sealing VM template
# =============================================================================

# =============================================================================
# PARAMETERS — edit before running
# =============================================================================

# Locales to install (first one becomes system default)
LOCALES="kk_KZ.UTF-8 ru_RU.UTF-8 en_US.UTF-8"
DEFAULT_LOCALE="kk_KZ.UTF-8"

# Timezone
TIMEZONE="Asia/Almaty"

# NTP servers
NTP_SERVERS="0.kz.pool.ntp.org 1.kz.pool.ntp.org 2.europe.pool.ntp.org"

# Umask
UMASK="027"

# Password policy
PASS_MAX_DAYS=365
PASS_MIN_DAYS=1
PASS_WARN_AGE=7
PASS_MIN_LEN=14

# Account lockout
LOCKOUT_ATTEMPTS=5
LOCKOUT_TIME=900

# Sudo timeout (minutes)
SUDO_TIMEOUT=15

# NOTE: Network is handled automatically by VCD IP Pool + VMware Tools
#       Hostname/DNS/NTP set per-VM via vm-customize.sh pasted in VCD

# =============================================================================
# END PARAMETERS
# =============================================================================

set -euo pipefail

LOG="/var/log/cis-hardening.log"
exec > >(tee -a "$LOG") 2>&1

echo "============================================="
echo " CIS Hardening - Debian 13"
echo " Started: $(date)"
echo "============================================="

# -----------------------------------------------------------------------------
# SECTION 0 - Locale & Timezone
# -----------------------------------------------------------------------------
echo "[0] Locale & Timezone"

apt-get update -qq
apt-get install -y -qq locales tzdata

# Generate required locales
for locale in $LOCALES; do
    if ! grep -q "^${locale}" /etc/locale.gen 2>/dev/null; then
        sed -i "s/^# *${locale}/${locale}/" /etc/locale.gen 2>/dev/null || true
        grep -q "^${locale}" /etc/locale.gen || echo "${locale} UTF-8" >> /etc/locale.gen
    fi
done
locale-gen

# Set system default locale
update-locale LANG="$DEFAULT_LOCALE"
echo "LANG=$DEFAULT_LOCALE" > /etc/default/locale

# Set timezone
timedatectl set-timezone "$TIMEZONE" 2>/dev/null || \
    ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime
echo "[0] Locale: $DEFAULT_LOCALE | Timezone: $TIMEZONE"

# -----------------------------------------------------------------------------
# SECTION 1 - Filesystem Configuration
# -----------------------------------------------------------------------------
echo "[1] Filesystem Configuration"

# 1.1 Disable unused filesystems
cat > /etc/modprobe.d/cis-disable-fs.conf << 'EOF'
# CIS - Disable unused/risky filesystems
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install usb-storage /bin/true
# Disable IPv6 module
blacklist ipv6
EOF

# 1.2 Apply mount options to /tmp
echo "[1.2] Hardening /tmp mount options"
if grep -qP '\s/tmp\s' /etc/fstab; then
    if ! grep -P '\s/tmp\s' /etc/fstab | grep -q "noexec"; then
        sed -i '/[[:space:]]\/tmp[[:space:]]/s/defaults/defaults,nodev,nosuid,noexec/' /etc/fstab
    fi
else
    echo "# /tmp is on LVM - mount options applied via systemd"
    mkdir -p /etc/systemd/system/tmp.mount.d
    cat > /etc/systemd/system/tmp.mount.d/cis.conf << 'EOF'
[Mount]
Options=mode=1777,strictatime,nosuid,nodev,noexec
EOF
fi

# 1.3 /dev/shm hardening
echo "[1.3] Hardening /dev/shm"
if ! grep -q "/dev/shm" /etc/fstab; then
    echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab
fi
mount -o remount,nodev,nosuid,noexec /dev/shm 2>/dev/null || true

# 1.4 Sticky bit on all world-writable directories
echo "[1.4] Setting sticky bit on world-writable dirs"
df --local -P 2>/dev/null | awk 'NR>1 {print $6}' | \
    xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | \
    xargs -r chmod a+t 2>/dev/null || true

# -----------------------------------------------------------------------------
# SECTION 2 - Software Updates & Package Management
# -----------------------------------------------------------------------------
echo "[2] Software & Package Management"

# 2.1 Update all packages
echo "[2.1] Updating packages"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
apt-get autoremove -y -qq

# 2.2 Install required security packages
echo "[2.2] Installing security packages"
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    auditd \
    audispd-plugins \
    aide \
    aide-common \
    libpam-pwquality \
    libpam-modules \
    acl \
    apparmor \
    apparmor-utils \
    apparmor-profiles \
    ufw \
    fail2ban \
    rsyslog \
    logrotate \
    open-vm-tools \
    chrony \
    sudo

# 2.3 Remove unnecessary packages
echo "[2.3] Removing unnecessary packages"
DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq \
    telnet \
    rsh-client \
    talk \
    xinetd \
    nis \
    tftp \
    tftpd-hpa \
    nfs-kernel-server \
    rpcbind \
    avahi-daemon \
    cups \
    isc-dhcp-server \
    bind9 \
    vsftpd \
    apache2 \
    dovecot-core \
    samba \
    squid \
    snmpd 2>/dev/null || true

apt-get autoremove -y -qq

# 2.4 Remove cloud-init completely
echo "[2.4] Removing cloud-init"
DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq cloud-init 2>/dev/null || true
rm -rf /etc/cloud /var/lib/cloud /run/cloud-init
apt-get autoremove -y -qq

# -----------------------------------------------------------------------------
# SECTION 3 - Bootloader Hardening
# -----------------------------------------------------------------------------
echo "[3] Bootloader Hardening"

# 3.1 Secure grub.cfg permissions
if [ -f /boot/grub/grub.cfg ]; then
    chown root:root /boot/grub/grub.cfg
    chmod 600 /boot/grub/grub.cfg
fi
if [ -f /boot/grub2/grub.cfg ]; then
    chown root:root /boot/grub2/grub.cfg
    chmod 600 /boot/grub2/grub.cfg
fi

# 3.2 Restrict core dumps
cat > /etc/security/limits.d/cis-coredump.conf << 'EOF'
* hard core 0
* soft core 0
EOF

# Also via systemd
mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/cis.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

# -----------------------------------------------------------------------------
# SECTION 4 - Kernel / sysctl Hardening
# -----------------------------------------------------------------------------
echo "[4] Kernel Parameter Hardening"

cat > /etc/sysctl.d/99-cis.conf << 'EOF'
# =============================================================================
# CIS Benchmark - Kernel Parameters - Debian 13
# =============================================================================

# --- Network: Disable IP forwarding ---
net.ipv4.ip_forward = 0

# --- Network: Disable packet redirect sending ---
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# --- Network: Disable ICMP redirect acceptance ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# --- Network: Disable secure ICMP redirect acceptance ---
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# --- Network: Log suspicious packets ---
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- Network: Disable source routing ---
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# --- Network: Enable reverse path filtering ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# --- Network: Ignore ICMP broadcast requests ---
net.ipv4.icmp_echo_ignore_broadcasts = 1

# --- Network: Ignore bogus ICMP error responses ---
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- Network: Enable SYN cookies ---
net.ipv4.tcp_syncookies = 1

# --- Network: Disable TCP timestamps ---
net.ipv4.tcp_timestamps = 0

# --- Disable IPv6 completely ---
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# --- Kernel: Restrict dmesg to root ---
kernel.dmesg_restrict = 1

# --- Kernel: Restrict ptrace ---
kernel.yama.ptrace_scope = 1

# --- Kernel: Disable magic SysRq key ---
kernel.sysrq = 0

# --- Kernel: Prevent core dump SUID ---
fs.suid_dumpable = 0

# --- Kernel: Randomize memory layout (ASLR) ---
kernel.randomize_va_space = 2

# --- Kernel: Restrict kernel pointers ---
kernel.kptr_restrict = 2

# --- Kernel: Restrict unprivileged BPF ---
kernel.unprivileged_bpf_disabled = 1

# --- Kernel: Restrict perf events ---
kernel.perf_event_paranoid = 3
EOF

chmod 600 /etc/sysctl.d/99-cis.conf
sysctl --system > /dev/null 2>&1

# -----------------------------------------------------------------------------
# SECTION 5 - SSH Hardening
# -----------------------------------------------------------------------------
echo "[5] SSH Hardening"

# Ensure SSH is installed
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server

SSHD_CONFIG="/etc/ssh/sshd_config"
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"

cat > "$SSHD_CONFIG" << 'EOF'
# =============================================================================
# CIS Benchmark - SSH Server Configuration - Debian 13
# =============================================================================

# --- Protocol & Port ---
Port 22

# --- Authentication ---
PermitRootLogin no
MaxAuthTries 4
MaxSessions 10
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
KbdInteractiveAuthentication no
UsePAM yes

# --- Host Keys ---
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# --- Security ---
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
Banner /etc/issue.net
PrintLastLog yes

# --- Ciphers & MACs (strong only) ---
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# --- Timeouts ---
ClientAliveInterval 300
ClientAliveCountMax 3
LoginGraceTime 60

# --- Logging ---
LogLevel VERBOSE
SyslogFacility AUTH

# --- Subsystems ---
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

# Validate config before restarting
sshd -t && systemctl restart ssh || {
    echo "ERROR: sshd config invalid, restoring backup"
    cp "${SSHD_CONFIG}.bak" "$SSHD_CONFIG"
    systemctl restart ssh
}

# -----------------------------------------------------------------------------
# SECTION 6 - PAM / Password Policy
# -----------------------------------------------------------------------------
echo "[6] PAM & Password Policy"

# 6.1 Password quality - pwquality.conf uses variable expansion so no quotes on EOF
cat > /etc/security/pwquality.conf << EOF
# CIS Password Quality Requirements
minlen = ${PASS_MIN_LEN}
minclass = 4
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
maxsequence = 3
gecoscheck = 1
dictcheck = 1
EOF

# 6.2 Password aging
sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   ${PASS_MAX_DAYS}/" /etc/login.defs
sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   ${PASS_MIN_DAYS}/" /etc/login.defs
sed -i "s/^PASS_WARN_AGE.*/PASS_WARN_AGE   ${PASS_WARN_AGE}/" /etc/login.defs

# 6.3 Account lockout via faillock (Debian 13 uses pam_faillock, not tally2)
cat > /etc/security/faillock.conf << EOF
# CIS - Account lockout policy
deny = ${LOCKOUT_ATTEMPTS}
fail_interval = ${LOCKOUT_TIME}
unlock_time = ${LOCKOUT_TIME}
audit
EOF

# 6.4 Password hashing SHA-512
if grep -q "^ENCRYPT_METHOD" /etc/login.defs; then
    sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
else
    echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs
fi
if ! grep -q "^SHA_CRYPT_MIN_ROUNDS" /etc/login.defs; then
    echo "SHA_CRYPT_MIN_ROUNDS 5000" >> /etc/login.defs
fi

# 6.5 Inactive account lockout (30 days after password expiry)
useradd -D -f 30

# -----------------------------------------------------------------------------
# SECTION 7 - User & Group Security
# -----------------------------------------------------------------------------
echo "[7] User & Group Security"

# 7.1 Check for non-root UID 0 accounts
echo "[7.1] Checking UID 0 accounts"
UID0_USERS=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd | grep -v "^root$" || true)
if [ -n "$UID0_USERS" ]; then
    echo "WARNING: Non-root UID 0 accounts found: $UID0_USERS"
else
    echo "[7.1] OK - root is the only UID 0 account"
fi

# 7.2 Root PATH integrity check
if echo "$PATH" | grep -q "::"; then
    echo "WARNING: Empty directory in root PATH"
fi
if echo "$PATH" | grep -q ":$"; then
    echo "WARNING: Trailing colon in root PATH"
fi

# 7.3 Lock system accounts (UID < 1000, skip root and accounts with valid shells)
echo "[7.3] Locking system accounts"
while IFS=: read -r username _ uid _ _ _ shell; do
    if [ "$uid" -lt 1000 ] && [ "$username" != "root" ] && \
       [ "$shell" != "/usr/sbin/nologin" ] && [ "$shell" != "/bin/false" ] && \
       [ "$shell" != "/sbin/nologin" ]; then
        passwd -l "$username" 2>/dev/null || true
    fi
done < /etc/passwd

# 7.4 Remove legacy + entries
sed -i '/^+:/d' /etc/passwd /etc/shadow /etc/group 2>/dev/null || true

# 7.5 Set umask
if grep -q "^UMASK" /etc/login.defs; then
    sed -i "s/^UMASK.*/UMASK ${UMASK}/" /etc/login.defs
else
    echo "UMASK ${UMASK}" >> /etc/login.defs
fi
echo "umask ${UMASK}" > /etc/profile.d/cis-umask.sh
chmod 644 /etc/profile.d/cis-umask.sh

# 7.6 Secure home directories
echo "[7.6] Securing home directories"
while IFS=: read -r user _ uid _ _ homedir shell; do
    if [ "$uid" -ge 1000 ] && \
       [ "$shell" != "/usr/sbin/nologin" ] && \
       [ "$shell" != "/bin/false" ] && \
       [ -d "$homedir" ]; then
        chmod 750 "$homedir" 2>/dev/null || true
    fi
done < /etc/passwd

# -----------------------------------------------------------------------------
# SECTION 8 - Auditd Configuration
# -----------------------------------------------------------------------------
echo "[8] Auditd Configuration"

# Ensure audit directory exists
mkdir -p /etc/audit/rules.d

cat > /etc/audit/rules.d/cis.rules << 'EOF'
# =============================================================================
# CIS Benchmark - Audit Rules - Debian 13
# =============================================================================

# Remove all existing rules
-D

# Buffer size
-b 8192

# Failure mode (1=printk, 2=panic)
-f 1

# --- Identity changes ---
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# --- Network/locale changes ---
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/networks -p wa -k system-locale

# --- Privileged commands ---
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=-1 -k privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -k privileged

# --- Login/logout events ---
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins

# --- Session events ---
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# --- DAC permission changes ---
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod

# --- Unauthorized file access ---
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k access

# --- Kernel module loading ---
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module,finit_module -k modules

# --- Sudoers changes ---
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# --- Time changes ---
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Make rules immutable — uncomment for production (requires reboot to change)
# -e 2
EOF

systemctl enable auditd
systemctl restart auditd

# -----------------------------------------------------------------------------
# SECTION 9 - Firewall (UFW)
# -----------------------------------------------------------------------------
echo "[9] Firewall Configuration"

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward
ufw allow ssh
ufw logging on
ufw --force enable

# -----------------------------------------------------------------------------
# SECTION 10 - AppArmor
# -----------------------------------------------------------------------------
echo "[10] AppArmor"

systemctl enable apparmor
systemctl start apparmor 2>/dev/null || true

# Enforce all available profiles
if command -v aa-enforce &>/dev/null; then
    find /etc/apparmor.d -maxdepth 1 -type f | while read -r profile; do
        aa-enforce "$profile" 2>/dev/null || true
    done
fi

# -----------------------------------------------------------------------------
# SECTION 11 - Logging (rsyslog)
# -----------------------------------------------------------------------------
echo "[11] Logging Configuration"

systemctl enable rsyslog
systemctl start rsyslog

# Set default file permissions for new log files
if grep -q '^\$FileCreateMode' /etc/rsyslog.conf; then
    sed -i 's/^\$FileCreateMode.*/\$FileCreateMode 0640/' /etc/rsyslog.conf
else
    echo '$FileCreateMode 0640' >> /etc/rsyslog.conf
fi

# Logrotate config
cat > /etc/logrotate.d/cis-rsyslog << 'EOF'
/var/log/syslog
/var/log/auth.log
/var/log/kern.log
/var/log/mail.log
{
    rotate 12
    weekly
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF

# -----------------------------------------------------------------------------
# SECTION 12 - Cron Hardening
# -----------------------------------------------------------------------------
echo "[12] Cron Hardening"

systemctl enable cron

# Restrict cron/at to root only
rm -f /etc/cron.deny /etc/at.deny
touch /etc/cron.allow /etc/at.allow
chown root:root /etc/cron.allow /etc/at.allow
chmod 600 /etc/cron.allow /etc/at.allow

# Secure cron directories
for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    if [ -d "$dir" ]; then
        chown root:root "$dir"
        chmod 700 "$dir"
    fi
done

chown root:root /etc/crontab
chmod 600 /etc/crontab

# -----------------------------------------------------------------------------
# SECTION 13 - File Permissions
# -----------------------------------------------------------------------------
echo "[13] Critical File Permissions"

# passwd/shadow/group
chown root:root /etc/passwd /etc/group
chmod 644 /etc/passwd /etc/group
chown root:shadow /etc/shadow /etc/gshadow
chmod 640 /etc/shadow /etc/gshadow

# SSH host keys
find /etc/ssh -name "ssh_host_*_key" -exec chown root:root {} \; -exec chmod 600 {} \;
find /etc/ssh -name "ssh_host_*_key.pub" -exec chown root:root {} \; -exec chmod 644 {} \;

# sysctl hardening file
chown root:root /etc/sysctl.d/99-cis.conf
chmod 600 /etc/sysctl.d/99-cis.conf

# 13.1 World-writable files (log for review)
echo "[13.1] World-writable files (review log):"
find / -xdev -type f -perm -0002 2>/dev/null | tee -a "$LOG" || true

# 13.2 SUID/SGID binaries (log for review)
echo "[13.2] SUID/SGID binaries (review log):"
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | tee -a "$LOG" || true

# -----------------------------------------------------------------------------
# SECTION 14 - Login Banners
# -----------------------------------------------------------------------------
echo "[14] Login Banners"

cat > /etc/issue << 'EOF'
*******************************************************************************
                    ТЕК РҰҚСАТ ЕТІЛГЕН ПАЙДАЛАНУШЫЛАР ҮШІН
Бұл жүйе тек рұқсат етілген пайдаланушыларға арналған.
Рұқсатсыз кіруге тыйым салынады және заңды жауапкершілікке әкелуі мүмкін.
Барлық әрекеттер бақыланады және тіркеледі.
-------------------------------------------------------------------------------
                    ТОЛЬКО ДЛЯ АВТОРИЗОВАННЫХ ПОЛЬЗОВАТЕЛЕЙ
Эта система предназначена исключительно для авторизованных пользователей.
Несанкционированный доступ запрещён и может повлечь юридическую ответственность.
Вся активность отслеживается и регистрируется.
-------------------------------------------------------------------------------
                         AUTHORIZED ACCESS ONLY
This system is restricted to authorized users for legitimate business purposes.
Unauthorized access is prohibited and may be subject to legal action.
All activity is monitored and logged.
*******************************************************************************
EOF

cp /etc/issue /etc/issue.net
chown root:root /etc/issue /etc/issue.net
chmod 644 /etc/issue /etc/issue.net
truncate -s 0 /etc/motd

# -----------------------------------------------------------------------------
# SECTION 15 - Time Synchronization (chrony)
# -----------------------------------------------------------------------------
echo "[15] Time Synchronization"

systemctl enable chrony

# Replace default pool/server entries with our NTP servers
sed -i '/^pool /d' /etc/chrony/chrony.conf
sed -i '/^server /d' /etc/chrony/chrony.conf
for srv in $NTP_SERVERS; do
    echo "server $srv iburst" >> /etc/chrony/chrony.conf
done

# Restrict chrony control to localhost
grep -q "^bindcmdaddress 127.0.0.1" /etc/chrony/chrony.conf || \
    echo "bindcmdaddress 127.0.0.1" >> /etc/chrony/chrony.conf

systemctl restart chrony

# -----------------------------------------------------------------------------
# SECTION 16 - Sudo Hardening
# -----------------------------------------------------------------------------
echo "[16] Sudo Hardening"

# Validate sudoers before editing
visudo -c -f /etc/sudoers || { echo "ERROR: sudoers invalid, skipping"; exit 1; }

grep -q "^Defaults.*timestamp_timeout" /etc/sudoers || \
    echo "Defaults timestamp_timeout=${SUDO_TIMEOUT}" >> /etc/sudoers

grep -q "^Defaults.*logfile" /etc/sudoers || \
    echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers

grep -q "^Defaults.*requiretty" /etc/sudoers || \
    echo "Defaults requiretty" >> /etc/sudoers

grep -q "^Defaults.*use_pty" /etc/sudoers || \
    echo "Defaults use_pty" >> /etc/sudoers

touch /var/log/sudo.log
chown root:root /var/log/sudo.log
chmod 600 /var/log/sudo.log

# -----------------------------------------------------------------------------
# SECTION 17 - Legacy Interface Naming + IPv6 Disable
# -----------------------------------------------------------------------------
echo "[17] Interface Naming & IPv6"

# 17.1 GRUB kernel parameters
if [ -f /etc/default/grub ]; then
    sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0 ipv6.disable=1"/' \
        /etc/default/grub
    update-grub 2>/dev/null || grub-mkconfig -o /boot/grub/grub.cfg
fi

# 17.2 udev rule for eth0 naming (template-safe: matches by driver not MAC)
cat > /etc/udev/rules.d/70-persistent-net.rules << 'EOF'
SUBSYSTEM=="net", ACTION=="add", DRIVERS=="vmxnet3", ATTR{type}=="1", KERNEL=="en*", NAME="eth0"
EOF

# 17.3 Disable systemd-networkd, use ifupdown
systemctl disable systemd-networkd 2>/dev/null || true
systemctl disable systemd-resolved 2>/dev/null || true
systemctl mask systemd-networkd 2>/dev/null || true
systemctl enable networking 2>/dev/null || true

echo "[17] Done - eth0 and IPv6 disable active after reboot"

# -----------------------------------------------------------------------------
# SECTION 18 - AIDE File Integrity
# -----------------------------------------------------------------------------
echo "[18] AIDE File Integrity"

echo "Initializing AIDE database - this may take several minutes..."
aideinit -y -f 2>/dev/null || aide --init 2>/dev/null || true

# Debian puts new db at aide.db.new
if [ -f /var/lib/aide/aide.db.new ]; then
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
elif [ -f /var/lib/aide/aide.db.new.gz ]; then
    mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
fi

# Daily AIDE check via cron
cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
/usr/bin/aide --check 2>&1 | /usr/bin/mail -s "AIDE Report - $(hostname) - $(date +%Y-%m-%d)" root
EOF
chmod 700 /etc/cron.daily/aide-check
chown root:root /etc/cron.daily/aide-check

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo "============================================="
echo " CIS Hardening Complete"
echo " Finished: $(date)"
echo "============================================="
echo ""
echo "NEXT STEPS before sealing template:"
echo "  1. Review world-writable files in $LOG"
echo "  2. Review SUID/SGID binaries in $LOG"
echo "  3. Verify SSH works — open new session before closing this one"
echo "  4. Reboot — verify eth0 naming and IP still works"
echo "  5. Enable audit immutability: uncomment -e 2 in /etc/audit/rules.d/cis.rules"
echo "  6. Run seal-vm.sh to seal template"
echo ""
echo "  PER-VM WORKFLOW:"
echo "    1. Deploy VM from template in VCD"
echo "    2. Set IP Pool on NIC — VMware Tools applies it automatically"
echo "    3. Edit HOSTNAME/DNS/NTP in vm-customize.sh"
echo "    4. Paste vm-customize.sh into VCD Guest OS Customization Script"
echo "    5. Power on — hostname, DNS and NTP configured on first boot"
echo ""
echo "  Verify with:"
echo "  findmnt -lo TARGET,OPTIONS"
echo "  sshd -T | grep -E 'permitroot|maxauthtries|x11forward'"
echo "  auditctl -l"
echo "  ufw status verbose"
echo "  aa-status"
echo "  ip a  # confirm eth0, no inet6"
echo ""
