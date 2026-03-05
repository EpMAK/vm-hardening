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

# NTP servers
NTP_SERVERS="0.kz.pool.ntp.org 1.kz.pool.ntp.org 2.europe.pool.ntp.org"

# Timezone
TIMEZONE="Asia/Almaty"

# Default umask
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
apt-get install -y -qq locales

# Generate required locales
for locale in $LOCALES; do
    sed -i "s/^# ${locale}/${locale}/" /etc/locale.gen 2>/dev/null ||         echo "${locale} UTF-8" >> /etc/locale.gen
done
locale-gen

# Set system default locale
update-locale LANG="$DEFAULT_LOCALE" LC_ALL="$DEFAULT_LOCALE"

# Set timezone
timedatectl set-timezone "$TIMEZONE"
echo "[0] Locale: $DEFAULT_LOCALE | Timezone: $TIMEZONE"

# -----------------------------------------------------------------------------
# SECTION 1 - Filesystem Configuration
# -----------------------------------------------------------------------------
echo "[1] Filesystem Configuration"

# 1.1 Disable unused filesystems
MODPROBE_CONF="/etc/modprobe.d/cis-disable-fs.conf"
cat > "$MODPROBE_CONF" << 'EOF'
# CIS - Disable unused/risky filesystems
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install usb-storage /bin/true
EOF

# 1.2 Apply mount options to /tmp
echo "[1.2] Hardening /tmp mount options"
if ! grep -q "nodev.*nosuid.*noexec" /etc/fstab | grep "/tmp"; then
    sed -i '/\s\/tmp\s/s/defaults/defaults,nodev,nosuid,noexec/' /etc/fstab
fi

# 1.3 /dev/shm hardening
echo "[1.3] Hardening /dev/shm"
if ! grep -q "/dev/shm" /etc/fstab; then
    echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab
fi

# Remount immediately
mount -o remount,nodev,nosuid,noexec /tmp 2>/dev/null || true
mount -o remount,nodev,nosuid,noexec /dev/shm 2>/dev/null || true

# 1.4 Sticky bit on all world-writable directories
echo "[1.4] Setting sticky bit on world-writable dirs"
df --local -P | awk '{if (NR!=1) print $6}' | \
    xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | \
    xargs chmod a+t 2>/dev/null || true

# -----------------------------------------------------------------------------
# SECTION 2 - Software Updates & Package Management
# -----------------------------------------------------------------------------
echo "[2] Software & Package Management"

# 2.1 Update all packages
echo "[2.1] Updating packages"
apt-get update -qq
apt-get upgrade -y -qq
apt-get autoremove -y -qq

# 2.2 Install required security packages
echo "[2.2] Installing security packages"
apt-get install -y -qq \
    auditd \
    audispd-plugins \
    aide \
    aide-common \
    libpam-pwquality \
    libpam-google-authenticator \
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
apt-get purge -y -qq \
    telnet \
    rsh-client \
    rsh-redone-client \
    talk \
    talkd \
    xinetd \
    nis \
    yp-tools \
    tftp \
    atftpd \
    tftpd \
    tftpd-hpa \
    finger \
    nfs-kernel-server \
    rpcbind 2>/dev/null || true

apt-get autoremove -y -qq

# -----------------------------------------------------------------------------
# SECTION 3 - Secure Boot / Bootloader
# -----------------------------------------------------------------------------
echo "[3] Bootloader Hardening"

# 3.1 Set GRUB password (generates a placeholder - change in production)
echo "[3.1] Setting GRUB permissions"
chown root:root /boot/grub/grub.cfg 2>/dev/null || true
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true

# 3.2 Restrict core dumps
echo "[3.2] Restricting core dumps"
cat > /etc/security/limits.d/cis-coredump.conf << 'EOF'
* hard core 0
EOF

cat >> /etc/sysctl.d/99-cis.conf << 'EOF'
# Disable core dumps
fs.suid_dumpable = 0
EOF

# -----------------------------------------------------------------------------
# SECTION 4 - Kernel / sysctl Hardening
# -----------------------------------------------------------------------------
echo "[4] Kernel Parameter Hardening"

cat > /etc/sysctl.d/99-cis.conf << 'EOF'
# =============================================================================
# CIS Benchmark - Kernel Parameters
# =============================================================================

# --- Network: Disable IP forwarding (not a router) ---
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# --- Network: Disable packet redirect sending ---
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# --- Network: Disable ICMP redirect acceptance ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# --- Network: Disable secure ICMP redirect acceptance ---
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# --- Network: Log suspicious packets ---
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- Network: Disable source routing ---
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# --- Network: Enable reverse path filtering ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# --- Network: Ignore ICMP broadcast requests ---
net.ipv4.icmp_echo_ignore_broadcasts = 1

# --- Network: Ignore bogus ICMP error responses ---
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- Network: Enable SYN cookies (SYN flood protection) ---
net.ipv4.tcp_syncookies = 1

# --- Network: Disable IPv6 router advertisements ---
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# --- Network: Disable TCP timestamps ---
net.ipv4.tcp_timestamps = 0

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

sysctl --system > /dev/null 2>&1

# -----------------------------------------------------------------------------
# SECTION 5 - SSH Hardening
# -----------------------------------------------------------------------------
echo "[5] SSH Hardening"

SSHD_CONFIG="/etc/ssh/sshd_config"
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"

cat > "$SSHD_CONFIG" << 'EOF'
# =============================================================================
# CIS Benchmark - SSH Server Configuration
# =============================================================================

# --- Protocol & Port ---
Port 22
Protocol 2

# --- Authentication ---
PermitRootLogin no
MaxAuthTries 4
MaxSessions 10
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
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

systemctl restart ssh

# -----------------------------------------------------------------------------
# SECTION 6 - PAM / Password Policy
# -----------------------------------------------------------------------------
echo "[6] PAM & Password Policy"

# 6.1 Password quality requirements
cat > /etc/security/pwquality.conf << 'EOF'
# CIS Password Quality Requirements
minlen = $PASS_MIN_LEN
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
sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   $PASS_MAX_DAYS/" /etc/login.defs
sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   $PASS_MIN_DAYS/" /etc/login.defs
sed -i "s/^PASS_WARN_AGE.*/PASS_WARN_AGE   $PASS_WARN_AGE/" /etc/login.defs

# 6.3 Account lockout via faillock
cat > /etc/security/faillock.conf << 'EOF'
# CIS - Account lockout policy
deny = $LOCKOUT_ATTEMPTS
fail_interval = $LOCKOUT_TIME
unlock_time = $LOCKOUT_TIME
EOF

# 6.4 Ensure password hashing is SHA-512
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
echo "SHA_CRYPT_MIN_ROUNDS 5000" >> /etc/login.defs

# 6.5 Inactive account lockout
useradd -D -f 30

# -----------------------------------------------------------------------------
# SECTION 7 - User & Group Security
# -----------------------------------------------------------------------------
echo "[7] User & Group Security"

# 7.1 Root is the only UID 0 account
echo "[7.1] Checking UID 0 accounts"
awk -F: '($3 == 0) { print $1 }' /etc/passwd | grep -v "^root$" | while read user; do
    echo "WARNING: Non-root UID 0 account found: $user"
done

# 7.2 Ensure root PATH integrity
if echo "$PATH" | grep -q "::"; then
    echo "WARNING: Empty directory in root PATH"
fi

# 7.3 Lock system accounts
echo "[7.3] Locking system accounts"
awk -F: '($3 < 1000) {print $1}' /etc/passwd | grep -v "^root$" | while read user; do
    passwd -l "$user" 2>/dev/null || true
done

# 7.4 Remove legacy + entries from passwd/shadow/group
sed -i '/^+:/d' /etc/passwd /etc/shadow /etc/group

# 7.5 Set umask
sed -i "s/^UMASK.*/UMASK $UMASK/" /etc/login.defs
echo "umask $UMASK" >> /etc/profile.d/cis-umask.sh

# 7.6 Ensure home directories exist and are secured
echo "[7.6] Securing home directories"
awk -F: '($3 >= 1000 && $7 != "/usr/sbin/nologin" && $7 != "/bin/false") {print $1":"$6}' \
    /etc/passwd | while IFS=: read user homedir; do
    if [ -d "$homedir" ]; then
        chmod 750 "$homedir" 2>/dev/null || true
        chown "$user" "$homedir" 2>/dev/null || true
    fi
done

# -----------------------------------------------------------------------------
# SECTION 8 - Auditd Configuration
# -----------------------------------------------------------------------------
echo "[8] Auditd Configuration"

cat > /etc/audit/rules.d/cis.rules << 'EOF'
# =============================================================================
# CIS Benchmark - Audit Rules
# =============================================================================

# --- Remove all existing rules ---
-D

# --- Set buffer size ---
-b 8192

# --- Failure mode (1=printk, 2=panic) ---
-f 1

# --- System calls: identity changes ---
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# --- System calls: network config changes ---
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale

# --- Privileged commands ---
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# --- Login/logout events ---
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# --- Session events ---
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# --- DAC permission changes ---
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# --- Unauthorized file access attempts ---
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# --- Kernel module loading ---
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# --- Sudo usage ---
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# --- Time changes ---
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# --- Make rules immutable (comment out during template build, enable for prod) ---
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
ufw allow ssh
ufw --force enable

# -----------------------------------------------------------------------------
# SECTION 10 - AppArmor
# -----------------------------------------------------------------------------
echo "[10] AppArmor"

systemctl enable apparmor
systemctl start apparmor

# Set all profiles to enforce mode
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

# -----------------------------------------------------------------------------
# SECTION 11 - Logging
# -----------------------------------------------------------------------------
echo "[11] Logging Configuration"

# 11.1 Ensure rsyslog is enabled
systemctl enable rsyslog
systemctl start rsyslog

# 11.2 Set rsyslog default file permissions
grep -q "^\$FileCreateMode" /etc/rsyslog.conf && \
    sed -i 's/^\$FileCreateMode.*/$FileCreateMode 0640/' /etc/rsyslog.conf || \
    echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf

# 11.3 Logrotate hardening
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

# Restrict cron to root only
rm -f /etc/cron.deny /etc/at.deny
touch /etc/cron.allow /etc/at.allow
chown root:root /etc/cron.allow /etc/at.allow
chmod 600 /etc/cron.allow /etc/at.allow

# Secure cron directories
for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    chown root:root "$dir"
    chmod 700 "$dir"
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

# Sysctl
chown root:root /etc/sysctl.conf
chmod 600 /etc/sysctl.conf

# 13.1 Find world-writable files (log only, review manually)
echo "[13.1] World-writable files (review log):"
find / -xdev -type f -perm -0002 2>/dev/null | tee -a "$LOG" || true

# 13.2 Find SUID/SGID binaries (log only)
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

# Remove MOTD
truncate -s 0 /etc/motd

# -----------------------------------------------------------------------------
# SECTION 15 - Time Synchronization
# -----------------------------------------------------------------------------
echo "[15] Time Synchronization"

systemctl enable chrony
systemctl start chrony

# Restrict chrony to localhost query
# Set NTP servers from parameters
for srv in $NTP_SERVERS; do
    grep -q "^server $srv" /etc/chrony/chrony.conf || \
        echo "server $srv iburst" >> /etc/chrony/chrony.conf
done
grep -q "^bindaddress" /etc/chrony/chrony.conf || \
    echo "bindaddress 127.0.0.1" >> /etc/chrony/chrony.conf

# -----------------------------------------------------------------------------
# SECTION 16 - Sudo Configuration
# -----------------------------------------------------------------------------
echo "[16] Sudo Hardening"

# Require password for sudo
grep -q "^Defaults.*timestamp_timeout" /etc/sudoers || \
    echo "Defaults timestamp_timeout=$SUDO_TIMEOUT" >> /etc/sudoers

# Log sudo usage
grep -q "^Defaults.*logfile" /etc/sudoers || \
    echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers

# Require TTY for sudo
grep -q "^Defaults.*requiretty" /etc/sudoers || \
    echo "Defaults requiretty" >> /etc/sudoers

# Secure sudo log
touch /var/log/sudo.log
chown root:root /var/log/sudo.log
chmod 600 /var/log/sudo.log

# -----------------------------------------------------------------------------
# SECTION 17 - Legacy Interface Naming (eth0 instead of ens/enp)
# -----------------------------------------------------------------------------
echo "[17] Legacy Interface Naming"

# 17.1 GRUB kernel parameters
sed -i 's/GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"/' \
    /etc/default/grub
update-grub

# 17.2 udev rule to pin first vmxnet3 NIC to eth0
cat > /etc/udev/rules.d/70-persistent-net.rules << 'EOF'
SUBSYSTEM=="net", ACTION=="add", DRIVERS=="vmxnet3", ATTR{type}=="1", NAME="eth0"
EOF

# 17.3 Ensure ifupdown is managing networking (not networkd)
systemctl disable systemd-networkd 2>/dev/null || true
systemctl disable systemd-resolved 2>/dev/null || true
systemctl enable networking

echo "[17] Legacy naming configured - eth0 will be active after reboot"

# -----------------------------------------------------------------------------
# SECTION 17b - Remove cloud-init if present
# -----------------------------------------------------------------------------
echo "[17b] Removing cloud-init"
apt-get purge -y -qq cloud-init 2>/dev/null || true
rm -rf /etc/cloud /var/lib/cloud
apt-get autoremove -y -qq

# -----------------------------------------------------------------------------
# SECTION 18 - AIDE Initialization
# -----------------------------------------------------------------------------
echo "[18] AIDE File Integrity"

# Initialize AIDE database (takes a few minutes)
echo "Initializing AIDE database - this may take a while..."
aideinit --yes 2>/dev/null || aide --init 2>/dev/null || true
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true

# Schedule daily AIDE check
cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
/usr/bin/aide --check | mail -s "AIDE Report - $(hostname) - $(date)" root
EOF
chmod 700 /etc/cron.daily/aide-check

# =============================================================================
# SECTION 19 - Drop-in Boot Customization Script
# =============================================================================
echo "[19] Installing boot customization script"

# This script is installed on the TEMPLATE.
# Before deploying each VM, edit /etc/vm-init/vm-init.conf with that VM's values.
# On first boot it applies hostname + static network config then disables itself.

mkdir -p /etc/vm-init

# --- Configuration file (fill in per VM before sealing or after deploy) ---
cat > /etc/vm-init/vm-init.conf << 'EOF'
# =============================================================================
# VM Init Configuration
# Fill in these values before deploying each VM from template
# =============================================================================

HOSTNAME="changeme"
IP_ADDRESS="10.0.0.1"
NETMASK="255.255.255.0"
GATEWAY="10.0.0.1"
DNS1="10.0.0.1"
DNS2="10.0.0.2"
SEARCH_DOMAIN="your.domain.local"
EOF

# --- Boot script ---
cat > /usr/local/sbin/vm-init.sh << 'INITEOF'
#!/bin/bash
# =============================================================================
# VM Init Script - runs once on first boot to apply network config
# =============================================================================

LOG="/var/log/vm-init.log"
CONF="/etc/vm-init/vm-init.conf"
DONE="/etc/vm-init/.done"

# Skip if already ran
if [ -f "$DONE" ]; then
    exit 0
fi

echo "$(date) - vm-init starting" >> "$LOG"

# Bail if config not filled in
if [ ! -f "$CONF" ]; then
    echo "$(date) - ERROR: $CONF not found" >> "$LOG"
    exit 1
fi

source "$CONF"

# Validate config was actually filled in
if [ "$HOSTNAME" = "changeme" ]; then
    echo "$(date) - ERROR: vm-init.conf not configured" >> "$LOG"
    exit 1
fi

# --- Apply hostname ---
hostnamectl set-hostname "$HOSTNAME"
sed -i "/127.0.1.1/d" /etc/hosts
echo "127.0.1.1 $HOSTNAME" >> /etc/hosts
echo "$(date) - Hostname set to $HOSTNAME" >> "$LOG"

# --- Apply network ---
cat > /etc/network/interfaces << EOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address ${IP_ADDRESS}
    netmask ${NETMASK}
    gateway ${GATEWAY}
    dns-nameservers ${DNS1} ${DNS2}
EOF

# --- Apply DNS ---
chattr -i /etc/resolv.conf 2>/dev/null || true
cat > /etc/resolv.conf << EOF
search ${SEARCH_DOMAIN}
nameserver ${DNS1}
nameserver ${DNS2}
EOF
chattr +i /etc/resolv.conf

# --- Restart networking ---
systemctl restart networking
echo "$(date) - Network configured: $IP_ADDRESS" >> "$LOG"

# --- Mark as done so it never runs again ---
touch "$DONE"
echo "$(date) - vm-init complete" >> "$LOG"

# --- Disable the service ---
systemctl disable vm-init.service
INITEOF

chmod 700 /usr/local/sbin/vm-init.sh
chown root:root /usr/local/sbin/vm-init.sh

# --- systemd service to run on first boot ---
cat > /etc/systemd/system/vm-init.service << 'EOF'
[Unit]
Description=VM First Boot Initialization
After=network-pre.target
Before=network.target
ConditionPathExists=!/etc/vm-init/.done

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vm-init.sh
RemainAfterExit=yes
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
EOF

systemctl enable vm-init.service
echo "[19] Boot customization script installed"
echo "     Edit /etc/vm-init/vm-init.conf before deploying each VM"

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
echo "  3. Verify SSH access still works (new session before closing this one)"
echo "  4. Enable audit immutability (-e 2) in /etc/audit/rules.d/cis.rules"
echo "     if deploying to production (cannot undo without reboot)"
echo "  5. Reboot once to verify eth0 naming before sealing"
echo "  6. Run seal-vm.sh after this script"
echo ""
echo "  PER-VM WORKFLOW:"
echo "  After deploying VM from template:"
echo "    1. Access via VCD console"
echo "    2. Edit /etc/vm-init/vm-init.conf with correct values"
echo "    3. Reboot — vm-init runs once, configures network, disables itself"
echo ""
echo "  Verify with:"
echo "  findmnt -lo TARGET,OPTIONS"
echo "  sshd -T | grep -E 'permitroot|maxauthtries|x11forward'"
echo "  auditctl -l"
echo "  ufw status verbose"
echo "  aa-status"
echo "  ip a  # confirm eth0"
echo ""
