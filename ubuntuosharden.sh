#!/bin/sh

#run "sudo sh linux.sh" to the rootuser 

#----------CIS_Ubuntu_Linux_16.04_LTS_Benchmark------------------------------------



#1.1.1.1 Ensure Mounting of cramfs is disabled (Scored)

echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.2 Ensure mounting of freevxfs filesystems is disabled (Scored)

echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.3 Ensure mounting of jffs2 filesystems is disabled (Scored)

echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.4 Ensure mounting of hfs filesystems is disabled (Scored)

echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.5 Ensure mounting of hfsplus filesystems is disabled (Scored)
echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.6 Ensure mounting of squashfs filesystems is disabled (Scored)

echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.7 Ensure mounting of udf filesystems is disabled (Scored)

echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.1.8 Ensure mounting of FAT filesystems is disabled (Scored)

echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf

#1.1.9 Ensure noexec option set on /var/tmp partition (Scored)
#1.1.10 Ensure separate partition exists for /var/log (Scored)
#1.1.11 Ensure separate partition exists for /var/log/audit (Scored)
#1.1.12 Ensure separate partition exists for /home (Scored)
#1.1.13 Ensure nodev option set on /home partition (Scored)
#1.1.14 Ensure nodev option set on /dev/shm partition (Scored)
#1.1.15 Ensure nosuid option set on /dev/shm partition (Scored)
#1.1.16 Ensure noexec option set on /dev/shm partition (Scored


#1.1.17 Ensure nodev option set on removable media partitions (Not Scored)
#1.1.18 Ensure nosuid option set on removable media partitions (Not Scored)
#1.1.19 Ensure noexec option set on removable media partitions (Not Scored)

#1.1.20 Ensure sticky bit is set on all world-writable directories (Scored)

 
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

#1.1.21 Disable Automounting (Scored)

systemctl disable autofs

#1.2 Configure Software Updates


#1.2.1 Ensure package manager repositories are configured (Not Scored)
#1.2.2 Ensure GPG keys are configured (Not Scored)

#1.3 Filesystem Integrity Checking
#1.3.1 Ensure AIDE is installed (Scored)

apt-get install aide 
aideinit

#1.3.2 Ensure filesystem integrity is regularly checked (Scored)

echo "0 5 * * * /usr/bin/aide --check" >> /tmp/crontab.m6Erxv/crontab
#(to do manually)

#1.4 Secure Boot Settings
#1.4.1 Ensure permissions on bootloader config are configured (Scored)


chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg

#1.4.2 Ensure bootloader password is set (Scored)

#grub-mkpasswd-pbkdf2 | tee grubpassword.tmp
#grubpassword=$(cat grubpassword.tmp | sed -e '1,2d' | cut -d ' ' -f7)
#echo " set superusers="root" " >> /etc/grub.d/40_custom
#echo " password_pbkdf2 root $grubpassword " >> /etc/grub.d/40_custom
#rm grubpassword.tmp
#update-grub
#(to do manually)


#1.4.3 Ensure authentication required for single user mode (Scored)
#passwd root
#(to do manually because it asks new password for the root user)

#1.5 Additional Process Hardening
#1.5.1 Ensure core dumps are restricted (Scored)

echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable=0

#1.5.2 Ensure XD/NX support is enabled (Not Scored)
#1.5.3 Ensure address space layout randomization (ASLR) is enabled (Scored)
   
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
sysctl -w kernel.randomize_va_space=2

#1.5.4 Ensure prelink is disabled (Scored)
  # not installed by default on Clean Ubuntu install, will add condition later on
apt-get remove prelink
#1.6 Mandatory Access Control
#1.6.1.1 Ensure SELinux is not disabled in bootloader configuration (Scored) N/A
#1.6.1.2 Ensure the SELinux state is enforcing (Scored) N/A
#1.6.1.3 Ensure SELinux policy is configured (Scored)  N/A
#1.6.1.4 Ensure no unconfined daemons exist (Scored)  N/A
#1.6.2.1 Ensure AppArmor is not disabled in bootloader configuration (Scored)
#1.6.2.2 Ensure all AppArmor Profiles are enforcing (Scored)
#1.6.3 Ensure SELinux or AppArmor are installed (Not Scored)

#1.7 Warning Banners
#1.7.1.1 Ensure message of the day is configured properly (Scored)
#1.7.1.2 Ensure local login warning banner is configured properly (Not Scored)
#1.7.1.3 Ensure remote login warning banner is configured properly (Not Scored)

#1.7.1.4 Ensure permissions on /etc/motd are configured (Not Scored)
#1.7.1.5 Ensure permissions on /etc/issue are configured (Scored)

chown root:root /etc/issue
chmod 644 /etc/issue

#1.7.1.6 Ensure permissions on /etc/issue.net are configured (Not Scored)

chown root:root /etc/issue.net
chmod 644 /etc/issue.net

#1.7.2 Ensure GDM login banner is configured (Scored)
#(to do manually)
#1.8 Ensure updates, patches, and additional security software are installed (Not Scored)

#apt-get update
#apt-get -y upgrade

############################################################


### NOT ENABLED ON CLEAN INSTALL
## Will configure later on for current install ##


#2 Services
#2.1 inetd Services
#2.1.1 Ensure chargen services are not enabled (Scored)
#.1.2 Ensure daytime services are not enabled (Scored)
#2.1.3 Ensure discard services are not enabled (Scored)
#2.1.4 Ensure echo services are not enabled (Scored)
#2.1.5 Ensure time services are not enabled (Scored)
#2.1.6 Ensure rsh server is not enabled (Scored)
#2.1.7 Ensure talk server is not enabled (Scored)
#2.1.8 Ensure telnet server is not enabled (Scored)
#2.1.9 Ensure tftp server is not enabled (Scored)
#2.1.10 Ensure xinetd is not enabled (Scored)

##############################################################
#2.2 Special Purpose Services
#2.2.1.1 Ensure time synchronization is in use (Not Scored)
#2.2.1.2 Ensure ntp is configured (Scored)

apt-get install ntp

echo "restrict -4 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
echo "RUNASUSER=ntp" >> /etc/init.d/ntp


#2.2.1.3 Ensure chrony is configured (Scored)

#apt-get install chrony

#2.2.2 Ensure X Window System is not installed (Scored)

#apt-get remove xserver-xorg*

#2.2.3 Ensure Avahi Server is not enabled (Scored)

systemctl disable avahi-daemon

#2.2.4 Ensure CUPS is not enabled (Scored)

systemctl disable cups

#2.2.5 Ensure DHCP Server is not enabled (Scored)

systemctl disable isc-dhcp-server
systemctl disable isc-dhcp-server6

#2.2.6 Ensure LDAP server is not enabled (Scored)

systemctl disable slapd

#2.2.7 Ensure NFS and RPC are not enabled (Scored)

systemctl disable nfs-kernel-server
systemctl disable rpcbind

#2.2.8 Ensure DNS Server is not enabled (Scored)

systemctl disable bind9

#2.2.9 Ensure FTP Server is not enabled (Scored)

systemctl disable vsftpd 

#2.2.10 Ensure HTTP server is not enabled (Scored)

systemctl disable apache2

#2.2.11 Ensure IMAP and POP3 server is not enabled (Scored)

systemctl disable dovecot

#2.2.12 Ensure Samba is not enabled (Scored)

systemctl disable smbd

#2.2.13 Ensure HTTP Proxy Server is not enabled (Scored)

systemctl disable squid

#2.2.14 Ensure SNMP Server is not enabled (Scored)

systemctl disable snmpd

#2.2.15 Ensure mail transfer agent is configured for local-only mode (Scored)

echo "inet_interfaces = localhost" >> /etc/postfix/main.cf
service postfix restart

#2.2.16 Ensure rsync service is not enabled (Scored)

systemctl disable rsync

#2.2.17 Ensure NIS Server is not enabled (Scored)

systemctl disable nis

#2.3 Service Clients
#2.3.1 Ensure NIS Client is not installed (Scored)

apt-get remove nis

#2.3.2 Ensure rsh client is not installed (Scored)

apt-get remove rsh-client rsh-redone-client

#2.3.3 Ensure talk client is not installed (Scored)

apt-get remove talk

#2.3.4 Ensure telnet client is not installed (Scored)

apt-get remove telnet

#2.3.5 Ensure LDAP client is not installed (Scored)

apt-get remove ldap-utils

#######################################################################

#3 Network Configuration
#3.1 Network Parameters (Host Only)
#3.1.1 Ensure IP forwarding is disabled (Scored)

echo"net.ipv4.ip_forward = 0" >>  /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.route.flush=1

#3.1.2 Ensure packet redirect sending is disabled (Scored)

echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1

#3.2 Network Parameters (Host and Router)
#3.2.1 Ensure source routed packets are not accepted (Scored)

echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1

#3.2.2 Ensure ICMP redirects are not accepted (Scored)

echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1

#3.2.3 Ensure secure ICMP redirects are not accepted (Scored)

echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1

#3.2.4 Ensure suspicious packets are logged (Scored)

echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1

#3.2.5 Ensure broadcast ICMP requests are ignored (Scored)

echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1

#3.2.6 Ensure bogus ICMP responses are ignored (Scored)

echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1

#3.2.7 Ensure Reverse Path Filtering is enabled (Scored)

echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1

#3.2.8 Ensure TCP SYN Cookies is enabled (Scored)

echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1

#3.3 IPv6
#3.3.1 Ensure IPv6 router advertisements are not accepted (Not Scored)

echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1

#3.3.2 Ensure IPv6 redirects are not accepted (Not Scored)

echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv6.route.flush=1

#3.3.3 Ensure IPv6 is disabled (Not Scored)

echo "GRUB_CMDLINE_LINUX="ipv6.disable=1"" >> /etc/default/grub
update-grub


#3.4 TCP Wrappers
#3.4.1 Ensure TCP Wrappers is installed (Scored)
# Installed by default


#3.4.2 Ensure /etc/hosts.allow is configured (Scored)

echo "ALL: 10.0.0.0/255.0.0.0" >> /etc/hosts.allow
echo "ALL: 192.168.0.0/255.255.0.0" >> /etc/hosts.allow
echo "ALL: 172.16.0.0/255.240.0.0" >> /etc/hosts.allow

#3.4.3 Ensure /etc/hosts.deny is configured (Scored)

echo "ALL: ALL" >> /etc/hosts.deny

#3.4.4 Ensure permissions on /etc/hosts.allow are configured (Scored)

chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow

#3.4.5 Ensure permissions on /etc/hosts.deny are 644 (Scored)

chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny

#3.5 Uncommon Network Protocols
#3.5.1 Ensure DCCP is disabled (Not Scored)

echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf

#3.5.2 Ensure SCTP is disabled (Not Scored)

echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf

#3.5.3 Ensure RDS is disabled (Not Scored)

echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf

#3.5.4 Ensure TIPC is disabled (Not Scored)

echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf

#3.6 Firewall Configuration
#3.6.1 Ensure iptables is installed (Scored)

apt-get install iptables

#3.6.2 Ensure default deny firewall policy (Scored)

#iptables -P INPUT DROP
#iptables -P OUTPUT DROP
#iptables -P FORWARD DROP

#3.6.3 Ensure loopback traffic is configured (Scored)

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
#iptables -A INPUT -s 127.0.0.0/8 -j DROP

#3.6.4 Ensure outbound and established connections are configured (Not Scored)

iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT


#3.6.5 Ensure firewall rules exist for all open ports (Scored)
#(to do manually)


#3.7 Ensure wireless interfaces are disabled (Not Scored)

#4 Logging and Auditing
#4.1 Configure System Accounting (auditd)

apt-get install auditd

#4.1.1.1 Ensure audit log storage size is configured (Not Scored)
#4.1.1.2 Ensure system is disabled when audit logs are full (Scored)

echo "space_left_action = email" >>  /etc/audit/auditd.conf
echo "action_mail_acct = root" >> /etc/audit/auditd.conf
echo "admin_space_left_action = halt" >> /etc/audit/auditd.conf

#4.1.1.3 Ensure audit logs are not automatically deleted (Scored)

echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf

#4.1.2 Ensure auditd service is enabled (Scored)

systemctl enable auditd

#4.1.3 Ensure auditing for processes that start prior to auditd is enabled (Scored)

echo "GRUB_CMDLINE_LINUX=audit=1" >> /etc/default/grub
update-grub

#4.1.4 Ensure events that modify date and time information are collected(Scored)

 
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/audit.rules 
echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/audit.rules
echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/audit.rules

#4.1.5 Ensure events that modify user/group information are collected (Scored)

echo "-w /etc/group -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/audit.rules

#4.1.6 Ensure events that modify the system's network environment are collected (Scored)

echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules 
echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules 
echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/audit.rules 
echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/audit.rules 
echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/audit.rules 
echo "-w /etc/network -p wa -k system-locale" >> /etc/audit/audit.rules 
echo "-w /etc/networks -p wa -k system-locale" >> /etc/audit/audit.rules 

#4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected (Scored)

echo "-w /etc/apparmor/ -p wa -k MAC-policy" >> /etc/audit/audit.rules
echo "-w /etc/apparmor.d/ -p wa -k MAC-policy" >> /etc/audit/audit.rules

#4.1.8 Ensure login and logout events are collected (Scored)

echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/audit.rules 
echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/audit.rules 
echo "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/audit.rules 

#4.1.9 Ensure session initiation information is collected (Scored)

echo "-w /var/run/utmp -p wa -k session" >>  /etc/audit/audit.rules
echo "-w /var/log/wtmp -p wa -k session" >>  /etc/audit/audit.rules
echo "-w /var/log/btmp -p wa -k session" >>  /etc/audit/audit.rules

#4.1.10 Ensure discretionary access control permission modification events are collected (Scored)


echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F
auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F
auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F
auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F
auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S
lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S
lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules



#4.1.11 Ensure unsuccessful unauthorized file access attempts are collected (Scored)

echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F
exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules 
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F
exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules 
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F
exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules 
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F
exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules 

#4.1.12 Ensure use of privileged commands is collected (Scored)

#4.1.13 Ensure successful file system mounts are collected (Scored)

echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
 
#4.1.14 Ensure file deletion events by users are collected (Scored)

echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -
F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -
F auid!=4294967295 -k delete" >> /etc/audit/audit.rules

#4.1.15 Ensure changes to system administration scope (sudoers) is collected (Scored)

echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/audit.rules
echo "-w /etc/sudoers.d -p wa -k scope" >> /etc/audit/audit.rules

#4.1.16 Ensure system administrator actions (sudolog) are collected (Scored)

echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/audit.rules

#4.1.17 Ensure kernel module loading and unloading is collected (Scored)

echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/audit.rules 
echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/audit.rules 
echo "-w /sbin/modprobe -p x -k modules">> /etc/audit/audit.rules 
echo "-a always,exit arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules 

#4.1.18 Ensure the audit configuration is immutable (Scored)

echo "-e 2" >> /etc/audit/audit.rules

#check

#4.2 Configure Logging
#4.2.1.1 Ensure rsyslog Service is enabled (Scored)

systemctl enable rsyslog

#4.2.1.2 Ensure logging is configured (Not Scored)
#4.2.1.3 Ensure rsyslog default file permissions configured (Scored)

echo "$FileCreateMode 0640" >> /etc/rsyslog.conf

#4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host (Scored)

echo "*.* @@loghost.example.com" >> /etc/rsyslog.conf
pkill -HUP rsyslogd

#4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts. (Not Scored)
#(if log hosts are designed as a log hosts)

echo "$ModLoad imtcp.so" >> /etc/rsyslog.conf 
echo "$InputTCPServerRun 514"  >> /etc/rsyslog.conf
pkill -HUP rsyslogd 

#4.2.2.1 Ensure syslog-ng service is enabled (Scored)

apt install syslog-ng-core
systemctl is-enabled syslog-ng
update-rc.d syslog-ng enable

#4.2.2.2 Ensure logging is configured (Not Scored)
#4.2.2.3 Ensure syslog-ng default file permissions configured (Scored)
#(comes default)
#4.2.2.4 Ensure syslog-ng is configured to send logs to a remote log host (Scored)

#4.2.2.5 Ensure remote syslog-ng messages are only accepted on designated log hosts (Not Scored)
#4.2.3 Ensure rsyslog or syslog-ng is installed (Scored)
#4.2.4 Ensure permissions on all logfiles are configured (Scored)

chmod -R g-wx,o-rwx /var/log/*

#4.3 Ensure logrotate is configured (Not Scored)


#5 Access, Authentication and Authorization
#5.1 Configure cron
#5.1.1 Ensure cron daemon is enabled (Scored)

systemctl enable cron

#5.1.2 Ensure permissions on /etc/crontab are configured (Scored)

chown root:root /etc/crontab  
chmod og-rwx /etc/crontab

#5.1.3 Ensure permissions on /etc/cron.hourly are configured (Scored)

chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly

#5.1.4 Ensure permissions on /etc/cron.daily are configured (Scored)

chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily

#5.1.5 Ensure permissions on /etc/cron.weekly are configured (Scored)

chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly

#5.1.6 Ensure permissions on /etc/cron.monthly are configured (Scored)

chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly

#5.1.7 Ensure permissions on /etc/cron.d are configured (Scored)

chown root:root /etc/cron*
chmod og-rwx /etc/cron*

#5.1.8 Ensure at/cron is restricted to authorized users (Scored)

touch /etc/cron.allow
touch /etc/at.allow

chmod og-rwx /etc/cron.allow /etc/at.allow
chown root:root /etc/cron.allow /etc/at.allow

#5.2 SSH Server Configuration
#5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Scored)

apt-get install openssh-server
service sshd reload
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

#5.2.2 Ensure SSH Protocol is set to 2 (Scored)

echo "Protocol 2" >> /etc/ssh/sshd_config


#5.2.3 Ensure SSH LogLevel is set to INFO (Scored)

echo "LogLevel INFO" >> /etc/ssh/sshd_config

#5.2.4 Ensure SSH X11 forwarding is disabled (Scored)

echo "X11Forwarding no" >> /etc/ssh/sshd_config

#5.2.5 Ensure SSH MaxAuthTries is set to 4 or less (Scored)

echo "MaxAuthTries 4" >> /etc/ssh/sshd_config

#5.2.6 Ensure SSH IgnoreRhosts is enabled (Scored)

echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config

#5.2.7 Ensure SSH HostbasedAuthentication is disabled (Scored)

echo "HostbasedAuthentication no" >>  /etc/ssh/sshd_config

#5.2.8 Ensure SSH root login is disabled (Scored)

echo "PermitRootLogin no" >> /etc/ssh/sshd_config

#5.2.9 Ensure SSH PermitEmptyPasswords is disabled (Scored)

echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config

#5.2.10 Ensure SSH PermitUserEnvironment is disabled (Scored)

echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config

#5.2.11 Ensure only approved MAC algorithms are used (Scored)

echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-
etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config 

#5.2.12 Ensure SSH Idle Timeout Interval is configured (Scored)

echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config

#5.2.13 Ensure SSH LoginGraceTime is set to one minute or less (Scored)

echo "LoginGraceTime 60" >> /etc/ssh/sshd_config 

#5.2.14 Ensure SSH access is limited (Scored)

#(to do manually)

#5.2.15 Ensure SSH warning banner is configured (Scored)

echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config

##Create user for SSH Access


#5.3 Configure PAM
#5.3.1 Ensure password creation requirements are configured (Scored)

#apt-get install libpam-pwquality
#echo "password requisite pam_pwquality.so try_first_pass retry=3" >> /etc/pam.d/common-passwd
#echo "minlen=14" >> /etc/security/pwquality.conf
#echo "dcredit=-1" >> /etc/security/pwquality.conf
#echo "ucredit=-1" >> /etc/security/pwquality.conf
#echo "ocredit=-1" >> /etc/security/pwquality.conf
#echo "lcredit=-1" >> /etc/security/pwquality.conf

#5.3.2 Ensure lockout for failed password attempts is configured (Not Scored)

#echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> /etc/pam.d/common-auth

#5.3.3 Ensure password reuse is limited (Scored)

#echo "password sufficient pam_unix.so remember=5" >> /etc/pam.d/common-password

#5.3.4 Ensure password hashing algorithm is SHA-512 (Scored)

#echo "password sufficient pam_unix.so sha512" >> /etc/pam.d/common-password 

#5.4 User Accounts and Environment
#5.4.1.1 Ensure password expiration is 90 days or less (Scored)

#echo "PASS_MAX_DAYS 90" >> /etc/login.defs

#5.4.1.2 Ensure minimum days between password changes is 7 or more (Scored)

#echo "PASS_MIN_DAYS 7" >> /etc/login.defs

#5.4.1.3 Ensure password expiration warning days is 7 or more (Scored)

echo "PASS_WARN_AGE 7" >> /etc/login.defs

#5.4.1.4 Ensure inactive password lock is 30 days or less (Scored)

useradd -D -f 30

#5.4.2 Ensure system accounts are non-login (Scored)

for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
  if [ $user != "root" ]; then
    usermod -L $user
  if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
    usermod -s /usr/sbin/nologin $user
  fi
  fi
done

#5.4.3 Ensure default group for the root account is GID 0 (Scored)

usermod -g 0 root

#5.4.4 Ensure default user umask is 027 or more restrictive (Scored)

echo "umask 027" >> /etc/bash.bashrc 
echo "umask 027" >> /etc/profile
sed -i s/umask\ 022/umask\ 027/g /etc/init.d/rc

#5.5 Ensure root login is restricted to system console (Not Scored)
#5.6 Ensure access to the su command is restricted (Scored)

echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su

#6 System Maintenance
#6.1 System File Permissions
#6.1.1 Audit system file permissions (Not Scored)
#6.1.2 Ensure permissions on /etc/passwd are configured (Scored)

chown root:root /etc/passwd
chmod 644 /etc/passwd

#6.1.3 Ensure permissions on /etc/shadow are configured (Scored)

chown root:shadow /etc/shadow
chmod o-rwx,g-wx /etc/shadow

#6.1.4 Ensure permissions on /etc/group are configured (Scored)

chown root:root /etc/group
chmod 644 /etc/group

#6.1.5 Ensure permissions on /etc/gshadow are configured (Scored)

chown root:shadow /etc/gshadow
chmod o-rwx,g-rw /etc/gshadow

#6.1.6 Ensure permissions on /etc/passwd - are configured (Scored)

chown root:root /etc/passwd-
chmod 600 /etc/passwd-

#6.1.7 Ensure permissions on /etc/shadow - are configured (Scored)

chown root:root /etc/shadow-
chmod 600 /etc/shadow-

#6.1.8 Ensure permissions on /etc/group - are configured (Scored)

chown root:root /etc/group-
chmod 600 /etc/group-

#6.1.9 Ensure permissions on /etc/gshadow - are configured (Scored)

chown root:root /etc/gshadow-
chmod 600 /etc/gshadow-

#6.1.10 Ensure no world writable files exist (Scored)
#6.1.11 Ensure no unowned files or directories exist (Scored)
#6.1.12 Ensure no ungrouped files or directories exist (Scored)
#6.1.13 Audit SUID executables (Not Scored)
#6.1.14 Audit SGID executables (Not Scored)
#6.2 User an d Group Settings
#6.2.1 Ensure password fields are not empty (Scored)
#6.2.2 Ensure no legacy "+" entries exist in /etc/passwd (Scored)
#6.2.3 Ensure no legacy "+" entries exist in /etc/shadow (Scored)
#6.2.4 Ensure no legacy "+" entries exist in /etc/group (Scored)
#6.2.5 Ensure root is the only UID 0 account (Scored)
#6.2.6 Ensure root PATH Integrity (Scored)
#6.2.7 Ensure all users' home directories exist (Scored)
#6.2.8 Ensure users' home directories permissions are 750 or more restrictive (Scored)
#6.2.9 Ensure users own their home directories (Scored)
#6.2.10 Ensure users' dot files are not group or world writable (Scored)
#6.2.11 Ensure no users have .forward files (Scored)
#6.2.12 Ensure no users have .netrc files (Scored)
#6.2.13 Ensure users' .netrc Files are not group or world accessible (Scored)
#6.2.14 Ensure no users have .rhosts files (Scored)
#6.2.15 Ensure all groups in /etc/passwd exist in /etc/group (Scored)
#6.2.16 Ensure no duplicate UIDs e xist (Scored)
#6.2.17 Ensure no duplicate GIDs exist (Scored)
#6.2.18 Ensure no duplicate user names exist (Scored)
#6.2.19 Ensure no duplicate group names exist (Scored)
#6.2.20 Ensure shadow group is empty (Scored
