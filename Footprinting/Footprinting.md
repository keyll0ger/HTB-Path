# Footprinting 

## Certificate Transparency

```bash
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .
[
{
"issuer_ca_id": 23451835427,
"issuer_name": "C=US, O=Let's Encrypt, CN=R3",
"common_name": "matomo.inlanefreight.com",
"name_value": "matomo.inlanefreight.com",
"id": 50815783237226155,
"entry_timestamp": "2021-08-21T06:00:17.173",
"not_before": "2021-08-21T05:00:16",
"not_after": "2021-11-19T05:00:15",
"serial_number": "03abe9017d6de5eda90"
},
{"issuer_ca_id": 68645
```

```bash
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep
name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk
'{gsub(/\\n/,"\n");}1;' | sort -u
account.ttn.inlanefreight.com
blog.inlanefreight.com
bots.inlanefreight.com
console.ttn.inlanefreight.com
ct.inlanefreight.com
data.ttn.inlanefreight.com
*.inlanefreight.com
inlanefreight.com
integrations.ttn.inlanefreight.com
iot.inlanefreight.com
mails.inlanefreight.com
marina.inlanefreight.com
marina-live.inlanefreight.com
matomo.inlanefreight.com
next.inlanefreight.com
noc.ttn.inlanefreight.com
preview.inlanefreight.com
shop.inlanefreight.com
smartfactory.inlanefreight.comttn.inlanefreight.com
vx.inlanefreight.com
www.inlanefreight.com
```

## Company Hosted Servers

```bash
for i in $(cat subdomainlist);do host $i | grep "has address" | grep
inlanefreight.com | cut -d" " -f1,4;done
blog.inlanefreight.com 10.129.24.93
inlanefreight.com 10.129.27.33
matomo.inlanefreight.com 10.129.127.22
www.inlanefreight.com 10.129.127.33
s3-website-us-west-2.amazonaws.com 10.129.95.250
```

## Shodan - IP List

```bash
for i in $(cat subdomainlist);do host $i | grep "has address" | grep
inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done
for i in $(cat ip-addresses.txt);do shodan host $i;done
10.129.24.93
City:Berlin
Country:Germany
Organization:
Updated:InlaneFreight
2021-09-01T09:02:11.370085
Number of open ports:2
Ports:80/tcp nginx
443/tcp nginx
10.129.27.33
City:Berlin
Country:Germany
Organization:
Updated:InlaneFreight
2021-08-30T22:25:31.572717
Number of open ports:3
Ports:
22/tcp OpenSSH (7.6p1 Ubuntu-4ubuntu0.3)
80/tcp nginx
443/tcp nginx
|-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, -TLSv1.3,
TLSv1.2
|-- Diffie-Hellman Parameters:
Bits:2048
Generator:2
10.129.27.22
City:Berlin
Country:
Organization:Germany
InlaneFreight
Updated:2021-09-01T15:39:55.446281
Number of open ports:8
Ports:
25/tcp
|-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, TLSv1.2,
TLSv1.3
53/tcp
53/udp
80/tcp Apache httpd
81/tcp Apache httpd
110/tcp
|-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, TLSv1.2
111/tcp
443/tcp Apache httpd
|-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, TLSv1.2,
TLSv1.3
|-- Diffie-Hellman Parameters:
Bits:
Generator:2048
2
Fingerprint:RFC3526/Oakley Group 14
444/tcp
10.129.27.33
City:Berlin
Country:GermanyOrganization:
Updated:InlaneFreight
2021-08-30T22:25:31.572717
Number of open ports:3
Ports:
22/tcp OpenSSH (7.6p1 Ubuntu-4ubuntu0.3)
80/tcp nginx
443/tcp nginx
|-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, -TLSv1.3,
TLSv1.2
|-- Diffie-Hellman Parameters:
Bits:2048
Generator:2
```

```bash
DNS Records
dig any inlanefreight.com
; <<>> DiG 9.16.1-Ubuntu <<>> any inlanefreight.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 52058
;; flags: qr rd ra; QUERY: 1, ANSWER: 17, AUTHORITY: 0, ADDITIONAL: 1
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;inlanefreight.com.
INANY
;; ANSWER SECTION:
inlanefreight.com.300INA10.129.27.33
inlanefreight.com.300INA10.129.95.250
inlanefreight.com.
inlanefreight.com.3600
3600IN
INMX
MX1 aspmx.l.google.com.
10 aspmx2.googlemail.com.
inlanefreight.com.3600INMX10 aspmx3.googlemail.com.
inlanefreight.com.3600INMX5 alt1.aspmx.l.google.com.
inlanefreight.com.
inlanefreight.com.3600
21600IN
INMX
NS5 alt2.aspmx.l.google.com.
ns.inwx.net.
inlanefreight.com.21600INNSns2.inwx.net.
inlanefreight.com.21600INNSns3.inwx.eu.
inlanefreight.com.
inlanefreight.com.3600
21600IN
INTXT
TXT"MS=ms92346782372"
"atlassian-domain-
verification=IJdXMt1rKCy68JFszSdCKVpwPN"inlanefreight.com.
3600
INTXT"google-site-
inlanefreight.com.
300
IN
verification=bow47-er9LdgoUeah"TXT"google-site-
inlanefreight.com.TXT"google-site-
verification=O7zV5-xFh_jn7JQ31"
3600
IN
verification=gZsCG-BINLopf4hr2"
inlanefreight.com.
3600
IN
TXT
"logmein-verification-
code=87123gff5a479e-61d4325gddkbvc1-b2bnfghfsed1-3c789427sdjirew63fc"
inlanefreight.com.
300
IN
TXT
"v=spf1
include:mailgun.org include:_spf.google.com
include:spf.protection.outlook.com include:_spf.atlassian.net
ip4:10.129.24.8 ip4:10.129.27.2 ip4:10.72.82.106 ~all"
inlanefreight.com.
21600
IN
SOA
ns.inwx.net.
hostmaster.inwx.net. 2021072600 10800 3600 604800 3600
;; Query time: 332 msec
;; SERVER: 127.0.0.53#53(127.0.0.53)
;; WHEN: Mi Sep 01 18:27:22 CEST 2021
;; MSG SIZE
rcvd: 940
```

## Cloud Resources

### Company Hosted Servers

```bash
for i in $(cat subdomainlist);do host $i | grep "has address" | grep
inlanefreight.com | cut -d" " -f1,4;done
blog.inlanefreight.com 10.129.24.93
inlanefreight.com 10.129.27.33
matomo.inlanefreight.com 10.129.127.22
www.inlanefreight.com 10.129.127.33
s3-website-us-west-2.amazonaws.com 10.129.95.250
```

## VSFTPD

Listing droits:

```bash
──(keylloger㉿Kali)-[~]
└─$ cat /etc/vsftpd.conf | grep -v "#"
listen=NO
listen_ipv6=YES
anonymous_enable=NO
local_enable=YES
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO
```

## Nmap FTP Scripts

```bash
sudo nmap --script-updatedb
Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 13:49 CEST
NSE: Updating rule database.
NSE: Script Database updated successfully.
Nmap done: 0 IP addresses (0 hosts up) scanned in 0.28 seconds
```
```bash
find / -type f -name ftp* 2>/dev/null | grep scripts
/usr/share/nmap/scripts/ftp-syst.nse
/usr/share/nmap/scripts/ftp-vsftpd-backdoor.nse
/usr/share/nmap/scripts/ftp-vuln-cve2010-4221.nse
/usr/share/nmap/scripts/ftp-proftpd-backdoor.nse
/usr/share/nmap/scripts/ftp-bounce.nse
/usr/share/nmap/scripts/ftp-libopie.nse
/usr/share/nmap/scripts/ftp-anon.nse
/usr/share/nmap/scripts/ftp-brute.nse
```

## Nmap

```bash
sudo nmap -sV -p21 -sC -A 10.129.14.136
Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-16 18:12 CEST
Nmap scan report for 10.129.14.136
Host is up (0.00013s latency).
PORT
STATE SERVICE VERSION
21/tcp open ftp
vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rwxrwxrwx
1 ftp
ftp
8138592 Sep 16 17:24 Calendar.pptx
[NSE: writeable]
| drwxrwxrwx
writeable]
| drwxrwxrwx
writeable]
| drwxrwxrwx
4 ftpftp4096 Sep 16 17:57 Clients [NSE:
2 ftpftp4096 Sep 16 18:05 Documents [NSE:
2 ftpftp4096 Sep 16 17:24 Employees [NSE:
writeable]
| -rwxrwxrwx
1 ftp
ftp
Notes.txt [NSE: writeable]
|_-rwxrwxrwx
1 ftp
[NSE: writeable]
| ftp-syst:
ftp
|
STAT:
| FTP server status:
|
|
|
Connected to 10.10.14.4
Logged in as ftp
TYPE: ASCII
41 Sep 16 17:24 Important
0 Sep 15 14:57 testupload.txt|
|No session bandwidth limit
Session timeout in seconds is 300
|
|
|Control connection is plain text
Data connections will be plain text
At session startup, client count was 2
|
vsFTPd 3.0.3 - secure, fast, stable
|_End of status
```

## Service Interaction
```bash
nc -nv 10.129.14.136 21
```

## Default Configuration

```bash
cat /etc/samba/smb.conf | grep -v "#\|\;"
[global]
workgroup = DEV.INFREIGHT.HTB
server string = DEVSMB
log file = /var/log/samba/log.%m
max log size = 1000
logging = file
panic action = /usr/share/samba/panic-action %d
server role = standalone server
obey pam restrictions = yes
unix password sync = yes
passwd program = /usr/bin/passwd %u
passwd chat = *Enter\snew\s*\spassword:* %n\n
*Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .
pam password change = yes
map to guest = bad userusershare allow guests = yes
[printers]
comment = All Printers
browseable = no
path = /var/spool/samba
printable = yes
guest ok = no
read only = yes
create mask = 0700
[print$]
comment = Printer Drivers
path = /var/lib/samba/printers
browseable = yes
read only = yes
guest ok = no
```

| Setting | Description |
|---------|------------|
| **sharename** | The name of the network share. |
| **workgroup** | Workgroup that will appear when clients query. WORKGROUP/DOMAIN |
| **path** | /path/here/ - The directory to which user is to be given access. |
| **server string** | STRING - The string that will show up when a connection is initiated. |
| **unix password sync** | yes - Synchronize the UNIX password with the SMB password? |
| **usershare allow guests** | yes - Allow non-authenticated users to access defined share? |
| **map to guest** | bad user - What to do when a user login request doesn't match a valid UNIX user? |
| **browseable** | yes - Should this share be shown in the list of available shares? |
| **guest ok** | yes - Allow connecting to the service without using a password? |
| **read only** | yes - Allow users to read files only? |
| **create mask** | 0700 - What permissions need to be set for newly created files? |


## Dangerous Settings

| Setting | Description |
|---------|------------|
| **browseable** | yes - Allow listing available shares in the current share? |
| **read only** | no - Forbid the creation and modification of files? |
| **writable** | yes - Allow users to create and modify files? |
| **guest ok** | yes - Allow connecting to the service without using a password? |
| **enable privileges** | yes - Honor privileges assigned to specific SID? |
| **create mask** | 0777 - What permissions must be assigned to the newly created files? |
| **directory mask** | 0777 - What permissions must be assigned to the newly created directories? |
| **logon script** | script.sh - What script needs to be executed on the user's login? |
| **magic script** | script.sh - Which script should be executed when the script gets closed? |
| **magic output** | script.out - Where the output of the magic script needs to be stored? |

### Summary
The settings listed above can introduce security risks. While they offer convenience for employees by allowing easy access and modifications, they also open doors for attackers if improperly secured. For example, setting `browseable = yes` enables employees to navigate shares easily, but an attacker gaining access would have the same visibility. Similarly, `guest ok = yes` removes authentication barriers, making unauthorized access much easier. Administrators should carefully evaluate these settings to balance usability and security.



## Brute Forcing User RIDs

```bash
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser
0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo
"";done
User Name
user_rid :
:
group_rid:
User Name
sambauser
0x1f5
0x201
:
mrb3n
user_rid :0x3e8
group_rid:0x201
User Name
:
cry0l1t3
user_rid :0x3e9
group_rid:0x201
```

## Impacket - Samrdump.py
```bash
samrdump.py 10.129.14.128
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
[*] Retrieving endpoint list from 10.129.14.128Found domain(s):
. DEVSMB
. Builtin
[*] Looking up users in domain DEVSMB
Found user: mrb3n, uid = 1000
Found user: cry0l1t3, uid = 1001
mrb3n (1000)/FullName:
mrb3n (1000)/UserComment:
mrb3n (1000)/PrimaryGroupId: 513
mrb3n (1000)/BadPasswordCount: 0
mrb3n (1000)/LogonCount: 0
mrb3n (1000)/PasswordLastSet: 2021-09-22 17:47:59
mrb3n (1000)/PasswordDoesNotExpire: False
mrb3n (1000)/AccountIsDisabled: False
mrb3n (1000)/ScriptPath:
cry0l1t3 (1001)/FullName: cry0l1t3
cry0l1t3 (1001)/UserComment:
cry0l1t3 (1001)/PrimaryGroupId: 513
cry0l1t3 (1001)/BadPasswordCount: 0
cry0l1t3 (1001)/LogonCount: 0
cry0l1t3 (1001)/PasswordLastSet: 2021-09-22 17:50:56
cry0l1t3 (1001)/PasswordDoesNotExpire: False
cry0l1t3 (1001)/AccountIsDisabled: False
cry0l1t3 (1001)/ScriptPath:
[*] Received 2 entries.
```

## Enum4Linux-ng - Installation
```bash
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng
pip3 install -r requirements.txt
```
## Enum4Linux-ng - Enumeration
```bash
./enum4linux-ng.py 10.129.14.128 -A
ENUM4LINUX - next generation==========================
|
Target Information
|
==========================
[*] Target ........... 10.129.14.128
[*] Username ......... ''
[*] Random Username .. 'juzgtcsu'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)
=====================================
|
Service Scan on 10.129.14.128
|
=====================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: connection refused
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp: connection refused
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp
=====================================================
|
NetBIOS Names and Workgroup for 10.129.14.128
|
=====================================================
[+] Got domain/workgroup name: DEVOPS
[+] Full NetBIOS names information:
- DEVSMB<00> -H <ACTIVE>Workstation Service
- DEVSMB
- DEVSMB<03> -
<20> -H <ACTIVE>
H <ACTIVE>Messenger Service
File Server Service
- ..__MSBROWSE__. <01> - <GROUP> H <ACTIVE>Master Browser
- DEVOPS<00> - <GROUP> H <ACTIVE>Domain/Workgroup Name
- DEVOPS
- DEVOPS<1d> -
H <ACTIVE>
<1e> - <GROUP> H <ACTIVE>Master Browser
Browser Service Elections
- MAC Address = 00-00-00-00-00-00
==========================================
|
SMB Dialect Check on 10.129.14.128
|
==========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
SMB 1.0: false
SMB 2.02: true
SMB 2.1: true
SMB 3.0: true
SMB1 only: false
Preferred dialect: SMB 3.0
SMB signing required: false
==========================================|
RPC Session Check on 10.129.14.128
|
==========================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user session
[+] Server allows session using username 'juzgtcsu', password ''
[H] Rerunning enumeration with user 'juzgtcsu' might give more results
====================================================
|
Domain Information via RPC for 10.129.14.128
|
====================================================
[+] Domain: DEVOPS
[+] SID: NULL SID
[+] Host is part of a workgroup (not a domain)
============================================================
|
Domain Information via SMB session for 10.129.14.128
|
============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: DEVSMB
NetBIOS domain name: ''
DNS domain: ''
FQDN: htb
================================================
|
OS Information via RPC for 10.129.14.128
|
================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[+] Found OS information via 'srvinfo'
[+] After merging OS information we have the following result:
OS: Windows 7, Windows Server 2008 R2
OS version: '6.1'
OS release: ''
OS build: '0'
Native OS: not supported
Native LAN manager: not supported
Platform id: '500'
Server type: '0x809a03'
Server type string: Wk Sv PrQ Unx NT SNT DEVSM
======================================
|
Users via RPC on 10.129.14.128
|
======================================
[*] Enumerating users via 'querydispinfo'
[+] Found 2 users via 'querydispinfo'
[*] Enumerating users via 'enumdomusers'
[+] Found 2 users via 'enumdomusers'[+] After merging user results we have 2 users total:
'1000':
username: mrb3n
name: ''
acb: '0x00000010'
description: ''
'1001':
username: cry0l1t3
name: cry0l1t3
acb: '0x00000014'
description: ''
=======================================
|
Groups via RPC on 10.129.14.128
|
=======================================
[*] Enumerating local groups
[+] Found 0 group(s) via 'enumalsgroups domain'
[*] Enumerating builtin groups
[+] Found 0 group(s) via 'enumalsgroups builtin'
[*] Enumerating domain groups
[+] Found 0 group(s) via 'enumdomgroups'
=======================================
|
Shares via RPC on 10.129.14.128
|
=======================================
[*] Enumerating shares
[+] Found 5 share(s):
IPC$:
comment: IPC Service (DEVSM)
type: IPC
dev:
comment: DEVenv
type: Disk
home:
comment: INFREIGHT Samba
type: Disk
notes:
comment: CheckIT
type: Disk
print$:
comment: Printer Drivers
type: Disk
[*] Testing share IPC$
[-] Could not check share: STATUS_OBJECT_NAME_NOT_FOUND
[*] Testing share dev
[-] Share doesn't exist
[*] Testing share home
[+] Mapping: OK, Listing: OK
[*] Testing share notes
[+] Mapping: OK, Listing: OK[*] Testing share print$
[+] Mapping: DENIED, Listing: N/A
==========================================
|
Policies via RPC for 10.129.14.128
|
==========================================
[*] Trying port 445/tcp
[+] Found policy:
domain_password_information:
pw_history_length: None
min_pw_length: 5
min_pw_age: none
max_pw_age: 49710 days 6 hours 21 minutes
pw_properties:
- DOMAIN_PASSWORD_COMPLEX: false
- DOMAIN_PASSWORD_NO_ANON_CHANGE: false
- DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
- DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
- DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
- DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
domain_lockout_information:
lockout_observation_window: 30 minutes
lockout_duration: 30 minutes
lockout_threshold: None
domain_logoff_information:
force_logoff_time: 49710 days 6 hours 21 minutes
==========================================
|
Printers via RPC for 10.129.14.128
|
==========================================
[+] No printers returned (this is not an error)
Completed after 0.61 seconds
```

## Show Available NFS Shares

```bash
showmount -e 10.129.14.128
Export list for 10.129.14.128:
/mnt/nfs 10.129.14.0/24
```

## Mounting NFS Share
```bash
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
cd target-NFS
tree .
.
└── mnt
└── nfs
├── id_rsa
├── id_rsa.pub
└── nfs.share
2 directories, 3 files
```

## Subdomain Brute Forcing

```bash
for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-
top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 |
grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a
subdomains.txt;done
ns.inlanefreight.htb.
604800
INA10.129.34.136
mail1.inlanefreight.htb. 604800 INA10.129.18.201
app.inlanefreight.htb.A10.129.18.15
```

## Nmap - Open Relay
```bash
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-30 02:29 CEST
NSE: Loaded 1 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 02:29
Completed NSE at 02:29, 0.00s elapsed
Initiating ARP Ping Scan at 02:29Scanning 10.129.14.128 [1 port]
Completed ARP Ping Scan at 02:29, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:29
Completed Parallel DNS resolution of 1 host. at 02:29, 0.03s elapsed
Initiating SYN Stealth Scan at 02:29
Scanning 10.129.14.128 [1 port]
Discovered open port 25/tcp on 10.129.14.128
Completed SYN Stealth Scan at 02:29, 0.06s elapsed (1 total ports)
NSE: Script scanning 10.129.14.128.
Initiating NSE at 02:29
Completed NSE at 02:29, 0.07s elapsed
Nmap scan report for 10.129.14.128
Host is up (0.00020s latency).
PORT
STATE SERVICE
25/tcp open
smtp
| smtp-open-relay: Server is an open relay (16/16 tests)
| MAIL FROM:<> -> RCPT TO:<[email protected]>
|MAIL FROM:<[email protected]> -> RCPT TO:<[email protected]>
|
|MAIL FROM:<antispam@ESMTP> -> RCPT TO:<[email protected]>
MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<[email protected]>
|MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:
<relaytest%nmap.scanme.org@[10.129.14.128]>
| MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:
<relaytest%nmap.scanme.org@ESMTP>
|
|
MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<"[email protected]">
MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:
<"relaytest%nmap.scanme.org">
| MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<[email
protected]@[10.129.14.128]>
|
MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<"[email
protected]"@[10.129.14.128]>
| MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<[email
protected]@ESMTP>
|
MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<@[10.129.14.128]:
[email protected]>
| MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<@ESMTP:[email
protected]>
| MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:
<nmap.scanme.org!relaytest>
|
MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:
<nmap.scanme.org!relaytest@[10.129.14.128]>
|_ MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:
<nmap.scanme.org!relaytest@ESMTP>
MAC Address: 00:00:00:00:00:00 (VMware)
NSE: Script Post-scanning.
Initiating NSE at 02:29
Completed NSE at 02:29, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
```
