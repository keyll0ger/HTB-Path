# Windows Privilege Escalation

Introduction to Windows Privilege Escalation

Une fois que nous avons obtenu un accès initial à un système, l'escalade de privilèges nous permettra de disposer de davantage d'options pour assurer notre persistance et pourra révéler des informations stockées localement qui pourront étendre notre accès au sein de l'environnement. L'objectif général de l'escalade de privilèges sous Windows est d'augmenter notre accès à un système donné pour devenir membre du groupe des Administrateurs locaux ou obtenir l'accès au compte NT AUTHORITY\SYSTEM ou LocalSystem.

Cependant, il peut y avoir des scénarios où l'escalade de privilèges vers un autre utilisateur peut suffire à atteindre notre objectif. L'escalade de privilèges est généralement une étape cruciale lors de toute mission de test. Nous devons utiliser l'accès obtenu, ou des données (comme des identifiants) trouvées uniquement une fois que nous avons une session avec un contexte élevé.

Dans certains cas, l'escalade de privilèges peut être l'objectif principal de l'évaluation si notre client nous embauche pour une évaluation de type "image dorée" ou "démarrage de poste de travail". L'escalade de privilèges est souvent essentielle pour progresser à travers un réseau vers notre objectif final, ainsi que pour les mouvements latéraux.

### Raisons pour escalader les privilèges

Nous pouvons être amenés à escalader nos privilèges pour les raisons suivantes :
1. Tester l'image Windows de l'entreprise du client (workstation et serveur) pour des vulnérabilités.
2. Escalader les privilèges localement pour accéder à une ressource locale telle qu'une base de données.
3. Obtenir un accès de niveau NT AUTHORITY\System sur une machine membre du domaine pour pénétrer dans l'environnement Active Directory du client.
4. Obtenir des identifiants pour se déplacer latéralement ou escalader des privilèges au sein du réseau du client.

### Outils pour l'escalade de privilèges

Il existe de nombreux outils à notre disposition en tant que testeurs d'intrusion pour faciliter l'escalade de privilèges. Cependant, il est également essentiel de comprendre comment effectuer des vérifications d'escalade de privilèges et exploiter manuellement les vulnérabilités dans le contexte donné. Nous pourrions nous retrouver dans une situation où le client nous place sur un poste de travail géré, sans accès Internet, avec un pare-feu sévère et des ports USB désactivés, ce qui nous empêche de charger des outils ou des scripts d'aide. Dans ce cas, il serait crucial de maîtriser les vérifications d'escalade de privilèges sous Windows en utilisant à la fois PowerShell et la ligne de commande Windows.

### Surface d'attaque des systèmes Windows

Les systèmes Windows présentent une vaste surface d'attaque. Voici quelques-unes des façons dont nous pouvons escalader nos privilèges :
- Abus des privilèges de groupe Windows
- Abus des privilèges d'utilisateur Windows
- Contournement du Contrôle de Compte Utilisateur (UAC)
- Abus des permissions faibles sur les services et fichiers
- Exploitation de vulnérabilités non corrigées du noyau
- Vol d'identifiants
- Capture de trafic
- Et bien plus encore...

## Scénario 1 - Contournement des Restrictions Réseau

Une fois, on m'a confié la tâche d'escalader les privilèges sur un système fourni par un client, sans accès Internet et avec les ports USB bloqués. En raison du contrôle d'accès réseau en place, je ne pouvais pas connecter ma machine d'attaque directement au réseau utilisateur pour m'aider. Lors de l'évaluation, j'avais déjà trouvé une faille dans le réseau, où le VLAN des imprimantes était configuré pour permettre les communications sortantes sur les ports 80, 443 et 445. J'ai utilisé des méthodes d'énumération manuelles pour trouver une faille liée aux permissions qui m'a permis d'escalader les privilèges et de réaliser un dump mémoire du processus LSASS. À partir de là, j'ai pu monter un partage SMB hébergé sur ma machine d'attaque sur le VLAN des imprimantes et exfiltrer le fichier DMP de LSASS. Avec ce fichier en main, j'ai utilisé Mimikatz hors ligne pour récupérer le hachage de mot de passe NTLM pour un administrateur de domaine, que j'ai pu cracker hors ligne et utiliser pour accéder à un contrôleur de domaine depuis le système fourni par le client.

## Scénario 2 - Pillage des Partages Ouverts

Lors d'une autre évaluation, je me suis retrouvé dans un environnement fortement sécurisé, bien surveillé, sans faille de configuration évidente ou de services/application vulnérables en cours d'utilisation. J'ai trouvé un partage de fichiers totalement ouvert, permettant à tous les utilisateurs de lister son contenu et de télécharger les fichiers qui y étaient stockés. Ce partage hébergeait des sauvegardes de machines virtuelles dans l'environnement. J'étais particulièrement intéressé par les fichiers de disque dur virtuel (.VMDK et .VHDX). J'ai pu accéder à ce partage depuis une machine virtuelle Windows, monter le fichier .VHDX en tant que disque local et explorer le système de fichiers. À partir de là, j'ai récupéré les hives du registre SYSTEM, SAM et SECURITY, les ai déplacées vers ma machine d'attaque Linux, puis j'ai extrait le hachage du mot de passe de l'administrateur local en utilisant l'outil `secretsdump.py`. L'organisation utilisait une image dorée, et le hachage de l'administrateur local pouvait être utilisé pour obtenir un accès administrateur sur presque tous les systèmes Windows via une attaque "pass-the-hash".

## Scénario 3 - Recherche de Credentials et Abus des Privilèges de Compte

Dans ce dernier scénario, j'ai été placé dans un réseau assez verrouillé avec pour objectif d'accéder aux serveurs de bases de données critiques. Le client m'a fourni un ordinateur portable avec un compte utilisateur de domaine standard, et j'avais la possibilité d'y charger des outils. J'ai fini par exécuter l'outil Snaffler pour rechercher des informations sensibles dans les partages de fichiers. J'ai trouvé des fichiers .sql contenant des identifiants de base de données à faibles privilèges pour une base de données sur l'un de leurs serveurs de base de données. J'ai utilisé un client MSSQL localement pour me connecter à la base de données en utilisant ces identifiants, activer la procédure stockée `xp_cmdshell` et obtenir une exécution de commande locale. En utilisant cet accès en tant que compte de service, j'ai confirmé que j'avais le privilège `SeImpersonatePrivilege`, qui peut être exploité pour une escalade de privilèges locale. J'ai téléchargé une version compilée sur mesure de Juicy Potato sur l'hôte pour m'aider avec l'escalade de privilèges et j'ai pu ajouter un utilisateur administrateur local. Ajouter un utilisateur n'était pas idéal, mais mes tentatives pour obtenir un shell inverse/ beacon ont échoué. Avec cet accès, j'ai pu me connecter à distance à l'hôte de la base de données et obtenir un contrôle total sur la base de données d'un des clients de l'entreprise.


Il n'y a pas une seule raison pour laquelle un ou plusieurs hôtes d'une entreprise peuvent être victimes d'escalade de privilèges, mais plusieurs causes sous-jacentes possibles existent. Certaines raisons typiques pour lesquelles des failles sont introduites et passent inaperçues sont liées au personnel et au budget. Beaucoup d'organisations n'ont tout simplement pas le personnel nécessaire pour suivre correctement la gestion des correctifs, la gestion des vulnérabilités, les évaluations internes périodiques (auto-évaluations), la surveillance continue, ainsi que des initiatives plus importantes et plus gourmandes en ressources. Ces initiatives peuvent inclure des mises à niveau des postes de travail et des serveurs, ainsi que des audits de partages de fichiers (pour verrouiller les répertoires et sécuriser/enlever des fichiers sensibles tels que des scripts ou des fichiers de configuration contenant des identifiants).

## Passons à l'Action

Les scénarios ci-dessus montrent à quel point la compréhension de l'escalade de privilèges sous Windows est cruciale pour un testeur d'intrusion. Dans la réalité, il est rare que nous attaquions un seul hôte et nous devons être capables de penser rapidement. Nous devons être en mesure de trouver des moyens créatifs pour escalader les privilèges et exploiter cet accès pour faire progresser notre objectif d'évaluation.

## Exemples Pratiques

Tout au long de ce module, nous couvrirons des exemples avec des sorties de commandes accompagnées, dont la plupart peuvent être reproduites sur les machines virtuelles cibles qui peuvent être créées dans les sections correspondantes. Des identifiants RDP vous seront fournis pour interagir avec les machines virtuelles cibles et réaliser les exercices et évaluations de compétences. Vous pouvez vous connecter depuis Pwnbox ou depuis votre propre machine virtuelle (après avoir téléchargé une clé VPN dès qu'une machine est lancée) via RDP en utilisant FreeRDP, Remmina ou le client RDP de votre choix.


Il existe de nombreux outils à notre disposition pour aider à énumérer les systèmes Windows à la recherche de vecteurs d'escalade de privilèges, qu'ils soient courants ou obscurs. Voici une liste de binaires et de scripts utiles, dont beaucoup seront couverts dans les sections suivantes du module.

| Outil | Description |
| --- | --- |
| **Seatbelt** | Projet C# pour effectuer une large gamme de vérifications d'escalade de privilèges locaux. |
| **winPEAS** | Script qui recherche des chemins possibles pour escalader les privilèges sur les hôtes Windows. Toutes les vérifications sont expliquées ici. |
| **PowerUp** | Script PowerShell pour trouver les vecteurs d'escalade de privilèges Windows courants qui reposent sur des erreurs de configuration. Il peut également être utilisé pour exploiter certaines des failles trouvées. |
| **SharpUp** | Version C# de PowerUp. |
| **JAW** | Script PowerShell pour énumérer les vecteurs d'escalade de privilèges écrit en PowerShell 2.0. |
| **SessionGopher** | Outil PowerShell qui trouve et déchiffre les informations de session enregistrées pour les outils d'accès à distance. Il extrait les informations de session enregistrées pour PuTTY, WinSCP, SuperPuTTY, FileZilla et RDP. |
| **Watson** | Outil .NET conçu pour énumérer les mises à jour manquantes et suggérer des exploits pour les vulnérabilités d'escalade de privilèges. |
| **LaZagne** | Outil utilisé pour récupérer les mots de passe stockés sur une machine locale depuis des navigateurs web, outils de chat, bases de données, Git, email, dumps mémoire, PHP, outils sysadmin, configurations réseau sans fil, mécanismes internes de stockage de mots de passe Windows, et plus encore. |
| **Windows Exploit Suggester - Next Generation (WES-NG)** | Outil basé sur la sortie de l'utilitaire `systeminfo` de Windows, qui fournit la liste des vulnérabilités auxquelles le système d'exploitation est susceptible, y compris les exploits pour ces vulnérabilités. Il prend en charge tous les systèmes Windows entre Windows XP et Windows 10, ainsi que leurs versions Server. |
| **Sysinternals Suite** | Plusieurs outils de la suite Sysinternals seront utilisés pour l'énumération, y compris AccessChk, PipeList, et PsService. |

Nous pouvons également trouver des binaires précompilés de Seatbelt et SharpUp ici, ainsi que des binaires autonomes de LaZagne là. Il est recommandé de toujours compiler nos outils à partir de la source si nous les utilisons dans un environnement client.

**Remarque :** Selon la manière dont nous obtenons l'accès à un système, nous n'aurons peut-être pas beaucoup de répertoires écrits par notre utilisateur pour télécharger des outils. Il est toujours prudent de télécharger les outils dans `C:\Windows\Temp` car le groupe **BUILTIN\Users** a un accès en écriture à cet emplacement.

## Outils Complémentaires

Cette liste n'est pas exhaustive. De plus, il est important de comprendre ce que chaque outil fait si un d'entre eux ne fonctionne pas comme prévu ou si nous ne pouvons pas les charger sur le système cible. Des outils comme ceux listés ci-dessus sont extrêmement utiles pour affiner nos vérifications et concentrer notre énumération. L'énumération d'un système Windows peut être une tâche décourageante avec une quantité énorme d'informations à trier et à comprendre. Les outils peuvent accélérer ce processus et nous fournir des résultats dans un format facile à lire. Cependant, un inconvénient de cette approche peut être une surcharge d'informations, car certains de ces outils, comme winPEAS, renvoient une quantité impressionnante d'informations, dont une grande partie ne nous sera pas utile.

Les outils peuvent être une arme à double tranchant. Bien qu'ils aident à accélérer le processus d'énumération et à fournir des sorties très détaillées, nous pourrions travailler de manière moins efficace si nous ne savons pas comment lire la sortie ou la restreindre aux points de données les plus intéressants. Ces outils peuvent aussi produire de faux positifs, c'est pourquoi nous devons avoir une compréhension approfondie de nombreuses techniques possibles d'escalade de privilèges pour résoudre les problèmes lorsque les choses vont mal ou ne sont pas ce qu'elles semblent être. Apprendre les techniques d'énumération manuellement nous aidera à nous assurer de ne pas manquer de défauts évidents en raison d'un problème avec un outil, comme un faux négatif ou un faux positif.

Tout au long de ce module, nous vous montrerons des techniques d'énumération manuelles pour les divers exemples que nous couvrons, ainsi que la sortie des outils lorsqu'elle est applicable. En plus des techniques d'énumération, il est également vital d'apprendre comment effectuer les étapes d'exploitation manuellement et de ne pas dépendre de scripts ou d'outils "autopwn" que nous ne pouvons pas contrôler. Il est tout à fait acceptable (et encouragé !) de rédiger nos propres outils/scripts pour effectuer les étapes d'énumération et d'exploitation, mais nous devrions être suffisamment confiants dans ces deux phases pour expliquer exactement ce que nous faisons à notre client à chaque étape du processus. Nous devrions également être capables d'opérer dans un environnement où nous ne pouvons pas charger d'outils (comme un réseau isolé ou des systèmes n'ayant pas d'accès à Internet ou ne nous permettant pas de brancher un périphérique externe tel qu'une clé USB).

Ces outils ne sont pas seulement bénéfiques pour les testeurs d'intrusion, mais peuvent également aider les administrateurs systèmes dans leur travail en les aidant à identifier les failles faciles à corriger avant une évaluation, à vérifier périodiquement la posture de sécurité de quelques machines, à analyser l'impact d'une mise à jour ou d'autres changements, ou à effectuer un examen approfondi de sécurité sur une nouvelle image dorée avant de la déployer en production. Les outils et méthodes montrés dans ce module peuvent bénéficier à toute personne en charge de l'administration des systèmes, de l'architecture ou de la sécurité interne et de la conformité.

## Risques d'Utilisation de Ces Outils

Comme pour toute automatisation, l'utilisation excessive de ces outils peut comporter des risques. Bien que rares, des énumérations excessives peuvent causer une instabilité du système ou des problèmes avec un système (ou des systèmes) déjà fragiles. De plus, ces outils sont bien connus, et la plupart (si ce n'est tous) seront détectés et bloqués par les solutions antivirus courantes, et presque certainement par des produits EDR plus avancés comme Cylance ou Carbon Black. Prenons par exemple la dernière version de l'outil LaZagne au moment de la rédaction, la version 2.4.3. En téléchargeant le binaire précompilé sur Virus Total, on constate que 47/70 produits le détectent.

Lorsqu'on se retrouve dans une situation, que ce soit dans notre vie quotidienne ou lors d'un projet tel qu'un test de pénétration réseau, il est toujours important de s'orienter dans l'espace et le temps. Nous ne pouvons pas fonctionner et réagir efficacement sans comprendre notre environnement actuel. Nous avons besoin de ces informations pour prendre des décisions éclairées sur nos prochaines étapes, afin d'agir de manière proactive plutôt que réactive.

Lorsque nous accédons à un système Windows ou Linux dans le but d'escalader les privilèges, il y a plusieurs éléments que nous devons toujours examiner pour planifier nos prochains mouvements. Nous pourrions découvrir d'autres hôtes que nous pouvons accéder directement, des protections en place qui devront être contournées, ou constater que certains outils ne fonctionneront pas contre le système en question.

## Informations Réseau

Recueillir des informations sur le réseau est une partie cruciale de notre énumération. Il se peut que nous découvrions que l'hôte est **dual-homed**, ce qui signifie que compromettre cet hôte pourrait nous permettre de nous déplacer latéralement vers une autre partie du réseau que nous n'avions pas pu atteindre auparavant. Un hôte **dual-homed** appartient à deux réseaux différents et, dans la plupart des cas, possède plusieurs interfaces réseau physiques ou virtuelles.

Nous devons toujours consulter les **tables de routage** pour obtenir des informations sur le réseau local et les réseaux autour de celui-ci. Nous pouvons également collecter des informations sur le **domaine local** (si l'hôte fait partie d'un environnement Active Directory), y compris les adresses IP des contrôleurs de domaine. Il est aussi important d'utiliser la commande **arp** pour consulter le cache ARP pour chaque interface et voir avec quels autres hôtes l'hôte a récemment communiqué. 

Ces informations peuvent nous aider dans nos mouvements latéraux après avoir obtenu des identifiants. Elles peuvent également indiquer quels hôtes les administrateurs connectent via RDP ou WinRM depuis cet hôte. 

Ces informations réseau peuvent directement ou indirectement aider avec l'escalade de privilèges locale. Elles peuvent nous conduire sur un autre chemin vers un système auquel nous pouvons accéder ou sur lequel nous pouvons escalader les privilèges, ou encore révéler des informations que nous pourrons utiliser pour des mouvements latéraux afin d'étendre notre accès après avoir escaladé les privilèges sur le système actuel.


# Afficher Toutes les Variables d'Environnement

Les variables d'environnement donnent beaucoup d'informations sur la configuration de l'hôte. Pour afficher ces variables, Windows fournit la commande `set`. Une des variables souvent négligées est **PATH**.

Dans la sortie ci-dessous, rien n'est hors du commun. Cependant, il n'est pas rare que les administrateurs (ou les applications) modifient la **PATH**. Un exemple courant est l'ajout de Python ou Java dans le path, ce qui permettrait l'exécution de fichiers Python ou `.JAR`. Si le dossier placé dans la PATH est accessible en écriture par votre utilisateur, il peut être possible d'effectuer des **injections DLL** contre d'autres applications.

Rappelez-vous que lorsque Windows exécute un programme, il cherche d'abord dans le **répertoire de travail actuel (CWD)**, puis dans le **PATH** de gauche à droite. Cela signifie que si le chemin personnalisé est placé à gauche (avant `C:\Windows\System32`), il est beaucoup plus dangereux que s'il est à droite.

En plus de la **PATH**, la commande `set` peut également fournir d'autres informations utiles comme le **HOME DRIVE**. Dans les entreprises, cela sera souvent un partage de fichiers. Naviguer jusqu'à ce partage peut révéler d'autres répertoires accessibles. Il n'est pas rare de pouvoir accéder à un répertoire "IT" contenant une feuille de calcul d'inventaire incluant des mots de passe.

De plus, les partages sont utilisés pour les répertoires personnels afin que l'utilisateur puisse se connecter à d'autres ordinateurs et avoir la même expérience/fichiers/bureau/etc. (Profils itinérants). Cela peut également signifier que l'utilisateur transporte des éléments malveillants avec lui. Si un fichier est placé dans `USERPROFILE\AppData\Microsoft\Windows\Start Menu\Programs\Startup`, ce fichier sera exécuté lorsque l'utilisateur se connectera à une autre machine.

## Exemple de sortie de la commande `set`

```powershell
C:\htb> set ALLUSERSPROFILE=C:\ProgramData APPDATA=C:\Users\Administrator\AppData\Roaming CommonProgramFiles=C:\Program Files\Common Files CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files CommonProgramW6432=C:\Program Files\Common Files COMPUTERNAME=WINLPE-SRV01 ComSpec=C:\Windows\system32\cmd.exe HOMEDRIVE=C: HOMEPATH=\Users\Administrator LOCALAPPDATA=C:\Users\Administrator\AppData\Local LOGONSERVER=\WINLPE-SRV01 NUMBER_OF_PROCESSORS=6 OS=Windows_NT Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\Sy stem32\WindowsPowerShell\v1.0;C:\Users\Administrator\AppData\Local\Micros oft\WindowsApps; PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC PROCESSOR_ARCHITECTURE=AMD64 PROCESSOR_IDENTIFIER=AMD64 Family 23 Model 49 Stepping 0, AuthenticAMD PROCESSOR_LEVEL=23 PROCESSOR_REVISION=3100 ProgramData=C:\ProgramData ProgramFiles=C:\Program Files ProgramFiles(x86)=C:\Program Files (x86) ProgramW6432=C:\Program Files PROMPT=$P$G PSModulePath=C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0 \Modules PUBLIC=C:\Users\Public SESSIONNAME=Console SystemDrive=C: SystemRoot=C:\Windows TEMP=C:\Users\ADMINI1\AppData\Local\Temp\1 TMP=C:\Users\ADMINI1\AppData\Local\Temp\1 USERDOMAIN=WINLPE-SRV01 USERDOMAIN_ROAMINGPROFILE=WINLPE-SRV01 USERNAME=Administrator USERPROFILE=C:\Users\Administrator windir=C:\Windows
```


## Afficher des Informations de Configuration Détail

La commande `systeminfo` permet de savoir si la machine a été récemment mise à jour et si elle est une machine virtuelle. Si la machine n'a pas été mise à jour récemment, obtenir un accès de niveau administrateur peut être aussi simple que d'exécuter un exploit connu. Il est possible de rechercher les KB installées sous **HotFixes** pour obtenir une idée de la dernière mise à jour de la machine. Cette information n'est pas toujours présente, car il est possible de cacher les hotfixes des utilisateurs non administrateurs.

La **date de démarrage du système** et la **version de l'OS** peuvent également être vérifiées pour évaluer le niveau de patch. Si la machine n'a pas redémarré depuis plus de six mois, il est probable qu'elle n'ait pas été patchée non plus.

De plus, de nombreux guides indiquent que les informations réseau sont importantes, car elles peuvent indiquer qu'il s'agit d'une machine **dual-homed** (connectée à plusieurs réseaux). En général, dans les entreprises, les appareils se voient accorder l'accès à d'autres réseaux via une règle de pare-feu, et non par un câble physique direct.

### Exemple de sortie de la commande `systeminfo`

```powershell
C:\htb> systeminfo Host Name: WINLPE-SRV01 OS Name: Microsoft Windows Server 2016 Standard OS Version: 10.0.14393 N/A Build 14393 OS Manufacturer: Microsoft Corporation OS Configuration: Standalone Server OS Build Type: Standalone Server System Manufacturer: VMware, Inc. System Model: VMware7,1 System Type: x64-based PC Processor(s): 3 Processor(s) Installed. [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz [03]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz BIOS Version: VMware, Inc. VMW71.00V.16707776.B64.2008070230, 8/7/2020 Windows Directory: C:\Windows System Directory: C:\Windows\system32 Boot Device: \Device\HarddiskVolume2 System Locale: en-us; English (United States) Time Zone: (UTC-08:00) Pacific Time (US & Canada) Total Physical Memory: 6,143 MB Available Physical Memory: 3,474 MB Virtual Memory: Max Size: 10,371 MB Virtual Memory: Available: 7,544 MB Virtual Memory: In Use: 2,827 MB Page File Location(s): C:\pagefile.sys Domain: WORKGROUP Logon Server: \WINLPE-SRV01 Hotfix(s): 3 Hotfix(s) Installed. [01]: KB3199986 [02]: KB5001078 [03]: KB4103723 Network Card(s): [01]: Intel(R) 82574L Gigabit Network Connection Connection Name: Ethernet0 DHCP Enabled: Yes IP address(es): 10.129.43.8 [02]: vmxnet3 Ethernet Adapter Connection Name: Ethernet1 DHCP Enabled: No IP address(es): 192.168.20.56
```

# Patches and Updates

Si la commande `systeminfo` ne montre pas les **hotfixes**, il est possible de les interroger avec WMI en utilisant le binaire `WMI-Command` avec **QFE (Quick Fix Engineering)** pour afficher les patches.

### Exemple avec la commande `wmic qfe`

```powershell
C:\htb> wmic qfe Caption CSName FixComments HotFixID InstallDate Name ServicePackInEffect Status InstalledBy

http://support.microsoft.com/?kbid=3199986 WINLPE-SRV01 Security Update KB3199986 11/21/2016 Security Update NT AUTHORITY\SYSTEM https://support.microsoft.com/help/5001078 WINLPE-SRV01 Security Update KB5001078 3/25/2021 Security Update NT AUTHORITY\SYSTEM http://support.microsoft.com/?kbid=4103723 WINLPE-SRV01 Security Update KB4103723 3/25/2021 Security Update NT AUTHORITY\SYSTEM
```

Nous pouvons également faire cela avec **PowerShell** en utilisant la cmdlet `Get-Hotfix`.

### Exemple avec PowerShell

# Patches and Updates

Si la commande `systeminfo` ne montre pas les **hotfixes**, il est possible de les interroger avec WMI en utilisant le binaire `WMI-Command` avec **QFE (Quick Fix Engineering)** pour afficher les patches.

### Exemple avec la commande `wmic qfe`

```powershell
C:\htb> wmic qfe Caption CSName FixComments HotFixID InstallDate Name ServicePackInEffect Status InstalledBy
``
http://support.microsoft.com/?kbid=3199986 WINLPE-SRV01 Security Update KB3199986 11/21/2016 Security Update NT AUTHORITY\SYSTEM https://support.microsoft.com/help/5001078 WINLPE-SRV01 Security Update KB5001078 3/25/2021 Security Update NT AUTHORITY\SYSTEM http://support.microsoft.com/?kbid=4103723 WINLPE-SRV01 Security Update KB4103723 3/25/2021 Security Update NT AUTHORITY\SYSTEM
``

Nous pouvons également faire cela avec **PowerShell** en utilisant la cmdlet `Get-Hotfix`.

### Exemple avec PowerShell
```powershell 
PS C:\htb> Get-HotFix | ft -AutoSize Source Description HotFixID InstalledBy InstalledOn

WINLPE-SRV01 Update KB3199986 NT AUTHORITY\SYSTEM 11/21/2016 WINLPE-SRV01 Update KB4054590 WINLPE-SRV01\Administrator 3/30/2021 WINLPE-SRV01 Security Update KB5001078 NT AUTHORITY\SYSTEM 3/25/2021 WINLPE-SRV01 Security Update KB3200970 WINLPE-SRV01\Administrator 4/13/2021
```


## Programmes Installés

WMI peut également être utilisé pour afficher les logiciels installés. Ces informations peuvent souvent nous guider vers des exploits difficiles à trouver. Par exemple, **FileZilla**, **Putty**, etc., sont-ils installés ? Vous pouvez exécuter **LaZagne** pour vérifier si des informations d'identification pour ces applications sont stockées.

Certains programmes peuvent être installés et exécutés en tant que service, ce qui peut les rendre vulnérables.

### Exemple avec la commande `wmic product get name`

```powershell
C:\htb> wmic product get name Name

Microsoft Visual C++ 2019 X64 Additional Runtime - 14.24.28127 Java 8 Update 231 (64-bit) Microsoft Visual C++ 2019 X86 Additional Runtime - 14.24.28127 VMware Tools Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.24.28127 Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.24.28127 Java Auto Updater <SNIP>
```
