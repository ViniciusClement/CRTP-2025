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

---|---|---


---|---|---


