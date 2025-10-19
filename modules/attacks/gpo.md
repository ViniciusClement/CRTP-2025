## Privilege Escalation - GPO Abuse
* A GPO with overly permissive ACL can be abused for multiple attacks. 
* Recall the ACL abuse diagram.

GPOddity combines NTLM relaying and modification of Group Policy Container. 
* By relaying credentials of a user who has WriteDACL on GPO, we can modify the path (gPCFileSysPath) of the group policy template (default is SYSVOL).
* This enables loading of a malicious template from a location that we control.

<img width="1394" height="669" alt="image" src="https://github.com/user-attachments/assets/acb3df37-0059-4e8c-96ba-9bd70df1e3f5" />



### GPO Enumeration
### Get list of GPO in current domain
```
Get-DomainGPO
Get-DomainGPO | select displayname
Get-DomainGPO -ComputerIdentity dcorp-student1
```

### Get GPOs which use Restricted Groups or groups.xml for interesting users
```
Get-DomainGPOLocalGroup
```

### Get users which are in a local group of a machine using GPO
```
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity dcorp-student1
```

### Get machines where the given user is member of a specific group
```
Get-DomainGPOUserLocalGroupMapping -Identity student1 -Verbose
```

### Get OUs in a domain
```
Get-DomainOU
Get-ADOrganizationalUnit -Filter * -Properties *
```

### List all the computers in the DevOps OU
```
(Get-DomainOU -Identity DevOps).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name
```

### Get GPO applied on an OU, read GPOname from gplink attribute from Get-NetOU
```
Get-DomainGPO -Identity "{0D1CC23D-1F20-4EEE...........}"
```

### Enumerate GPO applied on the DevOps OU
### To enumerate GPO applied on the DevOps OU, we need the name of the policy from the gplink attribute from the OU:
```
(Get-DomainOU -Identity DevOps).gplink
[LDAP://cn={0BF8D01C-1F62-4BDC-958C-57140B67D147},cn=policies,cn=system,DC=dollarcorp,DC=moneycorp,DC=local;0]
```

### Copy the value between {} including the brackets as well:  {0BF8D01C-1F62-4BDC-958C-57140B67D147}
```
Get-DomainGPO -Identity '{0BF8D01C-1F62-4BDC-958C-57140B67D147}'
```
### Or Enumerate GPO for DevOps OU in a unique command
```
Get-DomainGPO -Identity (Get-DomainOU -Identity DevOps).gplink.substring(11,(Get-DomainOU -Identity DevOps).gplink.length-72)
```