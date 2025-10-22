# Table of commands Powerview

**Get Domain policy for the current domain**
```
Get-DomainPolicyData
```

### Get Domain Information, Retrieves information about the current domain.
```
Get-NetDomain
```

### Enumerate Domain Controllers
```
Get-NetDomainController
```

### Lists all Domain Controllers in the current domain, List Domain Users
```
Get-NetUser
```

### Displays all users in the domain, along with detailed attributes, Find High-Value Targets
```
Get-NetUser -AdminCount 1
```

### Lists all users flagged as administrators, Enumerate Domain Groups
```
Get-NetGroup
```

### Retrieves all domain groups. Lists members of the "Domain Admins" group.
```
Get-NetGroupMember -GroupName "Domain Admins"
```

### Locate Domain Computers. Lists all computers in the domain.
```
Get-NetComputer
```

### Analyze Trust Relationships. Displays trust relationships between domains.
```
Get-NetDomainTrust
```

### Check ACLs on AD Objects. Shows ACLs for a specific user account, resolving GUIDs to human-readable names.
```
Get-ObjectAcl -SamAccountName "Administrator" -ResolveGUIDs
```

### Find Shares on Domain Computers. Locates shared folders across domain computers.
```
Invoke-ShareFinder
```

### Identify Delegation Configurations. Finds user accounts with Service Principal Names (SPNs), often used in Kerberos-based attacks.
```
Get-NetUser -SPN
```
-------------------------------------------
# Enumerate ACL/ACE using PowerView

### Get the ACLs associated with the specified object
```
Get-DomainObjectAcl -SamAccountName student1 -ResolveGUIDs
```

### Get the ACLs associated with the specified prefix to be used for search
```
Get-DomainObjectAcl -SearchBase "LDAP://CN=DomainAdmins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose
```

### Get the ACLs associated for Domain Admins
```
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose
```

### Analyze Trust Relationships (Displays trust relationships between domains)
```
Get-NetDomainTrust
```

### Check ACLs on AD Objects  (Shows ACLs for a specific user account, resolving GUIDs to human-readable names)
```
Get-ObjectAcl -SamAccountName "Administrator" -ResolveGUIDs
```

### Search for interesting ACEs
```
Find-InterestingDomainAcl -ResolveGUIDs
```

### Get ACLs where studentx has interesting permissions
```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "student867"}
```

### Get the ACLs associated with the specified path
```
Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"
```

-------------------------------------------
# GPO Enumeration
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
----------------------------------
# Domain Trust Enumeration
### List all domain trusts for the current domain
```
Get-DomainTrust
```

### List trusts for a specific domain
```
Get-DomainTrust -Domain us.dollarcorp.moneycorp.local
```

### Using Active Directory module
```
Get-ADTrust
Get-ADTrust -Identity us.dollarcorp.moneycorp.local
```
### List external trusts in the current forest
```
Get-DomainTrust | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```

### Forest Enumeration
### Get details about the current forest
```
Get-Forest
Get-Forest -Forest eurocorp.local
```

### Using Active Directory module
```
Get-ADForest
Get-ADForest -Identity eurocorp.local
```

### Retrieve all domains in the current forest:
```
Get-ForestDomain
Get-ForestDomain -Forest eurocorp.local
(Get-ADForest).Domains
```

### Retrieve all global catalogs for the forest:
```
Get-ForestGlobalCatalog
Get-ForestGlobalCatalog -Forest eurocorp.local
Get-ADForest | Select-Object -ExpandProperty GlobalCatalogs
```

### Map forest trust relationships (if any exist):
```
Get-ForestTrust
Get-ForestTrust -Forest eurocorp.local
```

### Alternative using Active Directory module
```
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
```
