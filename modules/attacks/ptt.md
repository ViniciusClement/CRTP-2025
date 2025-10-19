# Pass-The-Ticket

**Theory**

There are ways to come across (cached Kerberos tickets) or forge (overpass the hash, silver ticket and golden ticket attacks) Kerberos tickets. A ticket can then be used to authenticate to a system using Kerberos without knowing any password. 

This is called Pass the ticket. Another name for this is Pass the Cache (when using tickets from, or found on, UNIX-like systems).

Kerberos tickets can be cached on systems to allow for faster authentication without requiring users to re-enter credentials. Understanding how these tickets are stored is crucial for both defensive and offensive operations.

On Windows systems, Kerberos tickets are stored in memory by the Local Security Authority Subsystem Service (LSASS) process.

**Injecting the ticket**

On Windows systems, tools like Mimikatz and Rubeus inject the ticket in memory. Native Microsoft tools can then use the ticket just like usual.

On UNIX-like systems, the path to the .ccache ticket to use has to be referenced in the environment variable KRB5CCNAME

```
Rubeus.exe -args s4u /user:dcorp-adminsrv$ 
/aes256:1f556f9d4e5fcab7f1bf4730180eb1efd0fadd5bb1b5c1e810149f9016a7284d /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt
```