# Delegations

Kerberos Delegation allows to "reuse the end-user credentials to access resources hosted on a different server". 

* This is typically useful in multi-tier service or applications where  Kerberos Double Hop is required. For example, users authenticates to a web server (first hop) and web server makes requests to a database 
server (second hop). 

* User impersonation is the goal of delegation
__________________________

Kerberos delegations allow services to access other services on behalf of domain users.

### Types of delegation
The "Kerberos" authentication protocol features delegation capabilities described as follows. 

There are three types of Kerberos delegations

- 1. Unconstrained delegations (KUD): a service can impersonate users on any other service.
- 2. Constrained delegations (KCD): a service can impersonate users on a set of services
- 3. Resource based constrained delegations (RBCD) : a set of services can impersonate users on a service

With constrained and unconstrained delegations, the delegation attributes are set on the impersonating service (requires SeEnableDelegationPrivilege in the domain) whereas with RBCD, these attributes are set on the target service account itself (requires lower privileges).

### Extensions

Kerberos delegations can be abused by attackers to obtain access to valuable assets and sometimes even escalate to domain admin privileges. Regarding constrained delegations and rbcd, those types of delegation rely on Kerberos extensions called Service-for-User (S4U).

**Unix**
```
findDelegation.py "DOMAIN"/"USER":"PASSWORD"

# filter to list delegations for a specific account.
findDelegation.py -user "account" "DOMAIN"/"USER":"PASSWORD"
``` 

**BloodHound**
```
// Unconstrained Delegation
MATCH (c {unconstraineddelegation:true}) return c

// Constrained Delegation (with Protocol Transition)
MATCH (c) WHERE NOT c.allowedtodelegate IS NULL AND c.trustedtoauth=true return c

// Constrained Delegation (without Protocol Transition)
MATCH (c) WHERE NOT c.allowedtodelegate IS NULL AND c.trustedtoauth=false return c

// Resource-Based Constrained Delegation
MATCH p=(u)-[:AllowedToAct]->(c) RETURN p
```

**Windows**
```
Get-ADComputer "Account" -Properties TrustedForDelegation, TrustedToAuthForDelegation,msDS-AllowedToDelegateTo,PrincipalsAllowedToDelegateToAccount
```

| Property |  Delegatyion Type  | 
|--------------------------|----|
| TrustedForDelegation |		Unconstrained Delegation	        |
| TrustedToAuthForDelegation	|	Constrained Delegation with Protocol Transition	            |
| AllowedToDelegateTo	        |   Constrained Delegation, and list of services allowed to delegate to |
| PrincipalsAllowedToDelegateToAccount (i.e. refers to the msDS-AllowedToActOnBehalfOfOtherIdentity attribute)                             |  RBCD, list of services that can delegate to the account                                          |