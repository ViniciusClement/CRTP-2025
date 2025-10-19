## AD Enumeration

During penetration testing or red team engagements, enumerating Active Directory is a critical step for gathering intelligence about the environment. This process involves systematically identifying valuable information that can be used to map out the network, discover potential attack paths, and exploit misconfigurations or vulnerabilities.

Why Enumerate Active Directory? Active Directory is complex and interconnected, making it a prime target for attackers. Enumeration helps uncover:
* Domain structure and trust relationships.
* User accounts, groups, and their permissions.
* Domain Controllers (DCs) and critical services like DNS, LDAP, SMB, and Kerberos.
* Misconfigurations, such as weak passwords, open shares, and insecure policies.

Key Enumeration Goals:
1. Map the Environment: Identify key assets, including Domain Controllers and critical servers.
2. Identify Users: Discover domain accounts and their roles.
3. Assess Permissions: Look for overprivileged users, groups, or objects.
4. Locate Weaknesses: Misconfigurations, legacy systems, or unpatched vulnerabilities.
5. Set the Stage for Attacks: Gather the information needed for credential attacks, privilege escalation, or lateral movement.

Common Enumeration Tools and Techniques: Enumeration can be performed using a variety of tools and techniques, including:
* Nmap for network scanning and service discovery.
* SMB and LDAP enumeration tools to query shared resources and directory structures.
* BloodHound for mapping AD relationships and privilege escalation paths.
* Kerberos-based tools like Kerbrute to discover valid accounts through pre-authentication failures.
* PowerShell scripts for gathering system and domain information.

Reconnaissance Without Credentials: Even without valid domain credentials, attackers can leverage null sessions, misconfigured services, and network discovery tools to gain valuable information. These findings often serve as a foothold to further access.

### Domain Enumeration - User Hunting

Find all machines on the current domain where the current user has local admin access
* Find-LocalAdminAccess -Verbose

This function queries the DC of the current or provided domain for a list of computers (Get-NetComputer) and then use multi-threaded Invoke-CheckLocalAdminAccess on each machine.
This can also be done with the help of remote administration tools like WMI and PowerShell remoting. Pretty useful in cases ports (RPC and SMB) used by Find-LocalAdminAccess are blocked.

* See Find-WMILocalAdminAccess.ps1 and Find-PSRemotingLocalAdminAccess.ps1

<img width="1240" height="820" alt="image" src="https://github.com/user-attachments/assets/3f656553-1504-4c27-a86e-73303403fc3a" />


**Find computers where a domain admin (or specified user/group) has sessions**
* Find-DomainUserLocation -Verbose
* Find-DomainUserLocation -UserGroupIdentity "RDPUsers"

**Find computers where a domain admin session is available and current user has admin access (uses Test-AdminAccess)**
* Find-DomainUserLocation -CheckAccess

**Find computers (File Servers and Distributed File servers) where a domain admin session is available**
* Find-DomainUserLocation -Stealth

**List sessions on remote machines** (https://github.com/Leo4j/Invoke-SessionHunter)
* Invoke-SessionHunter -FailSafe

Above command doesn’t need admin access on remote machines. Uses Remote Registry and queries HKEY_USERS hive.

An opsec friendly command would be (avoid connecting to all the target machines by specifying targets)
* Invoke-SessionHunter -NoPortScan -Targets C:\AD\Tools\servers.txt AlteredSecurity
