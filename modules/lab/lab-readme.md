# LAB 

* [1 - LAB1️](lab1.md)
    - Enumerate dollarcorp domain
        - Users
        - Computers
        - Domain Administrators
        - Enterprise Administrators
        - Use BloodHound to identify the shortest path to Domain Admins in the dollarcorp domain.
        - Find a file share where studentx has Write permissions.
* [2 - LAB2️](lab2.md)
    - Enumerate dollarcorp domain
        - ACL for the Domain Admins group
        - ACLs where studentx has interesting permissions
        - Analyze the permissions for studentx in BloodHound UI
* [3 - LAB3️](lab3.md)
    - Enumerate dollarcorp domain
        - List all the OUs
        - List all the computers in the DevOps OU
        - List the GPOs 
        - Enumerate GPO applied on the DevOps OU
        - Enumerate ACLs for the Applocked and DevOps GPOs
* [4 - LAB4️](lab4.md)
    - Enumerate all domains in the moneycorp.local forest
        - Map the trusts of the dollarcorp.moneycorp.local domain.
        - Map External trusts in moneycorp.local forest. 
        - Identify external trusts of dollarcorp domain. 
        - Can you enumerate trusts for a trusting forest?
* [5 - LAB5️](lab5.md)
    - Exploit a service on dcorp-studentx and elevate privileges to local administrator. 
    - Identify a machine in the domain where studentx has local administrative access.
    - Using privileges of a user on Jenkins on 172.16.3.11:8080, get admin privileges on 172.16.3.11 - the dcorp-ci server
* [6 - LAB6️](lab6.md)
    - Abuse an overly permissive Group Policy (GPO) to add studentx to the local administrators group on dcorp-ci.
* [7 - LAB7️](lab7.md)
    - Identify a machine in the target domain where a Domain Admin session is available. 
    - Compromise the machine and escalate privileges to Domain Admin by abusing reverse shell on dcorp-ci.
    - Escalate privilege to DA by abusing derivative local admin through dcorp-adminsrv. 
    - On dcorp-adminsrv, tackle application allowlisting using: 
        - Gaps in Applocker rules. 
        - Disable Applocker by modifying GPO applicable to dcorp-adminsrv
* [8 - LAB8️](lab8.md)
    - Extract secrets from the domain controller of dollarcorp.
    - Using the secrets of krbtgt account, create a Golden ticket. 
    - Use the Golden ticket to (once again) get domain admin privileges from a machine
* [9 - LAB9️](lab9.md)
    - Try to get command execution on the domain controller by creating silver ticket for
        - HTTP
        - WMI
* [10 - LAB1️0️](lab10.md)
    - Use Domain Admin privileges obtained earlier to execute the Diamond Ticket attack. 
* [11 - LAB1️1️](lab11.md)
    - Use Domain Admin privileges obtained earlier to abuse the DSRM credential for persistence. 
* [12 - LAB1️2️](lab12.md) 
    - Check if studentx has Replication (DCSync) rights. 
    - If yes, execute the DCSync attack to pull hashes of the krbtgt user.
    - If no, add the replication rights for the studentx and execute the DCSync attack to pull hashes of the krbtgt user. 
* [13 - LAB1️3️](lab13.md)
    - Modify security descriptors on dcorp-dc to get access using PowerShell remoting and WMI without requiring administrator access.
    - Retrieve machine account hash from dcorp-dc without using administrator access and use that to execute a Silver Ticket attack to get code execution with WMI
* [14 - LAB1️4️](lab14.md)
    - Using the Kerberoasting attack, crack password of a SQL server service account. 
* [15 - LAB1️5️](lab15.md)
    - Find a server in the dcorp domain where Unconstrained Delegation is enabled. 
    - Compromise the server and escalate to Domain Admin privileges. 
    - Escalate to Enterprise Admins privileges by abusing Printer Bug!
* [16 - LAB1️6️](lab16.md)
    - Enumerate users in the domain for whom Constrained Delegation is enabled. 
        - For such a user, request a TGT from the DC and obtain a TGS for the service to which delegation is configured. 
        - Pass the ticket and access the service as DA. 
    - Enumerate computer accounts in the domain for which Constrained Delegation is enabled. 
        - For such a user, request a TGT from the DC.
        - Obtain an alternate TGS for LDAP service on the target machine. 
        - Use the TGS for executing DCSync attack.
* [17 - LAB1️7️](lab17.md)
    - Find a computer object in dcorp domain where we have Write permissions. 
    - Abuse the Write permissions to access that computer as Domain Admin
* [18 - LAB1️8️](lab18.md)
    - Using DA access to dollarcorp.moneycorp.local, escalate privileges to Enterprise Admins using the domain trust key. 
* [19 - LAB1️9️](lab19.md)
    - Using DA access to dollarcorp.moneycorp.local, escalate privileges to Enterprise Admins using dollarcorp's krbtgt hash.
* [20 - LAB2️0️](lab20.md)
    - With DA privileges on dollarcorp.moneycorp.local, get access to SharedwithDCorp share on the DC of eurocorp.local forest
    - Extract the trust key
    - Forge a referral ticket
* [21 - LAB2️1️](lab21.md)
    - Check if AD CS is used by the target forest and find any vulnerable/abusable templates. 
    - Abuse any such template(s) to escalate to Domain Admin and Enterprise Admin
    - Privilege Escalation to DA and EA using ESC1
    - Privilege Escalation to DA and EA using ESC3
* [22 - LAB2️2️](lab22.md)
    - Get a reverse shell on a SQL server in eurocorp forest by abusing database links from dcorp-mssql.
* [23 - LAB2️3️](lab23.md)
    - Lateral Movement – ASR Rules Bypass
    - LSASS DUMP using Custom APIs
