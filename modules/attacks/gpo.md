## Privilege Escalation - GPO Abuse
* A GPO with overly permissive ACL can be abused for multiple attacks. 
* Recall the ACL abuse diagram.

GPOddity combines NTLM relaying and modification of Group Policy Container. 
* By relaying credentials of a user who has WriteDACL on GPO, we can modify the path (gPCFileSysPath) of the group policy template (default is SYSVOL).
* This enables loading of a malicious template from a location that we control.

<img width="1394" height="669" alt="image" src="https://github.com/user-attachments/assets/acb3df37-0059-4e8c-96ba-9bd70df1e3f5" />
