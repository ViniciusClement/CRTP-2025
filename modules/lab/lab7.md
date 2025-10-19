# LAB 7

 - Identify a machine in the target domain where a Domain Admin session is available. 
    - Compromise the machine and escalate privileges to Domain Admin by abusing reverse shell on dcorp-ci.
    - Escalate privilege to DA by abusing derivative local admin through dcorp-adminsrv. 
    - On dcorp-adminsrv, tackle application allowlisting using: 
        - Gaps in Applocker rules. 
        - Disable Applocker by modifying GPO applicable to dcorp-adminsrv