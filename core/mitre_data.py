"""
HuntForge — Embedded MITRE ATT&CK Technique Data
Covers: Initial Access, Execution, Persistence, Privilege Escalation,
        Defense Evasion, Discovery, Lateral Movement, Collection, C2, Exfiltration

No internet required for core functionality.
"""

# ─── Tactic reference ─────────────────────────────────────────────────────────

TACTICS = {
    "TA0001": {"id": "TA0001", "name": "Initial Access",        "shortname": "initial-access"},
    "TA0002": {"id": "TA0002", "name": "Execution",             "shortname": "execution"},
    "TA0003": {"id": "TA0003", "name": "Persistence",           "shortname": "persistence"},
    "TA0004": {"id": "TA0004", "name": "Privilege Escalation",  "shortname": "privilege-escalation"},
    "TA0005": {"id": "TA0005", "name": "Defense Evasion",       "shortname": "defense-evasion"},
    "TA0006": {"id": "TA0006", "name": "Credential Access",     "shortname": "credential-access"},
    "TA0007": {"id": "TA0007", "name": "Discovery",             "shortname": "discovery"},
    "TA0008": {"id": "TA0008", "name": "Lateral Movement",      "shortname": "lateral-movement"},
    "TA0009": {"id": "TA0009", "name": "Collection",            "shortname": "collection"},
    "TA0010": {"id": "TA0010", "name": "Exfiltration",          "shortname": "exfiltration"},
    "TA0011": {"id": "TA0011", "name": "Command and Control",   "shortname": "command-and-control"},
}

# ─── Technique database ────────────────────────────────────────────────────────
# Each entry contains everything needed to generate a complete hunt playbook.

TECHNIQUES: dict = {

    # ── Initial Access ──────────────────────────────────────────────────────────

    "T1566": {
        "id": "T1566", "name": "Phishing",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "parent_id": None,
        "sub_techniques": ["T1566.001", "T1566.002", "T1566.003"],
        "related_techniques": ["T1204.002", "T1566.001", "T1566.002"],
        "description": "Adversaries may send phishing messages to gain access to victim systems. Phishing is an attempt to trick targets into providing information or taking action that benefits the adversary. All forms of phishing are electronically delivered social engineering.",
        "hunt_hypothesis": "An adversary has delivered a phishing message containing a malicious attachment or link. The target may have executed a macro-enabled document or downloaded a dropper, resulting in an initial foothold on the endpoint.",
        "event_ids": ["4688", "1", "11"],
        "log_sources": ["WinEventLog:Security", "Sysmon", "Email gateway logs", "Office 365 Unified Audit Log", "Defender for Endpoint"],
        "field_names": ["CommandLine", "ParentCommandLine", "ParentImage", "Image", "TargetFilename"],
        "processes": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "WINWORD.EXE", "EXCEL.EXE"],
        "command_patterns": ["mshta", "wscript", "cscript", "powershell", "cmd.exe", "rundll32"],
        "registry_keys": [],
        "file_paths": ["*.doc", "*.docm", "*.xls", "*.xlsm", "*.hta", "*.js", "*.vbs"],
        "network_ports": [80, 443, 25, 587],
        "detection_notes": "Focus on child processes spawned from Office applications (winword, excel, powerpnt, outlook). Macro execution spawning cmd/powershell is a high-fidelity indicator. Also look for unusual file drops to TEMP directories.",
        "confidence_score": 7,
        "confidence_rationale": "Phishing detection requires correlation between email gateway logs and endpoint telemetry. Detection fidelity improves significantly with Sysmon and Office application telemetry enabled.",
        "artifacts": {
            "event_ids": ["4688", "1", "11"],
            "files": ["%TEMP%\\*.docm", "%APPDATA%\\*.hta", "%USERPROFILE%\\Downloads\\*.xlsm"],
            "registry": [],
            "network": ["SMBv1 connections", "Unexpected SMTP egress"]
        }
    },

    "T1566.001": {
        "id": "T1566.001", "name": "Spearphishing Attachment",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "parent_id": "T1566",
        "sub_techniques": [],
        "related_techniques": ["T1566.002", "T1204.002", "T1059.001"],
        "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing.",
        "hunt_hypothesis": "A targeted spearphishing email carrying a weaponised attachment (Office macro, ISO, LNK, or archive) was delivered to a user. Upon opening, the attachment executes a payload establishing initial access.",
        "event_ids": ["4688", "1", "11", "15"],
        "log_sources": ["WinEventLog:Security", "Sysmon", "Email gateway", "Microsoft Defender SmartScreen"],
        "field_names": ["CommandLine", "ParentImage", "Image", "TargetFilename", "Hash"],
        "processes": ["winword.exe", "excel.exe", "powerpnt.exe", "acrord32.exe", "msdt.exe"],
        "command_patterns": ["-enc", "IEX", "DownloadString", "mshta", "wscript.exe", "cscript.exe", "regsvr32"],
        "registry_keys": ["HKCU\\Software\\Microsoft\\Office\\*\\Security\\VBAWarnings"],
        "file_paths": ["*.docm", "*.xlsm", "*.iso", "*.lnk", "*.hta"],
        "network_ports": [443, 80],
        "detection_notes": "High-value hunt: Office child process anomaly (winword.exe → cmd.exe, powershell.exe, wscript.exe). Zone.Identifier ADS on downloaded files (Sysmon Event 15). Script execution from %TEMP% or %APPDATA%.",
        "confidence_score": 8,
        "confidence_rationale": "Office-spawned shell processes are a very high-fidelity indicator. Sysmon Event 11/15 for file creation and ADS provide strong signal. Detection confidence high when Sysmon is deployed.",
        "artifacts": {
            "event_ids": ["4688", "1", "11", "15"],
            "files": ["%TEMP%\\*.exe", "%TEMP%\\*.dll", "%APPDATA%\\*.js", "%USERPROFILE%\\Downloads\\"],
            "registry": ["HKCU\\Software\\Microsoft\\Office\\*\\Security\\VBAWarnings=1"],
            "network": ["DNS queries to newly registered domains", "HTTP POST to external IP within minutes of document open"]
        }
    },

    "T1566.002": {
        "id": "T1566.002", "name": "Spearphishing Link",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "parent_id": "T1566",
        "sub_techniques": [],
        "related_techniques": ["T1566.001", "T1204.001", "T1071.001"],
        "description": "Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems. Typically the linked page will download a dropper or redirect to a credential harvesting page.",
        "hunt_hypothesis": "A user clicked a malicious link delivered via email or messaging platform. The link led to a credential phishing page or drove a browser-based exploit delivering malware to the endpoint.",
        "event_ids": ["4688", "1", "3", "22"],
        "log_sources": ["WinEventLog:Security", "Sysmon", "DNS logs", "Proxy/web gateway", "Browser history"],
        "field_names": ["CommandLine", "QueryName", "DestinationHostname", "Image"],
        "processes": ["chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "curl.exe", "wget.exe"],
        "command_patterns": ["http://", "https://", "ftp://", "DownloadFile", "Invoke-WebRequest"],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [80, 443],
        "detection_notes": "Browser-spawned processes (e.g., chrome.exe → cmd.exe) indicate browser exploitation. DNS queries to newly registered or DGA domains from the endpoint shortly after phishing delivery. Sysmon Event 22 for DNS queries.",
        "confidence_score": 6,
        "confidence_rationale": "Link-based phishing is harder to detect purely on endpoint — requires correlation with web proxy, DNS, and email gateway data. Detection confidence is moderate without full network visibility.",
        "artifacts": {
            "event_ids": ["4688", "1", "3", "22"],
            "files": ["%TEMP%\\*.exe", "%Downloads%\\*.exe"],
            "registry": [],
            "network": ["New domain first seen within 30 days", "URL shortener redirect chains"]
        }
    },

    "T1190": {
        "id": "T1190", "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "parent_id": None,
        "sub_techniques": [],
        "related_techniques": ["T1133", "T1505.003", "T1078"],
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.",
        "hunt_hypothesis": "An adversary exploited a vulnerability in a public-facing application (web server, VPN, Exchange, Confluence, etc.) to gain initial access. They may have uploaded a web shell or achieved remote code execution.",
        "event_ids": ["4688", "1", "3", "11"],
        "log_sources": ["Web application logs", "IIS logs", "Apache/Nginx logs", "Sysmon", "WinEventLog:Security", "WAF logs"],
        "field_names": ["CommandLine", "ParentImage", "cs-uri-stem", "cs-uri-query", "c-ip", "sc-status"],
        "processes": ["w3wp.exe", "httpd.exe", "nginx.exe", "java.exe", "python.exe", "php.exe"],
        "command_patterns": ["cmd.exe", "powershell", "whoami", "net user", "netstat", "curl", "wget"],
        "registry_keys": [],
        "file_paths": ["*.aspx", "*.php", "*.jsp", "*.ashx"],
        "network_ports": [80, 443, 8080, 8443],
        "detection_notes": "Look for web server processes (w3wp.exe, tomcat, java) spawning cmd.exe or PowerShell. Unusual file writes to web directories. HTTP 500 errors followed by HTTP 200 at same path. POST requests to newly created files.",
        "confidence_score": 7,
        "confidence_rationale": "Exploitation attempts generate specific parent-child process anomalies and web log patterns. Requires correlation of web server logs with process creation events.",
        "artifacts": {
            "event_ids": ["4688", "1", "11"],
            "files": ["\\inetpub\\wwwroot\\*.aspx", "\\webapps\\*.jsp", "\\htdocs\\*.php"],
            "registry": [],
            "network": ["Unusual HTTP methods (PUT/DELETE) to sensitive paths", "SQLi/XSS patterns in HTTP logs"]
        }
    },

    "T1133": {
        "id": "T1133", "name": "External Remote Services",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "parent_id": None,
        "sub_techniques": [],
        "related_techniques": ["T1021.001", "T1078", "T1190"],
        "description": "Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations.",
        "hunt_hypothesis": "An adversary is using legitimate remote access services (VPN, RDP, Citrix, SSH) with valid or stolen credentials to gain initial access. Look for logins from unusual geographic locations, anomalous hours, or new source IPs.",
        "event_ids": ["4624", "4625", "4776", "4648"],
        "log_sources": ["WinEventLog:Security", "VPN logs", "Citrix logs", "Azure AD Sign-in logs", "Firewall logs"],
        "field_names": ["IpAddress", "LogonType", "AccountName", "WorkstationName", "TargetUserName"],
        "processes": ["svchost.exe", "rdpclip.exe", "mstsc.exe"],
        "command_patterns": [],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [3389, 22, 443, 1194],
        "detection_notes": "Authentication from new IP ranges, off-hours logons, multiple failed attempts preceding success, impossible travel (same account from geographically distant IPs in short time). Correlate with threat intel for known bad IPs.",
        "confidence_score": 6,
        "confidence_rationale": "Requires baseline of normal authentication patterns. Detection confidence improves with UEBA/behavioral analytics. Raw log coverage is typically high for enterprise VPN/RDP.",
        "artifacts": {
            "event_ids": ["4624", "4625", "4648", "4776"],
            "files": [],
            "registry": [],
            "network": ["RDP connections from external IPs", "VPN auth from new geolocation"]
        }
    },

    "T1078": {
        "id": "T1078", "name": "Valid Accounts",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "parent_id": None,
        "sub_techniques": ["T1078.001", "T1078.002", "T1078.003"],
        "related_techniques": ["T1133", "T1110", "T1555"],
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "hunt_hypothesis": "An adversary has obtained valid account credentials (via phishing, credential dumping, or purchase) and is using them to authenticate to services. Activity may appear legitimate but originate from unusual sources or exhibit anomalous patterns.",
        "event_ids": ["4624", "4648", "4768", "4769", "4776"],
        "log_sources": ["WinEventLog:Security", "Active Directory logs", "Azure AD", "M365 Unified Audit Log"],
        "field_names": ["TargetUserName", "IpAddress", "LogonType", "WorkstationName", "ServiceName"],
        "processes": [],
        "command_patterns": [],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [389, 636, 88, 443],
        "detection_notes": "Look for logons with LogonType 3 (network) or 10 (RemoteInteractive) from unexpected sources. Service account logons to interactive sessions. Accounts with multiple concurrent sessions from different IPs.",
        "confidence_score": 5,
        "confidence_rationale": "Valid accounts by definition blend with normal traffic. Requires strong behavioral baseline. Detection confidence depends heavily on UEBA capability and log retention depth.",
        "artifacts": {
            "event_ids": ["4624", "4648", "4768", "4769"],
            "files": [],
            "registry": [],
            "network": ["Kerberos TGT requests from new workstations"]
        }
    },

    # ── Execution ──────────────────────────────────────────────────────────────

    "T1059": {
        "id": "T1059", "name": "Command and Scripting Interpreter",
        "tactic": "Execution", "tactic_id": "TA0002",
        "parent_id": None,
        "sub_techniques": ["T1059.001", "T1059.003", "T1059.004", "T1059.005", "T1059.006", "T1059.007"],
        "related_techniques": ["T1027", "T1140", "T1562.001"],
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms.",
        "hunt_hypothesis": "An adversary is leveraging built-in scripting interpreters (PowerShell, cmd, WScript, Python) to execute malicious commands. Look for unusual parent processes, encoded commands, and downloads via scripting engines.",
        "event_ids": ["4688", "4103", "4104", "1"],
        "log_sources": ["WinEventLog:Security", "WinEventLog:Microsoft-Windows-PowerShell/Operational", "Sysmon"],
        "field_names": ["CommandLine", "ParentCommandLine", "Image", "ParentImage"],
        "processes": ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "python.exe", "mshta.exe"],
        "command_patterns": ["-enc", "-encoded", "IEX", "Invoke-Expression", "cmd /c", "cmd.exe /c"],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [],
        "detection_notes": "Process creation auditing (Event 4688 with command line) or Sysmon Event 1 are essential. PowerShell script block logging (4104) catches obfuscated scripts. Focus on unusual parent-child relationships.",
        "confidence_score": 8,
        "confidence_rationale": "Command execution telemetry is rich when process creation logging and PowerShell logging are enabled. High detection confidence across Windows environments.",
        "artifacts": {
            "event_ids": ["4688", "4103", "4104", "1"],
            "files": [],
            "registry": [],
            "network": []
        }
    },

    "T1059.001": {
        "id": "T1059.001", "name": "PowerShell",
        "tactic": "Execution", "tactic_id": "TA0002",
        "parent_id": "T1059",
        "sub_techniques": [],
        "related_techniques": ["T1059.003", "T1027", "T1562.001", "T1086"],
        "description": "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code.",
        "hunt_hypothesis": "An adversary is using PowerShell to execute malicious code — potentially with obfuscation (base64 encoding, string concatenation, backtick insertion), download cradles (Net.WebClient, Invoke-WebRequest), or AMSI bypass techniques. Lateral movement via PowerShell remoting is also possible.",
        "event_ids": ["4103", "4104", "4688", "1", "400", "600"],
        "log_sources": ["WinEventLog:Microsoft-Windows-PowerShell/Operational", "WinEventLog:Security", "Sysmon", "WinEventLog:Windows PowerShell"],
        "field_names": ["CommandLine", "ScriptBlockText", "ParentCommandLine", "Image", "ParentImage", "Payload"],
        "processes": ["powershell.exe", "pwsh.exe"],
        "command_patterns": ["-enc", "-EncodedCommand", "-nop", "-NonInteractive", "-w hidden", "-WindowStyle Hidden", "IEX", "Invoke-Expression", "DownloadString", "Net.WebClient", "Invoke-WebRequest", "iwr", "curl", "wget", "FromBase64String", "System.Reflection.Assembly"],
        "registry_keys": ["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"],
        "file_paths": [],
        "network_ports": [80, 443, 5985, 5986],
        "detection_notes": "Enable Script Block Logging (Event 4104) to catch obfuscated PowerShell. Event 4688 with process name powershell.exe/pwsh.exe. Focus on: encoded commands (-enc), hidden windows (-w hidden), download cradles, AMSI bypass patterns (e[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')), and invocations from unusual parents (Office, WMI, scheduled tasks).",
        "confidence_score": 9,
        "confidence_rationale": "Script block logging (4104) provides extremely rich telemetry including deobfuscated content. Process creation logging provides baseline detection. Very high confidence when Script Block Logging and Sysmon are deployed.",
        "artifacts": {
            "event_ids": ["4103", "4104", "4688", "1"],
            "files": ["%TEMP%\\*.ps1", "%APPDATA%\\*.ps1"],
            "registry": ["HKCU\\SOFTWARE\\Classes\\ms-settings\\shell\\open\\command"],
            "network": ["HTTP(S) to external IPs from powershell.exe process", "WinRM connections (5985/5986)"]
        }
    },

    "T1059.003": {
        "id": "T1059.003", "name": "Windows Command Shell",
        "tactic": "Execution", "tactic_id": "TA0002",
        "parent_id": "T1059",
        "sub_techniques": [],
        "related_techniques": ["T1059.001", "T1059.005", "T1106"],
        "description": "Adversaries may abuse the Windows command shell for execution. The Windows command shell (cmd.exe) is the primary command prompt on Windows systems. Adversaries may interact with the Windows command shell directly or through the use of cmd.exe.",
        "hunt_hypothesis": "An adversary is using cmd.exe to execute commands, chain together malicious instructions, or invoke other scripting engines. Look for cmd.exe spawned from unusual parents, piped commands, and use of net/whoami/ipconfig for discovery.",
        "event_ids": ["4688", "1"],
        "log_sources": ["WinEventLog:Security", "Sysmon"],
        "field_names": ["CommandLine", "ParentCommandLine", "Image", "ParentImage"],
        "processes": ["cmd.exe"],
        "command_patterns": ["cmd /c", "cmd.exe /c", "cmd /k", "whoami", "net user", "net localgroup", "ipconfig", "systeminfo", "tasklist", "netstat", "dir /s", "copy", "xcopy", "del /f /q"],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [],
        "detection_notes": "cmd.exe spawned from Office applications, web servers (w3wp.exe), or service host (svchost.exe) is highly suspicious. Command line containing network recon commands (whoami, net, ipconfig) shortly after initial access indicates post-exploitation.",
        "confidence_score": 7,
        "confidence_rationale": "cmd.exe is ubiquitous and generates high false positives. Effective detection requires parent process context and command line content analysis. Good coverage with process creation auditing.",
        "artifacts": {
            "event_ids": ["4688", "1"],
            "files": [],
            "registry": [],
            "network": []
        }
    },

    "T1059.005": {
        "id": "T1059.005", "name": "Visual Basic",
        "tactic": "Execution", "tactic_id": "TA0002",
        "parent_id": "T1059",
        "sub_techniques": [],
        "related_techniques": ["T1059.001", "T1059.003", "T1566.001"],
        "description": "Adversaries may abuse Visual Basic (VB) for execution. VB is a programming language created by Microsoft with interoperability with many Windows technologies. Adversaries may use VBScript or VBA macros for execution of code.",
        "hunt_hypothesis": "An adversary delivered a VBA macro (embedded in an Office document) or VBScript (.vbs/.vbe) file to execute malicious code. The script may download additional payloads or directly execute shellcode.",
        "event_ids": ["4688", "1", "11"],
        "log_sources": ["WinEventLog:Security", "Sysmon", "Office VBA audit logs"],
        "field_names": ["CommandLine", "ParentImage", "Image", "TargetFilename"],
        "processes": ["wscript.exe", "cscript.exe"],
        "command_patterns": ["wscript", "cscript", ".vbs", ".vbe", "CreateObject", "WScript.Shell", "Shell.Application", "XMLHTTP"],
        "registry_keys": [],
        "file_paths": ["*.vbs", "*.vbe", "*.wsf"],
        "network_ports": [80, 443],
        "detection_notes": "wscript.exe or cscript.exe spawned from Office applications is a strong indicator of macro-based execution. WScript.Shell usage enables command execution. Look for downloads via XMLHTTP/WinHttp objects.",
        "confidence_score": 8,
        "confidence_rationale": "VBScript execution via wscript/cscript generates clear process creation events. Parent-child relationship analysis provides high-fidelity detection.",
        "artifacts": {
            "event_ids": ["4688", "1", "11"],
            "files": ["%TEMP%\\*.vbs", "%TEMP%\\*.vbe", "%APPDATA%\\*.wsf"],
            "registry": [],
            "network": []
        }
    },

    "T1047": {
        "id": "T1047", "name": "Windows Management Instrumentation",
        "tactic": "Execution", "tactic_id": "TA0002",
        "parent_id": None,
        "sub_techniques": [],
        "related_techniques": ["T1021.003", "T1059.001", "T1543"],
        "description": "Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads. WMI is an administration feature that provides a uniform environment to access Windows system components.",
        "hunt_hypothesis": "An adversary is using WMI (wmic.exe, Win32_Process, or WMI event subscriptions) to execute commands, move laterally, or persist. WMI activity from unusual parents or to remote hosts is particularly suspicious.",
        "event_ids": ["4688", "1", "19", "20", "21"],
        "log_sources": ["WinEventLog:Security", "Sysmon", "WinEventLog:Microsoft-Windows-WMI-Activity/Operational"],
        "field_names": ["CommandLine", "ParentImage", "Image", "Operation", "Consumer", "Filter"],
        "processes": ["wmic.exe", "wmiprvse.exe", "wsmprovhost.exe"],
        "command_patterns": ["wmic process call create", "wmic /node:", "Invoke-WmiMethod", "Get-WmiObject", "Win32_Process", "Win32_ScheduledJob"],
        "registry_keys": ["HKLM\\SOFTWARE\\Microsoft\\WBEM"],
        "file_paths": [],
        "network_ports": [135, 445],
        "detection_notes": "Sysmon Events 19/20/21 capture WMI event filter/consumer activity indicating potential persistence. wmic.exe with 'process call create' is a direct execution indicator. wmiprvse.exe spawning cmd/PowerShell indicates WMI-based lateral movement.",
        "confidence_score": 8,
        "confidence_rationale": "WMI activity logging (Sysmon 19-21) provides excellent coverage of persistence and lateral movement via WMI. Process creation logging catches direct wmic.exe usage.",
        "artifacts": {
            "event_ids": ["4688", "1", "19", "20", "21"],
            "files": [],
            "registry": ["HKLM\\SOFTWARE\\Microsoft\\WBEM\\Subscriptions"],
            "network": ["DCOM/RPC traffic on 135 to remote hosts"]
        }
    },

    "T1053.005": {
        "id": "T1053.005", "name": "Scheduled Task",
        "tactic": "Execution", "tactic_id": "TA0002",
        "parent_id": "T1053",
        "sub_techniques": [],
        "related_techniques": ["T1543.003", "T1059.001", "T1547"],
        "description": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence.",
        "hunt_hypothesis": "An adversary created a scheduled task to establish persistence or execute code at a recurring interval. The task may invoke PowerShell, cmd, or a dropper binary from an unusual location.",
        "event_ids": ["4698", "4702", "4699", "4700", "4701", "4688", "1"],
        "log_sources": ["WinEventLog:Security", "WinEventLog:Microsoft-Windows-TaskScheduler/Operational", "Sysmon"],
        "field_names": ["TaskName", "TaskContent", "CommandLine", "Image", "SubjectUserName"],
        "processes": ["schtasks.exe", "taskeng.exe", "taskhostw.exe", "at.exe"],
        "command_patterns": ["schtasks /create", "schtasks.exe /create", "/sc onlogon", "/sc onstartup", "/sc minute", "/ru SYSTEM", "AT \\\\", "Register-ScheduledTask"],
        "registry_keys": ["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"],
        "file_paths": ["%SystemRoot%\\System32\\Tasks\\", "%SystemRoot%\\SysWOW64\\Tasks\\"],
        "network_ports": [],
        "detection_notes": "Event 4698 (task created) with unusual task name or command. Tasks created in user profile directories or pointing to %TEMP%/%APPDATA%. Short recurrence intervals (per-minute) indicate malicious intent. Tasks running as SYSTEM from user accounts are suspicious.",
        "confidence_score": 8,
        "confidence_rationale": "Task Scheduler audit events (4698/4699/4700/4701/4702) provide excellent coverage. Task content logging reveals exact command executed. High confidence when Task Scheduler operational log is enabled.",
        "artifacts": {
            "event_ids": ["4698", "4699", "4700", "4701", "4702"],
            "files": ["%SystemRoot%\\System32\\Tasks\\*", "%TEMP%\\*.exe"],
            "registry": ["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache"],
            "network": []
        }
    },

    # ── Persistence ────────────────────────────────────────────────────────────

    "T1547.001": {
        "id": "T1547.001", "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence", "tactic_id": "TA0003",
        "parent_id": "T1547",
        "sub_techniques": [],
        "related_techniques": ["T1543.003", "T1053.005", "T1136"],
        "description": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the 'run keys' in the Registry or startup folder will cause the program referenced to be executed when a user logs in.",
        "hunt_hypothesis": "An adversary added a Registry run key or placed a file in a startup folder to ensure their malware executes whenever a user logs on or the system starts. The value will point to a suspicious executable or script.",
        "event_ids": ["13", "12", "14", "4657"],
        "log_sources": ["Sysmon", "WinEventLog:Security"],
        "field_names": ["TargetObject", "Details", "EventType", "Image", "ObjectName"],
        "processes": [],
        "command_patterns": [],
        "registry_keys": [
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
        ],
        "file_paths": [
            "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        ],
        "network_ports": [],
        "detection_notes": "Sysmon Event 13 (registry value set) on Run/RunOnce keys is the primary detection. Look for values pointing to %TEMP%, %APPDATA%, or unusual directories. Registry value names that mimic system components (svchost, explorer) are suspicious.",
        "confidence_score": 9,
        "confidence_rationale": "Registry modifications to Run keys generate Sysmon Event 13 with high fidelity. Very low false positive rate for values pointing to non-standard paths. Excellent detection coverage when Sysmon is deployed.",
        "artifacts": {
            "event_ids": ["13", "12", "14", "4657"],
            "files": ["%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*"],
            "registry": [
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*"
            ],
            "network": []
        }
    },

    "T1543.003": {
        "id": "T1543.003", "name": "Windows Service",
        "tactic": "Persistence", "tactic_id": "TA0003",
        "parent_id": "T1543",
        "sub_techniques": [],
        "related_techniques": ["T1547.001", "T1053.005", "T1569.002"],
        "description": "Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. Attackers may execute their malicious content by creating a new service or modifying an existing service to execute at startup.",
        "hunt_hypothesis": "An adversary installed or modified a Windows service to gain persistence. The service binary path points to a malicious executable, or a legitimate service was hijacked by modifying its ImagePath registry value.",
        "event_ids": ["7045", "7040", "4697", "13"],
        "log_sources": ["WinEventLog:System", "WinEventLog:Security", "Sysmon"],
        "field_names": ["ServiceName", "ServiceFileName", "ServiceType", "StartType", "AccountName"],
        "processes": ["sc.exe", "services.exe", "svchost.exe"],
        "command_patterns": ["sc create", "sc config", "New-Service", "sc.exe binpath", "sc.exe start"],
        "registry_keys": ["HKLM\\SYSTEM\\CurrentControlSet\\Services\\"],
        "file_paths": [],
        "network_ports": [],
        "detection_notes": "Event 7045 (new service installed) is the primary detection for service creation. Look for services with binary paths in %TEMP%, %APPDATA%, or user-writable directories. Services running as SYSTEM with unusual names or descriptions. Misspellings of common service names (svch0st, lsaas).",
        "confidence_score": 8,
        "confidence_rationale": "Service creation events (7045) are low-noise and high fidelity. Combined with path analysis, detection confidence is high. Coverage requires System event log and Sysmon.",
        "artifacts": {
            "event_ids": ["7045", "7040", "4697"],
            "files": ["%TEMP%\\*.exe", "%SystemRoot%\\Temp\\*.exe"],
            "registry": ["HKLM\\SYSTEM\\CurrentControlSet\\Services\\[service_name]\\ImagePath"],
            "network": []
        }
    },

    "T1136.001": {
        "id": "T1136.001", "name": "Local Account",
        "tactic": "Persistence", "tactic_id": "TA0003",
        "parent_id": "T1136",
        "sub_techniques": [],
        "related_techniques": ["T1136.002", "T1078", "T1098"],
        "description": "Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system.",
        "hunt_hypothesis": "An adversary created a new local user account on a compromised system to maintain persistent access. The account may have been added to the Administrators group for elevated privileges.",
        "event_ids": ["4720", "4722", "4732", "4728", "4688"],
        "log_sources": ["WinEventLog:Security", "Sysmon"],
        "field_names": ["TargetUserName", "SubjectUserName", "GroupName", "CommandLine"],
        "processes": ["net.exe", "net1.exe"],
        "command_patterns": ["net user /add", "net localgroup administrators", "New-LocalUser", "Add-LocalGroupMember"],
        "registry_keys": ["HKLM\\SAM\\SAM\\Domains\\Account\\Users"],
        "file_paths": [],
        "network_ports": [],
        "detection_notes": "Event 4720 (user account created) followed closely by 4732 (member added to local admin group) is a high-fidelity attack indicator. net.exe executing 'user /add' or 'localgroup administrators' commands. Look for accounts created outside business hours.",
        "confidence_score": 9,
        "confidence_rationale": "Account creation events are low-noise with very high signal. Event 4720 is specifically designed for this detection. Excellent coverage with Windows Security auditing enabled.",
        "artifacts": {
            "event_ids": ["4720", "4722", "4732", "4728"],
            "files": [],
            "registry": [],
            "network": []
        }
    },

    "T1505.003": {
        "id": "T1505.003", "name": "Web Shell",
        "tactic": "Persistence", "tactic_id": "TA0003",
        "parent_id": "T1505",
        "sub_techniques": [],
        "related_techniques": ["T1190", "T1059.001", "T1059.003"],
        "description": "Adversaries may backdoor web servers with web shells to establish persistent access to systems. A web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway into a network.",
        "hunt_hypothesis": "An adversary uploaded a web shell to a publicly accessible web server after exploiting a vulnerability or stolen credentials. The shell allows remote command execution via HTTP requests and provides persistent access.",
        "event_ids": ["4688", "1", "11", "3"],
        "log_sources": ["IIS/Apache/Nginx access logs", "Sysmon", "WinEventLog:Security", "Web Application Firewall"],
        "field_names": ["CommandLine", "ParentImage", "Image", "cs-uri-stem", "c-ip", "TargetFilename"],
        "processes": ["w3wp.exe", "httpd.exe", "php.exe", "java.exe"],
        "command_patterns": ["cmd.exe", "powershell", "whoami", "net user", "ipconfig", "certutil", "curl"],
        "registry_keys": [],
        "file_paths": ["\\inetpub\\wwwroot\\*.aspx", "\\wwwroot\\*.php", "\\htdocs\\*.php", "\\webapps\\*.jsp"],
        "network_ports": [80, 443, 8080],
        "detection_notes": "Web server processes (w3wp.exe, httpd.exe) spawning cmd.exe or PowerShell is a critical indicator. New web-accessible files (.aspx, .php, .jsp) with file creation/modification events. HTTP requests with cmd= or execute= parameters in query strings. POST requests to recently created files.",
        "confidence_score": 9,
        "confidence_rationale": "Web server process spawning shells is a near-zero false positive indicator. Sysmon Event 11 for new file creation in web roots, combined with process creation, provides excellent coverage.",
        "artifacts": {
            "event_ids": ["4688", "1", "11"],
            "files": ["\\inetpub\\wwwroot\\*.aspx", "\\inetpub\\wwwroot\\*.ashx", "\\htdocs\\*.php"],
            "registry": [],
            "network": ["HTTP POST to newly created .aspx/.php files", "cmd.exe network connections"]
        }
    },

    # ── Privilege Escalation ───────────────────────────────────────────────────

    "T1548.002": {
        "id": "T1548.002", "name": "Bypass User Account Control",
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "parent_id": "T1548",
        "sub_techniques": [],
        "related_techniques": ["T1134", "T1055", "T1059.001"],
        "description": "Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate its privileges to perform a task under administrator-level permissions by prompting the user for confirmation.",
        "hunt_hypothesis": "An adversary is using a UAC bypass technique to elevate privileges without triggering a UAC prompt. Common methods include using auto-elevating binaries (eventvwr, fodhelper, cmstp), DLL hijacking of trusted binaries, or token impersonation.",
        "event_ids": ["4688", "1", "13"],
        "log_sources": ["WinEventLog:Security", "Sysmon"],
        "field_names": ["CommandLine", "ParentImage", "Image", "IntegrityLevel", "TargetObject"],
        "processes": ["eventvwr.exe", "fodhelper.exe", "cmstp.exe", "computerdefaults.exe", "sdclt.exe"],
        "command_patterns": [],
        "registry_keys": [
            "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command",
            "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command",
            "HKCU\\Environment\\windir",
        ],
        "file_paths": [],
        "network_ports": [],
        "detection_notes": "Monitor for Sysmon Event 13 (registry modification) on HKCU\\Software\\Classes\\mscfile or ms-settings for eventvwr/fodhelper bypasses. Processes starting with high integrity level but unusual parents. eventvwr.exe/fodhelper.exe spawning cmd.exe or PowerShell.",
        "confidence_score": 8,
        "confidence_rationale": "Registry-based UAC bypasses generate clear Sysmon Events 12/13. Process integrity level (available in Sysmon) confirms elevation. High confidence detection when Sysmon monitors the specific registry keys.",
        "artifacts": {
            "event_ids": ["4688", "1", "13"],
            "files": [],
            "registry": [
                "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command",
                "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command"
            ],
            "network": []
        }
    },

    "T1055": {
        "id": "T1055", "name": "Process Injection",
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "parent_id": None,
        "sub_techniques": ["T1055.001", "T1055.002", "T1055.003", "T1055.012"],
        "related_techniques": ["T1134", "T1548.002", "T1059.001"],
        "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process.",
        "hunt_hypothesis": "An adversary is injecting shellcode or a DLL into a legitimate process (lsass, svchost, explorer) to evade detection and potentially elevate privileges. This may involve VirtualAllocEx, WriteProcessMemory, CreateRemoteThread API calls.",
        "event_ids": ["8", "10", "4688"],
        "log_sources": ["Sysmon", "WinEventLog:Security", "EDR telemetry"],
        "field_names": ["SourceImage", "TargetImage", "GrantedAccess", "StartAddress", "CallTrace"],
        "processes": ["lsass.exe", "svchost.exe", "explorer.exe", "notepad.exe"],
        "command_patterns": [],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [],
        "detection_notes": "Sysmon Event 8 (CreateRemoteThread) targeting lsass, svchost, or other system processes. Event 10 (process access) with suspicious granted access rights (0x1F0FFF, 0x1010). Unsigned code executing from RWX memory regions. LSASS memory access outside of known security products.",
        "confidence_score": 7,
        "confidence_rationale": "Sysmon Events 8 and 10 provide strong indicators of process injection. However, some EDR products and legitimate software also use these APIs. Requires tuning to reduce false positives.",
        "artifacts": {
            "event_ids": ["8", "10"],
            "files": [],
            "registry": [],
            "network": ["Unexpected network connections from injected processes"]
        }
    },

    "T1068": {
        "id": "T1068", "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "parent_id": None,
        "sub_techniques": [],
        "related_techniques": ["T1055", "T1548.002"],
        "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system to execute adversary-controlled code at an elevated privilege level.",
        "hunt_hypothesis": "An adversary exploited a local privilege escalation vulnerability (e.g., PrintNightmare, Dirty Pipe, or an unpatched kernel exploit) to gain SYSTEM or root-level access from a lower-privileged process.",
        "event_ids": ["4688", "1", "4697", "7045"],
        "log_sources": ["WinEventLog:Security", "Sysmon", "WinEventLog:System"],
        "field_names": ["CommandLine", "ParentImage", "Image", "SubjectUserSid", "TokenElevationType"],
        "processes": ["spoolsv.exe", "print spooler related"],
        "command_patterns": [],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [],
        "detection_notes": "Look for processes gaining unexpected SYSTEM privileges without a clear elevation event. PrintNightmare: spoolsv.exe spawning cmd.exe or dropping DLLs. Look for process token privilege changes (TokenElevationType=Full vs Limited). Windows Error Reporting events on kernel exploits.",
        "confidence_score": 5,
        "confidence_rationale": "Kernel exploit detection requires deep EDR telemetry or specific exploit signatures. Generic detection is difficult without endpoint behavioral analytics. Coverage varies greatly by specific CVE.",
        "artifacts": {
            "event_ids": ["4688", "1"],
            "files": [],
            "registry": [],
            "network": []
        }
    },

    # ── Defense Evasion ────────────────────────────────────────────────────────

    "T1070.001": {
        "id": "T1070.001", "name": "Clear Windows Event Logs",
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "parent_id": "T1070",
        "sub_techniques": [],
        "related_techniques": ["T1070.004", "T1562.001", "T1059.001"],
        "description": "Adversaries may clear Windows Event Logs to hide the activities of an intrusion. Windows Event Logs are a record of a computer's alerts and notifications. Adversaries may clear logs to evade detection post-compromise.",
        "hunt_hypothesis": "An adversary cleared or tampered with Windows event logs to destroy forensic evidence and evade detection. This is typically performed late in the attack lifecycle after achieving objectives.",
        "event_ids": ["1102", "104", "4688"],
        "log_sources": ["WinEventLog:Security", "WinEventLog:System", "Sysmon"],
        "field_names": ["SubjectUserName", "Channel", "CommandLine", "Image"],
        "processes": ["wevtutil.exe", "powershell.exe", "cmd.exe"],
        "command_patterns": ["wevtutil cl", "wevtutil.exe cl", "Clear-EventLog", "Remove-EventLog", "wevtutil /c", "GlobalSession"],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [],
        "detection_notes": "Event 1102 (audit log cleared) in Security log and Event 104 (log cleared) in System log are the primary indicators. wevtutil.exe with 'cl' (clear-log) argument. PowerShell Clear-EventLog cmdlet. These events may be the only remaining evidence after log clearing.",
        "confidence_score": 9,
        "confidence_rationale": "Events 1102 and 104 are specifically generated when logs are cleared and cannot be suppressed without disabling auditing. Near-100% detection coverage when auditing is enabled.",
        "artifacts": {
            "event_ids": ["1102", "104", "4688"],
            "files": [],
            "registry": [],
            "network": []
        }
    },

    "T1027": {
        "id": "T1027", "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "parent_id": None,
        "sub_techniques": ["T1027.001", "T1027.002", "T1027.004", "T1027.010"],
        "related_techniques": ["T1059.001", "T1140", "T1036"],
        "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and in many different stages of an intrusion.",
        "hunt_hypothesis": "An adversary is obfuscating malicious code or commands to evade signature-based detection. This includes base64-encoded PowerShell commands, XOR-encoded payloads, or packed executables that decode themselves at runtime.",
        "event_ids": ["4103", "4104", "4688", "1"],
        "log_sources": ["WinEventLog:Microsoft-Windows-PowerShell/Operational", "WinEventLog:Security", "Sysmon"],
        "field_names": ["CommandLine", "ScriptBlockText", "Image"],
        "processes": ["powershell.exe", "certutil.exe", "cmd.exe"],
        "command_patterns": ["-enc", "-EncodedCommand", "FromBase64String", "certutil -decode", "certutil -encode", "[System.Convert]::FromBase64String", "iex(", "Invoke-Obfuscation", "[char]", "join('')"],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [],
        "detection_notes": "Long base64 strings in PowerShell command lines (-EncodedCommand or [System.Convert]::FromBase64String). Script block logging (4104) captures decoded content. certutil.exe used for encoding/decoding. Look for concatenated strings and character code obfuscation.",
        "confidence_score": 7,
        "confidence_rationale": "Base64 encoded PowerShell is easily detectable. Script block logging captures decoded scripts. However, advanced obfuscation may require behavioral detection rather than signature matching.",
        "artifacts": {
            "event_ids": ["4104", "4688"],
            "files": [],
            "registry": [],
            "network": []
        }
    },

    "T1562.001": {
        "id": "T1562.001", "name": "Disable or Modify Tools",
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "parent_id": "T1562",
        "sub_techniques": [],
        "related_techniques": ["T1070.001", "T1112", "T1059.001"],
        "description": "Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities. This may take a number of forms, including tampering with Windows Defender, disabling logging, or killing EDR processes.",
        "hunt_hypothesis": "An adversary disabled or modified security tools (Windows Defender, EDR, AMSI, Sysmon) to evade detection. This is often one of the first defensive evasion actions taken after initial access.",
        "event_ids": ["4688", "1", "5001", "5004", "5007", "13"],
        "log_sources": ["WinEventLog:Security", "Sysmon", "WinEventLog:Microsoft-Windows-Windows Defender/Operational"],
        "field_names": ["CommandLine", "Image", "TargetObject", "Details"],
        "processes": ["powershell.exe", "cmd.exe", "sc.exe", "reg.exe"],
        "command_patterns": [
            "Set-MpPreference -Disable", "Add-MpPreference -ExclusionPath",
            "sc stop WinDefend", "sc config WinDefend start=disabled",
            "reg add.*DisableAntiSpyware", "tamper protection",
            "Uninstall-WindowsFeature Windows-Defender"
        ],
        "registry_keys": [
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware",
            "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\",
        ],
        "file_paths": [],
        "network_ports": [],
        "detection_notes": "Windows Defender events 5001/5004/5007 indicate protection status changes. Registry modifications to Windows Defender policy keys. PowerShell Set-MpPreference or Add-MpPreference exclusions. Process termination of security product processes (MsMpEng.exe, CylanceSvc, etc.).",
        "confidence_score": 8,
        "confidence_rationale": "Windows Defender operational log events and registry changes provide clear signals. Highly detectable when the defender log and Sysmon are operational (the irony being that disabling them is the attack).",
        "artifacts": {
            "event_ids": ["5001", "5004", "5007", "4688"],
            "files": [],
            "registry": ["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\*"],
            "network": []
        }
    },

    "T1036": {
        "id": "T1036", "name": "Masquerading",
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "parent_id": None,
        "sub_techniques": ["T1036.003", "T1036.004", "T1036.005"],
        "related_techniques": ["T1027", "T1218"],
        "description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses.",
        "hunt_hypothesis": "An adversary renamed a malicious binary to mimic a legitimate system executable (e.g., svchost.exe, explorer.exe) or placed it in a path associated with legitimate software to evade detection.",
        "event_ids": ["4688", "1"],
        "log_sources": ["WinEventLog:Security", "Sysmon"],
        "field_names": ["CommandLine", "Image", "OriginalFileName", "Company", "Description", "Hashes"],
        "processes": [],
        "command_patterns": [],
        "registry_keys": [],
        "file_paths": ["%TEMP%\\svchost.exe", "%APPDATA%\\explorer.exe", "%TEMP%\\lsass.exe"],
        "network_ports": [],
        "detection_notes": "Compare process image path against expected system paths. svchost.exe running from anywhere other than System32 is highly suspicious. Sysmon Event 1 includes OriginalFileName and Description fields from PE headers — mismatch with process name indicates masquerading. Check file hashes against known-good baselines.",
        "confidence_score": 8,
        "confidence_rationale": "Process image path analysis is straightforward and reliable. Sysmon's PE metadata fields enable strong detection of renamed binaries. Excellent coverage when Sysmon is deployed.",
        "artifacts": {
            "event_ids": ["1", "4688"],
            "files": ["%TEMP%\\*.exe", "%APPDATA%\\*.exe"],
            "registry": [],
            "network": []
        }
    },

    "T1218.011": {
        "id": "T1218.011", "name": "Rundll32",
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "parent_id": "T1218",
        "sub_techniques": [],
        "related_techniques": ["T1218", "T1036", "T1027"],
        "description": "Adversaries may abuse rundll32.exe to proxy execution of malicious code. Using rundll32.exe, vice executing directly, may avoid triggering security tools that may not monitor execution of the rundll32.exe process because of allowlists or false positives from normal operations.",
        "hunt_hypothesis": "An adversary is using rundll32.exe to execute a malicious DLL or invoke a COM function to bypass application whitelisting and evade security products that don't monitor rundll32 activity.",
        "event_ids": ["4688", "1", "7"],
        "log_sources": ["WinEventLog:Security", "Sysmon"],
        "field_names": ["CommandLine", "Image", "ParentImage", "ImageLoaded"],
        "processes": ["rundll32.exe"],
        "command_patterns": ["rundll32.exe javascript:", "rundll32.exe shell32.dll,ShellExec_RunDLL", "rundll32 url.dll", "rundll32.exe advpack.dll", "rundll32.exe ieadvpack.dll", "rundll32 pcwutl.dll,LaunchApplication"],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [],
        "detection_notes": "rundll32.exe with JavaScript: or vbscript: execution vectors. rundll32 loading DLLs from %TEMP% or user directories. Network connections initiated by rundll32.exe without a clear legitimate reason. rundll32 spawning child processes (cmd, PowerShell) is highly suspicious.",
        "confidence_score": 7,
        "confidence_rationale": "rundll32 has many legitimate uses making baseline difficult. Focus on specific LOLBin patterns (JavaScript execution, unusual exports, network connections). Coverage is good with process creation auditing.",
        "artifacts": {
            "event_ids": ["4688", "1", "7"],
            "files": [],
            "registry": [],
            "network": ["Network connections from rundll32.exe"]
        }
    },

    # ── Discovery ──────────────────────────────────────────────────────────────

    "T1082": {
        "id": "T1082", "name": "System Information Discovery",
        "tactic": "Discovery", "tactic_id": "TA0007",
        "parent_id": None,
        "sub_techniques": [],
        "related_techniques": ["T1033", "T1016", "T1057", "T1087"],
        "description": "An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from System Information Discovery during automated discovery to shape follow-on behaviors.",
        "hunt_hypothesis": "An adversary is performing system reconnaissance to understand the target environment — OS version, patch level, architecture, domain membership — to inform follow-on attack decisions such as choosing appropriate exploits or lateral movement paths.",
        "event_ids": ["4688", "1"],
        "log_sources": ["WinEventLog:Security", "Sysmon"],
        "field_names": ["CommandLine", "Image", "ParentImage"],
        "processes": ["systeminfo.exe", "wmic.exe", "powershell.exe"],
        "command_patterns": ["systeminfo", "wmic os get", "wmic computersystem get", "Get-ComputerInfo", "Get-WmiObject Win32_OperatingSystem", "hostname", "ver "],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [],
        "detection_notes": "systeminfo.exe or wmic.exe executed by unusual parent processes. Bulk execution of multiple discovery commands within a short timeframe is a strong indicator of automated post-exploitation. PowerShell Get-ComputerInfo or WMI OS queries.",
        "confidence_score": 6,
        "confidence_rationale": "Discovery commands are commonly used by legitimate admin tools. Detection requires clustering of multiple discovery events in short timeframes. Individual commands have high false positive rates.",
        "artifacts": {
            "event_ids": ["4688", "1"],
            "files": [],
            "registry": [],
            "network": []
        }
    },

    "T1087.001": {
        "id": "T1087.001", "name": "Local Account",
        "tactic": "Discovery", "tactic_id": "TA0007",
        "parent_id": "T1087",
        "sub_techniques": [],
        "related_techniques": ["T1087.002", "T1069.001", "T1033"],
        "description": "Adversaries may attempt to get a listing of local system accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior. Commands such as net user and query user are commonly used.",
        "hunt_hypothesis": "An adversary is enumerating local user accounts on a compromised system to identify service accounts, admin accounts, or other targets for credential theft and lateral movement.",
        "event_ids": ["4688", "1", "4798"],
        "log_sources": ["WinEventLog:Security", "Sysmon"],
        "field_names": ["CommandLine", "Image", "TargetUserName"],
        "processes": ["net.exe", "net1.exe", "wmic.exe", "powershell.exe"],
        "command_patterns": ["net user", "net1 user", "wmic useraccount", "Get-LocalUser", "query user", "Get-WmiObject Win32_UserAccount"],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [],
        "detection_notes": "net.exe 'user' enumeration is the most common indicator. Clustering with other discovery commands (T1082, T1016) within minutes indicates automated recon. Event 4798 (user local group membership enumerated).",
        "confidence_score": 6,
        "confidence_rationale": "These commands are used legitimately by admins. Effectiveness of detection depends on context (parent process, time of day, frequency). Moderate confidence without behavioral baseline.",
        "artifacts": {
            "event_ids": ["4688", "1", "4798"],
            "files": [],
            "registry": [],
            "network": []
        }
    },

    "T1046": {
        "id": "T1046", "name": "Network Service Discovery",
        "tactic": "Discovery", "tactic_id": "TA0007",
        "parent_id": None,
        "sub_techniques": [],
        "related_techniques": ["T1135", "T1016", "T1021"],
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port and/or vulnerability scans using tools such as nmap.",
        "hunt_hypothesis": "An adversary is conducting network service discovery to identify open ports and running services on internal hosts, mapping the network for lateral movement opportunities and identifying vulnerable services.",
        "event_ids": ["4688", "1", "3", "5156"],
        "log_sources": ["WinEventLog:Security", "Sysmon", "WinEventLog:Security (Windows Filtering Platform)", "Network flow data"],
        "field_names": ["CommandLine", "Image", "DestinationPort", "DestinationIp", "SourcePort"],
        "processes": ["nmap.exe", "netscan.exe", "PortQry.exe", "powershell.exe", "cmd.exe"],
        "command_patterns": ["nmap", "Test-NetConnection", "tnc", "nc.exe", "netcat", "masscan", "PortQryUI"],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [],
        "detection_notes": "High-rate connection attempts from a single internal host to multiple destinations on common ports (22, 80, 443, 445, 3389) in short timeframes. nmap.exe or known scanner binaries. Sysmon Event 3 showing port sweeps. Windows Filtering Platform block events for rapid sequential connections.",
        "confidence_score": 7,
        "confidence_rationale": "Port scanning generates distinctive network telemetry (high connection rate to multiple hosts/ports). Network flow analysis provides excellent detection coverage even without host telemetry.",
        "artifacts": {
            "event_ids": ["4688", "3", "5156"],
            "files": [],
            "registry": [],
            "network": ["Sequential SYN packets to multiple hosts", "ICMP sweeps", "Banner grabbing patterns"]
        }
    },

    "T1016": {
        "id": "T1016", "name": "System Network Configuration Discovery",
        "tactic": "Discovery", "tactic_id": "TA0007",
        "parent_id": None,
        "sub_techniques": [],
        "related_techniques": ["T1082", "T1046", "T1087"],
        "description": "Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information.",
        "hunt_hypothesis": "An adversary is mapping the network configuration of a compromised host — IP addresses, DNS servers, routing, proxy settings — to understand the network topology and identify further attack surfaces.",
        "event_ids": ["4688", "1"],
        "log_sources": ["WinEventLog:Security", "Sysmon"],
        "field_names": ["CommandLine", "Image", "ParentImage"],
        "processes": ["ipconfig.exe", "ifconfig", "netstat.exe", "route.exe", "arp.exe", "nslookup.exe"],
        "command_patterns": ["ipconfig /all", "ifconfig", "netstat -ano", "route print", "arp -a", "nslookup", "Get-NetIPConfiguration", "Get-DnsClientServerAddress"],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [],
        "detection_notes": "These commands individually are common admin activity. Look for execution from unusual parents (Office, web servers) or clustering with other discovery commands. ipconfig, netstat, arp, route executed in rapid succession from the same process tree is a strong indicator.",
        "confidence_score": 5,
        "confidence_rationale": "Very high false positive rate for individual commands. Requires contextual analysis (parent process, clustering with other discovery TTPs) for effective detection. Low standalone confidence.",
        "artifacts": {
            "event_ids": ["4688", "1"],
            "files": [],
            "registry": [],
            "network": []
        }
    },

    "T1057": {
        "id": "T1057", "name": "Process Discovery",
        "tactic": "Discovery", "tactic_id": "TA0007",
        "parent_id": None,
        "sub_techniques": [],
        "related_techniques": ["T1082", "T1087", "T1562.001"],
        "description": "Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network.",
        "hunt_hypothesis": "An adversary is enumerating running processes to identify security tools, determine the victim environment, find target processes for injection, or understand what software is installed.",
        "event_ids": ["4688", "1"],
        "log_sources": ["WinEventLog:Security", "Sysmon"],
        "field_names": ["CommandLine", "Image", "ParentImage"],
        "processes": ["tasklist.exe", "wmic.exe", "powershell.exe"],
        "command_patterns": ["tasklist", "wmic process list", "Get-Process", "ps", "Get-WmiObject Win32_Process", "tasklist /v", "tasklist /svc"],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [],
        "detection_notes": "Process enumeration is common in post-exploitation frameworks. Look for tasklist or Get-Process executed immediately after initial access or from suspicious parent processes. Adversaries often use process lists to detect and kill security tools before further actions.",
        "confidence_score": 5,
        "confidence_rationale": "Process discovery commands are used by administrators daily. Detection requires strong context. More valuable as part of a discovery cluster than as a standalone indicator.",
        "artifacts": {
            "event_ids": ["4688", "1"],
            "files": [],
            "registry": [],
            "network": []
        }
    },

    # ── Lateral Movement ───────────────────────────────────────────────────────

    "T1021.001": {
        "id": "T1021.001", "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement", "tactic_id": "TA0008",
        "parent_id": "T1021",
        "sub_techniques": [],
        "related_techniques": ["T1021.002", "T1078", "T1550.002"],
        "description": "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user. RDP is typically used by Windows administrators to remotely control their systems.",
        "hunt_hypothesis": "An adversary is using RDP to move laterally between systems, potentially using stolen credentials or pass-the-hash. Look for RDP connections between workstations (unusual in most environments), off-hours activity, and connections from non-standard admin hosts.",
        "event_ids": ["4624", "4625", "4648", "4779", "4778"],
        "log_sources": ["WinEventLog:Security", "Sysmon", "RDP/Terminal Services logs"],
        "field_names": ["IpAddress", "TargetUserName", "LogonType", "WorkstationName", "SubjectUserName"],
        "processes": ["mstsc.exe", "rdpclip.exe", "tstheme.exe"],
        "command_patterns": [],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [3389],
        "detection_notes": "Event 4624 with LogonType=10 (RemoteInteractive) from unexpected source IPs. Workstation-to-workstation RDP (LogonType 10) is unusual in most environments. Event 4779 (RDP session disconnected) followed by 4778 (reconnected) from different IPs suggests session hijacking.",
        "confidence_score": 7,
        "confidence_rationale": "RDP logon events (4624 LogonType=10) are specific and well-logged. Source IP analysis can identify lateral movement. Requires network topology knowledge to determine 'unexpected' connections.",
        "artifacts": {
            "event_ids": ["4624", "4625", "4648", "4778", "4779"],
            "files": [],
            "registry": ["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"],
            "network": ["TCP 3389 connections between internal hosts"]
        }
    },

    "T1021.002": {
        "id": "T1021.002", "name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement", "tactic_id": "TA0008",
        "parent_id": "T1021",
        "sub_techniques": [],
        "related_techniques": ["T1021.001", "T1078", "T1570"],
        "description": "Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user. Adversaries may use SMB to move laterally by copying files, executing commands, or interacting with admin shares.",
        "hunt_hypothesis": "An adversary is using SMB/Admin shares (C$, ADMIN$, IPC$) to copy malware to remote systems and execute it via service control or scheduled tasks, enabling lateral movement without explicit RDP.",
        "event_ids": ["4624", "4648", "5140", "5145", "4697", "7045"],
        "log_sources": ["WinEventLog:Security", "Sysmon", "WinEventLog:System"],
        "field_names": ["IpAddress", "ShareName", "TargetUserName", "ObjectType", "ServiceName"],
        "processes": ["services.exe", "svchost.exe"],
        "command_patterns": ["net use", "net view", "\\\\hostname\\C$", "\\\\hostname\\ADMIN$"],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [445, 139],
        "detection_notes": "Event 5140 (network share object accessed) with share C$ or ADMIN$ from unusual hosts. Event 4697 (service installation) on destination after SMB access indicates lateral movement via service. Impacket tooling leaves characteristic patterns in SMB traffic.",
        "confidence_score": 7,
        "confidence_rationale": "SMB admin share access events (5140/5145) provide good coverage. Requires Object Access auditing to be enabled. Network traffic analysis for Impacket patterns provides additional coverage.",
        "artifacts": {
            "event_ids": ["4624", "5140", "5145", "4697"],
            "files": [],
            "registry": [],
            "network": ["SMB connections to C$ and ADMIN$ shares", "Named pipe usage (\\\\pipe\\svcctl, \\\\pipe\\atsvc)"]
        }
    },

    "T1550.002": {
        "id": "T1550.002", "name": "Pass the Hash",
        "tactic": "Lateral Movement", "tactic_id": "TA0008",
        "parent_id": "T1550",
        "sub_techniques": [],
        "related_techniques": ["T1021.001", "T1021.002", "T1555", "T1003"],
        "description": "Adversaries may 'pass the hash' using stolen password hashes to move laterally within an environment, bypassing normal system access controls. PTH exploits an implementation flaw in the NTLM authentication protocol.",
        "hunt_hypothesis": "An adversary obtained NTLM password hashes (via credential dumping or network capture) and is using them directly to authenticate to remote systems without needing the plaintext password.",
        "event_ids": ["4624", "4625", "4776"],
        "log_sources": ["WinEventLog:Security", "Network capture (NTLM traffic)"],
        "field_names": ["LogonType", "LogonProcessName", "AuthenticationPackageName", "IpAddress", "TargetUserName"],
        "processes": ["lsass.exe"],
        "command_patterns": [],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [445, 139],
        "detection_notes": "Pass-the-Hash in Windows: Event 4624 with LogonType=3, AuthenticationPackageName=NTLM, IpAddress not null, and TargetUserName for privileged account. Event 4776 with error code 0x0 (success) for NTLM authentication on DC. Overpass-the-hash (pass-the-key) generates Kerberos events.",
        "confidence_score": 6,
        "confidence_rationale": "PTH detection requires distinguishing legitimate NTLM network logons from malicious ones. Detection improves with Kerberos enforcement. Network capture analysis for NTLM challenge/response patterns provides additional signal.",
        "artifacts": {
            "event_ids": ["4624", "4625", "4776"],
            "files": [],
            "registry": [],
            "network": ["NTLM type 3 messages on SMB connections", "Non-domain computer NTLM auth to domain systems"]
        }
    },

    # ── Collection ─────────────────────────────────────────────────────────────

    "T1005": {
        "id": "T1005", "name": "Data from Local System",
        "tactic": "Collection", "tactic_id": "TA0009",
        "parent_id": None,
        "sub_techniques": [],
        "related_techniques": ["T1039", "T1074", "T1560"],
        "description": "Adversaries may search local system sources, such as file systems and configuration files or local databases, to find files of interest and sensitive data prior to exfiltration.",
        "hunt_hypothesis": "An adversary is staging data from local system sources — searching for documents, credentials, configuration files, and other sensitive data — in preparation for exfiltration.",
        "event_ids": ["4688", "1", "11"],
        "log_sources": ["WinEventLog:Security", "Sysmon", "File Auditing"],
        "field_names": ["CommandLine", "Image", "TargetFilename", "ParentImage"],
        "processes": ["cmd.exe", "powershell.exe", "robocopy.exe", "xcopy.exe"],
        "command_patterns": ["dir /s /b", "Get-ChildItem -Recurse", "gci -recurse", "findstr /s", "where /r", "robocopy", "xcopy /s", "copy /y"],
        "registry_keys": [],
        "file_paths": ["*.docx", "*.xlsx", "*.pdf", "*.kdbx", "*.pfx", "*.pem", "id_rsa", "*.key"],
        "network_ports": [],
        "detection_notes": "Recursive directory listing or file searches targeting sensitive extensions (.docx, .pdf, .key, .pem, password*). File read access patterns on sensitive directories (Documents, Desktop, %APPDATA%\\passwords). Large-scale file access via robocopy or xcopy.",
        "confidence_score": 6,
        "confidence_rationale": "File collection generates file access events and process creation logs. Requires file auditing to be enabled for full coverage. Moderate confidence as many legitimate processes access files extensively.",
        "artifacts": {
            "event_ids": ["4688", "1", "11"],
            "files": [],
            "registry": [],
            "network": []
        }
    },

    "T1056.001": {
        "id": "T1056.001", "name": "Keylogging",
        "tactic": "Collection", "tactic_id": "TA0009",
        "parent_id": "T1056",
        "sub_techniques": [],
        "related_techniques": ["T1555", "T1113", "T1005"],
        "description": "Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new privileged accounts, which can then be used to pivot further into a network.",
        "hunt_hypothesis": "An adversary installed a keylogger to capture credentials, sensitive communications, and other input. The keylogger may operate as a kernel driver, a usermode hook, or a browser extension.",
        "event_ids": ["4688", "1", "7"],
        "log_sources": ["WinEventLog:Security", "Sysmon", "EDR telemetry"],
        "field_names": ["CommandLine", "Image", "ImageLoaded", "Signed"],
        "processes": [],
        "command_patterns": [],
        "registry_keys": ["HKLM\\SYSTEM\\CurrentControlSet\\Services\\*"],
        "file_paths": ["*.log", "keylog*", "*keystroke*"],
        "network_ports": [],
        "detection_notes": "SetWindowsHookEx API calls for keyboard hooking (detectable via EDR). DLL injection into browser processes. Unsigned kernel drivers loaded at startup. Files named keylog*.txt or similar in temp directories. High-frequency file write operations to small log files.",
        "confidence_score": 5,
        "confidence_rationale": "Keylogger detection is difficult without EDR API hooking monitoring. File-based indicators (log files) are detectable but easily obfuscated. Kernel-level keyloggers require deep telemetry.",
        "artifacts": {
            "event_ids": ["7", "4688"],
            "files": ["%TEMP%\\*.log", "%APPDATA%\\*.dat"],
            "registry": [],
            "network": []
        }
    },

    "T1560": {
        "id": "T1560", "name": "Archive Collected Data",
        "tactic": "Collection", "tactic_id": "TA0009",
        "parent_id": None,
        "sub_techniques": ["T1560.001"],
        "related_techniques": ["T1005", "T1039", "T1041"],
        "description": "An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network.",
        "hunt_hypothesis": "An adversary is compressing collected data into archives (ZIP, RAR, 7-zip) before exfiltration, potentially with password protection to prevent inspection.",
        "event_ids": ["4688", "1", "11"],
        "log_sources": ["WinEventLog:Security", "Sysmon"],
        "field_names": ["CommandLine", "Image", "TargetFilename"],
        "processes": ["7z.exe", "7za.exe", "rar.exe", "winrar.exe", "compress.exe", "zip.exe"],
        "command_patterns": ["7z a -p", "7za a", "rar a -hp", "Compress-Archive", "zip", "-p password"],
        "registry_keys": [],
        "file_paths": ["*.zip", "*.rar", "*.7z", "*.tar.gz"],
        "network_ports": [],
        "detection_notes": "7-zip or RAR creating password-protected archives containing many files. Archives created in TEMP directory or unusual locations. Compression followed closely by network transfer. Compress-Archive targeting sensitive directories.",
        "confidence_score": 7,
        "confidence_rationale": "Archive creation with command-line tools generates clear process creation events. File creation events for .zip/.7z/.rar files in unusual locations provide additional signal. Good coverage with Sysmon.",
        "artifacts": {
            "event_ids": ["4688", "1", "11"],
            "files": ["%TEMP%\\*.zip", "%TEMP%\\*.7z", "%TEMP%\\*.rar"],
            "registry": [],
            "network": []
        }
    },

    # ── Command and Control ────────────────────────────────────────────────────

    "T1071.001": {
        "id": "T1071.001", "name": "Web Protocols",
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "parent_id": "T1071",
        "sub_techniques": [],
        "related_techniques": ["T1071.004", "T1572", "T1105"],
        "description": "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.",
        "hunt_hypothesis": "An adversary established C2 communication over HTTP or HTTPS to blend with legitimate web traffic. The C2 beacon may use domain fronting, legitimate cloud services (Azure, AWS, OneDrive), or custom HTTP headers to evade detection.",
        "event_ids": ["3", "22", "4688"],
        "log_sources": ["Sysmon", "Network proxy logs", "DNS logs", "Firewall/NGFW logs"],
        "field_names": ["DestinationIp", "DestinationPort", "SourceIp", "QueryName", "Image"],
        "processes": ["powershell.exe", "cmd.exe", "mshta.exe", "regsvr32.exe"],
        "command_patterns": ["Invoke-WebRequest", "Net.WebClient", "curl", "wget", "DownloadString"],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [80, 443, 8080, 8443],
        "detection_notes": "Beaconing: regular periodic outbound HTTP(S) connections at consistent intervals (e.g., every 60s). Unusual user agents or HTTP headers. Long-running HTTP connections (content-type mismatch). Connections to newly registered domains or domains with low reputation. JA3/JA3S TLS fingerprints for known C2 frameworks.",
        "confidence_score": 6,
        "confidence_rationale": "HTTP/S C2 blends with legitimate traffic. Requires network behavioral analytics (beaconing detection, DGA detection, JA3 fingerprinting) for effective detection. Coverage depends heavily on network monitoring maturity.",
        "artifacts": {
            "event_ids": ["3", "22"],
            "files": [],
            "registry": [],
            "network": ["Regular periodic outbound HTTP(S)", "Unusual User-Agent strings", "TLS without SNI to IP addresses", "Long HTTP POST responses"]
        }
    },

    "T1071.004": {
        "id": "T1071.004", "name": "DNS",
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "parent_id": "T1071",
        "sub_techniques": [],
        "related_techniques": ["T1071.001", "T1572", "T1048.003"],
        "description": "Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.",
        "hunt_hypothesis": "An adversary is using DNS for C2 communications — encoding commands in DNS query labels and receiving responses in DNS answers. DNS tunneling tools like iodine, dnscat2, or custom implementations are commonly used.",
        "event_ids": ["22", "4688"],
        "log_sources": ["Sysmon", "DNS server logs", "Network flow data", "Firewall logs"],
        "field_names": ["QueryName", "QueryResults", "Image", "DestinationPort"],
        "processes": [],
        "command_patterns": [],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [53],
        "detection_notes": "DNS tunneling indicators: high-entropy subdomain labels (base64/hex encoded), unusually long query names (>50 chars), high frequency of queries to same domain, TXT/NULL/MX records for data transfer, DNS query volume anomalies from single host. Sysmon Event 22 for DNS queries on endpoints.",
        "confidence_score": 7,
        "confidence_rationale": "DNS tunneling generates characteristic patterns (long labels, high frequency, entropy) detectable via DNS analytics. Network-level DNS monitoring provides good coverage. Sysmon Event 22 provides endpoint-level DNS query visibility.",
        "artifacts": {
            "event_ids": ["22"],
            "files": [],
            "registry": [],
            "network": ["High-entropy DNS labels >50 chars", "High-volume DNS TXT queries", "DNS queries to uncommon TLDs", "Non-standard DNS ports"]
        }
    },

    "T1105": {
        "id": "T1105", "name": "Ingress Tool Transfer",
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "parent_id": None,
        "sub_techniques": [],
        "related_techniques": ["T1071.001", "T1059.001", "T1218"],
        "description": "Adversaries may transfer tools or other files from an external system into a compromised environment. Files may be copied from an external adversary-controlled system through the command and control channel to bring tools into the victim network or through alternate protocols.",
        "hunt_hypothesis": "An adversary downloaded additional tools, malware, or payloads from an external server to the compromised endpoint. This is often among the first actions taken after initial access to bring in a full-featured RAT or post-exploitation framework.",
        "event_ids": ["3", "11", "4688", "1"],
        "log_sources": ["Sysmon", "WinEventLog:Security", "Network proxy/firewall"],
        "field_names": ["DestinationIp", "DestinationPort", "TargetFilename", "Image", "CommandLine"],
        "processes": ["powershell.exe", "certutil.exe", "bitsadmin.exe", "mshta.exe", "curl.exe", "wget.exe"],
        "command_patterns": [
            "Invoke-WebRequest", "DownloadFile", "Net.WebClient", "certutil -urlcache",
            "bitsadmin /transfer", "curl -o", "wget -O", "Start-BitsTransfer"
        ],
        "registry_keys": [],
        "file_paths": ["%TEMP%\\*.exe", "%TEMP%\\*.dll", "%APPDATA%\\*.exe"],
        "network_ports": [80, 443],
        "detection_notes": "File creation in %TEMP% or %APPDATA% immediately after outbound HTTP(S) connection. certutil.exe downloading files (certutil -urlcache -f). bitsadmin.exe for background downloads. Sysmon Event 11 (file created) combined with Event 3 (network connection) from same process.",
        "confidence_score": 8,
        "confidence_rationale": "Correlation between network connection and file creation events provides strong detection signal. LOLBin-based downloads (certutil, bitsadmin) are well-known patterns. High coverage with Sysmon Events 3 and 11.",
        "artifacts": {
            "event_ids": ["3", "11", "4688"],
            "files": ["%TEMP%\\*.exe", "%TEMP%\\*.dll", "%TEMP%\\*.ps1"],
            "registry": [],
            "network": ["HTTP GET to external IP followed by executable file creation", "bitsadmin jobs"]
        }
    },

    "T1572": {
        "id": "T1572", "name": "Protocol Tunneling",
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "parent_id": None,
        "sub_techniques": [],
        "related_techniques": ["T1090", "T1071.004", "T1071.001"],
        "description": "Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and potentially to enable access to otherwise unreachable systems.",
        "hunt_hypothesis": "An adversary is tunneling C2 traffic through a legitimate or permitted protocol (DNS, ICMP, HTTP) to evade network filtering. SSH tunneling may also be used to access internal resources through a compromised external-facing system.",
        "event_ids": ["3", "22", "4688"],
        "log_sources": ["Sysmon", "Network flow data", "Firewall/NGFW", "DNS logs"],
        "field_names": ["DestinationPort", "DestinationIp", "Image", "CommandLine"],
        "processes": ["ssh.exe", "plink.exe", "chisel.exe", "ngrok.exe"],
        "command_patterns": ["ssh -L", "ssh -R", "ssh -D", "plink.exe", "-R 127.0.0.1", "chisel client", "ngrok tcp"],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [22, 53, 80, 443],
        "detection_notes": "SSH reverse tunnel: ssh.exe with -R flag. Ngrok/chisel running on endpoint (process names, network connections to ngrok infrastructure). ICMP packets with unusual payload size/content. Long-lived SSH sessions from unexpected hosts. DNS query volume anomalies.",
        "confidence_score": 6,
        "confidence_rationale": "Tunneling detection requires network behavioral analytics or specific process/binary monitoring. ngrok and chisel are known tools with detectable network signatures. Moderate confidence without deep network inspection.",
        "artifacts": {
            "event_ids": ["3", "4688"],
            "files": [],
            "registry": [],
            "network": ["Long-lived SSH connections from non-admin hosts", "ngrok.io DNS queries", "ICMP with large payloads"]
        }
    },

    # ── Exfiltration ───────────────────────────────────────────────────────────

    "T1041": {
        "id": "T1041", "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "parent_id": None,
        "sub_techniques": [],
        "related_techniques": ["T1048", "T1071.001", "T1560"],
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as C2 communications.",
        "hunt_hypothesis": "An adversary is exfiltrating collected data through their established C2 channel, encoding sensitive files within regular C2 beacons to avoid detection. Data volumes may spike relative to baseline C2 traffic.",
        "event_ids": ["3", "22"],
        "log_sources": ["Sysmon", "Network flow data", "Proxy logs", "Firewall"],
        "field_names": ["DestinationIp", "DestinationPort", "Image", "Bytes"],
        "processes": [],
        "command_patterns": [],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [80, 443],
        "detection_notes": "Anomalous data volumes in outbound HTTP(S) connections — especially POST requests with large payloads. Egress spikes after archive creation events. Data transfer during non-business hours. DLP alerts on sensitive file types in outbound traffic. Correlate file staging (T1560) with outbound network anomalies.",
        "confidence_score": 6,
        "confidence_rationale": "Requires network behavioral baseline to detect volume anomalies. Encrypted C2 channels obscure content. Coverage depends on DLP, proxy logging, and network flow analysis capabilities.",
        "artifacts": {
            "event_ids": ["3"],
            "files": [],
            "registry": [],
            "network": ["Large outbound HTTP POST > 1MB to external host", "Sustained data transfer over established C2 IP"]
        }
    },

    "T1048": {
        "id": "T1048", "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "parent_id": None,
        "sub_techniques": ["T1048.001", "T1048.002", "T1048.003"],
        "related_techniques": ["T1041", "T1567", "T1071.004"],
        "description": "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.",
        "hunt_hypothesis": "An adversary is exfiltrating data over a non-standard protocol (FTP, SCP, SMTP, DNS) to bypass controls focused on HTTP/S egress traffic. The alternative channel may circumvent DLP policies.",
        "event_ids": ["3", "5156", "4688"],
        "log_sources": ["Sysmon", "Firewall/NGFW", "Network flow data"],
        "field_names": ["DestinationIp", "DestinationPort", "Image", "CommandLine"],
        "processes": ["ftp.exe", "scp.exe", "sftp.exe", "smtp", "nslookup.exe"],
        "command_patterns": ["ftp -s:", "ftp.exe", "scp ", "sftp ", "Send-MailMessage", "smtp"],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [21, 22, 25, 53, 143, 993],
        "detection_notes": "Outbound connections on unusual ports from user workstations (FTP:21, SMTP:25, SSH:22 to non-corporate destinations). FTP or SCP binaries executed from unusual locations. DNS-based exfiltration: high-entropy subdomain queries with data-encoded content. Email with attachments sent via SMTP from endpoint.",
        "confidence_score": 7,
        "confidence_rationale": "Alternative protocol usage from endpoints is relatively unusual in well-controlled environments. Firewall egress logs provide good coverage for unexpected protocol usage.",
        "artifacts": {
            "event_ids": ["3", "4688"],
            "files": [],
            "registry": [],
            "network": ["Outbound FTP/SCP/SFTP connections", "SMTP egress from workstation", "High-entropy DNS TXT records"]
        }
    },

    "T1567": {
        "id": "T1567", "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "parent_id": None,
        "sub_techniques": ["T1567.001", "T1567.002"],
        "related_techniques": ["T1041", "T1048", "T1071.001"],
        "description": "Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. Popular Web services acting as an exfiltration mechanism may give a significant amount of cover.",
        "hunt_hypothesis": "An adversary is exfiltrating sensitive data to a legitimate web service (GitHub, Pastebin, OneDrive, Google Drive, Slack, Discord) to blend with normal web traffic and bypass DLP controls focused on unknown destinations.",
        "event_ids": ["3", "22", "4688"],
        "log_sources": ["Sysmon", "Proxy logs", "Network flow data", "DLP"],
        "field_names": ["DestinationHostname", "Image", "CommandLine", "QueryName"],
        "processes": ["powershell.exe", "curl.exe", "python.exe"],
        "command_patterns": ["github.com", "pastebin.com", "api.paste.ee", "discord.com/api", "slack.com/api", "api.telegram.org"],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [443],
        "detection_ports": [],
        "detection_notes": "Process not typically associated with cloud services (powershell.exe, cmd.exe) making connections to GitHub API, Pastebin, Discord, or Telegram. Large upload volume to cloud storage services. API calls with file upload patterns. DNS queries to cloud services from non-browser processes.",
        "confidence_score": 5,
        "confidence_rationale": "Cloud service exfiltration is difficult to detect without application-layer inspection since destinations are legitimate. Requires proxy logging with user-agent analysis and volume anomaly detection.",
        "artifacts": {
            "event_ids": ["3", "22"],
            "files": [],
            "registry": [],
            "network": ["Non-browser processes connecting to GitHub/Pastebin/Discord API", "Large POST to cloud storage APIs"]
        }
    },

    "T1020": {
        "id": "T1020", "name": "Automated Exfiltration",
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "parent_id": None,
        "sub_techniques": [],
        "related_techniques": ["T1041", "T1048", "T1560"],
        "description": "Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection. Automated exfiltration may occur when one or more exfiltration techniques are triggered automatically.",
        "hunt_hypothesis": "An adversary deployed a script or implant that automatically collects and exfiltrates data at scheduled intervals or in response to specific triggers, operating without manual interaction to reduce risk of detection.",
        "event_ids": ["4698", "4702", "3", "4688"],
        "log_sources": ["Sysmon", "WinEventLog:Security", "Network flow data"],
        "field_names": ["TaskName", "CommandLine", "DestinationIp", "Image"],
        "processes": ["powershell.exe", "python.exe", "cmd.exe"],
        "command_patterns": [],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [80, 443],
        "detection_notes": "Scheduled tasks (Event 4698) combined with network transfer patterns. Recurring outbound data transfers at regular intervals from non-user processes. Script files in startup locations with network connectivity. Correlation between archive creation and outbound transfer events.",
        "confidence_score": 6,
        "confidence_rationale": "Automated exfiltration requires correlation of multiple events (scheduled task + network). Individual events may be benign. Effective detection requires timeline analysis and volume baselining.",
        "artifacts": {
            "event_ids": ["4698", "3", "4688"],
            "files": [],
            "registry": [],
            "network": ["Periodic outbound data transfers at consistent intervals"]
        }
    },

    # ── Additional techniques ──────────────────────────────────────────────────

    "T1003.001": {
        "id": "T1003.001", "name": "LSASS Memory",
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "parent_id": "T1003",
        "sub_techniques": [],
        "related_techniques": ["T1550.002", "T1078", "T1055"],
        "description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM.",
        "hunt_hypothesis": "An adversary is attempting to dump credentials from LSASS memory using tools like Mimikatz, ProcDump, Task Manager, or Comsvcs.dll to obtain NTLM hashes, Kerberos tickets, or cleartext credentials for lateral movement.",
        "event_ids": ["10", "4688", "4656", "4663"],
        "log_sources": ["Sysmon", "WinEventLog:Security", "EDR telemetry"],
        "field_names": ["SourceImage", "TargetImage", "GrantedAccess", "CallTrace", "CommandLine"],
        "processes": ["procdump.exe", "procdump64.exe", "mimikatz.exe", "taskmgr.exe"],
        "command_patterns": [
            "procdump -ma lsass", "comsvcs.dll MiniDump", "sekurlsa::logonpasswords",
            "lsass.dmp", "Out-Minidump", "CreateMiniDump"
        ],
        "registry_keys": ["HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential"],
        "file_paths": ["lsass.dmp", "*.dmp"],
        "network_ports": [],
        "detection_notes": "Sysmon Event 10 with TargetImage=lsass.exe and GrantedAccess=0x1010 or 0x1F0FFF is the primary indicator. procdump.exe or taskmgr.exe accessing LSASS with dump rights. comsvcs.dll MiniDump function in PowerShell. Event 4656 (object handle requested) on lsass.exe process object.",
        "confidence_score": 9,
        "confidence_rationale": "LSASS access with memory dump rights is a very high-fidelity indicator with minimal legitimate use cases. Sysmon Event 10 with the right GrantedAccess masks provides near-perfect detection.",
        "artifacts": {
            "event_ids": ["10", "4656", "4663", "4688"],
            "files": ["lsass.dmp", "%TEMP%\\*.dmp"],
            "registry": ["HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"],
            "network": []
        }
    },

    "T1110.003": {
        "id": "T1110.003", "name": "Password Spraying",
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "parent_id": "T1110",
        "sub_techniques": [],
        "related_techniques": ["T1078", "T1110.001", "T1133"],
        "description": "Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. 'Password01'), or a small list of passwords, that may match the complexity policy of the domain.",
        "hunt_hypothesis": "An adversary is conducting password spraying against Active Directory or cloud identity providers, using common passwords against many accounts to avoid lockout thresholds while attempting to obtain valid credentials.",
        "event_ids": ["4625", "4648", "4771", "4776"],
        "log_sources": ["WinEventLog:Security", "Active Directory logs", "Azure AD Sign-in logs"],
        "field_names": ["TargetUserName", "IpAddress", "FailureReason", "Status", "SubStatus"],
        "processes": [],
        "command_patterns": [],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [389, 636, 88, 443],
        "detection_notes": "Multiple 4625 (failed logon) events from same source IP against different usernames within a short timeframe. Unlike brute force (many attempts against one account), password spray shows one attempt per account. Event 4771 (Kerberos pre-auth failed) for AD environments. Azure AD: many users failing with same IP/UA.",
        "confidence_score": 8,
        "confidence_rationale": "Password spraying creates a distinctive pattern of distributed failed logon events. Detection by correlation (count unique users per source IP within time window) is highly effective. Good coverage with Windows Security auditing.",
        "artifacts": {
            "event_ids": ["4625", "4771", "4776"],
            "files": [],
            "registry": [],
            "network": ["Multiple 4625 events for different accounts from same source IP"]
        }
    },

    "T1135": {
        "id": "T1135", "name": "Network Share Discovery",
        "tactic": "Discovery", "tactic_id": "TA0007",
        "parent_id": None,
        "sub_techniques": [],
        "related_techniques": ["T1039", "T1021.002", "T1046"],
        "description": "Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement.",
        "hunt_hypothesis": "An adversary is enumerating network shares across the environment to identify data repositories, backup shares, or accessible systems for lateral movement and data collection.",
        "event_ids": ["4688", "1", "5140"],
        "log_sources": ["WinEventLog:Security", "Sysmon"],
        "field_names": ["CommandLine", "Image", "ShareName", "IpAddress"],
        "processes": ["net.exe", "net1.exe", "powershell.exe"],
        "command_patterns": ["net share", "net view", "net view /all", "Get-SmbShare", "Invoke-ShareFinder", "Find-DomainShare"],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [445, 139],
        "detection_notes": "net.exe 'view' or 'share' commands. PowerShell Invoke-ShareFinder (common in PowerSploit). Large number of Event 5140 (network share accessed) from a single source against multiple targets indicates automated share discovery. SMB connections to IPC$ on multiple hosts.",
        "confidence_score": 7,
        "confidence_rationale": "Share discovery generates both process creation events and network share access events. Automated share enumeration across many hosts creates detectable patterns. Good coverage with SMB auditing.",
        "artifacts": {
            "event_ids": ["4688", "5140"],
            "files": [],
            "registry": [],
            "network": ["SMB IPC$ connections to multiple hosts", "NetShareEnum RPC calls"]
        }
    },

    "T1069.002": {
        "id": "T1069.002", "name": "Domain Groups",
        "tactic": "Discovery", "tactic_id": "TA0007",
        "parent_id": "T1069",
        "sub_techniques": [],
        "related_techniques": ["T1087.002", "T1069.001"],
        "description": "Adversaries may attempt to find domain-level groups and permission settings. The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group, aiding in follow-on lateral movement and privilege escalation activities.",
        "hunt_hypothesis": "An adversary is enumerating domain groups (Domain Admins, Enterprise Admins, IT, etc.) to identify high-value accounts and understand the privilege structure for targeting escalation paths.",
        "event_ids": ["4688", "1", "4799"],
        "log_sources": ["WinEventLog:Security", "Sysmon"],
        "field_names": ["CommandLine", "Image", "TargetUserName", "GroupName"],
        "processes": ["net.exe", "net1.exe", "powershell.exe", "ldifde.exe", "csvde.exe"],
        "command_patterns": ["net group", "net group /domain", "Get-ADGroup", "Get-ADGroupMember", "Get-DomainGroup", "ldapsearch"],
        "registry_keys": [],
        "file_paths": [],
        "network_ports": [389, 636],
        "detection_notes": "net.exe 'group /domain' commands, especially against high-value groups like 'Domain Admins'. LDAP queries for group membership from non-standard tooling. Event 4799 (security-enabled local group membership was enumerated). Bulk LDAP queries characteristic of BloodHound/SharpHound.",
        "confidence_score": 7,
        "confidence_rationale": "Domain group enumeration via net.exe generates clear process creation events. BloodHound-style bulk LDAP queries create detectable network patterns on the DC. Good detection coverage.",
        "artifacts": {
            "event_ids": ["4688", "4799"],
            "files": [],
            "registry": [],
            "network": ["LDAP queries to DC for group membership", "BloodHound collection patterns"]
        }
    },

}  # end TECHNIQUES


# ─── Helper functions ──────────────────────────────────────────────────────────

def get_technique(technique_id: str) -> dict | None:
    """Return technique data by ID (case-insensitive)."""
    return TECHNIQUES.get(technique_id.upper())


def search_techniques(query: str) -> list[dict]:
    """Search techniques by ID, name, tactic, or description keyword."""
    query_lower = query.lower()
    results = []
    for tid, tech in TECHNIQUES.items():
        if (query_lower in tid.lower()
                or query_lower in tech["name"].lower()
                or query_lower in tech["tactic"].lower()
                or query_lower in tech["description"].lower()):
            results.append({
                "id":          tid,
                "name":        tech["name"],
                "tactic":      tech["tactic"],
                "tactic_id":   tech["tactic_id"],
                "description": tech["description"][:200],
                "confidence_score": tech["confidence_score"],
            })
    return sorted(results, key=lambda x: x["id"])


def list_techniques(tactic_filter: str = "") -> list[dict]:
    """List all techniques, optionally filtered by tactic name or ID."""
    results = []
    for tid, tech in TECHNIQUES.items():
        if tactic_filter and tactic_filter.lower() not in (
            tech["tactic"].lower(), tech["tactic_id"].lower()
        ):
            continue
        results.append({
            "id":             tid,
            "name":           tech["name"],
            "tactic":         tech["tactic"],
            "tactic_id":      tech["tactic_id"],
            "parent_id":      tech.get("parent_id"),
            "sub_techniques": tech.get("sub_techniques", []),
            "confidence_score": tech["confidence_score"],
            "description":    tech["description"][:150] + "...",
        })
    return sorted(results, key=lambda x: (x["tactic_id"], x["id"]))
