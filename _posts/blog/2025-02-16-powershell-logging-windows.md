---
layout: post
title: "PowerShell Logging for Detection and Forensics"
subtitle: "Windows Configuration, Events, and Validation"
category: blog
tags: powershell windows logging security soc
titles_from_headings: false
---

* this unordered seed list will be replaced by the toc
{:toc}

## Objective

Enable PowerShell logging to improve early detection of adversarial behaviors such as:

* execution of PowerSploit/Mimikatz, credential dumping, pass-the-hash
* privilege escalation and lateral movement
* payload download or execution (second-stage), abnormal user or group creation

> Note: Logging increases storage and ingest costs, so calibrate the level of visibility to operational needs.

---

## 1) Recommended PowerShell Logging Modes

### A. Transcription (session capture)

**Purpose:** records full input and output for each PowerShell session to a file, which is well suited for forensic review.

* Strength: highly readable, provides session history
* Limitation: can be storage intensive

**GPO path:**

`Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`

* **Turn on PowerShell Transcription** = Enabled  
  * *Output directory*: e.g. `\\SERVER\PSLogs\Transcripts` or `C:\PSLogs\Transcripts`
  * (optional) “Include invocation headers” = Enabled

**Log location:**

* Transcript files in the configured share or local folder

**Example:** If the output directory is `C:\PSLogs\Transcripts`, a transcript file typically appears as:
`C:\PSLogs\Transcripts\PowerShell_transcript.<hostname>.<timestamp>.txt`

---

### B. Script Block Logging (strongly recommended)

**Purpose:** records executed script blocks, including content after PowerShell deobfuscation at runtime.

* Strength: highly valuable for detection and incident response
* Limitation: increases event volume

**GPO path:**

`Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`

* **Turn on PowerShell Script Block Logging** = Enabled
* (optional) “Log script block invocation start / stop events” = Enabled

**Event log:**

* `Applications and Services Logs > Microsoft > Windows > PowerShell > Operational`

**Common event IDs:**

* `4104` ScriptBlockLogging (most important)
* `4103` ModuleLogging
* `400`, `403`, `600`, `800` (engine start/stop, pipeline events)

**Example:** If an obfuscated command executes `IEX (New-Object Net.WebClient).DownloadString(...)`, event `4104` typically shows the deobfuscated script content in the message field.

---

### C. Module Logging

**Purpose:** records activity for invoked cmdlets and modules.

* Strength: reveals which modules and cmdlets were used
* Limitation: volume grows with module coverage

**GPO path:**

`Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`

* **Turn on Module Logging** = Enabled
* **Module Names**: use `*` for all modules, or specify critical modules only

**Event log:**

* `Microsoft-Windows-PowerShell/Operational`
* commonly `4103`

**Example:** If you set **Module Names** to `Microsoft.PowerShell.Management`, `4103` events will include cmdlets such as `Get-Process` or `Get-Service`.

---

## 2) Deployment Guidance (SOC Baseline)

* Minimum baseline: **Script Block Logging (4104)** and forward PowerShell Operational logs to SIEM
* If storage allows: add **Transcription** for session-level context
* Legacy endpoints: require **Windows Management Framework 5.1** for enhanced logging

---

## 3) SIEM Detection Ideas (from 4104 / transcripts)

Create alerts for common patterns:

* Download/execute: `IEX`, `Invoke-Expression`, `DownloadString`, `WebClient`, `Invoke-WebRequest`, `Start-BitsTransfer`
* Bypass and evasion: `-EncodedCommand`, `FromBase64String`, `Bypass`, `Unrestricted`
* Recon and lateral movement: `Invoke-Command`, `New-PSSession`, `Enter-PSSession`, `wmic`, `sc.exe`
* Credential theft: `Mimikatz`, `sekurlsa`, `lsadump`, `Invoke-Mimikatz`
* Persistence: user or group creation, scheduled tasks, registry run keys

**Example:** An alert rule may trigger when a `4104` message contains both `IEX` and `DownloadString` in the same script block.

---

## 4) Quick Validation After Enabling

1. Run a test command: `powershell -c "Get-Process | select -first 1"`
2. Open Event Viewer:
   `Microsoft > Windows > PowerShell > Operational`
3. Confirm `4104` events record the executed command content

**Example:** Use PowerShell to query the latest events:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 5 |
  Where-Object { $_.Id -eq 4104 } |
  Select-Object TimeCreated, Id, Message
```
