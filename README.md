# SOC Detection Project: Windows Attack Technique Analysis

## Overview
This project analyzes real Windows Event Log samples (Sysmon-based) representing three MITRE ATT&CK techniques, and demonstrates custom detection logic written in Python to identify each one.

Data source: [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) — a public repository of real attack log samples.

## Techniques Covered

### 1. Credential Access — LSASS Memory Dump (T1003.001)
- **What happened**: mimikatz.exe opened a handle into lsass.exe with access rights 0x1010.
- **Why it matters**: LSASS holds cached credentials. Dumping its memory is one of the most common ways attackers steal passwords/hashes post-compromise.
- **Detection logic**: Flag any Sysmon Event ID 10 (ProcessAccess) where the target process is lsass.exe.

### 2. Persistence — Hidden Registry Run Key (T1547.001)
- **What happened**: A process wrote a new value into HKLM\...\CurrentVersion\Run, pointing to a payload disguised as taskhost.exe.
- **Why it matters**: Programs in the Run key auto-launch every time a user logs in — a common way attackers maintain access after a reboot.
- **Detection logic**: Flag any Sysmon Event ID 13 (RegistryEvent) where the target path contains \Run\.

### 3. Privilege Escalation — UAC Bypass via DelegateExecute (T1548.002)
- **What happened**: explorer.exe modified a registry key tied to Windows Settings (ms-settings\shell\open\command\DelegateExecute), then set the default command to launch cmd.exe. This is the known UACME technique #33.
- **Why it matters**: This tricks Windows into launching a command prompt with elevated privileges without a UAC prompt — bypassing the user consent step entirely.
- **Detection logic**: Flag any Sysmon Event ID 13 where the target path contains DelegateExecute.

## Tools Used
- Python 3.9
- python-evtx library (for parsing .evtx files)
- React (Vite) dashboard for visualizing results
- Public dataset: EVTX-ATTACK-SAMPLES

## Limitations (Honest Scope)
This is pattern-matching against known field values, not real-time correlation or behavioral analysis. In production, this logic would need to run against a live log stream (e.g., in Splunk or an ELK stack), with tuning to reduce false positives. This project demonstrates detection engineering fundamentals, not a production-ready SIEM deployment.

## How to Run
### Python detection scripts
1. `pip3 install python-evtx`
2. `python3 detect_evtx.py`

### React dashboard
1. `npm install`
2. `npm run dev`

## Sample Data
Sample .evtx files are not included in this repo. Download them from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) — specific files used: Sysmon_UACME_33.evtx, evasion_persis_hidden_run_keyvalue_sysmon_13.evtx, sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx
