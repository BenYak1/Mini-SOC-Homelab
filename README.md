# Mini‑SOC Homelab — Splunk SIEM + Python Mini‑SOAR

A compact, five‑VM security operations lab that **detects**, **responds**, and **enriches** common attacks in under a minute.

* **Stack** : Splunk (Docker), custom async Python SOAR engine, Cowrie honeypot, rsyslog log shipping, AbuseIPDB, VirusTotal, Telegram Bot
* **Scenarios covered** : web recon with **Gobuster**, SSH **honeypot** login, **honeypot malware fetch & analysis** (curl/wget issued *inside* Cowrie — analysis‑only, no mitigation)
* **Automated actions** : iptables blocking (web recon), reputation look‑ups, malware detonation, Telegram alerts, round‑trip enrichment back to Splunk via HEC

---


**Watch a demonstration of the homelab in action:**

https://github.com/user-attachments/assets/6735c42f-4cbe-400f-a0fa-111d833dafb9




## Lab Topology

| VM             | IP               | Role                             | RAM  | Notes                               |
| -------------- | ---------------- | -------------------------------- | ---- | ----------------------------------- |
| **targetvm**   | `192.168.56.110` | Apache 2 server (attack surface) | 2 GB | Access log → rsyslog sender         |
| **honeypot**   | `192.168.56.109` | Cowrie SSH honeypot              | 2 GB | Cowrie log → rsyslog sender         |
| **attackervm** | `192.168.56.101` | Kali (attack generator)          | 2 GB | Launches Gobuster / SSH / wget      |
| **splunk‑vm**  | `192.168.56.105` | Splunk in Docker (SIEM)          | 4 GB | Receives UDP 514, runs alerts       |
| **mini‑soar**  | `192.168.56.108` | Python SOAR engine               | 2 GB | Tails forwarded log, runs playbooks |

---

## Repository Layout

```text
mini-soc-homelab/
├─ soar.py
├─ requirements.txt
├─ config.yml
├─ rules.yml
├─ targets.yml
├─ rsyslog/
│  ├─ targetvm/forward_to_splunk.conf
│  ├─ honeypot/forward_to_splunk.conf
│  ├─ splunk-vm/{udp-listener,honeypot,targetvm,splunk_forwarded}.conf
│  └─ mini-soar/{udp_listener,splunk_forwarded}.conf
├─ docker/splunk-compose.yml
├─ webhook
├─ ├─ webhook.py
├─ ├─ README.me
├─ docs/img/           # screenshots & GIF
└─ README.md
```

---

# End-to-End Data-Flow Diagram

![`Diagram`](img/diagram.jpg)

## 1 – Log & Alert Pipeline

1. **rsyslog** (on targetvm & honeypot) tails local logs → **UDP 514** to splunk‑vm.
2. splunk‑vm writes each source to its own file (`/var/log/targetvm.log`, `/var/log/honeypot.log`).
3. Those logs are mounted into the Splunk container, and indexed into `soar`.
4. Saved Search fires every minute, posts JSON to `http://172.17.0.1:8080` (basic Flask webhook).
5. Webhook appends message to `/var/log/splunk_forwarded.log` → rsyslog forwards to mini‑soar.
6. **mini‑soar** tails that file, matches YAML regex, triggers playbook based on match.
7. Playbook acts (iptables / VT / AbuseIPDB), sends Telegram, **posts enriched event** to Splunk **HEC** → index `soar_actions`.

---

## 2 – Detection Rules (Splunk Alerts)

### 2.1 Gobuster Scan

```spl
index=soar sourcetype=targetvm_apache2 "gobuster"
| rex field=_raw "^(?<src_host>\S+)\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval msg = src_host . " " . src_ip . " - - [" . strftime(_time,"%d/%b/%Y:%H:%M:%S %z") . "] scanned the server with gobuster"
| table msg
```

*Schedule*: 1 min cron, look‑back 60 min, **HTTP POST** alert action.

### 2.2 Honeypot Login

```spl
index=soar sourcetype="cowrie_log" host=honeypot "login attempt" "succeeded"
| rex field=_raw "HoneyPotSSHTransport,\d+,(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval _time = _indextime
| eval msg = host . " " . src_ip . " - - [" . strftime(_time,"%d/%b/%Y:%H:%M:%S %z") . "] connected to the honeypot"
| table msg
```

*Schedule*: 1 min, look‑back 2 min.

### 2.3 Malware Fetch & Analyze (Cowrie)

```spl
index=soar sourcetype="cowrie_log" host=honeypot ("CMD: curl" OR "CMD: wget")
| rex field=_raw "HoneyPotSSHTransport,\d+,(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| rex field=_raw "(CMD: (curl|wget) (?<url>https?:\/\/\S+))"
| eval _time = _indextime
| eval msg = host . " " . src_ip . " - - [" . strftime(_time,"%d/%b/%Y:%H:%M:%S %z") . "] downloaded a suspicious file to the honeypot from " . url
| table msg
```

*Schedule*: 1 min, look‑back 5 min.

![soarindex](https://github.com/user-attachments/assets/d2ce3a20-1aa2-4e8d-9cc2-bbbd28614d29)

---

## 3 – SOAR Configuration

### configs/config.yml

```yaml
# config.yml
tail_paths:
  - "/var/log/splunk_forwarded.log"
```

### configs/rules.yml

```yaml
# rules.yml
- id: gobuster_Scan
  match: '^\s*(?P<tgt>[a-zA-Z0-9_-]+)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+\[\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+\+\d{4}\]\s+scanned the server with gobuster'
  severity: high
  playbook: iptables_block

- id: honeypot_login
  match: '^\s*\w+\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - - \[.*\] connected to the honeypot'
  severity: medium
  playbook: alert

- id: honeypot_malware_fetch&analyze
  match: '^\s*(?P<tgt>[a-zA-Z0-9_-]+)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+\[[^\]]+\]\s+downloaded a suspicious file to the honeypot from (?P<url>https?:\/\/[^\s]+)'
  severity: medium
  playbook: malware_fetch&analyze
```

### configs/targets.yml

```yaml
targets:
  targetvm:
    host: 192.168.56.110
    user: soarbot
    key_path: /home/user/.ssh/soar_pubkey

  honeypot:
    host: 192.168.56.109
    user: vboxuser
    key_path: /home/user/.ssh/soar
```

---

## 4 – Playbooks

| **Playbook**                | **Trigger**                                   | **Key Actions**                                                                                                                                                                                                                 | **Telegram Alert**                                                                                    |
| --------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| **`iptables_block`**        | Web scan detected (e.g., Gobuster/Nikto)      | - SSH into target with passwordless key<br>- Run: `iptables -I INPUT -s <IP> -j DROP`<br>- Query [AbuseIPDB](https://www.abuseipdb.com/) for threat enrichment<br>- Send enriched event to Splunk via HEC                       | ![iptables\_block](https://github.com/user-attachments/assets/57ddc617-3853-4641-a175-7d9b9bbda98b)   |
| **`alert_enrichment`**      | Successful login to Cowrie SSH honeypot       | - Parse source IP from login event<br>- Query AbuseIPDB for threat score<br>- Send alert to Telegram with origin IP and score context                                                                                           | ![alert\_enrichment](https://github.com/user-attachments/assets/4b0d2eec-f70c-48db-a822-172ae838928e) |
| **`malware_fetch&analyze`** | File download attempt via curl/wget in Cowrie | - Extract URL from log line<br>- Download file directly from SOAR VM<br>- Submit to [VirusTotal](https://virustotal.com/) for analysis<br>- Send detection score, link, and verdict to Telegram<br>- Send full report to Splunk | ![malware\_fetch](https://github.com/user-attachments/assets/1e758342-5422-4314-bbdc-5740b1b526e5)    |



## VIRUSTOTAL report output:

![Screenshot_20250615_230717](https://github.com/user-attachments/assets/f0b7408a-bfa9-42b7-81f2-662f386f7a1f)


## Enriched event goes back to splunk, to index soar_actions:

![Screenshot_20250615_230241](https://github.com/user-attachments/assets/187f7a31-1e5e-4d2a-9196-c5f56717aab4)

---

## 5 – rsyslog Highlights

```conf
# rsyslog/targetvm/forward_to_splunk.conf
$ModLoad imfile
$InputFileName /var/log/apache2/access.log
$InputFileTag targetvm:
$InputFileStateFile stat-targetvm
$InputFileSeverity info
$InputFileFacility local6
$InputRunFileMonitor
local6.* @192.168.56.105:514
```

```conf
# rsyslog/splunk-vm/udp-listener.conf
module(load="imudp")
input(type="imudp" port="514")
```

*(See repo for all configs.)*

---

Author: Ben Yakoubov
