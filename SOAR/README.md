# SOAR‑Lite (`soar.py`)

A **Security Orchestration, Automation & Response (SOAR) micro‑engine** purpose‑built for a Mini‑SOC homelab.
It watches Splunk alert logs, matches each line against YAML‑defined rules, and executes **asynchronous playbooks** that can:

* **Block attackers instantly** with remote `iptables`
* **Enrich events** via AbuseIPDB & VirusTotal
* **Send enriched incidents back to Splunk (HEC)**
* **Alert you on Telegram in real time**

---

## How the pipeline works 🚦

```
[SPLUNK alert log] → tail() → process_line() → asyncio.Queue
                ↓                             ↑
        Regex rule hit            worker() pulls (event, playbook)
                                        ↓
                         Playbook (iptables / malware / alert)
                                        ↓
     Telegram  ←  AbuseIPDB / VirusTotal  →  Splunk HEC enrichment
```

| Stage           | Purpose                                                    | Key code                     |
| --------------- | ---------------------------------------------------------- | ---------------------------- |
| **File tail**   | Follow one or more Splunk‑generated log files in real time | `tail()`                     |
| **Rule engine** | Apply `rules.yml` regexes, build an `event` dict           | `process_line()`             |
| **Async queue** | Decouple I/O‑heavy playbooks from log ingestion            | `asyncio.Queue` + `worker()` |
| **Playbooks**   | `pb_iptables`, `pb_malware_analysis`, `pb_alert_only`      | see *Playbooks* section      |
| **Cooldown**    | Suppress duplicate alerts (default 1 h)                    | `_allow_event()`             |
| **Splunk HEC**  | Push enriched events back for dashboards                   | `send_to_splunk_hec()`       |

---

## Configuration essentials

* **`config.yml`** – global settings (log paths, thresholds, cooldowns).
* **`rules.yml`** – detection rules: regex pattern + playbook name.
* **`targets.yml`** – hostname → SSH credentials for remote firewall actions.
* **`.env`** – API keys & tokens *not* committed to git.

### Required environment variables

| Var                | Purpose                                       |
| ------------------ | --------------------------------------------- |
| `TELEGRAM_TOKEN`   | Bot API token                                 |
| `TELEGRAM_CHAT_ID` | Chat / group ID for alerts                    |
| `ABUSEIPDB_KEY`    | IP reputation look‑ups                        |
| `VT_API_KEY`       | Malware analysis                              |
| `SPLUNK_HEC_URL`   | e.g. `https://splunk:8088/services/collector` |
| `SPLUNK_HEC_TOKEN` | HEC auth token                                |

---

## Quick‑start ▶️

```bash
# 1. deps
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt  # aiohttp, pyyaml, python-dotenv, requests …

# 2. edit config.yml, rules.yml, targets.yml and create .env

# 3. run in verbose mode
python soar.py -d
```

*Ctrl‑C* shuts down all tasks gracefully.

---

## Playbooks 🛠️

### `iptables_block`

1. SSH to the target host from `targets.yml`.
2. Insert `DROP` rule: `sudo iptables -I INPUT -s <IP> -j DROP`.
3. Query AbuseIPDB → attach score.
4. Telegram alert + Splunk HEC enrichment.

### `malware_fetch_analyze`

1. Download suspicious URL captured by the honeypot.
2. soar engine tries to download the file in a temp format
3. If the file was downloaded, it upload file to VirusTotal, poll until the report is ready.
4. Telegram enriched alert attached with VT results to the event.

### `alert_only`

Low‑risk path (e.g. honeypot login): AbuseIPDB lookup + Telegram alert—no active blocking.

---

## Splunk HEC enrichment 📈

`send_to_splunk_hec()` wraps every playbook result as

```json
{ "event": { … }, "sourcetype": "soar" }
```

and `POST`s it with the HEC token. Build dashboards that correlate detections with SOAR actions in one place.

---

## Security & op‑sec notes 🛡️

* **SSH keys**: dedicate a user with limited sudo for `iptables`.
* **VirusTotal quota**: free API is rate‑limited—batch uploads will stall, 4 requests every minute for the free version..
* **Cooldown**: tune via `COOLDOWN_SEC`.
