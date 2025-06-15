#!/usr/bin/env python3
"""
SOAR-Lite tails Splunk log, matches rules and runs playbooks.
A minimal SOAR tool that tails a Splunk alerts log file, matches them against rules,
checks IP reputation, and if the score is above the configured threshold it blocks the ip with iptales,
enriches the splunk alert and sends it back to splunk and sends Telegram alerts. 

Author: Ben Yakoubov
"""

import os, sys, re, asyncio, logging, subprocess, argparse, signal  # stdlib imports
from pathlib import Path                                            # path utils
import json, requests                                               # for timestamps in Splunk events
from datetime import datetime                                       # for serializing event data to JSON
import yaml, aiohttp                                                # third-party libs          <-- aiosqlite gone
from dotenv import load_dotenv, find_dotenv                         # .env loader
import time                                                         # action cooldown
from collections import defaultdict                                 # action cooldown
import tempfile                                                     # pb_malware

COOLDOWN_SEC = 3600          # 1-hour window
_last_action: dict[str, float] = defaultdict(float)

# env var keys we must have
REQ_ENV = ("TELEGRAM_TOKEN", "TELEGRAM_CHAT_ID", "ABUSEIPDB_KEY", "VT_API_KEY", "SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN")

#  startup helpers

def check_env() -> dict:                                       # verify env vars
    load_dotenv(find_dotenv(usecwd=True) or ".env")            # load .env if present
    missing = [v for v in REQ_ENV if not os.getenv(v)]         # collect missing keys
    if missing:                                                # bail if anything absent
        sys.stderr.write(f"[startup] Missing env vars: {', '.join(missing)}\n")
        sys.exit(1)
    return {v: os.getenv(v) for v in REQ_ENV}                  # return dict of values


def cli(argv=None):                                            # parse CLI flags
    p = argparse.ArgumentParser(prog="triage-lite")
    p.add_argument("-c", "--config", default="config.yml")     # config path
    p.add_argument("-r", "--rules",  default="rules.yml")      # rules path
    p.add_argument("-t", "--targets", default="targets.yml")   # targets path
    p.add_argument("-d", "--debug",  action="store_true")      # verbose logging
    p.add_argument("--oneshot", action="store_true")           # stop at the end of the log file
    return p.parse_args(argv)

#  logging

class ColorFormatter(logging.Formatter):                           # colourise levels
    LEVEL = {
        'DEBUG':   '\x1b[36m',
        'INFO':    '\x1b[32m',
        'WARNING': '\x1b[33m',
        'ERROR':   '\x1b[31m',
        'CRITICAL':'\x1b[35m',
    }
    RESET = '\x1b[0m'
    def format(self, record):                                      # inject colour+brackets
        colour = self.LEVEL.get(record.levelname, '')
        record.levelname = f"{colour}[{record.levelname}]{self.RESET}"
        return super().format(record)


def setup_log(debug=False):                                       # root logger config
    level = logging.DEBUG if debug else logging.INFO
    handler = logging.StreamHandler()                             # stdout handler
    handler.setFormatter(ColorFormatter('%(levelname)s %(asctime)s %(name)s: %(message)s',
                                        '%Y-%m-%d %H:%M:%S'))
    logging.root.handlers = [handler]                             # replace default handler
    logging.root.setLevel(level)                                  # set level
    logging.getLogger('asyncio').setLevel(logging.WARNING)        # quiet asyncio

#  yaml load

def load_yaml(cfg_path: str, rules_path: str, trgs_path: str):    # read YAMLs
    def read(p):                                                  # helper to parse single file
        if not Path(p).exists():                                  # missing file → exit
            sys.exit(f"[startup] File not found: {p}")
        with open(p, encoding='utf-8') as f:
            return yaml.safe_load(f) or {}                        # empty file → {}
    cfg, rules, trgs = read(cfg_path), read(rules_path), read(trgs_path)
    if not isinstance(rules, list):                               # rules must be a list
        sys.exit("[startup] rules.yml must be a YAML list")
    return cfg, rules, trgs                                       # return tuple

#  file tail  (all DB hooks removed)

async def tail(path: str, rules, q: asyncio.Queue, oneshot=False):
    log = logging.getLogger(f"tail:{path}")
    try:
        with open(path) as f:
            f.seek(0, os.SEEK_END)                                # start at end
            while True:
                line = f.readline()                               # read next line
                if not line:                                      # nothing new
                    if oneshot: break                             # exit if oneshot
                    await asyncio.sleep(0.5)                      # wait before retry
                    continue
                await process_line(rules, q, line.rstrip(), path)
    except FileNotFoundError:
        log.error("file not found")

async def process_line(rules, q, line: str, src: str):            # handle single line
    logging.info(f"New log line from {src}: {line}")
    tgt_id_match = re.match(r'^([a-zA-Z0-9_-]+)\s+[0-9.]+\s+-\s+-', line)   # match first word before IP + - -
    tgt_id = tgt_id_match.group(1) if tgt_id_match else None

    for rule in rules:                                            # iterate rules
        m = re.search(rule['match'], line)                        # regex match
        if m:                                                     # if matched
            logging.info(f"✅ Captured groups: {m.groupdict()}")
            ev = m.groupdict()                                    # grab all regex fields
            await q.put(({'rule': rule['id'],                     # add rest of the fields - targets
                           'ip': m.groupdict().get('ip'),
                           'tgt_id': ev.get('tgt', tgt_id),
                           'raw': line,
                           'url': m.groupdict().get('url')},
                          rule.get('playbook', 'alert_only')))    # enqueue task
            logging.debug(f"rule hit {rule['id']}")

#  playbooks

async def pb_iptables(ev, sess, env, trgs):       # Gobuster response flow
    ip = ev['ip']
    tgt_id = ev.get('tgt_id')
    if not tgt_id or tgt_id not in trgs['targets']:               # check for known target
        logging.warning(f"No credentials found for target '{tgt_id}'")
        return
    creds = trgs['targets'][tgt_id]                               # {host,user,key_path}

    # block IP immediately
    ssh_cmd = [
        'ssh', '-o', 'StrictHostKeyChecking=no',
        '-i', creds['key_path'],                                  # private-key path
        f"{creds['user']}@{creds['host']}",                       # user@target
        f"sudo iptables -I INPUT -s {ip} -j DROP"]                # add DROP rule

    if not os.path.exists(creds['key_path']):                     # check key file exists
        logging.warning(f"SSH key not found: {creds['key_path']}")
        note = 'key missing'
    else:
        try:
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:                            # success
                logging.info(f"iptables rule added on {creds['host']}, {ip} blocked")
                note = 'blocked'
            else:                                                 # failure
                err = result.stderr.strip()
                if "Could not fetch rule set generation id" in err and "Permission denied" in err:
                    logging.warning('You must run as root in order for iptables rules to be changed!')
                else:
                    logging.warning(err or 'iptables command failed')
                note = 'block failed'
        except subprocess.TimeoutExpired:
            logging.warning("SSH command timed out")
            note = 'ssh timeout'
        except Exception as e:
            logging.warning(f"SSH command failed: {e}")
            note = 'ssh error'

    logging.info(f"Starting AbuseIPDB search for {ip}")
    r = await sess.get('https://api.abuseipdb.com/api/v2/check',  # query AbuseIPDB
                       params={'ipAddress': ip, 'maxAgeInDays': 90},
                       headers={'Key': env['ABUSEIPDB_KEY'], 'Accept': 'application/json'})
    data = await r.json()
    score = data['data']['abuseConfidenceScore']
    logging.info("AbuseIPDB search finished")

    note = f"AbuseIPDB rep score={score} | {note}"                # combine with block result

    text = (                                                      # send Telegram alert
        f"🚨 <b>{ev['rule']}</b>\n"
        f"IP: <code>{ip}</code>\n"
        f"{note}"
    )
    await sess.post(f"https://api.telegram.org/bot{env['TELEGRAM_TOKEN']}/sendMessage",
                    data={'chat_id': env['TELEGRAM_CHAT_ID'], 'text': text, 'parse_mode': 'HTML'})
    logging.info(f"Sent Telegram alert for rule {ev['rule']} and IP {ip}")

# malware analysis playbook, used when someone curls/wgets a file while inside the honeypot
# fetches the file an attacker has tried to download on the honeypot
# and sends it to virustotal to get a report on it and sends it to telegram

async def pb_malware_analysis(ev, sess, env):                              # Malware analysis flow
    ip = ev.get("ip")                                             # attacker IP
    raw_line = ev.get("raw")                                      # raw regex line from rules.yml
    url = ev["url"] if "url" in ev else None                      # define the url from rules.yml

    if not url:                                                   # fail if still missing
        logging.warning("No URL found in malware log line.")
        return

    try:                                                          # fetch file
        r = requests.get(url, timeout=10)
        r.raise_for_status()
    except Exception as e:                                        # download failed
        logging.warning(f"Failed to fetch malware from {url}: {e}")
        return

    with tempfile.NamedTemporaryFile(delete=False) as tmpf:       # save to temp file
        tmpf.write(r.content)
        tmp_path = tmpf.name

    vt_key = env["VT_API_KEY"]
    with open(tmp_path, "rb") as f:                               # upload to VirusTotal
        files = {"file": f}
        res = requests.post("https://www.virustotal.com/vtapi/v2/file/scan",
                            files=files, params={"apikey": vt_key})
    scan_id = res.json().get("scan_id")
    logging.debug(f"VT scan POST response: {res.status_code} - {res.text}")  
    
    time.sleep(30)
    rpt = requests.get("https://www.virustotal.com/vtapi/v2/file/report",
                   params={"apikey": vt_key, "resource": scan_id})
    data = rpt.json()

    if data.get("positives") is None:
        logging.debug("Initial VT report not ready. Waiting 30s and retrying once...")
        time.sleep(30)
        rpt = requests.get("https://www.virustotal.com/vtapi/v2/file/report",
                       params={"apikey": vt_key, "resource": scan_id})
    data = rpt.json()
    detections = data.get("positives", 0)
    total = data.get("total", 0)
    permalink = data.get("permalink", "N/A")

    text = (                                                      # send Telegram alert with the report
        f"🦠 <b>Malware Download Detected on Honeypot</b>\n"
        f"🧑‍💻: <code>{ip}</code>\n"
        f"🔗 File URL: <code>{url}</code>\n"
        f"🧪 VT: <b>{detections}/{total}</b> engines flagged it\n"
        f"<a href=\"{permalink}\">📄 View Full Report</a>"
    )

    await sess.post(f"https://api.telegram.org/bot{env['TELEGRAM_TOKEN']}/sendMessage",
                    data={'chat_id': env['TELEGRAM_CHAT_ID'], 'text': text, 'parse_mode': 'HTML'})

    ev["vt_result"] = {                                           # store result in event to pass to splunk HEC
        "detections": detections,
        "total": total,
        "report": permalink,
        "url": url
    }

    # ✅ Print VirusTotal report info before ending
    print("\n[VT SCAN RESULT]")
    print(f"Detected: {detections}/{total}")
    print(f"URL: {url}")
    print(f"Report: {permalink}\n")

    os.remove(tmp_path)                                           # cleanup
    logging.info(f"Malware playbook complete for IP {ip}")

#playbook for enriching with abuseipdb and notifying, used for honeypot connection
async def pb_alert(ev, sess, env):                         # AbuseIPDB + alert only
    ip = ev.get("ip")
    if not ip:                                                     # skip if IP missing
        logging.warning("No IP found in event")
        return

    logging.info(f"Running AbuseIPDB enrichment for IP {ip}")
    r = await sess.get('https://api.abuseipdb.com/api/v2/check',   # query AbuseIPDB
                       params={'ipAddress': ip, 'maxAgeInDays': 90},
                       headers={'Key': env['ABUSEIPDB_KEY'], 'Accept': 'application/json'})
    data = await r.json()
    score = data['data']['abuseConfidenceScore']
    logging.info(f"AbuseIPDB enrichment complete, score={score}")

    note = f"AbuseIPDB rep score={score}"                          # status note

    text = (                                                       # send Telegram alert
        f"🚨 <b>{ev['rule']}</b>\n"
        f"IP: <code>{ip}</code>\n"
        f"{note}"
    )

    await sess.post(f"https://api.telegram.org/bot{env['TELEGRAM_TOKEN']}/sendMessage",
                    data={'chat_id': env['TELEGRAM_CHAT_ID'], 'text': text, 'parse_mode': 'HTML'})
    logging.info(f"Sent honeypot login alert for IP {ip}")


def _allow_event(ev: dict) -> bool:
    """
    Return True if this event should trigger a playbook.
    For malware downloads, use finer-grained cooldown based on URL.
    For recon scans, stick to IP+rule+tgt cooldown.
    """
    rule = ev.get("rule")
    ip = ev.get("ip")
    tgt = ev.get("tgt_id")
    url = ev.get("url")

    # Malware: allow cooldown per (rule, ip, url)
    if rule == "honeypot_malware_fetch&analyze":
        key = f"{rule}|{ip}|{url}"
    elif rule == "honeypot_login":
        key = f"{rule}|{ip}"
    else:
        key = f"{rule}|{ip}|{tgt}"

    now = time.time()
    if now - _last_action[key] < COOLDOWN_SEC:
        logging.debug(f"Cooldown hit → skip duplicate action for {key}")
        return False
    _last_action[key] = now
    return True


#  worker - task processor

async def worker(q: asyncio.Queue, env, sess, trgs):             # main task processor
    while True:                                                  # infinite loop
        ev, playbook = await q.get()                             # pull from queue
        if not _allow_event(ev):                                 # cooldown filter
            q.task_done()
            continue
        try:                                                     # wrap playbook call
            logging.info(f"Playbook trigger → {playbook}")       # log chosen playbook
            if playbook == 'iptables_block' and ev.get('ip'):     # choose playbook
                await pb_iptables(ev, sess, env, trgs)
            elif playbook == 'malware_fetch&analyze' and ev.get('ip'):
                await pb_malware_analysis(ev, sess, env)
            else:
                await pb_alert(ev, sess, env)
                
            await send_to_splunk_hec(ev, env, sess)
        except Exception as e:                                   # catch and print error
            logging.error(f"Playbook execution failed: {e}")
            import traceback
            traceback.print_exc()
        q.task_done()

#  function to send to splunk via HEC
async def send_to_splunk_hec(ev: dict, env: dict, sess: aiohttp.ClientSession):
    """
    Sends enriched SOAR event to Splunk via HTTP Event Collector (HEC).
    Requires SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN in .env
    """
    url = os.getenv("SPLUNK_HEC_URL")
    token = os.getenv("SPLUNK_HEC_TOKEN")

    if not url or not token:
        logging.warning("SPLUNK_HEC_URL or SPLUNK_HEC_TOKEN missing from env")
        return

    rule = ev.get("rule", "unknown")
    playbook = "unknown"
    summary = []

    if rule == "gobuster_Scan":
        playbook = "iptables_block"
        if "AbuseIPDB rep score=" in ev.get("raw", ""):
            score = re.search(r"AbuseIPDB rep score=(\d+)", ev["raw"])
            if score:
                summary.append(f"AbuseIPDB score {score.group(1)}")
        if "blocked" in ev.get("raw", ""):
            summary.append("IP blocked on target")
        elif "block failed" in ev.get("raw", ""):
            summary.append("IP block failed")
        elif "ssh timeout" in ev.get("raw", ""):
            summary.append("SSH timeout")
        elif "ssh error" in ev.get("raw", ""):
            summary.append("SSH error")

    elif rule == "honeypot_malware_fetch&analyze":
        playbook = "malware_fetch&analyze"
        vt = ev.get("vt_result", {})
        if vt:
            summary.append(f"VT {vt.get('detections', '?')}/{vt.get('total', '?')}")
            summary.append("malware analyzed")

    elif rule == "honeypot_login":
        playbook = "alert_only"
        summary.append("AbuseIPDB lookup only")

    else:
        playbook = "alert_only"
        summary.append("Generic alert")

    ev["soar_action"] = f"{playbook} → " + " | ".join(summary)

    payload = {
        "event": ev,  # full event dict (already has rule, ip, raw, etc.)
        "sourcetype": "soar",  # set this in Splunk to make custom dashboards
        "time": time.time()         # epoch time for indexing
    }

    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type": "application/json"
    }

    try:
        async with sess.post(url, headers=headers, json=payload) as res:
            if res.status != 200:
                logging.warning(f"Splunk HEC failed: {res.status} - {await res.text()}")
            else:
                logging.info(f"✅ Event sent to Splunk HEC for rule {ev.get('rule')}")
    except Exception as e:
        logging.error(f"Splunk HEC request failed: {e}")


#  entrypoint  (all DB plumbing removed)

async def main():                                                # orchestrates everything
    args = cli()                                                 # parse CLI
    env = check_env()                                            # validate env
    setup_log(args.debug)                                        # configure logging
    cfg, rules, trgs = load_yaml(args.config, args.rules,args.targets)  # load YAML files

    sess = aiohttp.ClientSession()                               # HTTP session
    thr  = cfg.get('abuseipdb_threshold', 50)                    # score threshold
    q    = asyncio.Queue()                                       # work queue
    loop = asyncio.get_event_loop()                              # current loop
    stop = asyncio.Event()                                       # shutdown flag
    for sig in (signal.SIGINT, signal.SIGTERM):                  # handle Ctrl-C etc.
        loop.add_signal_handler(sig, stop.set)
    for p in cfg.get('tail_paths', []):                          # spawn tail tasks
        loop.create_task(tail(p, rules, q, oneshot=args.oneshot))
    loop.create_task(worker(q, env, sess, trgs))            # spawn worker
    await stop.wait()                                            # block until signal
    logging.info("shutdown…")
    await sess.close()                                           # cleanup HTTP

if __name__ == '__main__':                                       # CLI entry
    asyncio.run(main())
