import json
import time
import re
import logging
import tempfile
import shutil
from collections import defaultdict
from math import log2
from subprocess import run, CalledProcessError

# --- Configuration ---
EVE_LOG = "/var/log/suricata/eve.json"
SINKHOLE_FILE = "/etc/unbound/unbound.conf.d/sinkhole.conf"
DOMAIN_THRESHOLD = 5
ENTROPY_THRESHOLD = 3.8
TTL_THRESHOLD = 300
SLEEP_INTERVAL = 300  # seconds
WHITELIST = {"google.com", "facebook.com", "microsoft.com"}  # Example safe domains

# --- Logging Setup ---
logging.basicConfig(filename="dns_classifier.log",
                    level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

# --- Domain statistics ---
stats = defaultdict(lambda: {"count": 0, "ttls": [], "entropy": 0})

def entropy(domain):
    domain = domain.lower()
    prob = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return -sum(p * log2(p) for p in prob)

def parse_dns_logs():
    try:
        with open(EVE_LOG, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if entry.get("event_type") == "dns" and entry.get("dns", {}).get("type") == "query":
                        d = entry["dns"]["rrname"].strip('.').lower()
                        if not re.match(r'^[a-z0-9.-]+$', d):
                            continue
                        if d in WHITELIST:
                            continue
                        stats[d]["count"] += 1
                        if "answers" in entry["dns"]:
                            ttls = [a.get("ttl", 0) for a in entry["dns"]["answers"] if isinstance(a, dict)]
                            stats[d]["ttls"].extend(ttls)
                        stats[d]["entropy"] = entropy(d)
                except json.JSONDecodeError:
                    logging.warning("Malformed JSON skipped.")
    except FileNotFoundError:
        logging.error(f"EVE log file not found at {EVE_LOG}")
    except Exception as e:
        logging.exception("Unexpected error while parsing logs.")

def is_suspicious(domain, data):
    count = data["count"]
    avg_ttl = sum(data["ttls"]) / len(data["ttls"]) if data["ttls"] else 0
    ent = data["entropy"]
    suspicious = count > DOMAIN_THRESHOLD and (ent > ENTROPY_THRESHOLD or avg_ttl < TTL_THRESHOLD)
    if suspicious:
        logging.info(f"Suspicious domain detected: {domain} (Count={count}, TTL={avg_ttl:.2f}, Entropy={ent:.2f})")
    return suspicious

def update_sinkhole():
    try:
        with tempfile.NamedTemporaryFile('w', delete=False) as temp_file:
            for domain, info in stats.items():
                if is_suspicious(domain, info):
                    temp_file.write(f'local-zone: "{domain}." redirect\n')
                    temp_file.write(f'local-data: "{domain}. A 127.0.0.1"\n')

        shutil.move(temp_file.name, SINKHOLE_FILE)
        logging.info(f"Sinkhole file updated with {len(stats)} domains.")
        run(["sudo", "systemctl", "reload", "unbound"], check=True)
        logging.info("Unbound DNS reloaded successfully.")
    except CalledProcessError:
        logging.error("Failed to reload Unbound. Check systemctl and permissions.")
    except Exception as e:
        logging.exception("Error while updating sinkhole.")

if __name__ == "__main__":
    logging.info("Started behavioral DNS sinkhole daemon.")
    try:
        while True:
            parse_dns_logs()
            update_sinkhole()
            time.sleep(SLEEP_INTERVAL)
    except KeyboardInterrupt:
        logging.info("Daemon interrupted and stopped.")
    except Exception:
        logging.exception("Unhandled fatal exception.")
