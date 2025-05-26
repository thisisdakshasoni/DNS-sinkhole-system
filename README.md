# 🛡️ Dynamic DNS Sinkhole System

A Zero Trust DNS enforcement solution using **Unbound**, **Suricata**, and a **Python-based behavioral classifier**.

This project detects and blocks suspicious domains in real-time based on:
- DNS query frequency
- TTL values
- Entropy (for DGA detection)

---

## 🧱 Architecture

Suricata (EVE logs)
↓
Python Daemon (Behavior Analysis)
↓
Sinkhole Config Generation
↓
Unbound DNS (Redirect Suspicious Domains)

yaml

---

## 🚀 How It Works

1. **Suricata** captures DNS queries and logs them to `eve.json`
2. A **Python daemon** reads those logs and calculates:
   - Entropy of domain names
   - Query frequency
   - Average TTL
3. If a domain is flagged as suspicious:
   - It is added to the Unbound sinkhole config
   - Unbound DNS is reloaded
4. Queries to those domains are redirected to `127.0.0.1`

---

## 📂 Project Structure

| File | Description |
|------|-------------|
| `dns_classifier.py` | Main Python daemon |
| `dns_classifier.log` | Logs of domain behavior and sinkhole updates |
| `sinkhole.conf` | Generated config for Unbound to block domains |
| `packet_capture.pcap` | Captured DNS queries using tcpdump |
| `demo.mp4` | Full demo of detection + blocking |
| `DEMO_SCRIPT.txt` | Narrated steps for video recording |

---

## 🧪 How to Run

1. Launch Suricata:
   ```bash
   sudo suricata -c /etc/suricata/suricata.yaml -i lo -D
Run the daemon:

sudo python3 dns_classifier.py
Generate traffic:
for i in {1..10}; do dig suspicious-domain.test @127.0.0.1; done
Observe:

dns_classifier.log shows detection

sinkhole.conf gets updated

dig suspicious-domain.test returns 127.0.0.1

📦 Deliverables
✅ Code + Logs

✅ Configs + PCAP

✅ Demo video

✅ Written script for live walkthrough

