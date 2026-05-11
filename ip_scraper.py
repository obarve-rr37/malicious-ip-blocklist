#!/usr/bin/env python3
# ip_scraper.py
# Malicious IP scraper — fetches from 5 threat intel feeds
# Auto-updates blocklist.txt in your GitHub repo

import os
import re
import json
import time
import requests
import sys
from datetime import datetime, timezone
from pathlib import Path
from github import Github

# ── Config ────────────────────────────────────────────────────────────────────
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
OUTPUT_FILE   = "blocklist.txt"

# ── Patterns ──────────────────────────────────────────────────────────────────
IP_PATTERN   = re.compile(r'^\s*(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?\s*$')
COMMENT_LINE = re.compile(r'^\s*[#;]')

# ── Feeds ─────────────────────────────────────────────────────────────────────
FEEDS = [
    {
        "name": "Emerging Threats - Compromised IPs",
        "url":  "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    },
    {
        "name": "Feodo Tracker - C2 IPs",
        "url":  "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    },
    {
        "name": "Spamhaus DROP",
        "url":  "https://www.spamhaus.org/drop/drop.txt",
    },
    {
        "name": "CI Army",
        "url":  "http://cinsscore.com/list/ci-badguys.txt",
    },
]


# ── Fetchers ──────────────────────────────────────────────────────────────────
def fetch_feed(feed: dict) -> set[str]:
    """Download a plain-text feed and extract valid IPs / CIDRs."""
    ips = set()
    try:
        resp = requests.get(feed["url"], timeout=20)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or COMMENT_LINE.match(line):
                continue
            # Some feeds put extra fields — grab only the IP/CIDR part
            candidate = line.split()[0]
            if IP_PATTERN.match(candidate):
                ips.add(candidate)
        print(f"  {feed['name']}: {len(ips)} IPs")
    except requests.exceptions.Timeout:
        print(f"  [WARN] Timeout — {feed['name']} skipped")
    except requests.exceptions.ConnectionError:
        print(f"  [WARN] Connection error — {feed['name']} skipped")
    except Exception as e:
        print(f"  [WARN] Failed — {feed['name']}: {e}")
    return ips


def fetch_abuseipdb(confidence: int = 90) -> set[str]:
    """Fetch high-confidence abusive IPs from AbuseIPDB."""
    if not ABUSEIPDB_KEY:
        print("  AbuseIPDB: no key set — skipping")
        return set()
    ips = set()
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={
                "Key":    ABUSEIPDB_KEY,
                "Accept": "text/plain",
            },
            params={"confidenceMinimum": confidence},
            timeout=30,
        )
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if line and IP_PATTERN.match(line):
                ips.add(line)
        print(f"  AbuseIPDB: {len(ips)} IPs (confidence >= {confidence}%)")
    except requests.exceptions.Timeout:
        print("  [WARN] Timeout — AbuseIPDB skipped")
    except requests.exceptions.ConnectionError:
        print("  [WARN] Connection error — AbuseIPDB skipped")
    except Exception as e:
        print(f"  [WARN] AbuseIPDB failed: {e}")
    return ips


# ── Builder ───────────────────────────────────────────────────────────────────
def build_blocklist(all_ips: set[str]) -> str:
    """Sort and format the final blocklist file content."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def sort_key(ip):
        """Sort numerically by IP, put CIDRs after bare IPs."""
        try:
            base = ip.split("/")[0]
            return tuple(int(x) for x in base.split("."))
        except Exception:
            return (999, 999, 999, 999)

    sorted_ips = sorted(all_ips, key=sort_key)

    header = (
        f"# Malicious IP blocklist\n"
        f"# Auto-generated : {now}\n"
        f"# Total entries  : {len(sorted_ips)}\n"
        f"# Sources        : Emerging Threats, Feodo Tracker,\n"
        f"#                  Spamhaus DROP, CI Army, AbuseIPDB\n"
        f"# Raw feed URL   : https://raw.githubusercontent.com/"
        f"{os.environ.get('GITHUB_REPO','your-repo')}/main/blocklist.txt\n"
        f"#\n"
    )
    return header + "\n".join(sorted_ips) + "\n"



# ── Main ──────────────────────────────────────────────────────────────────────
def run():
    start = datetime.now(timezone.utc)
    print(f"\n[{start.strftime('%Y-%m-%d %H:%M UTC')}] Starting scrape...")

    all_ips: set[str] = set()

    # Plain-text feeds
    for feed in FEEDS:
        all_ips.update(fetch_feed(feed))
        time.sleep(1)       # be polite between requests

    # AbuseIPDB
    all_ips.update(fetch_abuseipdb(confidence=90))

    print(f"\n  Total unique IPs after dedup : {len(all_ips)}")

    content = build_blocklist(all_ips)
    # Write locally — workflow git step handles the push
    with open("blocklist.txt", "w") as f:
        f.write(content)
    print(f"  Written to blocklist.txt")

    elapsed = (datetime.now(timezone.utc) - start).seconds
    print(f"  Done in {elapsed}s\n")


if __name__ == "__main__":
    run()
