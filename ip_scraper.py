#!/usr/bin/env python3
# ip_scraper.py

import requests
import re
import schedule
import time
import base64
import os
from datetime import datetime, timezone
from github import Github

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
GITHUB_REPO  = os.environ["GITHUB_REPO"]
OUTPUT_FILE  = "blocklist.txt"

FEEDS = [
    {
        "name": "Emerging Threats - Compromised IPs",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "plaintext",
    },
    {
        "name": "Feodo Tracker - C2 IPs",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "type": "plaintext",
    },
    {
        "name": "Spamhaus DROP",
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "type": "plaintext",
    },
    {
        "name": "CI Army",
        "url": "http://cinsscore.com/list/ci-badguys.txt",
        "type": "plaintext",
    },
]

IP_PATTERN   = re.compile(r'\b(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?\b')
COMMENT_LINE = re.compile(r'^\s*[#;]')


def fetch_feed(feed: dict) -> set[str]:
    """Download a feed and extract IP addresses / CIDR blocks."""
    ips = set()
    try:
        resp = requests.get(feed["url"], timeout=20)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or COMMENT_LINE.match(line):
                continue
            # Extract first IP/CIDR from each line
            match = IP_PATTERN.search(line)
            if match:
                ips.add(match.group(0))
    except Exception as e:
        print(f"[WARN] Failed to fetch {feed['name']}: {e}")
    return ips


def build_blocklist(all_ips: set[str]) -> str:
    """Build the final file content."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = (
        f"# Malicious IP blocklist\n"
        f"# Auto-generated: {now}\n"
        f"# Total entries: {len(all_ips)}\n"
        f"# Sources: Emerging Threats, Feodo Tracker, Spamhaus DROP, CI Army\n"
        f"#\n"
    )
    sorted_ips = sorted(all_ips, key=lambda ip: tuple(int(x) for x in ip.split('/')[0].split('.')))
    return header + "\n".join(sorted_ips) + "\n"


def push_to_github(content: str) -> None:
    """Create or update the file in the GitHub repo."""
    g    = Github(GITHUB_TOKEN)
    repo = g.get_repo(GITHUB_REPO)

    message = f"chore: update blocklist ({datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')})"

    try:
        # File already exists — get its SHA to update it
        existing = repo.get_contents(OUTPUT_FILE)
        repo.update_file(
            path=OUTPUT_FILE,
            message=message,
            content=content,
            sha=existing.sha,
        )
        print(f"[OK] Updated {OUTPUT_FILE} in {GITHUB_REPO}")
    except Exception:
        # File doesn't exist yet — create it
        repo.create_file(
            path=OUTPUT_FILE,
            message=message,
            content=content,
        )
        print(f"[OK] Created {OUTPUT_FILE} in {GITHUB_REPO}")


def run():
    print(f"[{datetime.now(timezone.utc).isoformat()}] Starting scrape...")
    all_ips: set[str] = set()

    for feed in FEEDS:
        ips = fetch_feed(feed)
        print(f"  {feed['name']}: {len(ips)} IPs")
        all_ips.update(ips)

    print(f"  Total unique IPs after dedup: {len(all_ips)}")
    content = build_blocklist(all_ips)
    push_to_github(content)
    print("Done.\n")


if __name__ == "__main__":
    run()  # Run once immediately on start

    schedule.every(6).hours.do(run)
    while True:
        schedule.run_pending()
        time.sleep(60)
