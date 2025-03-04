#!/usr/bin/env python3

###################################################
# Pretvorba CERT-SI URL-jev v format Pi-hole za blokiranje phishing URL-jev
# Avtor: Jan-FCloud - 2025 (https://github.com/Jan-FCloud)
# Za več informacij o tem, kako uporabiti blocklist za blokiranje, si oglejte:
# https://github.com/Jan-FCloud/SI-CERT-PiHole
###################################################

import os
import json
import requests
import csv
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
from typing import Set

BLOCKLIST_FILE = "blocklist.txt"
METADATA_FILE = "blocklist_metadata.json"
SOURCE_URL = "https://www.cert.si/misp/urls/all.txt"

def fetch_phishing_urls() -> Set[str]:
    try:
        response = requests.get(SOURCE_URL)
        response.raise_for_status()
        
        urls = set()
        lines = response.text.strip().split('\n')
        for line in lines[1:]:
            if ',' in line:
                date, url = line.split(',', 1)
                if is_valid_url(url):
                    urls.add(url.strip())
        
        return urls
    except Exception as e:
        print(f"Error fetching URLs: {e}")
        return set()

def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ('http', 'https')
    except:
        return False

def update_blocklist(urls: Set[str]) -> None:
    existing_urls = set()
    lines = []
    
    slovenia_tz = timezone(timedelta(hours=1))
    current_time = datetime.now(slovenia_tz)
    
    header_lines = [
        "#\n",
        "# SI-CERT Phishing URL Blocklist\n",
        "# Source: https://www.cert.si/misp/urls/all.txt\n", 
        "# Author: Jan-FCloud (https://github.com/Jan-FCloud)\n",
        "# Repository: https://github.com/Jan-FCloud/SI-CERT-PiHole\n",
        "#\n",
        f"# Last updated: {current_time.strftime('%Y-%m-%d %H:%M:%S')}\n",
        "#\n"
    ]
    
    if os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            start_idx = 0
            while start_idx < len(lines) and lines[start_idx].startswith('#'):
                start_idx += 1
            existing_urls = set(line.strip().split()[1] for line in lines[start_idx:] if line.strip())
    
    all_urls = existing_urls.union(urls)
    
    with open(BLOCKLIST_FILE, 'w', encoding='utf-8') as f:
        for line in header_lines:
            f.write(line)
        
        for url in sorted(all_urls):
            f.write(f"0.0.0.0 {url}\n")
    
    metadata = {
        "last_updated": current_time.isoformat(),
        "total_urls": len(all_urls),
        "new_urls_added": len(urls - existing_urls),
        "source": SOURCE_URL
    }
    
    with open(METADATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)

def main():
    print("Starting SI-CERT phishing URL blocklist update...")
    
    print("Fetching phishing URLs...")
    urls = fetch_phishing_urls()
    
    if not urls:
        print("No URLs were fetched. Please check the source URL and try again.")
        return
    
    print(f"Updating blocklist with {len(urls)} URLs...")
    update_blocklist(urls)
    
    print("Update completed successfully!")

if __name__ == "__main__":
    main()