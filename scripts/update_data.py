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
from datetime import datetime, UTC
from urllib.parse import urlparse
import tldextract
import logging
from tranco import Tranco

# Configure logging to debug in case the action decided to fail :)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
SICERT_URL = "https://www.cert.si/misp/urls/all.txt"
DOMAIN_FILE = "blocklist_domains.txt"
METADATA_FILE = "blocklist_metadata.json"
CACHE_DIR = ".cache"

def setup_cache_dir():
    """Create cache directory if it doesn't exist."""
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)

def get_popular_domains(cache_time_hours=24):
    """Get list of popular domains from Tranco with caching."""
    cache_file = os.path.join(CACHE_DIR, "popular_domains.txt")
    
    try: # Check if cache exists and is recent (so we don't download the list every time yipeee we respect the rules)
        
        if os.path.exists(cache_file):
            cache_age = datetime.now(UTC) - datetime.fromtimestamp(os.path.getmtime(cache_file), UTC)
            if cache_age.total_seconds() < cache_time_hours * 3600:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    return set(line.strip() for line in f)
        
        logger.info("Downloading fresh domain list from Tranco...")
        t = Tranco(cache=True, cache_dir=CACHE_DIR)
        latest_list = t.list()
        
        popular_domains = set()
        for domain in latest_list.top(100000):
            ext = tldextract.extract(domain)
            base_domain = f"{ext.domain}.{ext.suffix}"
            popular_domains.add(base_domain)
        
        with open(cache_file, 'w', encoding='utf-8') as f:
            for domain in sorted(popular_domains):
                f.write(f"{domain}\n")
        
        return popular_domains
    
    except Exception as e: # If something goes wrong, we use the cache file regardless of age since we couldn't get the new one
        logger.error(f"Error getting popular domains: {e}")
        if os.path.exists(cache_file):
            with open(cache_file, 'r', encoding='utf-8') as f:
                return set(line.strip() for line in f)
        return set()

def is_valid_url(url):
    """Check if the URL is valid and not a local or internal link."""
    try:
        result = urlparse(url) # Check if the URL is valid and not a local or internal link so we dont block stuff like this: https://www.google.com/search?q=test
        return all([result.scheme, result.netloc]) and result.scheme in ('http', 'https')
    except:
        return False

def fetch_phishing_urls():
    """Fetch phishing URLs from SI-CERT website."""
    try:
        response = requests.get(SICERT_URL, timeout=30)
        response.raise_for_status()
        
        popular_domains = get_popular_domains()
        logger.info(f"Loaded {len(popular_domains)} popular domains")
        
        domains = set()  # For full domains
        lines = response.text.strip().split('\n')
        
        for line in lines[1:]:  # Skip the first line of the sicert list(header)
            if ',' in line:
                date, url = line.split(',', 1)
                url = url.strip()
                if is_valid_url(url):
                    parsed_url = urlparse(url)
                    domain = parsed_url.netloc
                    
                    # get domains to check popularity
                    ext = tldextract.extract(domain)
                    base_domain = f"{ext.domain}.{ext.suffix}"
                    
                    # only add to domain blocklist if it's not a popular domain
                    if base_domain not in popular_domains:
                        domains.add(domain)
                        logger.info(f"Added unknown domain to blocklist: {domain}")
        
        return domains
    except Exception as e:
        logger.error(f"Error fetching phishing URLs: {e}")
        return set()

def update_blocklists(domains):
    """Update the blocklist files with domains."""
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Domain update
    with open(DOMAIN_FILE, 'w', encoding='utf-8') as f:
        f.write("# SI-CERT Phishing URL Blocklist - Domains\n")
        f.write(f"# Updated: {timestamp}\n")
        f.write(f"# Source: {SICERT_URL}\n")
        f.write(f"# Repo: https://github.com/Jan-FCloud/SI-CERT-PiHole\n")
        f.write("# This file contains non-popular domains that are entirely blocked\n\n")
        for domain in sorted(domains):
            f.write(f"{domain}\n")
    
    # Metadata update
    metadata = {
        "last_updated": timestamp,
        "total_domains": len(domains),
        "source": SICERT_URL
    }
    
    with open(METADATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)

def main():
    """Main function to update the blocklists."""
    try:
        logger.info("Starting SI-CERT phishing URL blocklist update...")
        
        setup_cache_dir()
        
        domains = fetch_phishing_urls()
        
        if not domains:
            logger.error("No URLs were fetched. Exiting.")
            return False
        
        update_blocklists(domains)
        
        logger.info(f"Update completed successfully! Added {len(domains)} domains.")
        return True
    
    except Exception as e:
        logger.error(f"Error in main function: {e}")
        return False

if __name__ == "__main__":
    main()