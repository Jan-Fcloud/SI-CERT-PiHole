#!/bin/bash

# TEMP SOLUTION
# This might not be the best solution, but it works for now.
# Hopefully Pi-hole will add a better solution in the future :(

url="https://raw.githubusercontent.com/Jan-Fcloud/SI-CERT-PiHole/refs/heads/main/blocklist_regex.txt"

curl -s -o /tmp/regex_list.txt "$url"

if [[ $? -ne 0 ]]; then
  echo "Failed to download the regex list."
  exit 1
fi

tail -n +7 /tmp/regex_list.txt | while IFS= read -r line
do
  pihole --regex "$line"
done

# Restart Pi-hole DNS service to apply changes (this was ran on v6)
pihole reloadlists

echo "Regex import script finished."