This repository contains a Pi-hole blocklist generated from SI-CERT's phishing URL database. The blocklist is updated daily and uses a smart blocking approach to minimize false positives.

## Features

- Separates blocking rules into domains and regex patterns
- Protects against false positives by using regex for popular domains
- Updates daily via GitHub Actions
- Uses Tranco list to identify popular domains

## Usage

### Domain Blocklist

To add the domain blocklist to your Pi-hole, add this URL in your Pi-hole's blocklist settings:
```
https://raw.githubusercontent.com/Jan-Fcloud/SI-CERT-PiHole/main/blocklist_domains.txt
```

### Regex Blocklist

For the regex patterns (recommended for more precise blocking), copy the patterns from:
```
https://raw.githubusercontent.com/Jan-Fcloud/SI-CERT-PiHole/main/blocklist_regex.txt
```
and add them to your Pi-hole's "Regex blacklist" under Settings → Regex & Wildcards.

## How it Works

1. **Domain Blocking**: Unknown/suspicious domains are blocked entirely
2. **Regex Blocking**: 
   - Popular domains are only blocked at specific malicious paths
   - Specific paths on any domain are blocked using regex patterns

## Source

The blocklist is generated from SI-CERT's phishing URL list:
- Source URL: https://www.cert.si/misp/urls/all.txt
- Updates: Daily at midnight UTC
- Format: Processed for optimal Pi-hole compatibility

## Statistics

You can view the current blocklist statistics in the `blocklist_metadata.json` file.

## Contributing

Feel free to open issues or submit pull requests if you find any problems or have suggestions for improvements.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
