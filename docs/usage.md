# Usage Guide

## Basic Scanning

```bash
# Scan single URL
abyssforge scan "https://target.com?id=1"

# All modules (default)
abyssforge scan "https://target.com?id=1" --modules all

# Specific modules
abyssforge scan "https://target.com?id=1" --modules sqli,xss,csrf
```

## Advanced Options

```bash
# With proxy (Burp Suite)
abyssforge scan "https://target.com?id=1" \
  --proxy http://127.0.0.1:8080 \
  --no-verify-ssl

# With authentication
abyssforge scan "https://target.com/dashboard" \
  --cookie "session=abc123; user_id=42" \
  --header "Authorization: Bearer TOKEN"

# Crawl mode
abyssforge scan "https://target.com" \
  --crawl --depth 3

# Custom threading and rate limit
abyssforge scan "https://target.com?q=1" \
  --threads 20 --rate-limit 5 --timeout 45

# Save to custom output
abyssforge scan "https://target.com?id=1" \
  --output /tmp/reports --format json,html
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, no high+ findings |
| 1 | High severity findings found |
| 2 | Critical severity findings found |

## Fingerprinting

```bash
abyssforge fingerprint https://target.com
```

## Utility Commands

```bash
# List available modules
abyssforge modules

# Version info
abyssforge --version
```
