# ⚡ AbyssForge

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/version-1.0.0-orange.svg" alt="Version">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platform">
  <img src="https://img.shields.io/github/issues/faza-kamal/AbyssForge" alt="Issues">
</p>

<p align="center">
  <b>A powerful, extensible web vulnerability scanner for security researchers and bug bounty hunters.</b>
</p>

---

> ⚠️ **Legal Disclaimer**: AbyssForge is intended for **authorized security testing only**. Always obtain explicit written permission before testing any system. Unauthorized use is illegal and unethical. The author assumes no liability for misuse.

---

## 🌟 Features

### Vulnerability Modules
| Module | Detection Type | Severity |
|--------|---------------|----------|
| **SQL Injection** | Error-based, Time-based, Boolean-based, Union-based | Critical |
| **XSS** | Reflected, Stored, DOM-based | High |
| **CSRF** | Token analysis, SameSite validation | High |
| **LFI/Path Traversal** | Local file inclusion, path traversal | High |
| **Command Injection** | Time-based blind detection | Critical |
| **Security Misconfig** | Missing headers, exposed files, CORS, directory listing | Medium |
| **API Security** | GraphQL introspection, JWT analysis, endpoint discovery | High |

### Core Features
- 🚀 **Multi-threaded scanning** with configurable concurrency
- 🔄 **Rate limiting** to avoid bans (configurable req/sec)
- 🔒 **Proxy support** (HTTP/S, SOCKS4/5) for Burp Suite integration
- 🍪 **Cookie & session management**
- 🔁 **Automatic retry** with exponential backoff
- 🕵️ **WAF detection** (Cloudflare, AWS WAF, Imperva, Akamai, F5, ModSecurity)
- 🧰 **Technology fingerprinting** (WordPress, Django, Laravel, etc.)
- 📊 **Multiple report formats** (JSON, HTML, Markdown)
- 🗄️ **SQLite database** for scan history
- 🐳 **Docker support** for easy deployment

## 📦 Installation

### Using pip (recommended)
```bash
git clone https://github.com/faza-kamal/AbyssForge.git
cd AbyssForge
pip install -e .
```

### Using Docker
```bash
docker build -t abyssforge .
docker run --rm abyssforge scan https://example.com?id=1
```

### Requirements
- Python 3.9+
- See `requirements.txt` for dependencies

## 🚀 Quick Start

### Basic Scan
```bash
# Scan a single URL
abyssforge scan "https://example.com?id=1"

# Scan with specific modules
abyssforge scan "https://example.com?id=1" --modules sqli,xss

# Full scan with crawling
abyssforge scan "https://example.com" --crawl --depth 3

# Scan via proxy (Burp Suite)
abyssforge scan "https://example.com?id=1" -p http://127.0.0.1:8080 --no-verify-ssl

# Scan with authentication
abyssforge scan "https://example.com/dashboard" \
  -c "session=abc123; user_id=42" \
  -H "Authorization: Bearer eyJ..."
```

### CLI Commands
```bash
# List available modules
abyssforge modules

# Fingerprint target technology
abyssforge fingerprint https://example.com

# Get help
abyssforge --help
abyssforge scan --help
```

### Programmatic Usage
```python
from abyssforge.core.engine import ScanEngine
from abyssforge.reporters.html_reporter import HTMLReporter

config = {
    "scanner": {"threads": 10, "timeout": 30, "rate_limit": 5.0},
    "modules": {
        "sqli": {"enabled": True},
        "xss": {"enabled": True},
        "misconfig": {"enabled": True},
    },
}

engine = ScanEngine(config)
result = engine.scan("https://example.com?id=1")

print(f"Found {len(result.findings)} vulnerabilities")
for finding in result.findings:
    print(f"[{finding.severity}] {finding.vuln_type}: {finding.url}")

# Generate HTML report
reporter = HTMLReporter("output")
reporter.generate(result)
```

## ⚙️ Configuration

AbyssForge uses YAML configuration files. Copy and modify `config/default_config.yaml`:

```yaml
scanner:
  threads: 10
  timeout: 30
  rate_limit: 10  # requests per second
  verify_ssl: false

proxy:
  enabled: false
  http: "http://127.0.0.1:8080"

modules:
  sqli:
    enabled: true
    time_delay: 5
  xss:
    enabled: true
    max_payloads: 30

reporting:
  format: ["json", "html"]
  output_dir: "output"
```

Use custom config:
```bash
abyssforge scan https://example.com --config my_config.yaml
```

## 📊 Report Formats

### JSON Report
Machine-readable format with full finding details:
```json
{
  "scan": {
    "scan_id": "abc123",
    "target_url": "https://example.com",
    "findings": [...]
  }
}
```

### HTML Report
Professional visual report with color-coded severity levels, filtering, and detailed evidence.

## 🏗️ Architecture

```
abyssforge/
├── core/           # Scanning engine, HTTP requests, response parser
├── modules/        # Vulnerability detection modules
│   ├── sqli/       # SQL Injection
│   ├── xss/        # Cross-Site Scripting
│   ├── csrf/       # CSRF
│   ├── lfi/        # File Inclusion
│   ├── cmd_injection/  # Command Injection
│   ├── misconfig/  # Security Misconfiguration
│   └── api_security/   # API Security
├── reporters/      # JSON, HTML, Markdown reporters
├── utils/          # Helpers, validators, logger
└── db/             # SQLite storage
```

## 🔌 Adding Custom Modules

```python
from abyssforge.modules.base import BaseModule, Finding

class MyCustomModule(BaseModule):
    MODULE_NAME = "my_module"
    VULN_TYPE = "My Vulnerability"
    SEVERITY = "high"
    CWE = "CWE-XXX"
    DESCRIPTION = "Description of the vulnerability"
    REMEDIATION = "How to fix it"

    def scan(self, url: str, **kwargs) -> list:
        self.findings = []
        # Your detection logic here
        # Call self.add_finding() when vulnerability is found
        return self.findings
```

## 🧪 Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# With coverage report
pytest tests/ --cov=abyssforge --cov-report=html

# Run specific test file
pytest tests/test_modules/test_modules.py -v
```

## 🐳 Docker

```bash
# Build
docker build -t abyssforge .

# Run scan
docker run --rm -v $(pwd)/output:/app/output abyssforge \
  scan "https://example.com?id=1" -o /app/output

# Interactive mode
docker run --rm -it abyssforge bash
```

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Usage Guide](docs/usage.md)
- [Module Reference](docs/modules.md)
- [Contributing Guide](docs/contributing.md)
- [API Reference](docs/api_reference.md)

## 🎯 Target Selection for Testing

Test against these **legal** and **intentionally vulnerable** targets:
- [DVWA](http://www.dvwa.co.uk/) - Damn Vulnerable Web Application
- [WebGoat](https://owasp.org/www-project-webgoat/) - OWASP WebGoat
- [HackTheBox](https://www.hackthebox.com/) - CTF Platform
- [TryHackMe](https://tryhackme.com/) - Security Learning Platform
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - Labs

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](docs/contributing.md) for guidelines.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-module`)
3. Write tests for your changes
4. Commit your changes (`git commit -m 'Add: new vulnerability module'`)
5. Push to the branch (`git push origin feature/new-module`)
6. Open a Pull Request

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 👤 Author

**faza-kamal**
- GitHub: [@faza-kamal](https://github.com/faza-kamal)
- Repository: [AbyssForge](https://github.com/faza-kamal/AbyssForge)

---

<p align="center">Made with ❤️ for the security community</p>
<p align="center">
  <b>Use responsibly. Hack ethically. 🔐</b>
</p>
