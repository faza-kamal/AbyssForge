# Changelog — AbyssForge

Semua perubahan penting pada proyek ini didokumentasikan di sini.

---

## [1.0.0] — 2025-01-15

### Ditambahkan
- Core engine async (asyncio + aiohttp) dengan ScanConfig, ScanEngine, WebCrawler, AsyncHTTPClient
- Model data Finding dengan severity grading otomatis berbasis CVSS v3.1
- Modul SQL Injection: error-based, boolean-blind, time-based blind
- Modul XSS: reflected dan DOM-based heuristik
- Modul XXE: file read dan OOB probe
- Modul SSTI: dukungan Jinja2, Twig, ERB, Freemarker, Velocity, Spring EL
- Modul Broken Auth: cookie weakness, default credentials, account lockout check
- Modul Misconfiguration: security headers, CORS, directory listing, path traversal, SSL/TLS
- Modul Sensitive File Exposure: 70+ sensitive paths, credentials detection, fingerprinting
- Modul CSRF: form token check, JSON CSRF
- Modul SSRF: metadata cloud probing, internal service detection
- Modul Open Redirect: parameter-based dan JavaScript redirect detection
- Database SQLite dengan schema scans + findings
- Reporter JSON/HTML/PDF (PDF opsional via WeasyPrint)
- Flask web dashboard (read-only)
- CLI lengkap dengan argparse
- Unit tests komprehensif (pytest)
- Payload files: sqli_error.txt, sqli_time.txt, xss.txt
- Wordlist: sensitive_paths.txt

---

## [2.0.0] — Direncanakan

### Akan Ditambahkan
- SSL/TLS extended checks (cipher suites, certificate expiry)
- Authenticated scanning mode
- PDF report yang disempurnakan
- Dashboard dengan grafik statistik
- Plugin system dasar

---

## [3.0.0] — Direncanakan

- CVE database integration (NVD)
- API scanner (REST/GraphQL endpoint discovery)
- JavaScript rendering dengan Playwright
- Docker support
- Plugin marketplace
