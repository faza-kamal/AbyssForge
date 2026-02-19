# ⚡ AbyssForge

<div align="center">

```
 █████╗ ██████╗ ██╗   ██╗███████╗███████╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
███████║██████╔╝ ╚████╔╝ ███████╗███████╗█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
██╔══██║██╔══██╗  ╚██╔╝  ╚════██║╚════██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
██║  ██║██████╔╝   ██║   ███████║███████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
╚═╝  ╚═╝╚═════╝    ╚═╝   ╚══════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

**Web Vulnerability Scanner Full-Stack yang Modular, Async, dan Profesional**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-purple?style=for-the-badge)](CHANGELOG.md)
[![Author](https://img.shields.io/badge/Author-faza--kamal-red?style=for-the-badge)](https://github.com/faza-kamal)

> ⚠️ **PERINGATAN HUKUM:** AbyssForge hanya boleh digunakan untuk pengujian keamanan yang sah pada sistem yang Anda miliki atau telah mendapat izin eksplisit tertulis dari pemilik sistem. Penggunaan tanpa izin merupakan pelanggaran hukum. Pengembang tidak bertanggung jawab atas penyalahgunaan tool ini.

</div>

---

## 📌 Daftar Isi

- [Tentang AbyssForge](#-tentang-abyssforge)
- [Fitur Utama](#-fitur-utama)
- [Struktur Proyek](#-struktur-proyek)
- [Instalasi](#-instalasi)
- [Cara Penggunaan](#-cara-penggunaan)
- [Modul Deteksi](#-modul-deteksi)
- [Severity & CVSS Grading](#-severity--cvss-grading)
- [Laporan & Dashboard](#-laporan--dashboard)
- [Arsitektur & Layering Rules](#-arsitektur--layering-rules)
- [Roadmap](#-roadmap)
- [Kontribusi](#-kontribusi)
- [Lisensi & Disclaimer](#-lisensi--disclaimer)

---

## 🔍 Tentang AbyssForge

**AbyssForge** adalah web vulnerability scanner full-stack berbasis Python yang dirancang untuk pengujian keamanan aplikasi web secara profesional. Scanner ini dibangun dengan arsitektur **asinkron penuh** menggunakan `asyncio` dan `aiohttp`, sehingga mampu menjalankan ratusan permintaan HTTP secara paralel dengan efisien dan terkendali.

AbyssForge mengadopsi prinsip **modular layering** yang ketat — setiap lapisan komponen berdiri sendiri dengan aturan ketergantungan yang jelas. Pendekatan ini memastikan bahwa penambahan fitur baru tidak merusak komponen lain, sehingga proyek ini tetap maintainable dan scalable dalam jangka panjang.

Berbeda dari scanner umum yang mengutamakan kuantitas temuan, AbyssForge dirancang dengan filosofi akurasi lebih penting dari kebisingan. Setiap modul menggunakan teknik multi-vektor untuk meminimalkan false positive sekaligus memastikan setiap temuan yang dilaporkan bersifat actionable dan didukung oleh bukti yang jelas.

---

## ✨ Fitur Utama

**Deteksi komprehensif mencakup 10 kategori kerentanan** dari level CRITICAL hingga INFO, meliputi SQL Injection (Error/Blind/Time-based), XSS (Reflected/DOM), SSRF, XXE, SSTI, CSRF, Broken Authentication, Misconfiguration, Sensitive File Exposure, dan Open Redirect.

**Arsitektur async by design** — seluruh engine, crawler, dan modul deteksi berjalan secara asinkron, dengan rate limiting bawaan, retry otomatis, dan semaphore untuk mengontrol konkurensi agar tidak membebani server target.

**Auto severity grading berbasis CVSS** — setiap temuan secara otomatis mendapat label severity (CRITICAL/HIGH/MEDIUM/LOW/INFO) berdasarkan CVSS score yang telah dikalibrasi per jenis kerentanan.

**Web crawler built-in** yang menemukan URL melalui sitemap.xml, analisis HTML (link/form/action), dan BFS depth-limited crawling dengan deduplication otomatis.

**Laporan multi-format** dalam JSON (machine-readable untuk integrasi CI/CD), HTML (interaktif dengan dark theme profesional), dan PDF (via WeasyPrint).

**Web dashboard Flask** read-only untuk memantau semua hasil scan dengan filter severity dan tombol download laporan.

**SQLite storage persisten** — semua hasil scan dan temuan tersimpan secara lokal tanpa ketergantungan server eksternal, siap diakses kapan saja untuk audit trail.

---

## 📁 Struktur Proyek

```
AbyssForge/
├── main.py                        # Entry point CLI utama
├── requirements.txt               # Dependensi Python
├── README.md
│
├── core/                          # Engine inti — bebas dari dependensi modul lain
│   ├── config.py                  # ScanConfig dataclass & CVSS mapping
│   ├── engine.py                  # Orchestrator: crawl → dispatch → collect → save
│   ├── crawler.py                 # Async web crawler (sitemap, links, forms)
│   ├── http_client.py             # AsyncHTTPClient (aiohttp wrapper dengan retry)
│   └── finding.py                 # Model data Finding dengan serialisasi JSON
│
├── modules/                       # Modul deteksi (hanya boleh import core & utils)
│   ├── injection/
│   │   ├── sqli.py                # SQL Injection: Error, Boolean-blind, Time-based
│   │   ├── xss.py                 # XSS: Reflected, DOM-based heuristik
│   │   ├── xxe.py                 # XML External Entity Injection
│   │   └── ssti.py                # Server-Side Template Injection
│   ├── broken_auth/
│   │   └── auth_check.py          # Cookie weakness, default creds, lockout check
│   ├── misconfig/
│   │   └── headers.py             # Security headers, CORS, dir listing, SSL/TLS
│   ├── exposure/
│   │   └── sensitive_files.py     # .env, .git, phpinfo, credentials, error leaks
│   └── network/
│       ├── csrf.py                # CSRF token detection, JSON CSRF
│       ├── ssrf.py                # SSRF pada parameter URL-prone
│       └── open_redirect.py       # Open Redirect pada parameter redirect-prone
│
├── database/
│   └── db.py                      # SQLite interface: scans & findings tables
│
├── reporting/
│   └── reporter.py                # Generator laporan JSON/HTML/PDF
│
├── dashboard/
│   ├── app.py                     # Flask app (read-only, tidak melakukan scan)
│   └── templates/                 # Jinja2 templates dark-themed
│       ├── index.html
│       ├── scan_detail.html
│       └── error.html
│
├── utils/
│   ├── payload_loader.py          # Loader file payload & wordlist dari data/
│   ├── url_utils.py               # Validasi, normalisasi, injeksi parameter URL
│   └── logger.py                  # Setup logging terpusat
│
├── data/
│   ├── payloads/
│   │   ├── sqli_error.txt         # Payload SQLi error-based
│   │   ├── sqli_time.txt          # Payload SQLi time-based
│   │   └── xss.txt                # Payload XSS multi-vector
│   └── wordlists/
│       └── sensitive_paths.txt    # Wordlist path file sensitif
│
└── tests/
    └── test_abyssforge.py         # Unit tests komprehensif (pytest)
```

---

## 🚀 Instalasi

### Prasyarat

- Python 3.10 atau lebih baru
- pip (Python package manager)
- Git

### Langkah Instalasi

Clone repository dan masuk ke direktori proyek:

```bash
git clone https://github.com/faza-kamal/AbyssForge.git
cd AbyssForge
```

Buat dan aktifkan virtual environment (sangat direkomendasikan untuk menghindari konflik dependensi):

```bash
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# atau
venv\Scripts\activate           # Windows
```

Install dependensi utama:

```bash
pip install -r requirements.txt
```

Untuk mengaktifkan fitur PDF report, install WeasyPrint beserta dependensi sistem yang diperlukan:

```bash
# Ubuntu/Debian
sudo apt-get install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
pip install weasyprint

# macOS (via Homebrew)
brew install pango
pip install weasyprint
```

Verifikasi instalasi berhasil:

```bash
python3 main.py --help
```

---

## 💻 Cara Penggunaan

### Scan Dasar

Perintah berikut menjalankan scan dengan modul default (sqli, xss, misconfig, exposure):

```bash
python3 main.py --scan https://target.com
```

### Full Scan

Untuk menjalankan semua modul deteksi sekaligus:

```bash
python3 main.py --scan https://target.com --full
```

### Scan Modul Tertentu

Gunakan flag `--module` untuk memilih modul yang akan dijalankan, dipisahkan koma:

```bash
# Hanya SQL Injection dan XSS
python3 main.py --scan https://target.com --module sqli,xss

# Semua modul injection
python3 main.py --scan https://target.com --module sqli,xss,xxe,ssti

# Security misconfiguration dan file exposure
python3 main.py --scan https://target.com --module misconfig,exposure

# Modul jaringan
python3 main.py --scan https://target.com --module csrf,ssrf,redirect
```

Nama modul yang tersedia: `sqli`, `xss`, `xxe`, `ssti`, `auth`, `misconfig`, `exposure`, `csrf`, `ssrf`, `redirect`.

### Opsi Lanjutan

```bash
# Atur kedalaman crawl (default: 2) dan jumlah thread paralel (default: 10)
python3 main.py --scan https://target.com --depth 3 --threads 20

# Tambah delay antar request untuk menghormati server target
python3 main.py --scan https://target.com --delay 1.5

# Authenticated scan menggunakan session cookie
python3 main.py --scan https://target.com --cookie "session=abc123xyz; PHPSESSID=def456"

# Tambah header kustom (bisa digunakan berulang untuk beberapa header)
python3 main.py --scan https://target.com --header "Authorization:Bearer eyJ..." --header "X-Custom:value"

# Output verbose untuk debugging
python3 main.py --scan https://target.com --verbose
```

### Manajemen Scan

```bash
# Tampilkan semua scan yang tersimpan
python3 main.py --list-scans
```

Output yang dihasilkan:

```
ID     Target                                   Modules                        Findings   Date
----------------------------------------------------------------------------------------------------
3      https://example.com                      sqli,xss,misconfig,exposure    7          2025-01-15 10:30:22
2      https://testsite.com                     sqli,xss                       2          2025-01-14 15:20:11
1      https://demo.com                         sqli                           0          2025-01-13 09:15:33
```

### Generate Laporan

```bash
# Laporan HTML interaktif (direkomendasikan untuk review manual)
python3 main.py --report 3 --format html

# Laporan JSON untuk integrasi dengan tool lain
python3 main.py --report 3 --format json

# Laporan PDF (membutuhkan WeasyPrint)
python3 main.py --report 3 --format pdf

# Tentukan path output secara eksplisit
python3 main.py --report 3 --format html --output /tmp/laporan_keamanan.html
```

### Menjalankan Web Dashboard

```bash
python3 main.py --dashboard

# Port kustom
python3 main.py --dashboard --port 8080
```

Setelah dashboard berjalan, buka browser dan kunjungi `http://127.0.0.1:5000`.

### Menjalankan Unit Tests

```bash
# Jalankan semua test dengan output verbose
pytest tests/ -v

# Jalankan hanya test tertentu
pytest tests/ -v -k "test_sqli"
pytest tests/ -v -k "test_database"
```

---

## 🔬 Modul Deteksi

### SQL Injection (`sqli`)

Modul ini mendeteksi tiga varian SQL Injection pada parameter GET dan form POST.

**Error-based** bekerja dengan menyisipkan payload yang memicu pesan error database (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) dan mencocokkannya dengan lebih dari 15 pola regex error signature. Setiap konfirmasi error menghasilkan temuan dengan CVSS 9.1 (CRITICAL).

**Boolean-based Blind** membandingkan panjang response antara kondisi TRUE (`OR '1'='1`) dan FALSE (`OR '1'='2`). Perbedaan body lebih dari 50 byte mengindikasikan kerentanan dengan CVSS 8.0 (HIGH), meskipun confidence dikategorikan MEDIUM karena memerlukan verifikasi manual.

**Time-based Blind** menyisipkan perintah delay spesifik per database (SLEEP untuk MySQL, WAITFOR DELAY untuk MSSQL, pg_sleep untuk PostgreSQL) dengan threshold deteksi 4 detik. Teknik ini efektif untuk kasus di mana output tidak terlihat langsung di response. CVSS: 8.5 (HIGH).

### Cross-Site Scripting (`xss`)

**Reflected XSS** menyisipkan payload dengan canary unik per request, kemudian memeriksa apakah payload muncul di response tanpa encoding HTML yang memadai. Jika payload ditemukan dalam konteks `<script>`, CVSS meningkat ke 8.8. Untuk konteks non-script, CVSS adalah 7.4 (HIGH).

**DOM-based XSS** menganalisis source code halaman untuk menemukan pola taint: sumber data tidak aman (location.search, document.referrer, window.name) yang berpotensi mengalir ke sink berbahaya (innerHTML, eval, document.write). Deteksi ini bersifat heuristik dan selalu memerlukan konfirmasi manual. CVSS: 6.5 (MEDIUM).

### XXE — XML External Entity (`xxe`)

Mengirim tiga varian payload XML dengan external entity yang merujuk ke file sistem (/etc/passwd untuk Linux, win.ini untuk Windows) serta probe blind via HTTP. Respons diperiksa terhadap pola isi file yang khas. Kerentanan XXE dapat menyebabkan file read, SSRF internal, dan dalam kasus tertentu, Remote Code Execution. CVSS: 9.1 (CRITICAL).

### SSTI — Server-Side Template Injection (`ssti`)

Menggunakan ekspresi matematis deterministik `{{7*7}}` (menghasilkan 49) sebagai probe untuk engine Jinja2, Twig, ERB, Freemarker, Velocity, dan Spring Expression Language. Deteksi positif ketika output ekspresi muncul di response, mengkonfirmasi eksekusi kode template di server. SSTI sering kali berujung pada Remote Code Execution. CVSS: 9.8 (CRITICAL).

### Broken Authentication (`auth`)

Memeriksa tiga aspek utama. Pertama, kelemahan cookie session — apakah flag Secure, HttpOnly, dan SameSite ada, serta apakah nilai token terlalu pendek atau dapat ditebak. Kedua, default credentials — mencoba kombinasi standar (admin/admin, admin/password, root/root, dll.) pada form login yang terdeteksi. Ketiga, ketiadaan account lockout — mengirim enam permintaan autentikasi berturut-turut dan memeriksa apakah server menerapkan rate limiting atau blokir akun. CVSS: 6.5–9.8.

### Misconfiguration (`misconfig`)

Memeriksa enam aspek konfigurasi keamanan. Security headers yang hilang (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) serta header information disclosure (Server, X-Powered-By). Konfigurasi CORS yang berbahaya seperti wildcard dengan credentials atau origin reflection. Directory listing yang aktif pada path umum. Path traversal dengan berbagai variasi encoding. Dukungan TLS 1.0 yang sudah deprecated. CVSS: 3.1–9.1 tergantung temuan.

### Sensitive File Exposure (`exposure`)

Memeriksa lebih dari 70 path file sensitif umum termasuk `.env`, `.git/config`, `phpinfo.php`, Spring Boot Actuator endpoints, backup database, log file, dan panel admin. Selain itu, modul ini menganalisis body response semua halaman yang di-crawl untuk mendeteksi kredensial yang terekspos (API keys, AWS credentials, private keys, JWT tokens), stack trace, dan sidik jari teknologi. CVSS: 3.7–9.8 tergantung konten yang ditemukan.

### CSRF — Cross-Site Request Forgery (`csrf`)

Memeriksa setiap form POST yang tidak memiliki CSRF token (input dengan nama csrf, _token, authenticity_token, dll.) sekaligus memeriksa apakah session cookie menggunakan atribut SameSite. Form yang tidak terlindungi sama sekali mendapat CVSS 8.8 (HIGH), sementara yang dilindungi SameSite tapi tanpa token mendapat CVSS 4.3 (MEDIUM). Modul ini juga mendeteksi API JSON yang rentan CSRF via `text/plain` form submission.

### SSRF — Server-Side Request Forgery (`ssrf`)

Mengidentifikasi parameter URL-prone (url, redirect, callback, fetch, webhook, dll.) dan menyisipkan target internal: localhost, 127.0.0.1, metadata endpoint cloud AWS (169.254.169.254), GCP, Azure, serta protokol dict://, gopher://, dan file://. Response diperiksa untuk tanda kebocoran seperti isi /etc/passwd atau instance-id cloud. CVSS: 7.2–9.8.

### Open Redirect (`redirect`)

Mengidentifikasi parameter redirect-prone (redirect, next, return_url, goto, dest, dll.) dan menyisipkan URL domain berbahaya eksternal. Deteksi positif jika response berupa redirect HTTP 3xx ke domain tersebut, atau jika URL target muncul dalam meta refresh atau JavaScript redirect. CVSS: 5.4–6.1 (MEDIUM).

---

## 📊 Severity & CVSS Grading

AbyssForge menggunakan CVSS v3.1 score sebagai dasar penilaian severity. Konversi dilakukan secara otomatis melalui fungsi `cvss_to_severity()` di `core/config.py`.

| Severity | Rentang CVSS | Indikator | Deskripsi |
|----------|-------------|-----------|-----------|
| 🔴 CRITICAL | 9.0 – 10.0 | Eksploitasi langsung, dampak sangat besar | SQLi confirmed, SSTI RCE, .env terekspos |
| 🟠 HIGH | 7.0 – 8.9 | Eksploitasi mudah atau dampak tinggi | XSS reflected, SSRF, broken auth |
| 🟡 MEDIUM | 4.0 – 6.9 | Eksploitasi memerlukan kondisi tertentu | CORS misconfiguration, CSRF |
| 🔵 LOW | 0.1 – 3.9 | Dampak minimal, konteks terbatas | Missing headers opsional, info disclosure ringan |
| ⚪ INFO | 0.0 | Informatif, bukan kerentanan langsung | Technology fingerprint, open redirect tanpa impact |

---

## 📄 Laporan & Dashboard

### Laporan HTML

Laporan HTML menggunakan dark theme profesional dengan tampilan interaktif. Setiap temuan dapat diperluas untuk melihat detail lengkap termasuk URL, parameter, method, deskripsi, evidence, payload yang digunakan, dan langkah remediasi. Temuan dengan severity CRITICAL dan HIGH otomatis terbuka saat laporan dimuat. Laporan ini sepenuhnya self-contained (satu file HTML) sehingga mudah dibagikan.

### Laporan JSON

Format JSON cocok untuk integrasi dengan pipeline CI/CD, SIEM, atau tool pengelolaan kerentanan lainnya. Setiap temuan berisi semua field termasuk metadata teknis dan referensi OWASP.

### Laporan PDF

Memerlukan WeasyPrint. Menghasilkan dokumen PDF yang identik dengan laporan HTML, cocok untuk pelaporan formal kepada klien atau manajemen.

### Web Dashboard

Dashboard Flask yang berjalan secara lokal menampilkan semua riwayat scan dalam tabel, dengan link ke detail scan individual. Dari halaman detail, Anda dapat melihat semua temuan dengan filter, dan mengunduh laporan langsung dari browser. Dashboard tidak memiliki kemampuan scan — ia hanya membaca dari database.

---

## 🏗 Arsitektur & Layering Rules

AbyssForge menerapkan aturan ketergantungan yang ketat untuk menjaga integritas arsitektur:

```
core         →  Tidak boleh import: modules, database, dashboard, reporting
modules      →  Hanya boleh import: core, utils
database     →  Tidak boleh import: core, modules, dashboard, reporting
dashboard    →  Boleh import: database, reporting (tidak boleh: core, modules langsung)
reporting    →  Boleh import: database (tidak boleh: dashboard)
utils        →  Tidak boleh import komponen lain dalam proyek
```

Aturan ini diterapkan secara manual melalui code review. Di masa depan, linter kustom atau import checker dapat ditambahkan sebagai bagian dari CI/CD pipeline.

**Prinsip dependency injection** diterapkan di `core/engine.py` — engine menerima objek `Database` dari luar (bukan mengimpornya langsung), sehingga engine tetap bebas dari ketergantungan lapisan database.

---

## 🗺 Roadmap

### V1.0 — Core Foundation ✅

Engine utama dengan crawler async, deteksi SQLi dan XSS, pemeriksaan security headers, penyimpanan SQLite, dan laporan JSON/HTML.

### V2.0 — Extended Detection (Dalam Pengembangan)

Modul SSRF, XXE, SSTI, sensitive file exposure, SSL/TLS checks, web dashboard Flask, dan laporan PDF.

### V3.0 — Advanced Capabilities (Direncanakan)

Authenticated scanning dengan session management otomatis, API endpoint scanner (REST/GraphQL), integrasi CVE database (NVD), sistem plugin yang memungkinkan penambahan modul pihak ketiga, Docker support, dan optional JavaScript rendering dengan Playwright.

---

## 🤝 Kontribusi

Kontribusi sangat diterima! Berikut panduan singkat untuk berkontribusi:

**Melaporkan bug** — Buka issue baru di GitHub dengan judul yang deskriptif, langkah reproduksi, output aktual vs yang diharapkan, dan versi Python yang digunakan.

**Menambah modul baru** — Buat file modul di direktori yang sesuai (`modules/kategori/nama.py`), implementasikan fungsi `async def scan(config, http, crawled)` dengan interface standar, tambahkan unit test di `tests/test_abyssforge.py`, dan daftarkan modul di `MODULE_MAP` dalam `core/engine.py`.

**Menambah payload** — Tambahkan entri baru ke file `.txt` yang relevan di `data/payloads/` atau `data/wordlists/`. Sertakan komentar untuk konteks jika perlu.

Pastikan semua unit test tetap lulus (`pytest tests/ -v`) sebelum mengajukan Pull Request.

---

## ⚖️ Lisensi & Disclaimer

**Lisensi MIT** — Bebas digunakan, dimodifikasi, dan didistribusikan untuk keperluan yang sah. Lihat file [LICENSE](LICENSE) untuk detail lengkap.

**Disclaimer Penggunaan:** Tool ini dikembangkan semata-mata untuk tujuan edukasi dan pengujian keamanan yang sah (*authorized penetration testing*). Penggunaan AbyssForge tanpa izin eksplisit dari pemilik sistem merupakan pelanggaran hukum dan tidak etis. Pengembang tidak bertanggung jawab atas kerusakan, kerugian, atau konsekuensi hukum yang timbul dari penyalahgunaan tool ini.

**Selalu dapatkan izin tertulis sebelum melakukan pengujian keamanan pada sistem apapun.**

---

<div align="center">

Dibuat dengan ❤️ oleh **[faza-kamal](https://github.com/faza-kamal)**

[🐛 Laporkan Bug](https://github.com/faza-kamal/AbyssForge/issues) &bull; [💡 Request Fitur](https://github.com/faza-kamal/AbyssForge/issues) &bull; [⭐ Star Repo](https://github.com/faza-kamal/AbyssForge)

</div>
