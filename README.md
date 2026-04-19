# Cybersecurity Audit Tool

A multi-threaded network security scanner built in Python. Scans 1,000 ports in under 10 seconds, identifies open services via banner grabbing, flags dangerous configurations, and cross-references discovered services against NVD CVE data.

**[Read the full build writeup →](https://karim871.github.io/Portfolio/secondarypages/cybersecurity-audit-tool-blog.html)**

---

## Features

- Multi-threaded scanning via `ThreadPoolExecutor` — up to 500 concurrent workers
- Service fingerprinting via TCP banner grabbing
- Severity-rated vulnerability detection (LOW / MEDIUM / HIGH / CRITICAL)
- Real-time CVE lookups from NVD API v2.0 with 7-day TTL cache
- Geolocation context via IPinfo.io
- Structured JSON report export
- Real-time progress bars (`tqdm`)
- 20+ unit and integration tests, ~85% code coverage

## Quick Start

```bash
git clone https://github.com/karim871/cybersecurity-audit-tool.git
cd cybersecurity-audit-tool
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Basic scan (always test on localhost first)
python src/main.py 127.0.0.1 -p 1-1000

# Fast scan with verbose output
python src/main.py 127.0.0.1 -p 1-1000 -w 500 -v

# Full scan with CVE intelligence + JSON report
python src/main.py 127.0.0.1 -p 1-65535 --enable-cve -o reports/scan.json
```

## Options

```
positional arguments:
  target                Target IP address or hostname

options:
  -p, --ports PORTS     Port range (default: 1-1000). Examples: 1-1000, 22,80,443
  -t, --timeout TIMEOUT Connection timeout in seconds (default: 1.0)
  -w, --workers WORKERS Concurrent workers (default: 100, max: 500)
  -v, --verbose         Verbose output
  -o, --output FILE     Save results to JSON file
  --enable-cve          Cross-reference services against NVD CVE database
  --api-token TOKEN     IPinfo.io API token for geolocation
```

## Running Tests

```bash
python tests/test_suite.py
# or with pytest:
pytest tests/ -v --cov=src
```

## Legal Notice

For **educational purposes and authorized testing only**. Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal in most jurisdictions. Safe targets: localhost, your own VMs, HackTheBox/TryHackMe labs, scanme.nmap.org.

## License

MIT — see [LICENSE](LICENSE).

---

**Author:** Abdelkrim Zouaki · [Portfolio](https://karim871.github.io/Portfolio/) · Montreal, QC
