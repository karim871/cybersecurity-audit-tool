# 🔒 Cybersecurity Audit Tool v2.0

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A powerful, multi-threaded Python port scanner and security audit tool with comprehensive vulnerability detection, real-time progress tracking, and detailed reporting capabilities.

![Demo](docs/demo.gif) <!-- Add a GIF later -->

## ✨ Features

### v2.0 Enhancements
- 🚀 **Real-time Progress Bars** - Visual feedback for scan progress
- 📊 **Professional Logging** - Multi-level logging with file output
- 🏗️ **Clean Architecture** - Dataclass-based design for maintainability
- 🧪 **Comprehensive Tests** - 20+ unit and integration tests
- 🎯 **Enhanced Detection** - Advanced vulnerability identification with severity levels
- 📝 **Rich Reports** - JSON output with detailed metadata

### Core Features
- ⚡ Multi-threaded scanning (up to 500+ concurrent connections)
- 🔍 Service banner grabbing and identification
- 🌍 IP geolocation integration (ipinfo.io)
- 🚨 Vulnerability detection for dangerous services
- 📈 Configurable scan parameters
- 💾 JSON report generation
- 🎨 Clean, readable console output

## 🚀 Quick Start

### Installation
```bash
# Clone the repository
git clone https://github.com/karim871/cybersecurity-audit-tool.git
cd cybersecurity-audit-tool

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage
```bash
# Scan localhost (ALWAYS START HERE)
python src/main.py 127.0.0.1 -p 1-1000

# Fast scan with progress bar
python src/main.py 127.0.0.1 -p 1-1000 -w 500

# Full scan with report
python src/main.py 127.0.0.1 -p 1-65535 -o reports/full_scan.json -v

# Scan specific ports
python src/main.py 127.0.0.1 -p 22,80,443,3306,8080
```

### Advanced Usage
```bash
# Custom timeout and workers
python src/main.py 127.0.0.1 -p 1-10000 -t 0.5 -w 300

# Verbose logging to file
python src/main.py 127.0.0.1 -p 1-1000 -v --log scan.log

# With geolocation (requires API token)
python src/main.py 8.8.8.8 -p 1-100 --api-token YOUR_TOKEN
```

## 📖 Documentation

- [Migration Guide (v1 → v2)](docs/migration-guide.md)
- [API Documentation](docs/api.md)
- [Learning Exercises](docs/exercises.md)
- [Contributing Guidelines](CONTRIBUTING.md)

## 🧪 Testing
```bash
# Run all tests
python tests/test_suite.py

# With pytest
pytest tests/ -v

# With coverage
pytest tests/ --cov=src --cov-report=html
```

## 📊 Performance

| Metric | v1.0 | v2.0 | Improvement |
|--------|------|------|-------------|
| 1000 ports | ~45s | ~8s | **5.6x faster** |
| Memory usage | ~80MB | ~45MB | **44% reduction** |
| False positives | ~15% | ~5% | **67% reduction** |

## ⚠️ Legal Notice

**IMPORTANT:** This tool is for educational purposes and authorized security testing only.

### Legal Use Cases:
✅ Your own systems (localhost, personal VMs)
✅ Authorized penetration testing engagements
✅ Security research in controlled environments
✅ Educational labs (HackTheBox, TryHackMe)
✅ Explicitly authorized targets (e.g., scanme.nmap.org)

### NEVER Use On:
❌ Systems you don't own
❌ Networks without written permission
❌ Production systems without authorization
❌ Any system where scanning is prohibited

Unauthorized scanning may be **illegal** and could result in criminal prosecution.

## 🎓 Learning Path

This tool is designed for cybersecurity students and professionals. Check out the [learning exercises](docs/exercises.md) for:

- Week-by-week learning plans
- Real-world scenarios
- CTF-style challenges
- Career development guidance
- Certification preparation (Security+, CySA+, OSCP)

## 📝 What's New in v2.0
```python
# Before (v1.0)
python main.py 127.0.0.1 1 1000
# No progress feedback, basic output

# After (v2.0)
python src/main.py 127.0.0.1 -p 1-1000 -v
# [████████████████████░░░░] 80% | 800/1000 ports
# [+] Port 22 (SSH) - OPEN
# [!] Found 3 vulnerabilities
```

See [CHANGELOG.md](CHANGELOG.md) for full details.

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas where we'd love help:
- Additional vulnerability signatures
- Performance optimizations
- New scan types (UDP, SYN)
- Enhanced reporting formats
- Documentation improvements

## 📜 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by [Nmap](https://nmap.org/)
- Built with Python's networking libraries
- For and thanks to the cybersecurity community

## 📬 Contact

- **Author:** Abdelkrim Zouaki
- **Portfolio:** [karim871.github.io](https://karim871.github.io/)
- **Blog Post:** [Building a Cybersecurity Audit Tool](https://karim871.github.io/Portfolio/secondarypages/cybersecurity-audit-tool-blog.html)


---

**⭐ If this tool helped you learn, please star the repo!**

**🐛 Found a bug? [Open an issue](https://github.com/karim871/cybersecurity-audit-tool/issues)**
