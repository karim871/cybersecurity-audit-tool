# Contributing to Cybersecurity Audit Tool

Thank you for your interest in contributing! 🎉

## How to Contribute

### Reporting Bugs

1. Check if the bug already exists in [Issues](https://github.com/karim871/cybersecurity-audit-tool/issues)
2. If not, create a new issue with:
   - Clear description of the bug
   - Steps to reproduce
   - Expected vs actual behavior
   - Your environment (OS, Python version)

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Describe the feature and its use case
3. Explain why it would be valuable

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Add tests for new functionality
5. Run tests: `python tests/test_suite.py`
6. Commit: `git commit -m "Add amazing feature"`
7. Push: `git push origin feature/amazing-feature`
8. Open a Pull Request

## Development Setup
```bash
git clone https://github.com/karim871/cybersecurity-audit-tool.git
cd cybersecurity-audit-tool
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python tests/test_suite.py
```

## Code Style

- Follow PEP 8
- Use type hints where appropriate
- Add docstrings to functions and classes
- Keep functions focused and under 50 lines

## Testing

- Write tests for new features
- Maintain code coverage above 80%
- Run `python tests/test_suite.py` before submitting PR

## Questions?

Open an issue or reach out via [my portfolio](https://karim871.github.io/).

Thanks for contributing! 🙏
