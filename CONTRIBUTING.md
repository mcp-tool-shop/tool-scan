# Contributing to Tool-Scan

Thank you for your interest in contributing to Tool-Scan! This document provides guidelines for contributing.

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/mcp-tool-shop/tool-scan.git
cd tool-scan
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

3. Install development dependencies:
```bash
pip install -e ".[dev]"
```

4. Run tests:
```bash
pytest
```

## Code Style

- Follow PEP 8
- Use type hints
- Maximum line length: 100 characters
- Run `ruff check .` before committing

## Testing

- All new features must have tests
- Maintain test coverage above 90%
- Run `pytest --cov` to check coverage

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `pytest`
5. Run linting: `ruff check .`
6. Commit with descriptive message
7. Push and create a Pull Request

## Adding Security Patterns

When adding new security detection patterns:

1. Add the pattern to the appropriate list in `security_scanner.py`
2. Include:
   - Regex pattern
   - Description
   - Severity level (LOW, MEDIUM, HIGH, CRITICAL)
3. Add test cases in `tests/test_security_scanner.py`
4. Update documentation if needed

## Reporting Vulnerabilities

For security vulnerabilities, please email security@mcptoolshop.com instead of creating a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
