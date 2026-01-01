# Contributing to Memory Vault

Thank you for your interest in contributing to Memory Vault! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## Getting Started

### Prerequisites

- Python 3.8 or higher (3.10+ recommended)
- Git
- Virtual environment tool (venv, virtualenv, or conda)

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/kase1111-hash/memory-vault.git
   cd memory-vault
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install development dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

5. **Run tests to verify setup**
   ```bash
   pytest tests/ -v
   ```

## Development Workflow

### Before Making Changes

1. Create a new branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. Ensure you understand the existing code patterns by reading:
   - `SPECIFICATION.md` for architectural decisions
   - Existing code in similar modules

### Making Changes

1. **Write code following existing patterns**
   - Follow the existing code style
   - Keep functions focused and reasonably sized
   - Add docstrings for public functions and classes

2. **Security considerations**
   - Never log or print sensitive data (keys, plaintext, etc.)
   - Use constant-time comparisons for security-critical comparisons
   - Validate all inputs, especially from external sources
   - Follow the principle of least privilege

3. **Run linting**
   ```bash
   ruff check .
   ruff format --check .
   ```

4. **Run tests**
   ```bash
   pytest tests/ -v
   ```

5. **Check for security issues**
   ```bash
   pip-audit
   ruff check --select=S .  # Security-focused linting
   ```

### Commit Guidelines

- Write clear, concise commit messages
- Use present tense ("Add feature" not "Added feature")
- Reference issues when applicable: "Fix #123: Handle edge case"

Example:
```
Add cooldown bypass for emergency recalls

- Add emergency_override parameter to recall_memory
- Require Level 5 approval for emergency bypasses
- Log all emergency recalls with elevated priority

Closes #42
```

### Submitting Changes

1. **Push your branch**
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create a Pull Request**
   - Provide a clear description of the changes
   - Reference any related issues
   - Describe how to test the changes

3. **Respond to review feedback**
   - Make requested changes in new commits
   - Discuss any disagreements respectfully

## Testing

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=. --cov-report=term-missing

# Run specific test file
pytest tests/test_smoke.py -v

# Run specific test
pytest tests/test_smoke.py::TestCryptography::test_key_derivation_deterministic -v
```

### Writing Tests

- Add tests for new functionality in the `tests/` directory
- Follow existing test patterns
- Test both success and failure cases
- For security features, test edge cases and attack scenarios

### Test File Naming

- `test_<module>.py` - Unit tests for a specific module
- `test_integration_<feature>.py` - Integration tests

## Types of Contributions

### Bug Reports

When filing a bug report, include:
- Python version and OS
- Steps to reproduce
- Expected vs actual behavior
- Error messages and stack traces

### Feature Requests

- Describe the use case
- Explain why existing features don't meet the need
- Consider security implications

### Documentation

- Fix typos and improve clarity
- Add examples for complex features
- Keep documentation up to date with code changes

### Security Improvements

- See [SECURITY.md](SECURITY.md) for vulnerability reporting
- Security improvements should be discussed before implementation
- Consider threat model implications

## Architecture Guidelines

### Module Organization

| Module | Purpose |
|--------|---------|
| `vault.py` | Core MemoryVault class and API |
| `crypto.py` | Cryptographic operations |
| `db.py` | Database schema and operations |
| `cli.py` | Command-line interface |
| `models.py` | Data models and types |

### Security Principles

1. **Fail-closed**: Default to denying access
2. **Least privilege**: Request minimum necessary permissions
3. **Defense in depth**: Multiple layers of security
4. **Audit everything**: Log security-relevant events

### Code Style

- Maximum line length: 120 characters
- Use type hints for function signatures
- Docstrings for public APIs
- Comments for complex logic

## Release Process

Releases are managed by maintainers following semantic versioning:
- **MAJOR**: Breaking API changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, security updates

## Questions?

- Open a GitHub Discussion for general questions
- Open an Issue for bugs or feature requests
- See [SECURITY.md](SECURITY.md) for security concerns

Thank you for contributing to Memory Vault!
