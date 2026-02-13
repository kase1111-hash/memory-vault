# Support

This document provides guidance on how to get help with Memory Vault.

## Documentation

Before seeking support, please review the available documentation:

| Document | Description |
|----------|-------------|
| [README.md](README.md) | Quick start guide and feature overview |
| [SPECIFICATION.md](SPECIFICATION.md) | Full technical specification |
| [RECOVERY.md](RECOVERY.md) | Data recovery procedures |
| [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) | Integration guides for external systems |
| [SECURITY.md](SECURITY.md) | Security policy and vulnerability reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup and contribution guidelines |

## Getting Help

### GitHub Issues

For bugs or feature requests, please [open an issue](https://github.com/kase1111-hash/memory-vault/issues/new/choose) on GitHub.

**Before opening an issue:**
- Search existing issues to avoid duplicates
- For bugs, include reproduction steps, Python version, and OS
- For feature requests, describe the use case and consider security implications

### GitHub Discussions

For general questions, ideas, or community discussions, use [GitHub Discussions](https://github.com/kase1111-hash/memory-vault/discussions).

Appropriate topics:
- Questions about usage and best practices
- Architecture and design discussions
- Integration help and examples
- Community showcase of projects using Memory Vault

### Security Issues

**Do not report security vulnerabilities through public GitHub issues.**

See [SECURITY.md](SECURITY.md) for responsible disclosure procedures.

## Support Response Times

Memory Vault is an open source project maintained by volunteers. Response times vary based on maintainer availability.

- **Security issues**: Prioritized, typically acknowledged within 48 hours
- **Bug reports**: Addressed based on severity and impact
- **Feature requests**: Reviewed and discussed with the community
- **General questions**: Best-effort response

## Self-Help Resources

### Common Issues

1. **Installation problems**: Ensure Python 3.8+ is installed and pip is up to date
2. **TPM errors**: TPM support is Linux-only and requires hardware
3. **Token authentication**: See Physical Token Setup in README.md
4. **Database errors**: Check file permissions on the vault database

### Debugging

Use the following commands for troubleshooting:

```bash
# Verify vault integrity
python -m memory_vault.cli verify-integrity

# Check lockdown status
python -m memory_vault.cli lockdown-status

# List all profiles
python -m memory_vault.cli list-profiles
```

## Commercial Support

Commercial support is not currently available. For enterprise inquiries, please open a GitHub Discussion.

## Contributing Back

The best way to ensure long-term support is to contribute to the project:

- Report bugs with detailed reproduction steps
- Submit fixes for issues you encounter
- Improve documentation where unclear
- Share your integration experiences

See [CONTRIBUTING.md](CONTRIBUTING.md) to get started.
