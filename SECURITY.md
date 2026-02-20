# Security Policy

## Supported Versions

| Version       | Supported          |
| ------------- | ------------------ |
| 0.2.1-alpha   | :white_check_mark: |
| 0.2.0-alpha   | :x:                |
| 0.1.0-alpha   | :x:                |

## Reporting a Vulnerability

We take the security of Memory Vault seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via:

1. **GitHub Security Advisories**: Use the "Report a vulnerability" button on the Security tab of this repository
2. **Email**: Send details to the repository maintainer (see commit history for contact)

### What to Include

Please include the following information to help us triage your report:

- Type of vulnerability (e.g., cryptographic weakness, authentication bypass, information disclosure)
- Full paths of source file(s) related to the vulnerability
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if available)
- Impact assessment and potential attack scenarios

### Response Timeline

- **Initial Response**: Within 48 hours
- **Severity Assessment**: Within 5 business days
- **Fix Development**: Depends on severity (Critical: 7 days, High: 14 days, Medium: 30 days)
- **Public Disclosure**: Coordinated with reporter, typically 90 days after fix

### Security Measures in Memory Vault

Memory Vault implements multiple layers of security:

#### Cryptographic Standards
- **Encryption**: XSalsa20-Poly1305 (authenticated encryption)
- **Key Derivation**: Argon2id with maximum security parameters (1GB memory, 4 iterations)
- **Signing**: Ed25519 for audit trail integrity
- **Implementation**: libsodium via PyNaCl (audited, constant-time operations)

#### Access Control
- **6-Level Classification System**: From ephemeral (Level 0) to physically-gated (Level 5)
- **Cooldown Enforcement**: Per-memory access throttling
- **Human Approval Gates**: Required for Level 3+ recalls
- **Boundary Daemon Integration**: Runtime environment validation

#### Audit & Integrity
- **Merkle Tree Audit Trail**: Tamper-evident logging of all operations
- **Zero-Knowledge Proofs**: Prove existence without revealing content
- **Tombstone System**: Mark memories inaccessible while preserving audit trail

#### Fail-Safe Mechanisms
- **Fail-Closed Design**: All operations denied if security checks cannot complete
- **Lockdown Mode**: Emergency disable of all recalls
- **No Plaintext Persistence**: Decrypted content never written to disk

### Known Limitations

1. **TPM Support**: TPM sealing code is implemented but not validated on hardware
2. **FIDO2**: Device verification works but full credential lifecycle not implemented
3. **Side-Channel Attacks**: While PyNaCl uses constant-time operations, the Python layer may leak timing information

### Security Best Practices for Users

1. Use strong, unique passphrases for Human Passphrase profiles
2. Store keyfiles on encrypted storage only
3. Enable TPM sealing for high-security deployments (after validation)
4. Regular backup of vault with encrypted backup feature
5. Monitor audit logs for unauthorized access attempts
6. Use physical tokens for Level 5 (Black) classification

## Security Updates

Security updates are released as patch versions and announced via:
- GitHub Releases
- Security Advisories (for critical vulnerabilities)

Users are encouraged to watch the repository for security-related releases.
