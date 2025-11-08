# Security Policy

## Supported Versions

We actively support the latest version of rke2-node-init. Security patches will be applied to the current release.

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < main  | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in rke2-node-init, please report it responsibly.

### How to Report

**Please DO NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report security vulnerabilities through one of the following methods:

1. **GitHub Security Advisories (Preferred)**
   - Navigate to the [Security tab](https://github.com/cantrellr/rke2-node-init/security/advisories)
   - Click "Report a vulnerability"
   - Provide detailed information about the vulnerability

2. **Email**
   - Contact the repository maintainer directly
   - Include "SECURITY" in the subject line
   - Provide detailed information about the vulnerability

### What to Include

When reporting a vulnerability, please include:

- **Description**: A clear description of the vulnerability
- **Impact**: The potential impact and severity of the issue
- **Steps to Reproduce**: Detailed steps to reproduce the vulnerability
- **Affected Versions**: Which versions are affected
- **Proposed Fix**: If you have suggestions for fixing the issue
- **Your Contact Information**: How we can reach you for follow-up

### Response Timeline

- **Initial Response**: Within 48 hours of report submission
- **Triage**: Within 5 business days
- **Fix Timeline**: Depends on severity
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: 90 days

### Security Best Practices

When using rke2-node-init:

1. **Credential Management**
   - Never commit certificates, private keys, or tokens to version control
   - Use the provided `.gitignore` patterns to prevent accidental commits
   - Store sensitive data in production paths (`configs/production/`) which are git-ignored

2. **Certificate Handling**
   - Rotate certificates regularly
   - Use certificate generation scripts in `certs/scripts/`
   - Keep private keys with restrictive permissions (600 or 400)

3. **Air-Gapped Deployments**
   - Verify checksums for all downloaded artifacts
   - Use registry mirroring with authentication
   - Implement custom CA trust chains properly

4. **Script Execution**
   - Always review scripts before execution
   - Run with minimal required privileges (though root is required for system modifications)
   - Enable audit logging in production environments

5. **Configuration Files**
   - Use example configurations as templates only
   - Sanitize configuration files before sharing
   - Validate YAML syntax and content before deployment

### Known Security Considerations

1. **Root Execution Required**: The script requires root privileges to modify system networking, install packages, and configure services. This is inherent to the operations performed.

2. **Sensitive Data in Memory**: During execution, tokens and credentials are temporarily held in memory. The script uses best practices to minimize exposure.

3. **Registry Authentication**: Registry credentials are stored in `/etc/rancher/rke2/registries.yaml`. Ensure proper file permissions (600) are maintained.

4. **Offline Operations**: Most operations are designed for air-gapped environments, minimizing external attack surface.

### Disclosure Policy

- We follow **coordinated disclosure** principles
- We will work with reporters to understand and fix the issue
- Public disclosure will occur after a fix is available
- We will credit reporters (unless they prefer to remain anonymous)

### Security Updates

Security updates will be:
- Announced in the CHANGELOG.md
- Tagged with appropriate version numbers
- Communicated through GitHub Security Advisories
- Documented with CVE identifiers when applicable

## Questions?

If you have questions about this security policy, please open a general issue (not for vulnerabilities) or contact the maintainer.

---

Last Updated: 2025-11-08
