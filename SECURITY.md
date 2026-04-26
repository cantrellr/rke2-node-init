# Security Policy

## Supported Versions

Security fixes are applied to actively maintained code on the default branch.

| Version | Supported |
| ------- | --------- |
| main | :white_check_mark: |
| < main | :x: |

## Reporting a Vulnerability

Please do not open public issues for vulnerability reports.

### Preferred Reporting Channel

Use GitHub Security Advisories:

1. Go to the [Security Advisories page](https://github.com/cantrellr/rke2-node-init/security/advisories)
2. Select **Report a vulnerability**
3. Provide technical details and impact assessment

### Alternate Reporting Channel

If GitHub Advisories are unavailable, contact the maintainer privately and include `SECURITY` in the message subject.

## What To Include In A Report

Please include the following whenever possible:

- Vulnerability type and concise description
- Affected components and paths (for example, `bin/rke2nodeinit.sh`, `scripts/`, or `configs/`)
- Reproduction steps or proof-of-concept
- Impact and likely exploitability
- Suggested remediation (if available)
- Contact details for follow-up

## Coordinated Disclosure Process

- We follow coordinated disclosure practices.
- We will acknowledge receipt, triage, and provide status updates.
- We ask reporters to avoid public disclosure until a fix or mitigation is available.
- Reporter credit is provided unless anonymity is requested.

## Response Targets

These are targets, not guarantees:

- Initial response: within 48 hours
- Triage decision: within 5 business days
- Remediation target by severity:
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: 90 days

## Security Scope

In-scope repository content includes:

- Runtime automation and orchestration code in `bin/` and `scripts/`
- Manifest and configuration handling in `configs/`
- Test helpers and validation scripts in `tests/`
- CI validation logic in `.github/workflows/`

Out-of-scope items generally include:

- Third-party vulnerabilities that are not introduced by this repository
- Misconfiguration of external infrastructure outside this project
- Public data with no security impact

## Hardening And Safe Operation Guidance

1. Secrets and key handling
   - Never commit private keys, tokens, kubeconfigs, or registry credentials.
   - Treat all material under environment-scoped paths (for example `configs/cotpa/certs/` and `configs/preprod/certs/`) as sensitive.
   - Use restrictive permissions (`600` for sensitive files, `700` for private key directories).

2. Certificate lifecycle
   - Generate and rotate certificates using `scripts/certs/` tooling.
   - Validate trust chains before promotion to production-like environments.

3. Air-gap artifact integrity
   - Verify checksums/signatures of downloaded artifacts before staging.
   - Keep staging inputs immutable after verification.
   - Prefer internal registry mirroring with TLS and authenticated access.

4. Privilege and execution controls
   - Run scripts with least privilege; note that some actions require root for system changes.
   - Execute from controlled administrative hosts and keep audit records of runs.

5. Configuration hygiene
   - Use `configs/` manifests as templates and sanitize sensitive fields before sharing.
   - Validate YAML and rendered runtime configuration before deployment.

6. Continuous verification
   - Use repository test and validation scripts prior to merges and release cuts.
   - Run `scripts/run_vuln_scan.sh` regularly in CI or controlled admin environments.

## Known Security Considerations

1. Root-level operations are required for networking, package installation, and service management.
2. Sensitive values may exist in process memory during execution.
3. Registry authentication material may be written to `/etc/rancher/rke2/registries.yaml`; enforce strict permissions.
4. Air-gapped operation reduces external dependency risk but increases importance of internal artifact integrity.

## Security Updates

Security-related fixes are communicated through:

- [CHANGELOG.md](CHANGELOG.md)
- GitHub Security Advisories
- Tagged releases (and CVE references when applicable)

## Questions

For non-vulnerability security questions, open a standard GitHub issue.

---

Last Updated: 2026-04-25
