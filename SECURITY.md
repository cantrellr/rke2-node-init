# Security Policy

## Supported Versions

Security fixes are applied to actively maintained code on the default branch.

| Version | Supported |
| ------- | --------- |
| `main` | :white_check_mark: |
| Tags/releases based on `main` | Case-by-case |
| Historical branches | :x: |

## Reporting a Vulnerability

Please do **not** open public GitHub issues, pull requests, or discussions for suspected vulnerabilities.

Use the private reporting path first so the maintainer can validate impact, prepare a fix, and coordinate disclosure before details are public.

### Preferred Reporting Channel

Use GitHub private vulnerability reporting / Security Advisories:

1. Go to the repository **Security** tab.
2. Open **Security advisories**.
3. Select **Report a vulnerability**.
4. Include the technical details listed below.

Direct link:

<https://github.com/cantrellr/rke2-node-init/security/advisories/new>

### Alternate Reporting Channel

If GitHub Security Advisories are unavailable, contact the maintainer privately and include `SECURITY` in the subject.

Do not include secrets, private keys, registry credentials, kubeconfigs, or production-only IP/addressing details in public issues or PRs.

## What To Include In A Security Report

Please include the following whenever possible:

- Vulnerability type and concise description.
- Affected components and paths, for example `bin/`, `scripts/`, `configs/`, `.github/workflows/`, or generated systemd units.
- Affected version, commit SHA, branch, or tag.
- Reproduction steps or proof-of-concept in a safe lab environment.
- Security impact and likely exploitability.
- Whether exploitation requires root, local shell access, repository write access, cluster-admin access, registry access, or network adjacency.
- Suggested remediation or mitigation, if available.
- Whether you want public reporter credit or anonymity.
- Contact details for follow-up.

## Coordinated Disclosure Process

- We follow coordinated disclosure practices.
- We will acknowledge receipt, triage, and provide status updates.
- We ask reporters to avoid public disclosure until a fix or mitigation is available.
- Reporter credit is provided unless anonymity is requested.
- If a fix requires code changes, the maintainer may prepare a private advisory branch or a public PR with sensitive details omitted.

## Response Targets

These are targets, not guarantees:

| Severity | Initial response | Triage target | Remediation target |
| --- | ---: | ---: | ---: |
| Critical | 48 hours | 5 business days | 7 days |
| High | 48 hours | 5 business days | 14 days |
| Medium | 48 hours | 5 business days | 30 days |
| Low | 48 hours | 5 business days | 90 days |

## Security Scope

In-scope repository content includes:

- Runtime automation and orchestration code in `bin/` and `scripts/`.
- Manifest and configuration handling in `configs/` and `examples/`.
- Test helpers and validation scripts in `tests/`.
- CI validation logic in `.github/workflows/`.
- Documentation that directly affects secure operation.

Out-of-scope items generally include:

- Third-party vulnerabilities that are not introduced by this repository.
- Misconfiguration of external infrastructure outside this project.
- Public data with no security impact.
- Vulnerabilities requiring leaked credentials or private keys that were not committed to this repository.

## Repository Access And Contribution Security

This repository is public so anyone may clone it, inspect it, fork it, and propose changes through pull requests.

Direct write access to the upstream repository is restricted to the repository owner, explicitly approved maintainers, and approved automation. Public users should not expect upstream branch creation or direct commits to be available.

Security-sensitive changes should follow this flow:

1. Report privately through GitHub Security Advisories.
2. Coordinate mitigation details with the maintainer.
3. Open or review a public PR only after sensitive exploitation details have been removed or the issue is already mitigated.

For non-security changes, follow [CONTRIBUTING.md](CONTRIBUTING.md).

## Hardening And Safe Operation Guidance

1. Secrets and key handling
   - Never commit private keys, tokens, kubeconfigs, registry credentials, or production-only environment secrets.
   - Treat all material under environment-scoped paths, for example `configs/cotpa/certs/` and `configs/preprod/certs/`, as sensitive unless it is explicitly documented as sample data.
   - Use restrictive permissions (`600` for sensitive files, `700` for private key directories).

2. Certificate lifecycle
   - Generate and rotate certificates using `scripts/certs/` tooling.
   - Validate trust chains before promotion to production-like environments.
   - Keep root CA keys offline whenever possible.

3. Air-gap artifact integrity
   - Verify checksums/signatures of downloaded artifacts before staging.
   - Keep staging inputs immutable after verification.
   - Prefer internal registry mirroring with TLS and authenticated access.

4. Privilege and execution controls
   - Run scripts with least privilege; note that some actions require root for system changes.
   - Execute from controlled administrative hosts and keep audit records of runs.
   - Review generated systemd units and runtime configs before enabling services in production-like environments.

5. Configuration hygiene
   - Use `configs/` manifests as templates and sanitize sensitive fields before sharing.
   - Validate YAML and rendered runtime configuration before deployment.
   - Do not include production-only hostnames, tokens, private registry credentials, or private CA keys in issue reports.

6. Continuous verification
   - Use repository test and validation scripts prior to merges and release cuts.
   - Run `scripts/run_vuln_scan.sh` regularly in CI or controlled admin environments.
   - Keep GitHub security features enabled where available: Dependabot alerts, Dependabot security updates, secret scanning, push protection, CodeQL/code scanning, and private vulnerability reporting.

## Known Security Considerations

1. Root-level operations are required for networking, package installation, and service management.
2. Sensitive values may exist in process memory during execution.
3. Registry authentication material may be written to `/etc/rancher/rke2/registries.yaml`; enforce strict permissions.
4. Air-gapped operation reduces external dependency risk but increases the importance of internal artifact integrity.
5. Public examples and manifests should remain sanitized templates, not production inventories.

## Security Updates

Security-related fixes are communicated through:

- [CHANGELOG.md](CHANGELOG.md)
- GitHub Security Advisories
- Tagged releases and CVE references when applicable

## Questions

For non-vulnerability security questions, open a standard GitHub issue using the appropriate issue template.

---

Last updated: 2026-06-24
