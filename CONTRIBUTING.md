# Contributing to rke2-node-init

Thanks for contributing. This guide covers the current workflow, repository layout, validation requirements, access model, and documentation expectations.

## Repository Access Model

This repository is public so anyone may:

- Clone the repository.
- Fork the repository.
- Open issues for non-security bugs, enhancements, and documentation requests.
- Open pull requests from a fork.

Direct upstream write access is intentionally restricted. Only the repository owner, explicitly approved maintainers, and approved automation may create branches or push commits in `cantrellr/rke2-node-init`.

External contributors should use a fork-based workflow unless they have been explicitly granted write access.

```bash
git clone https://github.com/cantrellr/rke2-node-init.git
cd rke2-node-init
# For external contributors, fork first, then push to your fork and open a PR.
```

## Security Issues

Do not open public issues or PRs for vulnerabilities. Follow [SECURITY.md](SECURITY.md) and use GitHub private vulnerability reporting whenever possible.

Security-sensitive changes should not expose proof-of-concept exploit details, private infrastructure details, tokens, private keys, kubeconfigs, registry credentials, or production-only hostnames/IPs in public content.

## Prerequisites

- Bash 4+
- Python 3.11+ for validation tooling
- Python package tooling (`pip`) for the internal IPAM app under `apps/ipam/`
- `shellcheck`, `yamllint`, and `markdownlint` available locally
- Familiarity with RKE2 air-gapped deployment patterns

## Repository Layout (Current)

```text
.
├── bin/                    # Main executable and helper scripts
├── configs/                # Environment and cluster rkeprep/v2 YAML manifests
├── docs/                   # Technical docs and redesign archive
├── examples/               # Demo scripts and YAML examples
├── scripts/                # Supporting utilities and operational scripts
├── tests/                  # Bash-based test and CI validation scripts
├── vm/                     # vSphere provisioning scripts and templates
└── vm-configs/             # VM GitOps schema + declarative VM configs
```

## Development Workflow

### Maintainer workflow

1. Create a feature branch from `main`.
2. Keep changes scoped: code, config, tests, and docs updated together.
3. Run local validation before opening a PR.
4. Open a PR with test evidence and impacted docs list.
5. Wait for required checks and review before merging.
6. Delete the feature branch after merge.

### External contributor workflow

1. Fork the repository.
2. Create a branch in your fork.
3. Make changes without committing secrets or production-only details.
4. Run validation locally.
5. Open a pull request against `cantrellr/rke2-node-init:main`.
6. Complete the PR template, including test evidence and risk/rollback notes.
7. Respond to maintainer review comments.

## Pull Request Expectations

Each PR should include:

- Problem statement and rationale.
- Technical summary of changes.
- Validation evidence with commands and results.
- Docs updated list.
- Risk/rollback notes for operational changes.
- Confirmation that no secrets, private keys, kubeconfigs, or real registry credentials were committed.

Pull requests that touch runtime behavior, CI, manifests, systemd units, certificates, registry behavior, networking, or security-sensitive code should be treated as operational changes and include a clear rollback path.

## Local Validation Checklist

### Bash

```bash
shellcheck bin/*.sh
shellcheck scripts/*.sh
shellcheck tests/*.sh
```

### YAML / JSON

```bash
yamllint configs examples vm-configs
python3 scripts/vm-config/config_validator.py vm-configs/ --all
python3 -c "import json; json.load(open('vm-configs/schema.json'))"
```

### Markdown

```bash
markdownlint README.md CONTRIBUTING.md SECURITY.md docs/**/*.md scripts/**/*.md examples/**/*.md
```

### Internal IPAM App

```bash
python -m pip install -e ./apps/ipam[dev]
PYTHONPATH=apps/ipam/src python -m pytest apps/ipam/tests
```

### Repository Tests

```bash
bash tests/test_hardened_cni_fetch.sh
bash tests/test_truncated_image_staging.sh
bash tests/test_verify_stage_images.sh
bash tests/verify_no_duplicate_tokenfile.sh
bash tests/ci/test_ca_generation.sh
bash tests/ci/test_subordinate_encryption.sh
```

For single-node changes, also run:

```bash
bash tests/test-single-node-profile.sh
```

## CI Workflows You Should Expect

- `.github/workflows/validate-rke-configs.yml`
- `.github/workflows/validate-vm-configs.yml`
- `.github/workflows/verify-tokenfile.yml`
- `.github/workflows/certs-ci.yml`
- `.github/workflows/ipam-app-ci.yml`

Changes to VM GitOps manifests may also interact with `.github/workflows/apply-vm-configs.yml` on self-hosted runners.

## Coding Standards

- Use `set -Eeuo pipefail` in Bash scripts.
- Prefer explicit validation and actionable error messages.
- Keep public flags/options backward compatible unless intentionally versioned.
- Avoid hardcoding secrets, tokens, private keys, production endpoints, or customer-specific data.
- Prefer idempotent operations and clear dry-run/verify paths where practical.

## Documentation Standards

When behavior changes, update all relevant docs in the same PR:

- [README.md](README.md)
- [docs/README.md](docs/README.md)
- [docs/CLI-REFERENCE.md](docs/CLI-REFERENCE.md)
- [docs/OPERATIONAL-RUNBOOK.md](docs/OPERATIONAL-RUNBOOK.md)
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
- [docs/TESTING-GUIDE.md](docs/TESTING-GUIDE.md)
- [examples/config/README.md](examples/config/README.md)
- [CHANGELOG.md](CHANGELOG.md)

Documentation updates must include:

1. Correct command paths (`bin/rke2nodeinit.sh`, `scripts/...`).
2. Current action/flag names and supported kinds.
3. Updated date metadata when present.
4. Security-safe examples with no real credentials.
5. `docs/MIGRATION-v2.0.md` updated when path or behavior changes are breaking.
6. `docs/PR-VALIDATION-CHECKLIST.md` gates satisfied before merge.

## Issue Guidance

Use GitHub issues for:

- Non-security bugs.
- Enhancement requests.
- Documentation fixes.
- Operational questions that do not expose private infrastructure details.

Do not use public issues for:

- Vulnerability reports.
- Secrets, private keys, kubeconfigs, or registry credentials.
- Production-only topology, hostnames, IP plans, or certificate material.

## Maintainer Review Guidance

Maintainers should verify:

- The PR is scoped and understandable.
- CI and relevant manual validation passed.
- New behavior is documented.
- Secrets and environment-specific values are not committed.
- Operational rollback is realistic.
- Security-sensitive changes are reviewed carefully before merge.

## Security Reporting

Do not open public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md).
