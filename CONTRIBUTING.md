# Contributing to rke2-node-init

Thanks for contributing. This guide covers the current workflow, repository layout, validation requirements, and documentation expectations.

## Prerequisites

- Bash 4+
- Python 3.11+ for validation tooling
- `shellcheck`, `yamllint`, and `markdownlint` available locally
- Familiarity with RKE2 air-gapped deployment patterns

## Repository Layout (Current)

```
.
├── bin/                    # Main executable (rke2nodeinit.sh)
├── certs/                  # Certificate materials and generation scripts
├── clusters/               # Cluster-scoped rkeprep/v2 YAML manifests
├── configs/                # Additional configuration manifests
├── docs/                   # Technical docs and redesign archive
├── examples/               # Demo scripts and YAML examples
├── scripts/                # Supporting utilities and operational scripts
├── tests/                  # Bash-based test and CI validation scripts
├── vm/                     # vSphere provisioning scripts and templates
└── vm-configs/             # VM GitOps schema + declarative VM configs
```

## Development Workflow

1. Create a feature branch from `main`.
2. Keep changes scoped (code, config, and docs updated together).
3. Run local validation before opening a PR.
4. Open PR with test evidence and impacted docs list.

## Local Validation Checklist

### Bash

```bash
shellcheck bin/rke2nodeinit.sh
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
markdownlint README.md docs/**/*.md certs/**/*.md examples/**/*.md
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

## CI Workflows You Should Expect

- `.github/workflows/validate-rke-configs.yml`
- `.github/workflows/validate-vm-configs.yml`
- `.github/workflows/verify-tokenfile.yml`
- `.github/workflows/certs-ci.yml`

Changes to VM GitOps manifests may also interact with `.github/workflows/apply-vm-configs.yml` on self-hosted runners.

## Coding Standards

- Use `set -Eeuo pipefail` in Bash scripts.
- Prefer explicit validation and actionable error messages.
- Keep public flags/options backward compatible unless intentionally versioned.
- Avoid hardcoding secrets, tokens, private keys, or production endpoints.

## Documentation Standards

When behavior changes, update all relevant docs in the same PR:

- [README.md](README.md)
- [docs/README.md](docs/README.md)
- [examples/config/README.md](examples/config/README.md)
- [CHANGELOG.md](CHANGELOG.md)

Documentation updates must include:

1. Correct command paths (`bin/rke2nodeinit.sh`, `scripts/...`).
2. Current action/flag names and supported kinds.
3. Updated date metadata when present.
4. Security-safe examples (no real credentials).

## Pull Request Expectations

Each PR should include:

- Problem statement and rationale
- Technical summary of changes
- Validation evidence (commands and results)
- Docs updated list
- Risk/rollback notes for operational changes

## Security Reporting

Do not open public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md).
