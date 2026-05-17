# RKE2 Node Init Documentation Index

**Last Updated:** April 24, 2026  
**Project Status:** Active development (post-Phase 5 hardening/automation)

---

## Documentation Scope

This directory contains technical references for RKE2 node bootstrap, air-gapped image preparation, STIG hardening, first-boot ISO workflows, and historical redesign records.

For operational entrypoints, start with:

1. [Main README](../README.md) for script capabilities and action workflows
2. [Configuration examples](../examples/config/README.md) for `rkeprep/v2` YAML usage
3. [Roadmap](../ROADMAP.md) and [Changelog](../CHANGELOG.md) for delivery state

---

## Core Technical Guides

| Document | Purpose |
| --- | --- |
| [CLI-REFERENCE.md](CLI-REFERENCE.md) | Canonical CLI actions, flags, and command patterns |
| [OPERATIONAL-RUNBOOK.md](OPERATIONAL-RUNBOOK.md) | End-to-end operational workflow from image build through node provisioning |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Failure signatures, triage flow, and remediation playbooks |
| [TESTING-GUIDE.md](TESTING-GUIDE.md) | Local + CI validation workflow and required pre-PR test set |
| [SCRIPTS-REFERENCE.md](SCRIPTS-REFERENCE.md) | Inventory of all operational scripts and utility tools |
| [MIGRATION-v2.0.md](MIGRATION-v2.0.md) | Breaking path changes and migration checklist for v2.0 |
| [PR-VALIDATION-CHECKLIST.md](PR-VALIDATION-CHECKLIST.md) | Merge-gate checklist for quality, path integrity, and release hygiene |
| [HARDENED_CNI.md](HARDENED_CNI.md) | Hardened CNI plugin behavior, tag alignment, and offline staging guidance |
| [RKE2_AIRGAP_GOLDEN_IMAGE_PLAN.md](RKE2_AIRGAP_GOLDEN_IMAGE_PLAN.md) | Golden image build flow for disconnected environments |
| [STIG-README.md](STIG-README.md) | STIG helper execution model and persistent CNI permissions remediation |
| [STIG-CHECKLIST.md](STIG-CHECKLIST.md) | STIG checklist references and operational checks |
| [HYPERV-VM-NAME-SETUP.md](HYPERV-VM-NAME-SETUP.md) | Hyper-V first-boot ISO workflow using virtual CD payloads (`/config/<yaml>`) |
| [CONFIG-YAML-TRANSFER-ANALYSIS.md](CONFIG-YAML-TRANSFER-ANALYSIS.md) | YAML schema and migration analysis notes |
| [GITOPS-IMPLEMENTATION-SUMMARY.md](GITOPS-IMPLEMENTATION-SUMMARY.md) | VM GitOps workflow implementation summary |
| [IPAM-APP.md](IPAM-APP.md) | Internal web app for tracking sites, subnets, and IP assignments |

---

## Historical Redesign Archive

The redesign phase documentation lives under [docs/redesign](redesign/) and is intentionally retained as implementation history.

- See [redesign/README.md](redesign/README.md) for archive usage guidance and current-behavior mapping notes.

- Phase implementation, summary, and completion artifacts (`PHASE1` through `PHASE5`)
- Quick references and progress reports
- Design analysis and change rationale

Use these documents for historical decisions and architecture evolution, not as the canonical source for current CLI behavior.

---

## Validation & Reporting Artifacts

| Location | Purpose |
| --- | --- |
| [report](report/) | Action-level implementation and behavior reports |
| [report/README.md](report/README.md) | Notes on interpreting historical report snippets versus current behavior |
| [validation-report.md](validation-report.md) | Consolidated validation notes and output snapshots |
| [stigs](stigs/) | STIG-related resources and supporting material |

---

## CI/Workflow References

Repository workflows that enforce configuration quality live under [../.github/workflows](../.github/workflows):

- `validate-rke-configs.yml`: validates `rkeprep/v2` YAML files changed in PRs
- `validate-vm-configs.yml`: validates VM config schema/semantics and detects name conflicts
- `verify-tokenfile.yml`: checks duplicate token-file references in examples/configs
- `certs-ci.yml`: runs certificate generation tests
- `apply-vm-configs.yml`: applies changed VM configs on a self-hosted runner

---

## Documentation Maintenance Rules

When updating docs in this repository:

1. Validate command paths against current tree (`bin/rke2nodeinit.sh`, `scripts/*`, `tests/*`).
2. Prefer linking to current canonical docs (top-level README and examples/config README).
3. Keep historical redesign docs scoped as archival references.
4. Update date metadata when behavior/paths/flags change.
5. Ensure examples align with current CLI help and workflow files.

---

## Need Help

- Open an issue: [GitHub Issues](https://github.com/cantrellr/rke2-node-init/issues)
- Security reports: see [../SECURITY.md](../SECURITY.md)
- Contribution guidelines: see [../CONTRIBUTING.md](../CONTRIBUTING.md)
