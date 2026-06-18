# RKE2 Node Init Documentation

`rke2-node-init` is the offline-first automation repo for preparing, validating, and bootstrapping RKE2 nodes in connected, staged, and air-gapped environments.

This `docs/` folder now follows the same documentation standard used across the related air-gap repositories: one current-state design document, one operator runbook, one hardening/validation checklist, one documentation-maintenance guide, and one clear boundary for legacy reference material.

---

## Start Here

| Document | Purpose |
| --- | --- |
| [../README.md](../README.md) | Top-level project overview, action summary, command examples, and feature list. |
| [System-Design-Document.md](System-Design-Document.md) | Current-state architecture, workflows, trust boundaries, artifact lifecycle, and Mermaid diagrams. |
| [operator-runbook.md](operator-runbook.md) | Operator workflow for image staging, registry push, server/add-server/agent bootstrap, verify, rollback, and troubleshooting. |
| [hardening-checklist.md](hardening-checklist.md) | Security, offline, artifact, registry, OS, certificate, and documentation integrity checklist. |
| [documentation-maintenance.md](documentation-maintenance.md) | Rules for keeping docs, Mermaid sources, generated exports, and legacy references synchronized. |
| [../examples/config/README.md](../examples/config/README.md) | `rkeprep/v2` YAML examples and configuration patterns. |

---

## Canonical Operating Model

The current documentation treats the repo as a node lifecycle automation system with these phases:

1. **Connected staging** using the `image` or `airgap` action to download and validate RKE2 artifacts, image archives, checksums, CNI images, container runtime bundles, optional CA material, and optional boot-service payloads.
2. **Offline registry population** using the `push` action to load, retag, generate metadata/SBOM output, and push staged images into an internal registry.
3. **Offline node bootstrap** using the `server`, `add-server`, or `agent` actions to configure host identity, static networking, RKE2 config, registry trust, custom CA trust, and install the correct RKE2 service.
4. **Validation and lifecycle operations** using `verify`, `label-node`, `taint-node`, and `custom-ca` workflows.

Only connected artifact-gathering workflows should require public Internet access. Registry sync and node bootstrap workflows are designed to execute after the environment is staged.

---

## Diagrams

Mermaid diagram sources live under [`../diagrams/mermaid-source`](../diagrams/mermaid-source). The design document embeds matching Mermaid blocks and links to generated SVG/PNG exports.

Use this workflow from the repo root:

```bash
./diagrams/apply-diagram-updates.sh . --install-deps --install-browser-deps
./diagrams/apply-diagram-updates.sh .
```

Generated exports are written to:

```text
diagrams/svg/
diagrams/png/
```

Commit Mermaid source, Markdown changes, and generated exports together.

---

## Legacy and Reference Material

The older docs are retained as implementation history and deep reference material. They are not the first-read operator path anymore.

| Location | Status | Notes |
| --- | --- | --- |
| `CLI-REFERENCE.md` | Legacy reference | Use when checking historical CLI detail not yet folded into the runbook. |
| `OPERATIONAL-RUNBOOK.md` | Legacy reference | Superseded by `operator-runbook.md`. |
| `TROUBLESHOOTING.md` | Legacy reference | Mine for known failure signatures; fold active items into `operator-runbook.md`. |
| `TESTING-GUIDE.md` | Legacy reference | Use for historical local/CI testing notes. |
| `SCRIPTS-REFERENCE.md` | Legacy reference | Script inventory; should eventually be reduced into current docs. |
| `HARDENED_CNI.md` | Legacy reference | Hardened CNI details; active checklist items belong in `hardening-checklist.md`. |
| `RKE2_AIRGAP_GOLDEN_IMAGE_PLAN.md` | Legacy reference | Historical golden-image planning material. |
| `STIG-README.md`, `STIG-CHECKLIST.md`, `STIG-MANUAL-ACTIONS.md` | STIG reference | Keep as supporting compliance material. |
| `HYPERV-VM-NAME-SETUP.md` | Platform reference | Hyper-V/ISO workflow notes. |
| `CONFIG-YAML-TRANSFER-ANALYSIS.md` | Historical analysis | Not canonical for current schema behavior. |
| `GITOPS-IMPLEMENTATION-SUMMARY.md` | Historical implementation summary | Use for background only. |
| `redesign/` | Archive | Design and phase history. |
| `report/` | Archive | Historical reports and snapshots. |
| `stigs/` | Reference payloads | STIG source content and supporting resources. |

---

## Maintenance Contract

When behavior changes, update the docs in this order:

1. `docs/System-Design-Document.md`
2. `docs/operator-runbook.md`
3. `docs/hardening-checklist.md`
4. `diagrams/mermaid-source/*`
5. `docs/documentation-maintenance.md`, if the doc process changes
6. Top-level `README.md`, if the public entrypoint changes

The old docs should not be expanded unless they are intentionally being preserved as archive notes. Active behavior belongs in the canonical set above.
