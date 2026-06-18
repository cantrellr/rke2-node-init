# RKE2 Node Init Hardening and Validation Checklist

Use this checklist before building templates, pushing images to an internal registry, or bootstrapping RKE2 nodes in disconnected environments.

---

## 1. Repository Hygiene

- [ ] `bin/rke2nodeinit.sh` passes Bash syntax validation.
- [ ] Runtime paths remain ignored: `logs/`, `outputs/`, `downloads/`.
- [ ] No credentials, tokens, kubeconfigs, private keys, or production config files are staged in Git.
- [ ] Documentation changes include updates to the design doc, runbook, and diagrams when behavior changes.
- [ ] Generated Mermaid SVG/PNG exports are produced locally and committed with the source diagrams.

---

## 2. Connected Artifact Staging

- [ ] `image` or `airgap` is run only on a connected staging host.
- [ ] RKE2 version is pinned or intentionally auto-detected.
- [ ] RKE2 binary tarball, image archive, checksum file, and installer content are downloaded.
- [ ] CNI-specific image archives are present for the selected CNI stack.
- [ ] Required image/tag validation passes.
- [ ] Checksum validation passes.
- [ ] `/opt/rke2/stage` contains the expected staged artifacts.
- [ ] Optional boot-service ISO artifacts are generated only when required.

---

## 3. Registry and Image Promotion

- [ ] Internal registry DNS and port are reachable from the push host.
- [ ] Registry authentication is tested before bulk push.
- [ ] Registry CA is installed into OS trust and container runtime trust when needed.
- [ ] Image retagging uses the intended internal registry prefix.
- [ ] `--dry-push` is used before changing registry naming or credentials.
- [ ] SBOM or inspect metadata is generated under `outputs/sbom`.
- [ ] Pushed image count matches the staged image set.

---

## 4. Node OS and Network

- [ ] Host OS is Ubuntu/Debian with `systemd`, `apt`, and `netplan`.
- [ ] Script is run as root with `sudo`.
- [ ] Static IP, prefix, gateway, DNS, search domains, MTU, and routing metrics are reviewed.
- [ ] Only the intended interface owns the default route.
- [ ] Cloud-init network rendering is disabled when the script owns networking.
- [ ] Netplan output is reviewed before applying immediately on remote hosts.
- [ ] Time synchronization is available in the air-gapped environment.

---

## 5. RKE2 Server and Agent Bootstrap

- [ ] `server`, `add-server`, and `agent` workflows run only after artifacts are staged.
- [ ] `registries.yaml` points to internal mirrors.
- [ ] Custom CA trust is present when the registry or cluster requires it.
- [ ] Token file exists and matches the target cluster.
- [ ] TLS SANs include required DNS names, VIPs, and node addresses.
- [ ] Node names are unique.
- [ ] RKE2 services are enabled and healthy after install.

---

## 6. Custom CA and Token Controls

- [ ] Custom CA root and intermediate files are stored outside Git.
- [ ] Token generation uses the intended CA material.
- [ ] Token files are protected with restrictive permissions.
- [ ] Token paths in YAML resolve correctly on the target host.
- [ ] Sanitized YAML output is used when reviewing configs that may contain secrets.

---

## 7. STIG and CNI Permission Controls

- [ ] STIG helper scope is understood before execution.
- [ ] CNI permission remediation is enabled unless intentionally disabled.
- [ ] Manual STIG actions are tracked separately from automation.
- [ ] STIG reference payloads under `docs/stigs/` remain read-only reference material.

---

## 8. Documentation Integrity

- [ ] `docs/README.md` points operators to the current canonical documents.
- [ ] `docs/System-Design-Document.md` reflects actual workflow behavior.
- [ ] `docs/operator-runbook.md` contains current commands and troubleshooting flow.
- [ ] `docs/documentation-maintenance.md` reflects the current doc workflow.
- [ ] Legacy uppercase docs are treated as reference unless intentionally promoted.
- [ ] Mermaid source, diagram index, and generated exports stay synchronized.

---

## 9. Final Validation Commands

```bash
bash -n bin/rke2nodeinit.sh
sudo bin/rke2nodeinit.sh -h
./diagrams/apply-diagram-updates.sh .
git status --short
git diff --check
```

Use `verify` against the relevant YAML before mutating a node:

```bash
sudo bin/rke2nodeinit.sh -f examples/config/<verify-config>.yaml
```
