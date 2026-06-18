# RKE2 Node Init Operator Runbook

This runbook is the current operator path for using `rke2-node-init` to prepare and bootstrap RKE2 nodes in connected, staged, and air-gapped environments.

The canonical design reference is [System-Design-Document.md](System-Design-Document.md).

---

## 1. Roles and Environments

| Environment | Purpose | Internet access |
| --- | --- | --- |
| Connected staging host | Run `image` or `airgap` to download RKE2 artifacts and stage image archives. | Required. |
| Offline registry host | Run `push` to load, retag, generate metadata/SBOM output, and push images. | Not required after staging. |
| RKE2 server node | Run `server` or `add-server`. | Not required after staging. |
| RKE2 agent node | Run `agent`. | Not required after staging. |
| Validation host | Run `verify` against a manifest. | Depends on check scope. |

---

## 2. Preflight Checklist

```bash
sudo bash -n bin/rke2nodeinit.sh
sudo bin/rke2nodeinit.sh -h
```

Confirm the target host is Ubuntu/Debian with `systemd`, `apt`, and `netplan`; YAML uses `apiVersion: rkeprep/v2`; `metadata.name` is set; network values are correct; registry endpoint and CA trust are available; token/custom CA material exists only where required; and generated outputs/logs/downloads/keys/token files are not committed.

---

## 3. Connected Artifact Staging

Use `image` when preparing a VM that will later become a server or agent template.

```bash
sudo bin/rke2nodeinit.sh -f examples/config/<image-config>.yaml -y
```

Use `airgap` when the workflow should stage content and power off for templating.

```bash
sudo bin/rke2nodeinit.sh -f examples/config/<airgap-config>.yaml -y
```

Expected outputs include RKE2 image archives, the binary tarball, checksum file, installer content, optional nerdctl bundles, optional CA trust material, optional boot-service ISO artifacts, logs, and run output. Do not move to offline registry or node bootstrap until required image/tag validation passes.

---

## 4. Offline Registry Push

```bash
sudo bin/rke2nodeinit.sh -f examples/config/<push-config>.yaml -y
```

Dry-run first when changing registry naming or credentials:

```bash
sudo bin/rke2nodeinit.sh -f examples/config/<push-config>.yaml --dry-push -y
```

Validate registry DNS, port, credentials, CA trust, retag prefix, generated SBOM/inspect metadata under `outputs/sbom`, and pushed image count.

---

## 5. First Server Bootstrap

```bash
sudo bin/rke2nodeinit.sh -f examples/config/<server-config>.yaml -y
```

Validate after the node comes up:

```bash
sudo systemctl status rke2-server --no-pager
sudo journalctl -u rke2-server -n 200 --no-pager
sudo /var/lib/rancher/rke2/bin/kubectl get nodes
```

---

## 6. Additional Server Bootstrap

```bash
sudo bin/rke2nodeinit.sh -f examples/config/<add-server-config>.yaml -y
```

Validate the server URL, join token, CA trust, unique node name, and TLS SAN coverage.

---

## 7. Agent Bootstrap

```bash
sudo bin/rke2nodeinit.sh -f examples/config/<agent-config>.yaml -y
```

Validate locally and from a server node:

```bash
sudo systemctl status rke2-agent --no-pager
sudo journalctl -u rke2-agent -n 200 --no-pager
sudo /var/lib/rancher/rke2/bin/kubectl get nodes -o wide
```

---

## 8. Verify Workflow

Run `verify` before mutating a host or when troubleshooting staging problems.

```bash
sudo bin/rke2nodeinit.sh -f examples/config/<verify-config>.yaml
```

---

## 9. Boot Service ISO Workflow

For VM factory or Hyper-V first-boot workflows:

1. Create one YAML manifest per node.
2. Enable boot-service ISO generation in the image/airgap workflow.
3. Attach the generated ISO to the cloned VM.
4. Boot the VM in the air-gapped network.
5. Confirm the service copied YAML from `/config` and invoked `rke2nodeinit.sh -f <yaml> -y`.

Troubleshooting commands:

```bash
sudo systemctl status rke2-boot.service --no-pager
sudo journalctl -u rke2-boot.service -n 200 --no-pager
lsblk
mount | grep -i iso || true
```

---

## 10. Documentation and Diagram Validation

When docs or diagrams change:

```bash
bash diagrams/apply-diagram-updates.sh . --install-deps --install-browser-deps
bash diagrams/apply-diagram-updates.sh .
git status --short
```

Expected result: Mermaid source exists, the design document has matching Mermaid/export blocks, generated SVG/PNG exports are refreshed, and source/Markdown/index/export files are committed together.

---

## 11. Common Recovery Actions

| Symptom | Action |
| --- | --- |
| `image` cannot find required CNI image | Confirm selected CNI stack and re-run connected staging. |
| `push` fails authentication | Validate registry credentials and CA trust. Use `--dry-push` first. |
| `server` fails to start | Inspect `journalctl -u rke2-server`; confirm staged artifacts and registry mirror. |
| `agent` cannot join | Validate server URL, token, DNS, CA trust, and network reachability. |
| Wrong static IP/default route | Fix manifest interface definitions; avoid multiple unintentional default routes. |
| Custom CA token mismatch | Regenerate token from the correct CA material and confirm file paths. |
| Boot ISO ignored | Confirm ISO is attached, readable, and contains `/config/<node>.yaml`. |

---

## 12. Commit Hygiene

Before pushing changes:

```bash
git status --short
git diff --check
```

Never commit downloads, outputs, logs, token files, generated private keys, local registry credentials, production kubeconfigs, or site-specific configs that belong under ignored config directories.
