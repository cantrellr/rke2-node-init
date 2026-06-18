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

Before running any mutating workflow:

```bash
sudo bash -n bin/rke2nodeinit.sh
sudo bin/rke2nodeinit.sh -h
```

Confirm:

- target host is Ubuntu/Debian with `systemd`, `apt`, and `netplan`;
- script is executed with `sudo` or as root;
- YAML uses `apiVersion: rkeprep/v2`;
- `metadata.name` is set;
- interfaces, gateways, DNS, and search domains are accurate;
- registry endpoint and CA trust are available;
- token files and custom CA material are present only where required;
- generated outputs, logs, downloads, keys, and token files are not committed.

---

## 3. Connected Artifact Staging

Use the `image` action when preparing a VM that will later become a server or agent template.

```bash
sudo bin/rke2nodeinit.sh -f examples/config/<image-config>.yaml -y
```

Use `airgap` when the workflow should stage content and power off for templating.

```bash
sudo bin/rke2nodeinit.sh -f examples/config/<airgap-config>.yaml -y
```

Expected outputs:

- RKE2 image archives under `downloads/` and `/opt/rke2/stage`;
- RKE2 binary tarball and checksum file;
- installer content;
- optional nerdctl bundles;
- optional custom CA trust material;
- optional boot-service ISO artifacts;
- logs under `logs/`;
- run output under `outputs/`.

Do not move to offline registry or node bootstrap until required image/tag validation passes.

---

## 4. Offline Registry Push

After staging artifacts, run `push` from a host that can reach the private registry.

```bash
sudo bin/rke2nodeinit.sh -f examples/config/<push-config>.yaml -y
```

Use dry-run first when changing registry naming or credentials:

```bash
sudo bin/rke2nodeinit.sh -f examples/config/<push-config>.yaml --dry-push -y
```

Validate:

- registry endpoint resolves;
- CA trust works;
- credentials are correct when authentication is enabled;
- tags are retagged to the intended internal registry prefix;
- SBOM or inspect metadata was generated under `outputs/sbom`;
- pushed image count matches the staged image set.

---

## 5. First Server Bootstrap

Run `server` on the first control-plane node.

```bash
sudo bin/rke2nodeinit.sh -f examples/config/<server-config>.yaml -y
```

Validate after the node comes up:

```bash
sudo systemctl status rke2-server --no-pager
sudo journalctl -u rke2-server -n 200 --no-pager
sudo /var/lib/rancher/rke2/bin/kubectl get nodes
```

If the kubeconfig is needed by a non-root operator, copy it intentionally and protect file permissions.

---

## 6. Additional Server Bootstrap

Run `add-server` for additional control-plane nodes.

```bash
sudo bin/rke2nodeinit.sh -f examples/config/<add-server-config>.yaml -y
```

Validate:

- server URL points to the correct control-plane endpoint;
- join token matches the cluster;
- CA trust matches the first server;
- node name is unique;
- TLS SANs include required hostnames and VIPs.

---

## 7. Agent Bootstrap

Run `agent` for worker nodes.

```bash
sudo bin/rke2nodeinit.sh -f examples/config/<agent-config>.yaml -y
```

Validate:

```bash
sudo systemctl status rke2-agent --no-pager
sudo journalctl -u rke2-agent -n 200 --no-pager
```

From a server node:

```bash
sudo /var/lib/rancher/rke2/bin/kubectl get nodes -o wide
```

---

## 8. Verify Workflow

Run `verify` before mutating a host or when troubleshooting staging problems.

```bash
sudo bin/rke2nodeinit.sh -f examples/config/<verify-config>.yaml
```

Use `verify` to catch missing artifacts, invalid network inputs, missing tools, missing CA material, and broken registry configuration before installing services.

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
./diagrams/apply-diagram-updates.sh . --install-deps --install-browser-deps
./diagrams/apply-diagram-updates.sh .
git status --short
```

Expected result:

- Mermaid source exists under `diagrams/mermaid-source/`;
- design document includes matching Mermaid blocks and `Diagram export:` lines;
- SVG and PNG exports are regenerated locally;
- source, Markdown, index, and exports are committed together.

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

Never commit:

- `downloads/`;
- `outputs/`;
- `logs/`;
- token files;
- generated private keys;
- local registry credentials;
- production kubeconfigs;
- site-specific configs that belong under ignored config directories.
