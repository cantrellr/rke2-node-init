# COTPA single-node replacement clusters

This folder contains the COTPA single-node replacement-cluster configuration set.

## Files

```text
configs/cotpa-single-nodes/
├── image-hyperv-v1.35.5+rke2r2-singlenode.yaml   # kind: singleNodeImage
└── nodes/
    ├── dc1manager.yaml                           # kind: singleNodeServer
    ├── dc1domain.yaml                            # kind: singleNodeServer
    ├── dc2domain.yaml                            # kind: singleNodeServer
    └── dc3domain.yaml                            # kind: singleNodeServer
```

## Intent

These are replacement clusters, not parallel clusters. The primary node IPs intentionally reuse the existing replacement addresses.

| Cluster | Manifest | Primary IP | Secondary IP | Cluster CIDR | Service CIDR | Cluster DNS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `dc1manager` | `nodes/dc1manager.yaml` | `172.16.15.101` | `172.16.210.101` | `10.101.0.0/16` | `10.1.0.0/16` | `10.1.0.10` |
| `dc1domain` | `nodes/dc1domain.yaml` | `172.16.15.102` | `172.16.210.102` | `10.102.0.0/16` | `10.1.0.0/16` | `10.1.0.10` |
| `dc2domain` | `nodes/dc2domain.yaml` | `172.16.15.103` | `172.16.210.103` | `10.103.0.0/16` | `10.1.0.0/16` | `10.1.0.10` |
| `dc3domain` | `nodes/dc3domain.yaml` | `172.16.15.104` | `172.16.210.104` | `10.104.0.0/16` | `10.1.0.0/16` | `10.1.0.10` |

## Kind-driven flow

The public entrypoint is `bin/rke2nodeinit.sh`. It dispatches directly from `kind` when no explicit action is supplied:

| Kind | Process |
| --- | --- |
| `singleNodeImage` | Delegates to the existing image process |
| `singleNodeServer` | Applies the single-node overlay, installs the preflight guards, then delegates to the existing server process |

This keeps the operator flow consistent: supply a manifest and let the kind choose the process.

## Image-level DNS format

The `singleNodeImage` manifest intentionally defines image-level DNS values as scalar CSV:

```yaml
spec:
  defaultDns: 172.16.10.11,172.16.10.12
  defaultSearchDomains: k8.cantrellcloud.net,cantrellcloud.net
```

That format is deliberate because the base image action consumes these values as shell CSV when preparing the golden image and logging the effective `DEFAULT_DNS` / `DEFAULT_SEARCH_DOMAINS`. Node-level interface DNS can still use YAML list syntax in the `singleNodeServer` manifests.

## Build the golden image

Run this on the connected image/template host:

```bash
sudo bash bin/rke2nodeinit.sh -f configs/cotpa-single-nodes/image-hyperv-v1.35.5+rke2r2-singlenode.yaml -y
```

Equivalent explicit form:

```bash
sudo bash bin/rke2nodeinit.sh image -f configs/cotpa-single-nodes/image-hyperv-v1.35.5+rke2r2-singlenode.yaml -y
```

The image manifest keeps `bootService.enabled: false`. That is intentional. The safe single-node path must apply the single-node overlay and preflight guards before the base server action runs.

## Provision a replacement cluster

Run the kind-driven wrapper on the cloned target VM for the specific replacement cluster:

```bash
sudo bash bin/rke2nodeinit.sh -f configs/cotpa-single-nodes/nodes/dc1manager.yaml -y
sudo bash bin/rke2nodeinit.sh -f configs/cotpa-single-nodes/nodes/dc1domain.yaml -y
sudo bash bin/rke2nodeinit.sh -f configs/cotpa-single-nodes/nodes/dc2domain.yaml -y
sudo bash bin/rke2nodeinit.sh -f configs/cotpa-single-nodes/nodes/dc3domain.yaml -y
```

Only run the command matching the VM being provisioned.

Equivalent explicit form:

```bash
sudo bash bin/rke2nodeinit.sh server -f configs/cotpa-single-nodes/nodes/dc1manager.yaml -y
```

## CIS, swap, and config preflight

`spec.singleNode.enableCIS: true` enables RKE2 `profile: "cis"` and `protect-kernel-defaults: true`. RKE2 will refuse to start if required kernel parameters are not already set. Kubelet can also exit immediately if the Ubuntu VM template boots with `/swap.img` active. The single-node helper installs systemd `ExecStartPre` guards for `rke2-server` so the final pre-start state is corrected even after reboot or after the base server action rewrites `/etc/rancher/rke2/config.yaml`.

The preflight guards manage:

- `/usr/local/sbin/rke2-single-node-swap-preflight.sh`
- `/etc/systemd/system/rke2-server.service.d/05-single-node-swap-preflight.conf`
- `/usr/local/sbin/rke2-single-node-preflight.sh`
- `/etc/systemd/system/rke2-server.service.d/10-single-node-preflight.conf`
- `/etc/sysctl.d/99-rke2-single-node-cis.conf`
- `swapoff -a` when swap is active
- `vm.overcommit_memory=1`
- `kernel.panic=10`
- `kernel.panic_on_oops=1`
- cleanup of stale or invalid `import-images:` keys from RKE2 config files

This protects against the observed single-node failures: RKE2 rejecting `import-images`, RKE2 refusing CIS startup because kernel parameters were still at OS defaults, and kubelet exiting when the VM template booted with swap active.

## Validation

Render and dry-run before deployment:

```bash
bash bin/rke2-single-node-profile.sh render -f configs/cotpa-single-nodes/nodes/dc1manager.yaml
bash tests/test-single-node-profile.sh
```

After deployment and reboot:

```bash
sudo bash bin/rke2-single-node-profile.sh verify
sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes -o wide
sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get pods -A
sudo rke2 etcd-snapshot ls
sudo rke2 secrets-encrypt status
```
