# COTPA single-node replacement clusters

This folder contains the COTPA single-node replacement-cluster configuration set.

## Files

```text
configs/cotpa-single-nodes/
├── image-hyperv-v1.35.5+rke2r2-singlenode.yaml
└── nodes/
    ├── dc1manager.yaml
    ├── dc1domain.yaml
    ├── dc2domain.yaml
    └── dc3domain.yaml
```

## Intent

These are replacement clusters, not parallel clusters. The primary node IPs intentionally reuse the existing replacement addresses.

| Cluster | Manifest | Primary IP | Secondary IP | Cluster CIDR | Service CIDR | Cluster DNS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `dc1manager` | `nodes/dc1manager.yaml` | `172.16.15.101` | `172.16.210.101` | `10.101.0.0/16` | `10.1.0.0/16` | `10.1.0.10` |
| `dc1domain` | `nodes/dc1domain.yaml` | `172.16.15.102` | `172.16.210.102` | `10.102.0.0/16` | `10.1.0.0/16` | `10.1.0.10` |
| `dc2domain` | `nodes/dc2domain.yaml` | `172.16.15.103` | `172.16.210.103` | `10.103.0.0/16` | `10.1.0.0/16` | `10.1.0.10` |
| `dc3domain` | `nodes/dc3domain.yaml` | `172.16.15.104` | `172.16.210.104` | `10.104.0.0/16` | `10.1.0.0/16` | `10.1.0.10` |

## Build the golden image

Run this on the connected image/template host:

```bash
sudo bash bin/rke2nodeinit.sh image -f configs/cotpa-single-nodes/image-hyperv-v1.35.5+rke2r2-singlenode.yaml -y
```

The image manifest keeps `bootService.enabled: false`. That is intentional. The safe single-node path must apply the single-node overlay before the base server action runs.

## Provision a replacement cluster

Run the wrapper on the cloned target VM for the specific replacement cluster:

```bash
sudo bash bin/rke2-single-node-profile.sh server -f configs/cotpa-single-nodes/nodes/dc1manager.yaml -y
sudo bash bin/rke2-single-node-profile.sh server -f configs/cotpa-single-nodes/nodes/dc1domain.yaml -y
sudo bash bin/rke2-single-node-profile.sh server -f configs/cotpa-single-nodes/nodes/dc2domain.yaml -y
sudo bash bin/rke2-single-node-profile.sh server -f configs/cotpa-single-nodes/nodes/dc3domain.yaml -y
```

Only run the command matching the VM being provisioned.

## Why the wrapper matters

`bin/rke2-single-node-profile.sh server` applies the single-node RKE2 drop-in and low-resource manifests first, then delegates to:

```bash
bash bin/rke2nodeinit.sh server -f <node-yaml>
```

Calling `bin/rke2nodeinit.sh server` directly skips the single-node overlay. That means the node can come up without CIS profile settings, secrets-at-rest encryption, tuned snapshots, low-resource add-on overrides, and the default-deny network policy.

## Token path convention

All node manifests use the image metadata name for the generated bootstrap token path:

```text
/rke2-node-init/outputs/image-hyperv-v1.35.5+rke2r2-singlenode/image-hyperv-v1.35.5+rke2r2-singlenode-bootstrap-token.txt
```

Keep that path aligned with `metadata.name` in the image manifest.

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
