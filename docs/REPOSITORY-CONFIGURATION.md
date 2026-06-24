# Repository configuration model

This repo supports two provisioning tracks from the same automation base:

1. **Multi-node RKE2 clusters** using `image`, `push`, `server`, `add-server`, `agent`, and `verify` actions from `bin/rke2nodeinit.sh`.
2. **Single-node RKE2 clusters** using explicit `rkeprep/v2` kinds: `singleNodeImage` and `singleNodeServer`.

## Current top-level workflow

```text
connected host / template VM
  └─ bin/rke2-single-node-profile.sh -f <kind: singleNodeImage>
       └─ delegates to bin/rke2nodeinit.sh image
       └─ downloads and stages RKE2 artifacts
       └─ validates required images and CNI artifacts
       └─ prepares golden image artifacts

offline registry host
  └─ bin/rke2nodeinit.sh push
       └─ loads, retags, records SBOM/inspect data, and pushes staged images

single-node target host
  └─ bin/rke2-single-node-profile.sh -f <kind: singleNodeServer>
       └─ writes /etc/rancher/rke2/config.yaml.d/20-single-node-production.yaml
       └─ writes low-resource HelmChartConfig manifests
       └─ prepares CIS host prerequisites where possible
       └─ delegates to bin/rke2nodeinit.sh server
            └─ writes base RKE2 config, network, registry trust, and installs rke2-server

multi-node target hosts
  └─ bin/rke2nodeinit.sh server
  └─ bin/rke2nodeinit.sh add-server
  └─ bin/rke2nodeinit.sh agent
```

## Important design decision

The single-node implementation is a profile overlay, not a fork of `bin/rke2nodeinit.sh`. The repo keeps one golden-image supply chain and one server provisioning contract. The overlay uses RKE2's native `config.yaml.d/*.yaml` support so it can add production-style guardrails without fighting the existing base `config.yaml` generator.

The single-node helper exists to prevent operator sequencing mistakes. It dispatches `kind: singleNodeImage` to the image process, and `kind: singleNodeServer` to the overlay-plus-server process.

## COTPA single-node configuration

The COTPA replacement clusters live in:

```text
configs/cotpa-single-nodes/
├── image-hyperv-v1.35.5+rke2r2-singlenode.yaml   # kind: singleNodeImage
└── nodes/
    ├── dc1manager.yaml                           # kind: singleNodeServer
    ├── dc1domain.yaml                            # kind: singleNodeServer
    ├── dc2domain.yaml                            # kind: singleNodeServer
    └── dc3domain.yaml                            # kind: singleNodeServer
```

The image manifest stages RKE2 `v1.35.5+rke2r2`, Multus, Canal, embedded-registry support, offline registry guardrails, and the shared COTPA custom CA chain from `configs/cotpa/certs`.

The node manifests are replacement clusters, not parallel clusters. The reused primary IP addresses are intentional. Each node manifest explicitly sets `cluster-dns: 10.1.0.10` because the configured `service-cidr` is `10.1.0.0/16`.

## New and updated files

| Path | Purpose |
| --- | --- |
| `bin/rke2-single-node-profile.sh` | Applies/renders/verifies the single-node profile overlay and dispatches `singleNodeImage` / `singleNodeServer` manifests. |
| `configs/single-node/golden-image.yaml` | Example `kind: singleNodeImage` manifest. |
| `configs/single-node/production-server.yaml` | Production-style `kind: singleNodeServer` manifest. |
| `configs/single-node/dev-low-resource-server.yaml` | Lower-retention dev `kind: singleNodeServer` manifest. |
| `configs/cotpa-single-nodes/image-hyperv-v1.35.5+rke2r2-singlenode.yaml` | COTPA replacement-cluster `kind: singleNodeImage` manifest. |
| `configs/cotpa-single-nodes/nodes/*.yaml` | COTPA replacement `kind: singleNodeServer` manifests. |
| `configs/cotpa-single-nodes/README.md` | Operator runbook for the COTPA replacement set. |
| `docs/SINGLE-NODE-CLUSTERS.md` | Detailed operator guide and decision framework. |
| `docs/REPOSITORY-CONFIGURATION.md` | Current repo configuration and workflow map. |
| `tests/test-single-node-profile.sh` | Lightweight syntax/render/kind smoke test for the helper and COTPA manifests. |
| `make/single-node.mk` | Optional make-style helper targets for local operators. |

## Optional make helper

The GitHub contents API may not preserve executable bits for newly-added shell scripts. The examples therefore call the helper through `bash`.

```bash
make -f make/single-node.mk single-node-image
make -f make/single-node.mk single-node-render
make -f make/single-node.mk single-node-apply
make -f make/single-node.mk single-node-server
make -f make/single-node.mk single-node-verify
make -f make/single-node.mk single-node-test
```

Override the manifest path when needed:

```bash
make -f make/single-node.mk single-node-image SINGLE_NODE_IMAGE_CONFIG=configs/cotpa-single-nodes/image-hyperv-v1.35.5+rke2r2-singlenode.yaml
make -f make/single-node.mk single-node-server SINGLE_NODE_CONFIG=configs/cotpa-single-nodes/nodes/dc1manager.yaml
```

## Boot service guidance

The existing boot service path remains appropriate for standard multi-node manifests. For single-node clusters, use the kind-driven wrapper command so the profile is applied before server provisioning:

```bash
sudo bash bin/rke2-single-node-profile.sh -f <single-node-server.yaml> -y
```

The COTPA single-node image manifest keeps `bootService.enabled: false` to avoid a first-boot sequence that skips the single-node overlay.

## Operational guidance

Use `configs/single-node/production-server.yaml` as the template for long-lived labs. Use `configs/single-node/dev-low-resource-server.yaml` for disposable clusters. Use `configs/cotpa-single-nodes` for the COTPA replacement set. These profiles keep CPU and memory requests low for packaged add-ons, but they do not set aggressive static-pod limits for etcd or kube-apiserver.

## Backward compatibility

Existing multi-node manifests do not need `spec.clusterMode` or `spec.singleNode`. The single-node helper refuses to run overlay/server paths unless the manifest uses `kind: singleNodeServer`, opts into single-node mode, or `--force` is passed.
