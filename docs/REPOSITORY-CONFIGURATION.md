# Repository configuration model

This repo supports two provisioning tracks from the same automation base:

1. **Multi-node RKE2 clusters** using `image`, `push`, `server`, `add-server`, `agent`, and `verify` actions from `bin/rke2nodeinit.sh`.
2. **Single-node RKE2 clusters** using the same golden-image and server flow, plus `bin/rke2-single-node-profile.sh` to apply RKE2 drop-in configuration and low-resource packaged-component overrides before first server start.

## Current top-level workflow

```text
connected host / template VM
  └─ bin/rke2nodeinit.sh image|airgap
       └─ downloads and stages RKE2 artifacts
       └─ validates required images and CNI artifacts
       └─ prepares golden image / boot service ISO flow

offline registry host
  └─ bin/rke2nodeinit.sh push
       └─ loads, retags, records SBOM/inspect data, and pushes staged images

single-node target host
  └─ bin/rke2-single-node-profile.sh apply
       └─ writes /etc/rancher/rke2/config.yaml.d/20-single-node-production.yaml
       └─ writes low-resource HelmChartConfig manifests
       └─ prepares CIS host prerequisites where possible
  └─ bin/rke2nodeinit.sh server
       └─ writes base RKE2 config, network, registry trust, and installs rke2-server

multi-node target hosts
  └─ bin/rke2nodeinit.sh server
  └─ bin/rke2nodeinit.sh add-server
  └─ bin/rke2nodeinit.sh agent
```

## Important design decision

The single-node implementation is a profile overlay, not a fork of `bin/rke2nodeinit.sh`. That matters. The repo keeps one golden-image supply chain and one server provisioning contract. The overlay uses RKE2's native `config.yaml.d/*.yaml` support so it can add production-style guardrails without fighting the existing base `config.yaml` generator.

## New files

| Path | Purpose |
| --- | --- |
| `bin/rke2-single-node-profile.sh` | Applies/renders/verifies the single-node profile overlay. |
| `configs/single-node/golden-image.yaml` | Example golden image manifest for single-node and multi-node reuse. |
| `configs/single-node/production-server.yaml` | Production-style single-node server manifest. |
| `configs/single-node/dev-low-resource-server.yaml` | Lower-retention dev single-node server manifest. |
| `docs/SINGLE-NODE-CLUSTERS.md` | Detailed operator guide and decision framework. |
| `docs/REPOSITORY-CONFIGURATION.md` | Current repo configuration and workflow map. |
| `tests/test-single-node-profile.sh` | Lightweight syntax/render smoke test for the new helper. |
| `make/single-node.mk` | Optional make-style helper targets for local operators. |

## Optional make helper

The GitHub contents API may not preserve executable bits for newly-added shell scripts. The examples therefore call the helper through `bash`.

```bash
make -f make/single-node.mk single-node-render
make -f make/single-node.mk single-node-apply
make -f make/single-node.mk single-node-verify
make -f make/single-node.mk single-node-test
```

Override the manifest path when needed:

```bash
make -f make/single-node.mk single-node-render SINGLE_NODE_CONFIG=configs/single-node/dev-low-resource-server.yaml
```

## Operational guidance

Use `configs/single-node/production-server.yaml` as the template for long-lived labs. Use `configs/single-node/dev-low-resource-server.yaml` for disposable clusters. Both keep CPU and memory requests low for packaged add-ons, but they do not undercut etcd or kube-apiserver with aggressive static-pod limits. That is intentional. Control-plane starvation is a self-inflicted outage.

## Backward compatibility

Existing multi-node manifests do not need `spec.clusterMode` or `spec.singleNode`. The new helper refuses to run unless the manifest opts into single-node mode or `--force` is passed.
