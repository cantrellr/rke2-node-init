# rke2nodeinit refactor phases

This folder tracks the staged refactor that makes `bin/rke2nodeinit.sh` the public kind-aware entrypoint while keeping the existing install flows working.

## Implemented phase map

| Phase | Commit intent | Result |
| --- | --- | --- |
| 0 | Record plan | Added this phase tracker so later commits have a documented rollback map. |
| 1 | Main dispatcher | Preserved the original implementation as `bin/rke2nodeinit-core.sh` and replaced `bin/rke2nodeinit.sh` with a compact kind-aware dispatcher. |
| 2 | Single-node helper routing | Added `bin/rke2nodeinit-single-node.sh` and routed `singleNodeImage` / `singleNodeServer` manifests through the existing single-node implementation without recursive dispatch. |
| 3 | Config helper library | Added `bin/rke2nodeinit-config.sh` for RKE2 config file discovery, invalid-key sanitation, and drop-in writing helpers. |
| 4 | CNI helper library | Added `bin/rke2nodeinit-cni.sh` for CNI permission remediation service/timer ownership and dependency validation. |
| 5 | YAML/router/system helpers | Added `bin/rke2nodeinit-yaml.sh`, `bin/rke2nodeinit-router.sh`, and `bin/rke2nodeinit-system.sh` as incremental extraction targets. |
| 6 | Docs and tests | Extended smoke tests and this documentation for the dispatcher/core/helper split. |

## Current command contract

The public operator command is now always:

```bash
sudo bash bin/rke2nodeinit.sh -f <rkeprep-v2-yaml> -y
```

When no explicit action is supplied, `bin/rke2nodeinit.sh` reads `kind:` from the manifest and dispatches accordingly.

Examples:

```bash
sudo bash bin/rke2nodeinit.sh -f configs/cotpa-single-nodes/image-hyperv-v1.35.5+rke2r2-singlenode.yaml -y
sudo bash bin/rke2nodeinit.sh -f configs/cotpa-single-nodes/nodes/dc1manager.yaml -y
```

Legacy explicit actions remain supported:

```bash
sudo bash bin/rke2nodeinit.sh image -f configs/cotpa-single-nodes/image-hyperv-v1.35.5+rke2r2-singlenode.yaml -y
sudo bash bin/rke2nodeinit.sh server -f configs/cotpa-single-nodes/nodes/dc1manager.yaml -y
sudo bash bin/rke2nodeinit.sh -f configs/cotpa-single-nodes/nodes/dc1manager.yaml server -y
```

## Script layout

```text
bin/
├── rke2nodeinit.sh                # public dispatcher
├── rke2nodeinit-core.sh           # preserved legacy implementation
├── rke2nodeinit-single-node.sh    # single-node helper bridge
├── rke2-single-node-profile.sh    # existing single-node implementation
├── rke2nodeinit-config.sh         # config helper library
├── rke2nodeinit-cni.sh            # CNI helper library
├── rke2nodeinit-yaml.sh           # YAML helper library
├── rke2nodeinit-router.sh         # kind/action router helpers
└── rke2nodeinit-system.sh         # system helper library
```

## Rollback guidance

Because each phase is committed separately, revert from newest to oldest if needed. Avoid reverting `bin/rke2nodeinit-core.sh` by itself unless `bin/rke2nodeinit.sh` is also reverted to the old monolithic implementation.

## Validation

Run:

```bash
bash tests/test-single-node-profile.sh
```

That smoke test checks syntax for the dispatcher, preserved core, single-node helper, and helper libraries. It also validates `singleNodeImage` and `singleNodeServer` dispatch output in dry-run mode.
