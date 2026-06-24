# rke2nodeinit refactor phases

This folder tracks the staged refactor that makes `bin/rke2nodeinit.sh` the public kind-aware entrypoint while keeping the existing install flows working.

## Phase map

1. Preserve the existing implementation as `bin/rke2nodeinit-core.sh` and make `bin/rke2nodeinit.sh` a kind-aware dispatcher.
2. Introduce single-node helper routing for `singleNodeImage` and `singleNodeServer`.
3. Add config helper functions for generated RKE2 config validation and sanitization.
4. Add CNI helper functions for permission remediation and service/timer ownership.
5. Add YAML/router/system helper libraries to reduce future script growth.
6. Update docs and smoke tests for kind-driven dispatch.

Each phase is committed separately so the branch can be reverted by phase if needed.
