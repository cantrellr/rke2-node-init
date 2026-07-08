# Operational Runbook

Last Updated: April 24, 2026

This runbook defines the recommended end-to-end workflow for preparing and operating RKE2 nodes with this repository.

## Phase 1: Preparation

1. Validate environment requirements:
   - root/sudo access
   - network prerequisites (online host for `image` action)
   - registry reachability for `push`
2. Validate manifests:

```bash
yamllint configs examples
```

3. Validate key scripts:

```bash
shellcheck bin/rke2nodeinit.sh scripts/*.sh tests/*.sh
```

## Phase 2: Certificate Material

Use environment-scoped certificate paths in manifests.

- COTPA cert material: `configs/cotpa/certs/`
- PREPROD cert material: `configs/preprod/certs/`

Optional certificate generation:

```bash
./scripts/certs/generate-root-ca.sh --out-dir scripts/certs/outputs/root-ca
./scripts/certs/generate-subordinate-ca.sh \
  --input examples/certs/rke2clusterCA-example.yaml \
  --out-dir scripts/certs/outputs/sub-ca \
  --root-key scripts/certs/outputs/root-ca/root-ca-key.pem \
  --root-cert scripts/certs/outputs/root-ca/root-ca.crt
./scripts/certs/verify-chain.sh \
  --root scripts/certs/outputs/root-ca/root-ca.crt \
  --sub scripts/certs/outputs/sub-ca/subordinate-ca.crt
```

## Phase 3: Image Build (Online)

```bash
sudo ./bin/rke2nodeinit.sh -f configs/preprod/preprod-vmware-v1.35.3+rke2r3-image.yaml image
```

Expected outcomes:
- staged artifacts under `/opt/rke2/stage`
- optional custom CA installation
- optional boot ISO generation when enabled

## Phase 4: Registry Push (As Needed)

```bash
sudo ./bin/rke2nodeinit.sh -f configs/preprod/preprod-vmware-v1.35.3+rke2r3-image.yaml push
```

## Phase 5: Node Provisioning (Offline)

Server:

```bash
sudo ./bin/rke2nodeinit.sh -f configs/preprod/nodes/dc1manager-ctrl01.yaml server
```

Additional server:

```bash
sudo ./bin/rke2nodeinit.sh -f configs/preprod/nodes/dc1manager-ctrl02.yaml add-server
```

Worker:

```bash
sudo ./bin/rke2nodeinit.sh -f configs/preprod/nodes/dc1manager-work01.yaml agent
```

Token policy for node provisioning:
- Use `spec.tokenFile` (or `spec.token-file`) with the canonical protected host path `/etc/rancher/rke2/token.d/bootstrap.token`.
- `server`, `agent`, and `add-server` now fail fast when the canonical token file is missing or unreadable.

Post-bootstrap cleanup and artifact retention:
- After successful `server`, `agent`, or `add-server` completion, the runtime working repository at `/rke2-node-init` is removed.
- Cleanup is allow-listed and only executes for the expected path to prevent unintended deletions.
- Operational evidence is retained before cleanup:
  - Logs: `/var/log/rke2-node-init/<action>-<timestamp>/`
  - SBOM and metadata artifacts: `/var/lib/rke2-node-init/artifacts/<action>-<timestamp>/`
- If artifact retention fails, repo cleanup is skipped for safety.

## Phase 6: Verification

```bash
sudo ./bin/rke2nodeinit.sh -f configs/preprod/nodes/dc1manager-ctrl01.yaml verify
```

Check:
- network config
- staged artifacts
- service state
- token file and custom CA references
- retained logs under `/var/log/rke2-node-init/`
- retained SBOM/metadata under `/var/lib/rke2-node-init/artifacts/`

## Phase 7: Hardening

```bash
sudo ./scripts/apply-stigs.sh --report-only
sudo ./scripts/apply-stigs.sh --apply
```

## Boot ISO Workflow

When `bootService.enabled: true` in image manifest:
1. build ISOs with `make boot-isos` or image action automation
2. attach `metadata.name.iso` to VM CD media
3. first boot service executes first YAML found under `/config`

## Change Control

For production updates:
1. update manifests in `configs/`
2. update docs in same PR
3. run tests from `docs/TESTING-GUIDE.md`
4. include migration notes for path or behavior changes
