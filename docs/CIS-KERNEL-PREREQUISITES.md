# RKE2 CIS Kernel Prerequisites

This document describes the host kernel parameters that `rke2-node-init` enforces when an RKE2 node is configured to use the CIS profile.

## Why this exists

RKE2 validates host kernel runtime parameters before starting when `profile: cis` is enabled. If the live kernel values do not match the RKE2 CIS requirements, `rke2-server` or `rke2-agent` exits before Kubernetes starts.

A common failure is:

```text
invalid kernel parameter value vm.overcommit_memory=0 - expected 1
```

The Ubuntu default for `vm.overcommit_memory` may be `0`, while the RKE2 CIS profile requires `1`.

## Required values

`rke2-node-init` enforces and persists the following values:

```text
vm.overcommit_memory = 1
vm.panic_on_oom = 0
kernel.panic = 10
kernel.panic_on_oops = 1
```

The persistent configuration is written to:

```text
/etc/sysctl.d/99-rke2-cis.conf
```

The values are also applied immediately with `sysctl` before control is handed to the RKE2 provisioning engine.

## Automatic enforcement

The public dispatcher, `bin/rke2nodeinit.sh`, performs CIS prerequisite preparation before the following actions:

- `Server`
- `AddServer`
- `Agent`
- `singleNodeServer`

Enforcement is activated when either of these conditions is true:

1. The supplied `rkeprep/v2` manifest declares `spec.profile: cis`.
2. The supplied single-node manifest enables `spec.singleNode.enableCIS: true`.
3. Existing RKE2 configuration under `/etc/rancher/rke2/config.yaml` or `/etc/rancher/rke2/config.yaml.d/` declares `profile: cis`.

The dispatcher fails early if the required kernel values cannot be applied or verified. This is intentional: allowing provisioning to continue would only move the failure downstream to RKE2 startup.

## Dry-run behavior

When `--dry-run` is used, the dispatcher does not modify the host. It reports the exact CIS kernel values that would be applied.

Example:

```bash
sudo bin/rke2nodeinit.sh -f server.yaml --dry-run -y
```

Expected message:

```text
DRY-RUN would apply RKE2 CIS kernel prerequisites: vm.overcommit_memory=1, vm.panic_on_oom=0, kernel.panic=10, kernel.panic_on_oops=1
```

## Manual remediation

For a host that is already failing with a CIS kernel parameter error, apply the values manually:

```bash
sudo tee /etc/sysctl.d/99-rke2-cis.conf >/dev/null <<'EOF'
# RKE2 CIS kernel runtime requirements
vm.overcommit_memory = 1
vm.panic_on_oom = 0
kernel.panic = 10
kernel.panic_on_oops = 1
EOF

sudo sysctl --system
```

Verify:

```bash
sysctl \
  vm.overcommit_memory \
  vm.panic_on_oom \
  kernel.panic \
  kernel.panic_on_oops
```

Expected output:

```text
vm.overcommit_memory = 1
vm.panic_on_oom = 0
kernel.panic = 10
kernel.panic_on_oops = 1
```

Then restart the appropriate RKE2 service:

```bash
sudo systemctl restart rke2-server
```

or:

```bash
sudo systemctl restart rke2-agent
```

## Troubleshooting

Check the live values:

```bash
sysctl -n vm.overcommit_memory
sysctl -n vm.panic_on_oom
sysctl -n kernel.panic
sysctl -n kernel.panic_on_oops
```

Inspect persistent definitions:

```bash
grep -RInE \
  'vm\.overcommit_memory|vm\.panic_on_oom|kernel\.panic|kernel\.panic_on_oops' \
  /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d 2>/dev/null
```

Inspect RKE2 startup logs:

```bash
sudo journalctl -u rke2-server -b --no-pager
```

or:

```bash
sudo journalctl -u rke2-agent -b --no-pager
```

If a later sysctl file overrides the managed values, remove or correct the conflicting definition so the effective runtime values remain aligned with the RKE2 CIS requirements.
