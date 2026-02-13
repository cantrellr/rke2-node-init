# STIG Script Guide

This document describes what scripts/apply-stigs.sh does and how to run it safely.

## What scripts/apply-stigs.sh does

The script follows a report-first workflow for host firewall and RKE2 STIG checks. It:

- Reports current firewall and RKE2 STIG-relevant settings.
- Prompts before applying changes (unless --apply is used).
- Prompts to run kubectl validations when RKE2 is detected.
- Applies firewall zone configuration (DOMAIN, NFS, SEGMENT1) when approved.
- Applies a limited set of RKE2 config hardening changes in /etc/rancher/rke2/config.yaml when approved.
- Optionally restarts rke2-server or rke2-agent when --restart-rke2 is provided.
- Prints a firewall status report at the end.
- Reports pre-run RKE2 settings even if RKE2 is not installed or running.

## Report workflow

1. Collects host firewall and RKE2 STIG signals.
2. Prints a single report with PASS/FAIL/MANUAL/NOT-RUN/NOT-APPLICABLE statuses.
3. Prompts to apply remediations unless --apply or --report-only is used.
4. Optionally prompts to run kubectl validations if RKE2 is detected.

Status meanings:

- PASS: The check is satisfied by current settings.
- FAIL: The check is not satisfied and may be remediated by the script.
- MANUAL: The check requires human review or cluster-level controls.
- NOT-RUN: A dependent tool (kubectl) was skipped or unavailable.
- NOT-APPLICABLE: The control does not apply to the detected role.

## Supported actions

### Firewall (host)

- Ensures firewalld is installed, enabled, and running.
- Creates zones DOMAIN, NFS, SEGMENT1.
- Binds interfaces ens33, ens35, ens36 to the zones.
- Sets zone targets to DROP and enables masquerade only on DOMAIN.

### RKE2 (host-side)

- Detects rke2-server or rke2-agent.
- Reports (and can apply) select configuration flags for TLS, kubelet auth, and secure binding.
- Enforces ownership and mode on /etc/rancher/rke2/config.yaml.
- Reports protection checks for /etc/rancher/rke2 and /var/lib/rancher/rke2.
- Optionally prompts for kubectl validation checks.

## RKE2 STIG control coverage

The script aligns with RGS RKE2 STIG V2R5 and reports a subset of control IDs. Coverage is split between host-only checks and kubectl-dependent checks:

Host-only checks (no kubectl required):

- SV-254553r1016525_rule (TLS min version and cipher suites)
- SV-254554r1043176_rule (controller manager credentials)
- SV-254556r1137638_rule (controller manager secure binding)
- SV-254557r1137638_rule (kubelet anonymous auth)
- SV-254559r1137639_rule (kubelet read-only port)
- SV-254561r1137639_rule (kubelet explicit authorization)
- SV-254562r1137640_rule (API server anonymous auth)
- SV-254563r960906_rule (audit policy configured)
- SV-254564r1156618_rule (config/data path protection)
- SV-254555r1056186_rule (components configured per guidance) - manual
- SV-254565r960963_rule (essential configuration only) - manual
- SV-254568r1016534_rule (session termination) - manual
- SV-254569r1016537_rule (isolate security functions) - manual
- SV-254571r1156616_rule (prevent nonprivileged privileged functions) - manual
- SV-254572r1016560_rule (restrict privileged updates/images) - manual
- SV-268321r1017019_rule (verified packages) - manual

Kubectl-dependent checks (optional):

- SV-254566r1173952_rule (PPSM CAL ports/protocols)
- SV-254567r1016559_rule (cryptographic password storage)
- SV-254570r1137645_rule (separate execution domains)
- SV-254574r961677_rule (remove old components)
- SV-254575r1137649_rule (latest authorized images)

## Usage examples

### Report only (no changes)

```bash
./scripts/apply-stigs.sh --report-only
```

### Report first, then prompt to apply changes

```bash
./scripts/apply-stigs.sh
```

### Apply changes without prompting

```bash
./scripts/apply-stigs.sh --apply
```

### Apply changes and restart RKE2 services

```bash
./scripts/apply-stigs.sh --apply --restart-rke2
```

### Dry-run (show actions without changes)

```bash
./scripts/apply-stigs.sh --dry-run
```

### Non-interactive mode (fails if a prompt is required)

```bash
./scripts/apply-stigs.sh --non-interactive
```

### Golden image mode (pre-STIG a template)

```bash
./scripts/apply-stigs.sh -image
```

## Flags

- --report-only: Print report and exit without applying changes.
- --apply: Apply remediations without prompting.
- --dry-run: Show commands without applying changes.
- --restart-rke2: Restart rke2-server or rke2-agent after config changes.
- -image: Golden image mode (apply + yes + non-interactive).
- -y, --yes: Auto-confirm prompts.
- --non-interactive: Fail if a prompt would be required.

## Notes

- Run as root or with sudo available.
- RKE2 changes apply only when an rke2-server or rke2-agent service is detected.
- kubectl validation checks are optional and depend on kubeconfig access.
- On agent nodes, server-only controls are reported as NOT-APPLICABLE.

## Persistent CNI Permissions Remediation (Canal + Multus)

If Multus fails with `cannot find valid master CNI config` and `/etc/cni/net.d` was hardened to restrictive modes, install the persistent remediation below.

For golden image workflows, this can also be enabled during `image` action by setting `spec.fixCNIPermissions: true` in YAML or using `--fix-cni-permissions` on the CLI.

1) Install the remediation script:

```bash
sudo install -m 0755 scripts/fix-cni-perms.sh /usr/local/sbin/fix-cni-perms.sh
```

2) Install and enable the systemd units:

```bash
sudo install -m 0644 scripts/systemd/rke2-cni-perms.service /etc/systemd/system/rke2-cni-perms.service
sudo install -m 0644 scripts/systemd/rke2-cni-perms.timer /etc/systemd/system/rke2-cni-perms.timer
sudo systemctl daemon-reload
sudo systemctl enable --now rke2-cni-perms.service rke2-cni-perms.timer
```

3) Verify:

```bash
sudo ls -ld /etc/cni/net.d
sudo ls -l /etc/cni/net.d/10-canal.conflist /etc/cni/net.d/00-multus.conf
kubectl -n kube-system get pods -l k8s-app=canal -o wide
kubectl -n kube-system get pods -l app=rke2-multus -o wide
```

Expected permissions:

- `/etc/cni/net.d` => `0755`
- `10-canal.conflist` => `0644`
- `00-multus.conf` => `0644`

Security note: this remediation does not relax `calico-kubeconfig` to world-readable mode.
