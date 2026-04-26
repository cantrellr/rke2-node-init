# Troubleshooting Guide

Last Updated: April 24, 2026

This guide maps common failures to targeted remediation.

## Quick Triage

1. Confirm manifest path and action are correct.
2. Confirm custom CA files exist at referenced runtime path.
3. Confirm staging artifacts are present for offline actions.
4. Inspect log output under `logs/` and action output under `outputs/`.

## Common Issues

### 1) Custom CA file not found

Symptoms:
- action fails before install
- path resolution errors for `rootCrt` / `rootKey`

Checks:

```bash
ls -la configs/cotpa/certs
ls -la configs/preprod/certs
```

Fix:
- use environment-scoped runtime paths in YAML:
  - `/rke2-node-init/configs/cotpa/certs/...`
  - `/rke2-node-init/configs/preprod/certs/...`

### 2) Boot service does not execute node manifest

Symptoms:
- VM boots but action does not run

Checks:

```bash
systemctl status rke2-boot.service
journalctl -u rke2-boot.service -b --no-pager
```

Fix:
- ensure ISO payload contains `/config/<yaml>`
- ensure `bootService.yamlPath` points to a directory with node YAMLs
- verify ISO attached to correct VM as CD media

### 3) Multus/Canal CNI permission failures

Symptoms:
- errors like `cannot find valid master CNI config`

Fix:

```bash
sudo install -m 0755 scripts/fix-cni-perms.sh /usr/local/sbin/fix-cni-perms.sh
sudo install -m 0644 scripts/systemd/rke2-cni-perms.service /etc/systemd/system/
sudo install -m 0644 scripts/systemd/rke2-cni-perms.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rke2-cni-perms.timer
```

### 4) Token file failures on server/agent join

Checks:

```bash
grep -R "tokenFile:" configs/preprod configs/cotpa
ls -la outputs
```

Fix:
- confirm token path points to `/rke2-node-init/outputs/...`
- regenerate bootstrap token if needed

### 5) Registry push failures

Checks:

```bash
sudo ./bin/rke2nodeinit.sh --dry-push push -r <registry> -u <user> -p <pass>
```

Fix:
- validate credentials
- validate registry CA trust and mirror configuration
- validate name resolution and firewall

### 6) STIG script side effects

Use report-first mode:

```bash
sudo ./scripts/apply-stigs.sh --report-only
```

Only apply after reviewing expected changes.

## Escalation Data to Capture

1. command used
2. manifest file path
3. relevant log excerpt (`logs/*.log`)
4. `journalctl` excerpt for failing service
5. output of `verify` action
