# Hyper-V Boot Service ISO Workflow

## Overview

Boot service no longer depends on VM-name or hostname matching.

Current behavior:
- The first-boot service discovers attached ISO9660 media.
- It selects the first YAML file found under `/config` inside the ISO.
- It copies that YAML to `/root/server-config/` and runs `rke2nodeinit.sh -f <copied-yaml> -y`.
- In `persistent` mode, it reruns only when the selected YAML hash changes.

## Prerequisites

- Hyper-V host with PowerShell access.
- A template VM prepared with boot service enabled (`image` or `airgap` action).
- Boot ISO artifacts built from your node YAML directory.

## Build Boot ISOs

Option 1: use the Makefile helper.

```bash
cd /rke2-node-init
make boot-isos \
  BOOT_ISO_YAML_DIR=configs/preprod/nodes \
  BOOT_ISO_OUTPUT_DIR=outputs/boot-isos
```

Option 2: call the builder directly.

```bash
cd /rke2-node-init
bash scripts/build-boot-isos.sh \
  --yaml-dir configs/preprod/nodes \
  --output-dir outputs/boot-isos \
  --manifest outputs/boot-isos/manifest.tsv
```

Expected artifacts:
- `outputs/boot-isos/<metadata.name>.iso`
- `outputs/boot-isos/manifest.tsv`

## ISO Payload Contract

The ISO must contain YAML under this path:

- `/config/<yaml-file>`

The YAML content is copied into the ISO as-is.

## Hyper-V Provisioning Steps

### 1. Attach ISO as virtual DVD

Run on the Hyper-V host:

```powershell
$vmName = "dc1manager-ctrl01"
$isoPath = "C:\VM-ISO\dc1manager-ctrl01.iso"

# Attach (or replace) DVD media
Get-VMDvdDrive -VMName $vmName -ErrorAction SilentlyContinue | Remove-VMDvdDrive -ErrorAction SilentlyContinue
Add-VMDvdDrive -VMName $vmName -Path $isoPath
```

### 2. Start VM

```powershell
Start-VM -Name "dc1manager-ctrl01"
```

## What Happens at Boot

1. `rke2-boot.service` starts.
2. The script scans attached ISO9660 devices.
3. It mounts each ISO read-only and looks for `*.yaml`/`*.yml` under `/config`.
4. It selects the first YAML found.
5. It copies the file to `/root/server-config/<yaml-filename>` with mode `0600`.
6. It executes `rke2nodeinit.sh -f /root/server-config/<yaml-filename> -y`.
7. In `oneshot` mode, systemd creates `/var/lib/rke2-boot-complete` and does not run again.
8. In `persistent` mode, rerun happens only when the YAML hash differs from `/var/lib/rke2-boot-last-iso.sha256`.

## Verification

```bash
sudo systemctl status rke2-boot
sudo journalctl -u rke2-boot -n 200 --no-pager
```

Look for these log patterns:
- `Step 1: Discover attached configuration ISO`
- `Config path: /config/<yaml>`
- `Step 4: Execute RKE2 node initialization`

## Troubleshooting

### No ISO detected

Symptoms:
- `No attached ISO media detected (type iso9660).`

Checks:
- Confirm ISO is attached as DVD in Hyper-V.
- Confirm guest sees optical block device (`lsblk -f`).

### ISO found but no YAML selected

Symptoms:
- `ISO on <device> does not contain a YAML file under /config`
- `No attached ISO provided /config/<yaml>`

Checks:
- Verify ISO has `/config/<yaml>` (not `/configs`).
- Rebuild ISO if needed using `scripts/build-boot-isos.sh`.

### Persistent mode skipped execution

Symptom:
- `Persistent mode: ISO config hash unchanged; skipping bootstrap`

Meaning:
- Selected YAML content hash is unchanged from last successful run.

### Bootstrap command failed

Symptom:
- `RKE2 node initialization failed`

Checks:
- Review `rke2-boot` logs and `rke2nodeinit` logs under `logs/`.
- Validate YAML syntax and required fields (`apiVersion`, `kind`, action-specific spec fields).

## Legacy Note

`VirtualMachineName` KVP and hostname-based config matching are no longer required for boot service operation. You can still use KVP for other automation workflows, but boot-service config selection is now ISO-path based (`/config`).
