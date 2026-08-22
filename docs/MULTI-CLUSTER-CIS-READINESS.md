# Multi-Cluster CIS Readiness Controls

## Purpose

Multi-node and multi-cluster deployments must start from a sealed image that contains staged RKE2 artifacts but no prior node, kubelet, CNI, or etcd identity. A VM that was previously started as a single-node RKE2 server must not be cloned directly.

## Template workflow

Prepare the connected or air-gapped image as normal. Immediately before converting the VM to a VMware template, run:

```bash
sudo bin/rke2-template-sanitize.sh --force
```

The command stops RKE2, removes cluster-specific runtime state, clears the machine ID and SSH host keys, cleans cloud-init, writes a sanitization marker, and powers off. It preserves staged air-gap artifacts, repository content, OS CA trust, registry configuration, and `/etc/rancher/rke2/token.d`.

Use `--no-poweroff` only during automated validation.

## First-boot preflight

Before the RKE2 server or agent workflow, run the appropriate preflight:

```bash
sudo bin/rke2-multicluster-preflight.sh server
sudo bin/rke2-multicluster-preflight.sh add-server
sudo bin/rke2-multicluster-preflight.sh agent
```

The preflight:

- creates a machine ID when the cloned image was correctly sealed with an empty ID;
- rejects stale etcd, kubelet, CNI, or node-password state;
- validates the RKE2 CIS `etcd` account and required kernel settings when a CIS config is already present;
- warns when no default route exists.

For an intentional retry on an already initialized node, set `RKE2NODEINIT_ALLOW_EXISTING_STATE=1`. Do not use that override on newly cloned nodes.

## Network policy

For the Segment 1 deployment, `ens33` is the primary routed interface and must use:

```yaml
- name: ens33
  gateway: 1.0.0.1
```

Secondary interfaces, including `ens36`, must not contain a gateway. Apply this directly in each deployment node manifest before regenerating the boot ISOs.

## CNI image preparation

For Multus plus Canal images, retain the default CNI permission remediation:

```yaml
spec:
  cni:
    - multus
    - canal
  fixCNIPermissions: true
```

Disabling this remediation is not recommended for CIS or hardened-CNI templates unless the resulting binaries and host-local directories have been independently validated.
