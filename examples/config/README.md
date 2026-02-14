# RKE2 Node Init Configuration Examples

This directory provides runnable `rkeprep/v2` YAML examples for `bin/rke2nodeinit.sh` actions.

**Last Updated:** February 13, 2026

---

## Quick Start

```bash
cp examples/config/server-example.yaml my-server.yaml
sudo ./bin/rke2nodeinit.sh -f my-server.yaml -P server
sudo ./bin/rke2nodeinit.sh -f my-server.yaml server
```

Use `-P` first to print sanitized configuration and confirm parsed values.

---

## Example Files and Action Mapping

| Example | Kind | Primary Action |
| --- | --- | --- |
| `image-example.yaml` | `Image` | `image` |
| `airgap-example.yaml` | `Airgap` | `airgap` |
| `push-example.yaml` | `Push` | `push` |
| `server-example.yaml` | `Server` | `server` |
| `add-server-example.yaml` | `AddServer` | `add-server` |
| `agent-example.yaml` | `Agent` | `agent` |
| `verify-example.yaml` | `Verify` | `verify` |
| `custom-ca-example.yaml` | `CustomCA` | `custom-ca` |

Additional node lifecycle actions (`label-node`, `taint-node`, `list-images`) can also consume YAML with `rkeprep/v2` metadata when applicable.

---

## API Contract (rkeprep/v2)

All manifests require:

```yaml
apiVersion: rkeprep/v2
kind: <Kind>
metadata:
  name: <unique-name>
spec: {}
```

### Commonly Used `spec` Fields

- `rke2Version`, `rke2CNIVersion`
- `registry`, `registryUsername`, `registryPassword`
- `customCA.rootCrt`, `customCA.intermediateCrt`, `customCA.installToOSTrust`
- `interfaces[]` for multi-NIC declarations
- `cluster.serverUrl`, `cluster.token`, `cluster.tlsCertFingerprint`
- `fixCNIPermissions` to enable timer-based CNI permission remediation during `image`

The script accepts both camelCase and several legacy kebab-case aliases.

---

## Validation and Safe Preflight

```bash
# YAML parse check
python3 -c "import yaml; list(yaml.safe_load_all(open('examples/config/server-example.yaml')))"

# Script-level validation without mutation
sudo ./bin/rke2nodeinit.sh -f examples/config/verify-example.yaml verify --dry-run

# Print effective config with masked secrets
sudo ./bin/rke2nodeinit.sh -f examples/config/server-example.yaml -P server
```

---

## Common Workflows

### Air-Gapped Cluster Build

1. Online prep host:

```bash
sudo ./bin/rke2nodeinit.sh -f examples/config/image-example.yaml image
```

1. Offline registry sync host:

```bash
sudo ./bin/rke2nodeinit.sh -f examples/config/push-example.yaml push
```

1. Offline first control plane:

```bash
sudo ./bin/rke2nodeinit.sh -f examples/config/server-example.yaml server
```

1. Offline additional servers/workers:

```bash
sudo ./bin/rke2nodeinit.sh -f examples/config/add-server-example.yaml add-server
sudo ./bin/rke2nodeinit.sh -f examples/config/agent-example.yaml agent
```

### Golden Image Template

```bash
sudo ./bin/rke2nodeinit.sh -f examples/config/airgap-example.yaml airgap
```

This performs image preparation and powers off at completion for template capture.

---

## Security Guidance

- Never commit real credentials or tokens in YAML.
- Keep production manifests outside committed example paths.
- Use placeholders in committed files and inject secrets at runtime.
- Use restrictive file permissions for private material (`chmod 600`).

See [../../SECURITY.md](../../SECURITY.md) for reporting and policy details.
