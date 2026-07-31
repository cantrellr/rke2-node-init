# RKE2 Node Init Configuration Examples

This directory provides runnable `rkeprep/v2` YAML examples for `bin/rke2nodeinit.sh` actions.

**Last Updated:** July 31, 2026

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
| `image-example.yaml` | `Image` | Online golden-image preparation |
| `airgap-example.yaml` | `Airgap` | Golden-image preparation and shutdown |
| `push-example.yaml` | `Push` | `push` |
| `server-example.yaml` | `Server` | `server` |
| `live-node-secure-registry-example.yaml` | `Server` | Live `server` execution with authenticated registry configuration |
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

- `rke2Version`, `rke2CNIVersion`, `rke2MultusVersion`, `rke2FlannelVersion`
- `registry`, `registryUsername`, `registryPassword`
- `secureRegistry`, `registryUsernameFile`, `registryPasswordFile`
- `customCA.rootCrt`, `customCA.intermediateCrt`, `customCA.installToOSTrust`
- `interfaces[]` for multi-NIC declarations
- `cluster.serverUrl`, `cluster.token`, `cluster.tlsCertFingerprint`
- `fixCNIPermissions` to enable timer-based CNI permission remediation during `image`

The script accepts both camelCase and several legacy kebab-case aliases.

### Authenticated registry configuration at live execution

Set `spec.secureRegistry: true` only on a `Server`, `singleNodeServer`, `AddServer`, or `Agent` manifest. Prefer absolute references to protected files copied into the environment-specific deployment image:

```yaml
spec:
  registry: kubeharbor.dev.kube
  secureRegistry: true
  registryUsernameFile: /etc/rancher/rke2/registry-credentials/username
  registryPasswordFile: /etc/rancher/rke2/registry-credentials/token
```

Do not set `secureRegistry` or embed deployment credentials in the `Image`, `singleNodeImage`, or `Airgap` manifest. The golden-image phase runs while connected to the Internet and produces a reusable template. Private CA material and registry credentials are copied later into the environment-specific deployment image, before it is cloned into final nodes.

At live `server`, `add-server`, or `agent` execution, the dispatcher resolves both credential files into a temporary `0600` manifest under `/run/rke2-node-init`. The existing provisioning core consumes that manifest, writes authenticated settings to `/etc/rancher/rke2/registries.yaml`, and the dispatcher removes the temporary manifest when the action returns. Missing or insecure credential files stop execution before the core runs.

See [`../../docs/SECURE-REGISTRY-CREDENTIALS.md`](../../docs/SECURE-REGISTRY-CREDENTIALS.md) for the full golden-image-to-deployment-image lifecycle, source precedence, validation behavior, and verification commands.

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

1. Prepare the reusable golden image while connected to the Internet:

```bash
sudo ./bin/rke2nodeinit.sh -f examples/config/image-example.yaml image
```

2. Shut down and clone the golden image into an environment-specific deployment image.

3. Boot the deployment image with a temporary network identity and copy its CA certificates and protected registry credential files.

4. Clone the deployment image into the final nodes and attach each node's boot ISO.

5. Let the live node manifest configure the first server and remaining nodes:

```bash
sudo ./bin/rke2nodeinit.sh \
  -f examples/config/live-node-secure-registry-example.yaml \
  server -y

sudo ./bin/rke2nodeinit.sh -f examples/config/add-server-example.yaml add-server
sudo ./bin/rke2nodeinit.sh -f examples/config/agent-example.yaml agent
```

### Golden Image Template

```bash
sudo ./bin/rke2nodeinit.sh -f examples/config/airgap-example.yaml airgap
```

This performs image preparation and powers off at completion for template capture. The golden-image manifest must not contain environment-specific registry credentials.

### Prepare deployment-time registry files

```bash
sudo install -d -o root -g root -m 700 \
  /etc/rancher/rke2/registry-credentials
sudo install -o root -g root -m 600 /path/to/username \
  /etc/rancher/rke2/registry-credentials/username
sudo install -o root -g root -m 600 /path/to/token \
  /etc/rancher/rke2/registry-credentials/token
```

Perform this on the environment-specific deployment image before cloning the final nodes.

---

## Security Guidance

- Never commit real credentials or tokens in YAML.
- Keep `secureRegistry` in live node manifests, not golden-image manifests.
- Prefer `registryUsernameFile` and `registryPasswordFile`.
- Keep both credential files outside the repository with mode `0600`.
- Put only credential-file path references on boot media.
- Copy private CA material and credentials into the deployment image before final node cloning.
- Keep production manifests outside committed example paths.
- Avoid direct environment values for unattended systemd execution.

See [../../SECURITY.md](../../SECURITY.md) for reporting and policy details.
