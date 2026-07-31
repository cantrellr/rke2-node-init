# Secure registry credentials for image manifests

`rkeprep/v2` `Image` and `singleNodeImage` manifests can set:

```yaml
spec:
  registry: kubeharbor.dev.kube
  secureRegistry: true
```

When `secureRegistry` is true, `rke2nodeinit` refuses to continue unless it can resolve both a registry username and password/token. The dispatcher materializes those values into a temporary root-only manifest under `/run/rke2-node-init`, passes that manifest to the existing provisioning core, and removes it after the action completes. The provisioning core then writes the authenticated RKE2 runtime configuration to:

```text
/etc/rancher/rke2/registries.yaml
```

That file is installed with mode `0600` by the existing registry renderer.

## Recommended configuration

Keep credentials outside the repository and reference protected files:

```yaml
apiVersion: rkeprep/v2
kind: Image
metadata:
  name: rke2-secure-image
spec:
  rke2Version: v1.35.6+rke2r1
  registry: kubeharbor.dev.kube
  secureRegistry: true
  registryUsernameFile: /root/.config/rke2-node-init/kubeharbor-pull-username
  registryPasswordFile: /root/.config/rke2-node-init/kubeharbor-pull-token
```

Prepare the files:

```bash
sudo install -d -m 700 /root/.config/rke2-node-init
sudo install -m 600 /path/to/username \
  /root/.config/rke2-node-init/kubeharbor-pull-username
sudo install -m 600 /path/to/token \
  /root/.config/rke2-node-init/kubeharbor-pull-token
```

Relative credential paths are resolved relative to the manifest file. The password/token file must not be group- or world-accessible.

## Supported credential sources

Credentials are resolved in this order:

1. `spec.registryUsernameFile` and `spec.registryPasswordFile`
2. `RKE2_REGISTRY_USERNAME_FILE` and `RKE2_REGISTRY_PASSWORD_FILE`
3. `RKE2_REGISTRY_USERNAME` and `RKE2_REGISTRY_PASSWORD`
4. Legacy inline `spec.registryUsername` and `spec.registryPassword`

File-based inputs are preferred. Inline credentials remain supported for backward compatibility but should not be committed to Git.

Example using environment-provided file locations:

```bash
export RKE2_REGISTRY_USERNAME_FILE=/root/.config/rke2-node-init/kubeharbor-pull-username
export RKE2_REGISTRY_PASSWORD_FILE=/root/.config/rke2-node-init/kubeharbor-pull-token
sudo --preserve-env=RKE2_REGISTRY_USERNAME_FILE,RKE2_REGISTRY_PASSWORD_FILE \
  bin/rke2nodeinit.sh -f image.yaml -y
```

## Failure behavior

The image action stops before provisioning when any of the following is true:

- `spec.registry` is missing.
- A username cannot be resolved.
- A password/token cannot be resolved.
- A referenced credential file is missing or unreadable.
- The password/token file has group or world permissions.
- Python 3 or PyYAML is unavailable.

No credential value is printed by the secure-registry helper. Operators should still avoid shell tracing (`set -x`) and should protect process environments when using direct environment variables.

## Verification

After the image action completes, verify the generated runtime file without printing its password:

```bash
sudo test "$(stat -c '%a' /etc/rancher/rke2/registries.yaml)" = 600
sudo grep -q '^configs:' /etc/rancher/rke2/registries.yaml
sudo grep -q '^    auth:' /etc/rancher/rke2/registries.yaml
```

Use the RKE2 runtime to test an actual pull after installation:

```bash
sudo /var/lib/rancher/rke2/bin/crictl pull \
  kubeharbor.dev.kube/rancher/rancher-shell:<tag>
```
