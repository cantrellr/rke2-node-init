# Secure registry credentials at live node execution

`secureRegistry` is a live node deployment control. It belongs in an `rkeprep/v2` `Server`, `singleNodeServer`, `AddServer`, or `Agent` manifest—not in the `Image`, `singleNodeImage`, or `Airgap` manifest used to create the golden image.

```yaml
spec:
  registry: kubeharbor.dev.kube
  secureRegistry: true
```

When `secureRegistry` is true during a live node action, `rke2nodeinit` refuses to continue unless it can resolve both a registry username and a registry password/token. The dispatcher materializes those values into a temporary root-only manifest under `/run/rke2-node-init`, passes that manifest to the existing provisioning core, and removes it after the action completes.

The provisioning core writes the authenticated RKE2 container-runtime configuration to:

```text
/etc/rancher/rke2/registries.yaml
```

The existing registry renderer installs that file with mode `0600`.

## Air-gapped image and deployment lifecycle

The intended workflow keeps environment-specific private data out of the reusable golden image and out of the boot ISO:

1. On an Internet-connected VM, run the `Image`, `singleNodeImage`, or `Airgap` action to download and stage RKE2 artifacts and install the first-boot machinery.
2. Do not place `secureRegistry`, a registry username, or a registry token in the golden-image manifest.
3. Shut down the completed golden image and clone it to an environment-specific deployment image.
4. Boot the deployment image with a temporary network identity so the administration host can reach it.
5. Copy the environment CA certificates, registry username file, registry token file, and other private deployment data into protected paths on the deployment image.
6. Shut down the deployment image and clone it into the final RKE2 nodes.
7. Attach the correct boot ISO to each node. The ISO carries the node's `Server`, `AddServer`, `Agent`, or `singleNodeServer` manifest and contains only credential-file references—not credential values.
8. During first-boot live execution, `rke2nodeinit` resolves the two files, creates a temporary `0600` manifest, invokes the provisioning core, writes `/etc/rancher/rke2/registries.yaml`, and securely removes the temporary manifest.

This allows one reusable golden image to serve multiple environments while each deployment image receives its own CA chain, robot account, and pull token before node cloning.

## Live node manifest

Use absolute credential paths because the manifest may be read from boot media or copied into a runtime staging directory:

```yaml
apiVersion: rkeprep/v2
kind: Server
metadata:
  name: j64seg1opman-server-01
spec:
  rke2Version: v1.35.6+rke2r1
  registry: kubeharbor.dev.kube
  secureRegistry: true
  registryUsernameFile: /etc/rancher/rke2/registry-credentials/username
  registryPasswordFile: /etc/rancher/rke2/registry-credentials/token
```

The same fields are supported by `singleNodeServer`, `AddServer`, and `Agent` manifests.

## Prepare the deployment image

Copy private material only after the golden image has been converted into an environment-specific deployment image:

```bash
sudo install -d -o root -g root -m 700 \
  /etc/rancher/rke2/registry-credentials

sudo install -o root -g root -m 600 /path/to/registry-username \
  /etc/rancher/rke2/registry-credentials/username

sudo install -o root -g root -m 600 /path/to/registry-token \
  /etc/rancher/rke2/registry-credentials/token
```

Both files must exist, be readable during live execution, contain non-empty UTF-8 text, and not be group- or world-accessible.

## Credential resolution order

Credentials are resolved in this order:

1. `spec.registryUsernameFile` and `spec.registryPasswordFile`
2. `RKE2_REGISTRY_USERNAME_FILE` and `RKE2_REGISTRY_PASSWORD_FILE`
3. `RKE2_REGISTRY_USERNAME` and `RKE2_REGISTRY_PASSWORD`
4. Legacy inline `spec.registryUsername` and `spec.registryPassword`

File-based inputs are preferred. Inline credentials remain supported for backward compatibility but must never be committed to Git, stored in boot media, or captured in a reusable image.

Environment-provided file locations are useful for manual live execution:

```bash
export RKE2_REGISTRY_USERNAME_FILE=/etc/rancher/rke2/registry-credentials/username
export RKE2_REGISTRY_PASSWORD_FILE=/etc/rancher/rke2/registry-credentials/token

sudo --preserve-env=RKE2_REGISTRY_USERNAME_FILE,RKE2_REGISTRY_PASSWORD_FILE \
  bin/rke2nodeinit.sh -f server.yaml -y
```

For unattended first-boot execution, manifest file references are preferred because ordinary shell environment variables are not automatically inherited by systemd services.

## Failure behavior

The live node action stops before the provisioning core runs when any of the following is true:

- `spec.registry` is missing.
- A registry username cannot be resolved.
- A registry password/token cannot be resolved.
- A referenced credential file is missing, unreadable, empty, or not valid UTF-8.
- Either credential file has group or world permissions.
- Python 3 or PyYAML is unavailable.

`rke2nodeinit` also rejects `secureRegistry: true` on `Image`, `singleNodeImage`, and `Airgap` manifests. Move the setting and credential-file references into the live node manifest carried by the boot ISO.

No credential value is printed by the secure-registry helper. Operators should still avoid shell tracing (`set -x`) and direct environment variables where process-environment exposure is a concern.

## Verification

After the live `server`, `add-server`, or `agent` action completes, verify the generated runtime file without printing its password:

```bash
sudo test "$(stat -c '%a' /etc/rancher/rke2/registries.yaml)" = 600
sudo grep -q '^configs:' /etc/rancher/rke2/registries.yaml
sudo grep -q '^    auth:' /etc/rancher/rke2/registries.yaml
sudo find /run/rke2-node-init -maxdepth 1 \
  -name 'live-secure-registry.*.yaml' -print -quit | grep -q '^$'
```

After RKE2 starts, test an authenticated pull using an image that exists in the private registry:

```bash
sudo /var/lib/rancher/rke2/bin/crictl pull \
  kubeharbor.dev.kube/rancher/rancher-shell:<tag>
```
