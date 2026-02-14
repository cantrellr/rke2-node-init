# RKE2 Air‑Gapped Golden Image Plan (v1.35.0+rke2r3)

## 1) Inputs and guardrails

### Given inputs
- **Target OS/distro:** **Ubuntu Server 24.04 LTS amd64**. SELinux **not enabled**.
- **Registry (internal):** `altregistry.dev.kube:8443` (registry authority) with a required namespace/project prefix of **`/rke2`** (i.e. image push target is `altregistry.dev.kube:8443/rke2/...`). **No auth required.**
- **Embedded registry mirror:** **Enabled** (RKE2 distributed mirror / Spegel).

### Non‑negotiables
- Every image in:
  - the **RKE2 image list/manifest** for the target version
  - the **hardened-cni-plugins** image/tag manifest for the target version
  must be downloaded and made available.
- Cluster nodes must **never** reach outside for images.
- Nodes must be able to **pull from each other** (peer sharing) and/or your internal registry.

### A critical constraint (don’t fight this)
`system-default-registry` can only be a RFC3986 authority (host + optional port). That means **you cannot set** `system-default-registry: altregistry.dev.kube:8443/rke2`.

So we treat:
- `altregistry.dev.kube:8443` as the **registry authority** used by containerd endpoints.
- `/rke2` as the **namespacing rule** we implement via **registry rewrites** in `registries.yaml`.


**Recommendation for your `/rke2` layout:** do **not** set `system-default-registry` at all; rely on `registries.yaml` mirrors + rewrites to route upstream image names into `altregistry.dev.kube:8443/rke2/...`. If you set `system-default-registry: altregistry.dev.kube:8443`, RKE2 will reference images without the `/rke2` prefix and pulls will fail unless you also publish duplicates at the root path.


## 2) High-level architecture

### Network zones
1. **Restricted “build” network (has controlled egress)**
   - Runs your repo pipelines.
   - Downloads RKE2 artifacts + image archives/manifests.
   - Pushes images into `altregistry.dev.kube:8443/rke2`.

2. **Air‑gapped target network**
   - Nodes install RKE2 from **pre-staged artifacts**.
   - Nodes resolve all images via:
     - the internal registry (`altregistry.dev.kube:8443`), and
     - the embedded registry mirror for peer-to-peer “image lending”.

### “Source of truth” for images
- **Primary source:** `altregistry.dev.kube:8443/rke2/...` (internal registry)
- **Secondary source:** Embedded registry mirror (spegel) to cover “node A has it, node B needs it”.

Operationally: the internal registry guarantees *baseline availability*; the embedded mirror guarantees *cluster resiliency* if a node is missing an image locally.


## 3) Repo update plan (rke2-node-init)

Your repo already has the right primitives (`image`, `push`, `verify`, `airgap`). What you need is tighter alignment to your **Harbor-style /rke2 prefix** and “no external pulls” enforcement.

### 3.1 Add first-class support for `/rke2` in registry mirroring
**Problem:** Today, the repo can push to `REGISTRY/namespace/...` (good), but `registries.yaml` doesn’t rewrite pulls to add `/rke2`.

**Fix:** Extend registry generation to support a required namespace prefix.

**Implementation approach (repo current-state):**
- Set **`spec.registry`** to the full *host + project* value, e.g. `altregistry.dev.kube:8443/rke2`.
- The tooling infers:
  - registry host: `altregistry.dev.kube:8443`
  - project/prefix: `rke2`
- It then generates `/etc/rancher/rke2/registries.yaml` with:
  - mirrors for *all registries referenced by your image lists*
  - endpoint(s): `https://altregistry.dev.kube:8443`
  - rewrite rules that prepend `rke2/` to the image name

**Example `registries.yaml` pattern (generated):**
```yaml
mirrors:
  docker.io:
    endpoint:
      - "https://altregistry.dev.kube:8443"
    rewrite:
      "^(.*)$": "rke2/docker.io/$1"

  registry.k8s.io:
    endpoint:
      - "https://altregistry.dev.kube:8443"
    rewrite:
      "^(.*)$": "rke2/registry.k8s.io/$1"

  ghcr.io:
    endpoint:
      - "https://altregistry.dev.kube:8443"
    rewrite:
      "^(.*)$": "rke2/ghcr.io/$1"

configs:
  "altregistry.dev.kube:8443":
    tls:
      ca_file: /etc/rancher/rke2/certs/altregistry-ca.crt
    # No auth (per requirements)
```

**Why the mixed patterns?**
- For **all registries**, we use the same collision-proof layout: `rke2/<upstream-registry>/<repo>`.

This aligns with the repo's `push` action, which tags/pushes images into `altregistry.dev.kube:8443/rke2/<upstream-registry>/<repo>:<tag>`.

### 3.2 Enforce “no external pulls” at the containerd layer
Add to `/etc/rancher/rke2/config.yaml`:
```yaml
disable-default-registry-endpoint: true
```
Then ensure the generated `registries.yaml` covers every upstream registry in the manifests.

This makes failures loud and early: if an image isn’t mirrored/present, the node fails instead of “mysteriously going outbound”.

### 3.3 Embedded registry mirror defaults and validation
Ensure your generated config supports:
```yaml
embedded-registry: true
```
And the repo docs/scripts explicitly call out network requirements:
- TCP **9345** (RKE2 supervisor)
- TCP **5001** (embedded registry mirror)

### 3.4 Manifest-driven completeness checks
You already have a strong “required images” concept. Make it unambiguous:
- Always fetch and store:
  - `rke2-images-*.txt` for the selected RKE2 version/arch/CNI(s)
  - hardened CNI plugin image/tag list(s)
- Build a **single union file** `required-images.txt`
- Gate the pipeline:
  - **FAIL** if `required-images.txt` contains an image not found in the final pushed inventory.

### 3.5 Push action: normalize image names before push
The current `push` action mirrors what is present in the containerd store. Tighten it by:
- Normalizing image names so they include an explicit registry (especially for `docker.io`).
- Producing a post-push report:
  - list of images pushed
  - list of images skipped/failed
  - list of images still missing vs `required-images.txt`


### 3.6 No-auth registry pushes
Your registry allows anonymous push/pull. Update `action_push()` so it **skips** `nerdctl login/logout` when `registryUsername`/`registryPassword` are empty. This avoids a hard failure on `nerdctl login` in no-auth environments.


## 4) Golden image build workflow (restricted network)

### 4.1 Build host prerequisites
- OS: Ubuntu 24.04 (or the distro you’re templating)
- Tools (repo can bootstrap these): `curl`, `zstd`, `nerdctl`, `skopeo` (optional), `jq`, `sha256sum`

### 4.2 Step-by-step pipeline (single version)
Assume:
- `RKE2_VERSION=v1.35.0+rke2r3`
- Registry push target is `altregistry.dev.kube:8443/rke2`

**Step A — Build the golden image staging directory**
Run repo action:
```bash
./bin/rke2nodeinit.sh image -f configs/<your-image-config>.yaml
```
Expected outputs (conceptual):
- RKE2 artifacts cached (binary/tarball + checksums)
- RKE2 image archives and/or “images list” files
- hardened-cni-plugins artifacts
- `required-images.txt` (union)

**Step B — Push all images to the internal registry**
```bash
./bin/rke2nodeinit.sh push -f configs/<your-image-config>.yaml
```
This should push to:
- `altregistry.dev.kube:8443/rke2/...`

**Step C — Verify completeness**
```bash
./bin/rke2nodeinit.sh verify -f configs/<your-image-config>.yaml
```
Verification gates:
- `required-images.txt` has 0 missing
- `registries.yaml` includes all required upstream registries
- (optional) run spot-check pulls from the registry for a few critical images


## 5) Air‑gapped node bootstrap workflow

You have two supported image-availability strategies in the airgap:

### Strategy 1 — Private registry + embedded mirror (recommended)
- Nodes pull from `altregistry.dev.kube:8443` (with rewrite to `/rke2/...`).
- Embedded mirror covers missing-local-image scenarios between nodes.

**Node config files**
- `/etc/rancher/rke2/config.yaml` (server example):
```yaml
# baseline cluster settings omitted for brevity
cni:
  - multus
  - canal
embedded-registry: true
# hard fail if a registry isn’t mirrored
disable-default-registry-endpoint: true
```

- `/etc/rancher/rke2/registries.yaml` generated by the repo (copied onto every node).

**RKE2 artifacts**
- Pre-stage the RKE2 install artifacts (tarball method) so installation never needs the internet.

### Strategy 2 — Fully “manual images on every node” (fallback)
If you need the absolute minimum moving parts:
- Copy the RKE2 image archives into:
  - `/var/lib/rancher/rke2/agent/images/`
- RKE2 imports them on start.

This is viable, but operationally noisier (you must keep every node in sync). The embedded mirror reduces the pain, but the registry method still scales better.


## 6) “All nodes share images” design

### Embedded registry mirror (Spegel)
With `embedded-registry: true` and correct registry mirroring config:
- If Node B needs an image and can’t find it locally, it can pull it from Node A’s containerd store.
- This avoids depending on an external registry for intra-cluster pulls.

### What still matters
- Peer sharing is not magic: if **no node** has the image, the pull will fail (by design, because you’re disabling outbound fallbacks).
- Therefore your **pre-flight** completeness checks are the real control point.


## 7) Operational playbook (how this runs day-to-day)

### 7.1 New cluster deployment
1. In restricted network:
   - `image` → `push` → `verify`
2. Bake golden image (Packer/Image Builder/Hyper-V template) that includes:
   - cached RKE2 artifacts
   - `registries.yaml` template
   - registry CA bundle
   - optional: preloaded images in containerd (nice-to-have)
3. In airgap:
   - deploy nodes from golden image
   - apply cluster config (`config.yaml` + `registries.yaml`)
   - start `rke2-server` then `rke2-agent`

### 7.2 Upgrades
Repeat the same pipeline per version. The rule is simple:
- No node moves to the new version until:
  - all new images are in the registry (and/or staged)
  - `verify` passes

### 7.3 Handling a “missing image” incident
If you see image pull failures:
- First check: is the image in `required-images.txt`?
  - If yes: it should exist in the internal registry.
  - If no: you have a workload-level dependency not captured by RKE2 manifests—add it to an **app image bundle** managed separately.
- Second check: is `disable-default-registry-endpoint` enabled?
  - If yes: good. Failure is signal.
  - If no: you’re likely leaking to upstream endpoints (bad).


## 8) Remaining hard inputs (only if you want it ultra-precise)
To make the repo changes completely “drop-in” with no edits later, the remaining hard input is:
- The **exact OS** you want the golden image to target (Ubuntu 24.04 vs 22.04 vs Debian 12 vs Rocky/Alma etc).
- Registry auth: **none required** (per requirements).

