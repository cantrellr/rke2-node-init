Hardened CNI HTTP Download
==========================

The script supports staging an upstream `hardened-cni-plugins` tarball via HTTP(S) for air-gapped installs. To enable this, set the `HARDENED_CNI_URL` environment variable (or provide it in your YAML) to a direct downloadable tarball URL.

- The downloaded artifact is saved to the repository `DOWNLOADS_DIR` and its SHA256 is appended to the canonical manifest `sha256sum-<arch>.txt` so it participates in the same `sha256sum -c` verification performed during staging.
- During `image`, the script stages a chart-matched `hardened-cni-plugins` tarball into `/var/lib/rancher/rke2/agent/images/` so offline installs do not attempt to pull a mismatched tag.
- Example usage:

```bash
export HARDENED_CNI_URL="https://example.com/hardened-cni-plugins-amd64.tar"
sudo ./bin/rke2nodeinit.sh image
```

The script appends the manifest entry idempotently; re-running `image` will update the manifest line if the artifact changes.

Skopeo mirroring & automatic tag selection
-----------------------------------------

- If `skopeo` is available, the script will attempt to mirror `rancher/hardened-cni-plugins` from Docker Hub into the local `downloads` directory. This avoids requiring an operator-provided HTTP tarball.
- Tag selection logic:
	- If you set `HARDENED_CNI_TAG` (or pass an explicit tag to the helper), the script will use that tag.
	- Otherwise the script will try to infer a compatible hardened-cni tag for the RKE2 version being staged.
	- If that inference fails, the script selects the highest semver-like hardened-cni tag available on Docker Hub.

Staging behavior
----------------

- The script resolves the hardened-cni tag expected by the chart and ensures the tarball staged in `/var/lib/rancher/rke2/agent/images/` matches that tag exactly.
- The tarball is written as a docker-archive with the `rancher/hardened-cni-plugins:<tag>` reference, so no retagging is required at runtime.
- During `image`, the script now performs a CNI-aware preflight using `spec.cni` and verifies required images are present in staged archives. For `multus`/`canal` this includes chart images such as `hardened-multus-cni`, `hardened-calico`, and `hardened-flannel` in addition to `hardened-cni-plugins`.

Important: `hardened-cni-plugins` alone is not a complete Multus/Canal offline set.

- Recommended golden-image workflow: stage all required `rke2-images-*` flavor bundles for your selected CNI stack (for example via `INSTALL_RKE2_ARTIFACT_PATH`) so `image` preflight passes and runtime does not attempt external pulls.

Environment variables:

- `HARDENED_CNI_URL`: direct HTTP(S) tarball (overrides skopeo fallback).
- `HARDENED_CNI_TAG`: explicit tag to use when mirroring with skopeo.
- `HARDENED_MULTUS_TAG`: explicit tag to use when mirroring `rancher/hardened-multus-cni`.
- `HARDENED_FLANNEL_TAG`: explicit tag to use when mirroring `rancher/hardened-flannel`.
- `HARDENED_CNI_REQUIRED`: set to `0` to allow skipping hardened-cni acquisition (default: required).

List effective image tags
-------------------------

To enumerate the effective image:tag set for a host (base RKE2 list + chart-required list + staged archive RepoTags), run:

```bash
./scripts/list-effective-rke2-images.sh
```

This is useful when troubleshooting why an optional image (for example `hardened-multus-cni`) was selected via auto-fallback instead of derived from the base `rke2-images` bundle.

Logs
----

Tag-derivation note: missing tag extraction is logged as `INFO` when a local hardened-cni tar already exists, and as `WARN` when no local hardened-cni artifact is present.

The script writes raw skopeo output to `logs/skopeo-hardened-cni-plugins-*.log` and includes a short tail of that output in the main run log on error to simplify debugging.
