Hardened CNI HTTP Download
==========================

The script supports staging an upstream `hardened-cni-plugins` tarball via HTTP(S) for air-gapped installs. To enable this, set the `HARDENED_CNI_URL` environment variable (or provide it in your YAML) to a direct downloadable tarball URL.

- The downloaded artifact is saved to the repository `DOWNLOADS_DIR` and its SHA256 is appended to the canonical manifest `sha256sum-<arch>.txt` so it participates in the same `sha256sum -c` verification performed during staging.
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

Environment variables:

- `HARDENED_CNI_URL`: direct HTTP(S) tarball (overrides skopeo fallback).
- `HARDENED_CNI_TAG`: explicit tag to use when mirroring with skopeo.

Logs
----

The script writes raw skopeo output to `logs/skopeo-hardened-cni-plugins-*.log` and includes a short tail of that output in the main run log on error to simplify debugging.
