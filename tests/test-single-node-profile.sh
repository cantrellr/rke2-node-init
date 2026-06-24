#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
SCRIPT="${ROOT}/bin/rke2-single-node-profile.sh"
IMAGE_CONFIG="${ROOT}/configs/single-node/golden-image.yaml"
CONFIG="${ROOT}/configs/single-node/production-server.yaml"
COTPA_IMAGE_CONFIG="${ROOT}/configs/cotpa-single-nodes/image-hyperv-v1.35.5+rke2r2-singlenode.yaml"
COTPA_CONFIG="${ROOT}/configs/cotpa-single-nodes/nodes/dc1manager.yaml"

bash -n "$SCRIPT"

grep -q '^kind: singleNodeImage$' "$IMAGE_CONFIG"
grep -q '^kind: singleNodeServer$' "$CONFIG"
grep -q '^kind: singleNodeImage$' "$COTPA_IMAGE_CONFIG"
grep -q '^kind: singleNodeServer$' "$COTPA_CONFIG"

grep -q '^  defaultDns: 172.16.10.11,172.16.10.12$' "$COTPA_IMAGE_CONFIG"
grep -q '^  defaultSearchDomains: k8.cantrellcloud.net,cantrellcloud.net$' "$COTPA_IMAGE_CONFIG"

bash "$SCRIPT" --help | grep -q 'kind: singleNodeImage'
bash "$SCRIPT" --help | grep -q 'kind: singleNodeServer'
bash "$SCRIPT" --help | grep -q 'bin/rke2nodeinit.sh -f <rkeprep-yaml> image'

rendered="$(bash "$SCRIPT" render -f "$CONFIG")"

grep -q 'profile: "cis"' <<<"$rendered"
grep -q 'secrets-encryption: true' <<<"$rendered"
grep -q 'etcd-snapshot-compress: true' <<<"$rendered"
grep -q 'ingress-controller: "none"' <<<"$rendered"
grep -q 'kube-apiserver-arg+:' <<<"$rendered"

cotpa_rendered="$(bash "$SCRIPT" render -f "$COTPA_CONFIG")"
grep -q 'audit-log-maxage=30' <<<"$cotpa_rendered"
grep -q 'etcd-snapshot-retention: 12' <<<"$cotpa_rendered"

image_dispatch="$(bash "$SCRIPT" image -f "$IMAGE_CONFIG" --dry-run -y 2>&1 || true)"
grep -q 'bin/rke2nodeinit.sh --dry-run -y -f ' <<<"$image_dispatch"
grep -q ' image' <<<"$image_dispatch"

cotpa_image_dispatch="$(bash "$SCRIPT" -f "$COTPA_IMAGE_CONFIG" --dry-run -y 2>&1 || true)"
grep -q 'bin/rke2nodeinit.sh --dry-run -y -f ' <<<"$cotpa_image_dispatch"
grep -q ' image' <<<"$cotpa_image_dispatch"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

bash "$SCRIPT" apply -f "$CONFIG" \
  --output-dir "$workdir/config.yaml.d" \
  --manifest-dir "$workdir/manifests" \
  --dry-run >/dev/null

bash "$SCRIPT" apply -f "$COTPA_CONFIG" \
  --output-dir "$workdir/cotpa-config.yaml.d" \
  --manifest-dir "$workdir/cotpa-manifests" \
  --dry-run >/dev/null

bash "$SCRIPT" -f "$CONFIG" \
  --output-dir "$workdir/dispatch-config.yaml.d" \
  --manifest-dir "$workdir/dispatch-manifests" \
  --dry-run -y >/dev/null || true

echo "single-node profile smoke test passed"
