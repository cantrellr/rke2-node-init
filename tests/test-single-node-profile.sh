#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
SCRIPT="${ROOT}/bin/rke2-single-node-profile.sh"
CONFIG="${ROOT}/configs/single-node/production-server.yaml"
COTPA_CONFIG="${ROOT}/configs/cotpa-single-nodes/nodes/dc1manager.yaml"

bash -n "$SCRIPT"

rendered="$(bash "$SCRIPT" render -f "$CONFIG")"

grep -q 'profile: "cis"' <<<"$rendered"
grep -q 'secrets-encryption: true' <<<"$rendered"
grep -q 'etcd-snapshot-compress: true' <<<"$rendered"
grep -q 'ingress-controller: "none"' <<<"$rendered"
grep -q 'kube-apiserver-arg+:' <<<"$rendered"

cotpa_rendered="$(bash "$SCRIPT" render -f "$COTPA_CONFIG")"
grep -q 'audit-log-maxage=30' <<<"$cotpa_rendered"
grep -q 'etcd-snapshot-retention: 12' <<<"$cotpa_rendered"

bash "$SCRIPT" --help | grep -q 'server -f <rkeprep-yaml>'

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

sudo_prefix=()
if [[ ${EUID} -ne 0 ]]; then
  # The helper can dry-run without root when output paths are temporary.
  sudo_prefix=()
fi

"${sudo_prefix[@]}" bash "$SCRIPT" apply -f "$CONFIG" \
  --output-dir "$workdir/config.yaml.d" \
  --manifest-dir "$workdir/manifests" \
  --dry-run >/dev/null

"${sudo_prefix[@]}" bash "$SCRIPT" apply -f "$COTPA_CONFIG" \
  --output-dir "$workdir/cotpa-config.yaml.d" \
  --manifest-dir "$workdir/cotpa-manifests" \
  --dry-run >/dev/null

echo "single-node profile smoke test passed"
