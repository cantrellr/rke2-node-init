#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
MAIN="${ROOT}/bin/rke2nodeinit.sh"
CORE="${ROOT}/bin/rke2nodeinit-core.sh"
SCRIPT="${ROOT}/bin/rke2-single-node-profile.sh"
SINGLE_NODE_HELPER="${ROOT}/bin/rke2nodeinit-single-node.sh"
SYSTEM_HELPER="${ROOT}/bin/rke2nodeinit-system.sh"
IMAGE_CONFIG="${ROOT}/configs/single-node/golden-image.yaml"
CONFIG="${ROOT}/configs/single-node/production-server.yaml"
COTPA_IMAGE_CONFIG="${ROOT}/configs/cotpa-single-nodes/image-hyperv-v1.35.5+rke2r2-singlenode.yaml"
COTPA_CONFIG="${ROOT}/configs/cotpa-single-nodes/nodes/dc1manager.yaml"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

CIS_CONFIG="${workdir}/cis-server.yaml"
NON_CIS_CONFIG="${workdir}/non-cis-server.yaml"

cat > "$CIS_CONFIG" <<'YAML'
apiVersion: rkeprep/v2
kind: Server
metadata:
  name: cis-server
spec:
  profile: cis
YAML

cat > "$NON_CIS_CONFIG" <<'YAML'
apiVersion: rkeprep/v2
kind: Server
metadata:
  name: non-cis-server
spec:
  profile: ""
YAML

bash -n "$MAIN"
bash -n "$CORE"
bash -n "$SCRIPT"
bash -n "$SINGLE_NODE_HELPER"
bash -n "${ROOT}/bin/rke2nodeinit-config.sh"
bash -n "${ROOT}/bin/rke2nodeinit-cni.sh"
bash -n "${ROOT}/bin/rke2nodeinit-yaml.sh"
bash -n "${ROOT}/bin/rke2nodeinit-router.sh"
bash -n "$SYSTEM_HELPER"

grep -q 'CORE_SCRIPT=.*rke2nodeinit-core.sh' "$MAIN"
grep -q 'SINGLE_NODE_SCRIPT=.*rke2nodeinit-single-node.sh' "$MAIN"
grep -q 'SYSTEM_HELPER=.*rke2nodeinit-system.sh' "$MAIN"
grep -q 'singleNodeImage  -> single-node image flow' "$MAIN"
grep -q 'singleNodeServer -> single-node server flow' "$MAIN"
grep -q 'RKE2NODEINIT_CORE_DELEGATE=1' "$MAIN"
grep -q 'rke2nodeinit_system_prepare_cis_for_action' "$MAIN"
grep -q 'RKE2NODEINIT_CORE_DELEGATE=1' "$SINGLE_NODE_HELPER"
grep -q 'rke2-single-node-swap-preflight.sh' "$SINGLE_NODE_HELPER"
grep -q '05-single-node-swap-preflight.conf' "$SINGLE_NODE_HELPER"
grep -q 'swapoff -a' "$SINGLE_NODE_HELPER"

grep -q 'rke2nodeinit_system_manifest_requires_cis' "$SYSTEM_HELPER"
grep -q 'rke2nodeinit_system_apply_cis_kernel_prereqs' "$SYSTEM_HELPER"
grep -q 'rke2nodeinit_system_ensure_cis_etcd_account' "$SYSTEM_HELPER"
grep -q 'groupadd --system etcd' "$SYSTEM_HELPER"
grep -q 'useradd --system --no-create-home' "$SYSTEM_HELPER"
grep -q '99-rke2-cis.conf' "$SYSTEM_HELPER"
grep -q 'vm.overcommit_memory = 1' "$SYSTEM_HELPER"
grep -q 'vm.panic_on_oom = 0' "$SYSTEM_HELPER"
grep -q 'kernel.panic = 10' "$SYSTEM_HELPER"
grep -q 'kernel.panic_on_oops = 1' "$SYSTEM_HELPER"

# shellcheck source=bin/rke2nodeinit-system.sh
source "$SYSTEM_HELPER"

rke2nodeinit_system_manifest_requires_cis "$CIS_CONFIG"
rke2nodeinit_system_manifest_requires_cis "$COTPA_CONFIG"

if rke2nodeinit_system_manifest_requires_cis "$NON_CIS_CONFIG"; then
  echo "non-CIS manifest incorrectly detected as CIS" >&2
  exit 1
fi

grep -q '^kind: singleNodeImage$' "$IMAGE_CONFIG"
grep -q '^kind: singleNodeServer$' "$CONFIG"
grep -q '^kind: singleNodeImage$' "$COTPA_IMAGE_CONFIG"
grep -q '^kind: singleNodeServer$' "$COTPA_CONFIG"

grep -q '^  defaultDns: 172.16.10.11,172.16.10.12$' "$COTPA_IMAGE_CONFIG"
grep -q '^  defaultSearchDomains: k8.cantrellcloud.net,cantrellcloud.net$' "$COTPA_IMAGE_CONFIG"

for manifest in \
  "$CONFIG" \
  "${ROOT}/configs/cotpa-single-nodes/nodes/dc1manager.yaml" \
  "${ROOT}/configs/cotpa-single-nodes/nodes/dc1domain.yaml" \
  "${ROOT}/configs/cotpa-single-nodes/nodes/dc2domain.yaml" \
  "${ROOT}/configs/cotpa-single-nodes/nodes/dc3domain.yaml"; do
  ! grep -q 'node-role.kubernetes.io/control-plane' "$manifest"
  ! grep -q 'node-role.kubernetes.io/worker' "$manifest"
done

bash "$MAIN" --help | grep -q 'singleNodeImage'
bash "$MAIN" --help | grep -q 'singleNodeServer'
bash "$MAIN" --help | grep -q 'CIS'
bash "$SCRIPT" --help | grep -q 'kind: singleNodeImage'
bash "$SCRIPT" --help | grep -q 'kind: singleNodeServer'
bash "$SCRIPT" --help | grep -q 'bin/rke2nodeinit.sh -f <rkeprep-yaml> image'
bash "$SCRIPT" --help | grep -q 'preflight guard'

grep -q '99-rke2-single-node-cis.conf' "$SCRIPT"
grep -q 'rke2nodeinit_system_ensure_cis_etcd_account' "$SCRIPT"
grep -q 'vm.overcommit_memory = 1' "$SCRIPT"
grep -q 'kernel.panic = 10' "$SCRIPT"
grep -q 'kernel.panic_on_oops = 1' "$SCRIPT"
grep -q 'import-images' "$SCRIPT"
grep -q 'ExecStartPre=/usr/local/sbin/rke2-single-node-preflight.sh' "$SCRIPT"

rendered="$(bash "$SCRIPT" render -f "$CONFIG")"

grep -q 'profile: "cis"' <<<"$rendered"
grep -q 'protect-kernel-defaults: true' <<<"$rendered"
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

cotpa_image_dispatch="$(bash "$MAIN" -f "$COTPA_IMAGE_CONFIG" --dry-run -y 2>&1 || true)"
grep -q 'bin/rke2nodeinit.sh --dry-run -y -f ' <<<"$cotpa_image_dispatch"
grep -q ' image' <<<"$cotpa_image_dispatch"

cis_dispatch="$(bash "$MAIN" -f "$CIS_CONFIG" --dry-run -y 2>&1 || true)"
grep -q 'DRY-RUN would ensure CIS etcd account prerequisites' <<<"$cis_dispatch"
grep -q 'DRY-RUN would apply RKE2 CIS kernel prerequisites' <<<"$cis_dispatch"
grep -q 'vm.overcommit_memory=1' <<<"$cis_dispatch"
grep -q 'vm.panic_on_oom=0' <<<"$cis_dispatch"

server_dispatch="$(bash "$MAIN" -f "$COTPA_CONFIG" --dry-run -y 2>&1 || true)"
grep -q 'DRY-RUN would apply RKE2 CIS kernel prerequisites' <<<"$server_dispatch"
grep -q 'DRY-RUN would install single-node swap preflight guard' <<<"$server_dispatch"
grep -q 'DRY-RUN would install rke2-server ExecStartPre preflight guard' <<<"$server_dispatch"
grep -q 'bin/rke2nodeinit.sh --dry-run -y -f ' <<<"$server_dispatch"
grep -q ' server' <<<"$server_dispatch"

bash "$SCRIPT" apply -f "$CONFIG" \
  --output-dir "$workdir/config.yaml.d" \
  --manifest-dir "$workdir/manifests" \
  --dry-run >/dev/null

bash "$SCRIPT" apply -f "$COTPA_CONFIG" \
  --output-dir "$workdir/cotpa-config.yaml.d" \
  --manifest-dir "$workdir/cotpa-manifests" \
  --dry-run >/dev/null

bash "$MAIN" -f "$CONFIG" \
  --output-dir "$workdir/dispatch-config.yaml.d" \
  --manifest-dir "$workdir/dispatch-manifests" \
  --dry-run -y >/dev/null || true

echo "single-node profile smoke test passed"
