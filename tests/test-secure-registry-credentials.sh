#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
HELPER="${ROOT}/bin/rke2nodeinit-registry.sh"
DISPATCHER="${ROOT}/bin/rke2nodeinit.sh"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

username_file="${workdir}/registry-username"
password_file="${workdir}/registry-password"
secure_manifest="${workdir}/image-secure.yaml"
insecure_manifest="${workdir}/image-insecure.yaml"
missing_manifest="${workdir}/image-missing-credentials.yaml"
runtime_manifest="${workdir}/runtime-image.yaml"

printf '%s\n' 'robot$k8mm-pull' > "$username_file"
printf '%s\n' 'test-token-do-not-use' > "$password_file"
chmod 600 "$username_file" "$password_file"

cat > "$secure_manifest" <<YAML
apiVersion: rkeprep/v2
kind: Image
metadata:
  name: secure-image
spec:
  rke2Version: v1.35.6+rke2r1
  registry: kubeharbor.dev.kube
  secureRegistry: true
  registryUsernameFile: ${username_file}
  registryPasswordFile: ${password_file}
YAML

cat > "$insecure_manifest" <<'YAML'
apiVersion: rkeprep/v2
kind: Image
metadata:
  name: public-image
spec:
  rke2Version: v1.35.6+rke2r1
  registry: registry.example.com
  secureRegistry: false
YAML

cat > "$missing_manifest" <<'YAML'
apiVersion: rkeprep/v2
kind: Image
metadata:
  name: missing-credentials
spec:
  rke2Version: v1.35.6+rke2r1
  registry: kubeharbor.dev.kube
  secureRegistry: true
YAML

bash -n "$HELPER"
bash -n "$DISPATCHER"

# shellcheck source=bin/rke2nodeinit-registry.sh
source "$HELPER"

rke2nodeinit_registry_manifest_is_secure "$secure_manifest"
if rke2nodeinit_registry_manifest_is_secure "$insecure_manifest"; then
  echo "insecure manifest incorrectly detected as secure" >&2
  exit 1
fi

rke2nodeinit_registry_materialize_secure_manifest "$secure_manifest" "$runtime_manifest"

python3 - "$runtime_manifest" <<'PY'
import stat
import sys
from pathlib import Path

import yaml

path = Path(sys.argv[1])
document = yaml.safe_load(path.read_text(encoding="utf-8"))
spec = document["spec"]

assert spec["secureRegistry"] is True
assert spec["registry"] == "kubeharbor.dev.kube"
assert spec["registryUsername"] == "robot$k8mm-pull"
assert spec["registryPassword"] == "test-token-do-not-use"
assert "registryUsernameFile" not in spec
assert "registryPasswordFile" not in spec
assert stat.S_IMODE(path.stat().st_mode) == 0o600
PY

if rke2nodeinit_registry_materialize_secure_manifest "$missing_manifest" "${workdir}/missing-runtime.yaml" 2>"${workdir}/missing.err"; then
  echo "secure manifest without credentials unexpectedly succeeded" >&2
  exit 1
fi

grep -q 'secureRegistry requires a username' "${workdir}/missing.err"
! grep -q 'test-token-do-not-use' "${workdir}/missing.err"

grep -q 'REGISTRY_HELPER=.*rke2nodeinit-registry.sh' "$DISPATCHER"
grep -q 'prepare_secure_registry_config' "$DISPATCHER"
grep -q 'registryUsernameFile and registryPasswordFile' "$DISPATCHER"

echo "secure registry credential smoke test passed"
