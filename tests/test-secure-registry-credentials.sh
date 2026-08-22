#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
HELPER="${ROOT}/bin/rke2nodeinit-registry.sh"
DISPATCHER="${ROOT}/bin/rke2nodeinit.sh"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

username_file="${workdir}/registry-username"
password_file="${workdir}/registry-password"
live_manifest="${workdir}/server-secure.yaml"
single_node_manifest="${workdir}/single-node-secure.yaml"
image_manifest="${workdir}/image-secure.yaml"
insecure_manifest="${workdir}/server-insecure.yaml"
missing_manifest="${workdir}/server-missing-credentials.yaml"
runtime_manifest="${workdir}/runtime-server.yaml"

printf '%s\n' 'robot$k8mm-pull' > "$username_file"
printf '%s\n' 'test-token-do-not-use' > "$password_file"
chmod 600 "$username_file" "$password_file"

cat > "$live_manifest" <<YAML
apiVersion: rkeprep/v2
kind: Server
metadata:
  name: secure-live-server
spec:
  registry: kubeharbor.dev.kube
  secureRegistry: true
  registryUsernameFile: ${username_file}
  registryPasswordFile: ${password_file}
YAML

cat > "$single_node_manifest" <<YAML
apiVersion: rkeprep/v2
kind: singleNodeServer
metadata:
  name: secure-live-single-node
spec:
  registry: kubeharbor.dev.kube
  secureRegistry: true
  registryUsernameFile: ${username_file}
  registryPasswordFile: ${password_file}
YAML

cat > "$image_manifest" <<YAML
apiVersion: rkeprep/v2
kind: Image
metadata:
  name: golden-image-must-not-resolve-live-secrets
spec:
  registry: kubeharbor.dev.kube
  secureRegistry: true
YAML

cat > "$insecure_manifest" <<'YAML'
apiVersion: rkeprep/v2
kind: Agent
metadata:
  name: public-live-agent
spec:
  registry: registry.example.com
  secureRegistry: false
YAML

cat > "$missing_manifest" <<'YAML'
apiVersion: rkeprep/v2
kind: AddServer
metadata:
  name: missing-live-credentials
spec:
  registry: kubeharbor.dev.kube
  secureRegistry: true
YAML

bash -n "$HELPER"
bash -n "$DISPATCHER"

# shellcheck source=bin/rke2nodeinit-registry.sh
source "$HELPER"

rke2nodeinit_registry_manifest_requires_live_credentials "$live_manifest"
rke2nodeinit_registry_manifest_requires_live_credentials "$single_node_manifest"

if rke2nodeinit_registry_manifest_requires_live_credentials "$image_manifest"; then
  echo "Image manifest incorrectly treated as a live credential consumer" >&2
  exit 1
fi
rke2nodeinit_registry_image_manifest_misuses_secure_registry "$image_manifest"

if rke2nodeinit_registry_manifest_requires_live_credentials "$insecure_manifest"; then
  echo "secureRegistry: false manifest incorrectly required credentials" >&2
  exit 1
fi

rke2nodeinit_registry_materialize_live_manifest "$live_manifest" "$runtime_manifest"

python3 - "$runtime_manifest" <<'PY'
import stat
import sys
from pathlib import Path

import yaml

path = Path(sys.argv[1])
document = yaml.safe_load(path.read_text(encoding="utf-8"))
spec = document["spec"]

assert document["kind"] == "Server"
assert spec["secureRegistry"] is True
assert spec["registry"] == "kubeharbor.dev.kube"
assert spec["registryUsername"] == "robot$k8mm-pull"
assert spec["registryPassword"] == "test-token-do-not-use"
assert "registryUsernameFile" not in spec
assert "registryPasswordFile" not in spec
assert stat.S_IMODE(path.stat().st_mode) == 0o600
PY

if rke2nodeinit_registry_materialize_live_manifest "$missing_manifest" "${workdir}/missing-runtime.yaml" 2>"${workdir}/missing.err"; then
  echo "secure live manifest without credentials unexpectedly succeeded" >&2
  exit 1
fi

grep -q 'secureRegistry requires a registry username' "${workdir}/missing.err"
! grep -q 'test-token-do-not-use' "${workdir}/missing.err"

chmod 644 "$username_file"
if rke2nodeinit_registry_materialize_live_manifest "$live_manifest" "${workdir}/loose-runtime.yaml" 2>"${workdir}/loose.err"; then
  echo "group/world-readable username file unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'registryUsernameFile must not be group/world accessible' "${workdir}/loose.err"
chmod 600 "$username_file"

# Dispatcher integration: replace the provisioning core with a recorder so the
# test can prove that the live-only temporary manifest reaches the core and is
# removed after the action completes.
harness="${workdir}/harness"
capture="${workdir}/capture"
mkdir -p "$harness/bin" "$capture"
cp "$DISPATCHER" "$HELPER" "$harness/bin/"

cat > "$harness/bin/rke2nodeinit-system.sh" <<'SH'
#!/usr/bin/env bash
rke2nodeinit_system_prepare_cis_for_action() { :; }
SH

cat > "$harness/bin/rke2nodeinit-single-node.sh" <<'SH'
#!/usr/bin/env bash
exit 99
SH

cat > "$harness/bin/rke2nodeinit-core.sh" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
capture="${RKE2NODEINIT_TEST_CAPTURE_DIR:?}"
config=""
pending=0
for arg in "$@"; do
  if [[ "$pending" -eq 1 ]]; then
    config="$arg"
    pending=0
    continue
  fi
  case "$arg" in
    -f|--file) pending=1 ;;
    --file=*) config="${arg#*=}" ;;
  esac
done
[[ -n "$config" && -f "$config" ]]
printf '%s\n' "$config" > "$capture/staged-path"
stat -c '%a' "$config" > "$capture/staged-mode"
cp "$config" "$capture/materialized.yaml"
touch "$capture/core-called"
SH
chmod +x "$harness/bin/"*.sh

RKE2NODEINIT_RUNTIME_DIR="${workdir}/dispatcher-run" \
RKE2NODEINIT_TEST_CAPTURE_DIR="$capture" \
  bash "$harness/bin/rke2nodeinit.sh" -f "$live_manifest" --dry-run -y \
  >"${workdir}/dispatcher.out" 2>"${workdir}/dispatcher.err"

grep -q 'live registry credentials resolved' "${workdir}/dispatcher.err"
test -f "$capture/core-called"
test "$(cat "$capture/staged-mode")" = 600
staged_path="$(cat "$capture/staged-path")"
test ! -e "$staged_path"

python3 - "$capture/materialized.yaml" <<'PY'
import sys
from pathlib import Path
import yaml
spec = yaml.safe_load(Path(sys.argv[1]).read_text(encoding="utf-8"))["spec"]
assert spec["registryUsername"] == "robot$k8mm-pull"
assert spec["registryPassword"] == "test-token-do-not-use"
PY

rm -f "$capture/core-called"
if RKE2NODEINIT_RUNTIME_DIR="${workdir}/dispatcher-run" \
   RKE2NODEINIT_TEST_CAPTURE_DIR="$capture" \
     bash "$harness/bin/rke2nodeinit.sh" -f "$missing_manifest" --dry-run -y \
     >"${workdir}/dispatcher-missing.out" 2>"${workdir}/dispatcher-missing.err"; then
  echo "dispatcher unexpectedly allowed a live secureRegistry manifest without credentials" >&2
  exit 1
fi
test ! -e "$capture/core-called"
grep -q 'secureRegistry requires a registry username' "${workdir}/dispatcher-missing.err"

if RKE2NODEINIT_RUNTIME_DIR="${workdir}/dispatcher-run" \
   RKE2NODEINIT_TEST_CAPTURE_DIR="$capture" \
     bash "$harness/bin/rke2nodeinit.sh" -f "$image_manifest" --dry-run -y \
     >"${workdir}/dispatcher-image.out" 2>"${workdir}/dispatcher-image.err"; then
  echo "dispatcher unexpectedly allowed secureRegistry on an Image manifest" >&2
  exit 1
fi
test ! -e "$capture/core-called"
grep -q 'secureRegistry is a live node setting' "${workdir}/dispatcher-image.err"
grep -q 'manifest carried by the boot ISO' "${workdir}/dispatcher-image.err"

! grep -R -q 'test-token-do-not-use' \
  "${workdir}/missing.err" \
  "${workdir}/loose.err" \
  "${workdir}/dispatcher.err" \
  "${workdir}/dispatcher-missing.err" \
  "${workdir}/dispatcher-image.err"

grep -q 'rke2nodeinit_registry_manifest_requires_live_credentials' "$DISPATCHER"
grep -q 'rke2nodeinit_registry_materialize_live_manifest' "$DISPATCHER"
grep -q 'Server, AddServer, Agent, and singleNodeServer' "$DISPATCHER"

echo "secure registry live-execution credential smoke test passed"
