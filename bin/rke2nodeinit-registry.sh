#!/usr/bin/env bash
# Secure-registry manifest helper for rke2nodeinit.
#
# The legacy provisioning core already writes registry authentication into
# /etc/rancher/rke2/registries.yaml when registryUsername/registryPassword are
# present. This helper lets operators keep those credentials outside Git while
# preserving the existing core contract.

set -Eeuo pipefail

rke2nodeinit_registry_require_yaml_support() {
  command -v python3 >/dev/null 2>&1 || {
    echo "ERROR: secureRegistry requires python3." >&2
    return 1
  }

  python3 -c 'import yaml' >/dev/null 2>&1 || {
    echo "ERROR: secureRegistry requires the Python PyYAML module." >&2
    return 1
  }
}

rke2nodeinit_registry_manifest_is_secure() {
  local manifest="${1:-}"
  [[ -n "$manifest" && -f "$manifest" ]] || return 1

  rke2nodeinit_registry_require_yaml_support || return 1

  python3 - "$manifest" <<'PY'
import sys
from pathlib import Path

import yaml

path = Path(sys.argv[1])


def truthy(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {
        "1", "true", "yes", "y", "on", "enabled"
    }


def normalize_kind(value):
    return "".join(ch for ch in str(value or "").lower() if ch.isalnum())

try:
    documents = [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc]
except (OSError, UnicodeError, yaml.YAMLError):
    raise SystemExit(1)

for document in documents:
    if not isinstance(document, dict):
        continue
    kind = normalize_kind(document.get("kind"))
    if kind not in {"image", "singlenodeimage"}:
        continue
    spec = document.get("spec") or {}
    if not isinstance(spec, dict):
        continue
    secure = spec.get("secureRegistry", spec.get("secure-registry"))
    if truthy(secure):
        raise SystemExit(0)

raise SystemExit(1)
PY
}

rke2nodeinit_registry_materialize_secure_manifest() {
  local source_manifest="${1:-}"
  local output_manifest="${2:-}"

  [[ -n "$source_manifest" && -f "$source_manifest" ]] || {
    echo "ERROR: source manifest does not exist: ${source_manifest:-<empty>}" >&2
    return 1
  }
  [[ -n "$output_manifest" ]] || {
    echo "ERROR: secure-registry output manifest path is required." >&2
    return 1
  }

  rke2nodeinit_registry_require_yaml_support || return 1

  python3 - "$source_manifest" "$output_manifest" <<'PY'
import os
import stat
import sys
from pathlib import Path

import yaml

source = Path(sys.argv[1]).resolve()
output = Path(sys.argv[2])


def fail(message):
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def truthy(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {
        "1", "true", "yes", "y", "on", "enabled"
    }


def normalize_kind(value):
    return "".join(ch for ch in str(value or "").lower() if ch.isalnum())


def resolve_secret_path(raw_value, field_name):
    value = str(raw_value or "").strip()
    if not value:
        return None
    value = os.path.expandvars(os.path.expanduser(value))
    path = Path(value)
    if not path.is_absolute():
        path = source.parent / path
    path = path.resolve()
    if not path.is_file():
        fail(f"{field_name} does not reference a readable file: {path}")
    if not os.access(path, os.R_OK):
        fail(f"{field_name} is not readable: {path}")
    return path


def read_secret_file(path, field_name, require_private=False):
    if require_private:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            fail(
                f"{field_name} must not be group/world accessible: {path}; "
                "run chmod 600 on the file"
            )
    try:
        raw = path.read_bytes()
    except OSError:
        fail(f"unable to read {field_name}: {path}")
    if b"\x00" in raw:
        fail(f"{field_name} contains a NUL byte: {path}")
    try:
        value = raw.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError:
        fail(f"{field_name} must contain UTF-8 text: {path}")
    if not value:
        fail(f"{field_name} is empty: {path}")
    return value


def resolve_credential(spec, value_key, file_key, env_value, env_file, private_file):
    file_value = spec.get(file_key) or os.environ.get(env_file, "")
    if file_value:
        path = resolve_secret_path(file_value, file_key)
        return read_secret_file(path, file_key, require_private=private_file)

    env_direct = os.environ.get(env_value, "")
    if env_direct:
        return env_direct.rstrip("\r\n")

    inline = spec.get(value_key)
    if inline is not None and str(inline) != "":
        return str(inline)

    return ""

try:
    documents = list(yaml.safe_load_all(source.read_text(encoding="utf-8")))
except OSError:
    fail(f"unable to read manifest: {source}")
except UnicodeError:
    fail(f"manifest is not valid UTF-8: {source}")
except yaml.YAMLError as exc:
    fail(f"manifest YAML is invalid: {exc}")

matched = 0
for document in documents:
    if not isinstance(document, dict):
        continue

    kind = normalize_kind(document.get("kind"))
    if kind not in {"image", "singlenodeimage"}:
        continue

    spec = document.get("spec")
    if spec is None:
        spec = {}
        document["spec"] = spec
    if not isinstance(spec, dict):
        fail("spec must be a YAML mapping when secureRegistry is enabled")

    secure = spec.get("secureRegistry", spec.get("secure-registry"))
    if not truthy(secure):
        continue

    matched += 1
    registry = str(spec.get("registry") or "").strip()
    if not registry:
        fail("spec.registry is required when spec.secureRegistry is true")

    username = resolve_credential(
        spec,
        "registryUsername",
        "registryUsernameFile",
        "RKE2_REGISTRY_USERNAME",
        "RKE2_REGISTRY_USERNAME_FILE",
        False,
    )
    password = resolve_credential(
        spec,
        "registryPassword",
        "registryPasswordFile",
        "RKE2_REGISTRY_PASSWORD",
        "RKE2_REGISTRY_PASSWORD_FILE",
        True,
    )

    if not username:
        fail(
            "secureRegistry requires a username from spec.registryUsernameFile, "
            "RKE2_REGISTRY_USERNAME_FILE, RKE2_REGISTRY_USERNAME, or "
            "spec.registryUsername"
        )
    if not password:
        fail(
            "secureRegistry requires a password/token from spec.registryPasswordFile, "
            "RKE2_REGISTRY_PASSWORD_FILE, RKE2_REGISTRY_PASSWORD, or "
            "spec.registryPassword"
        )

    spec["secureRegistry"] = True
    spec.pop("secure-registry", None)
    spec["registryUsername"] = username
    spec["registryPassword"] = password
    spec.pop("registryUsernameFile", None)
    spec.pop("registryPasswordFile", None)

if matched == 0:
    fail("no Image or singleNodeImage document has spec.secureRegistry set to true")

output.parent.mkdir(parents=True, exist_ok=True)
with output.open("w", encoding="utf-8") as handle:
    yaml.safe_dump_all(
        documents,
        handle,
        default_flow_style=False,
        sort_keys=False,
        explicit_start=len(documents) > 1,
    )
os.chmod(output, 0o600)
PY
}

rke2nodeinit_registry_remove_staged_manifest() {
  local path="${1:-}"
  [[ -n "$path" && -f "$path" ]] || return 0

  chmod 600 "$path" 2>/dev/null || true
  if command -v shred >/dev/null 2>&1; then
    shred -u "$path" 2>/dev/null || rm -f "$path"
  else
    rm -f "$path"
  fi
}
