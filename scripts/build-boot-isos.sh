#!/usr/bin/env bash
# Build per-node boot ISO artifacts from YAML configs.
# Each output ISO is named after metadata.name and contains:
#   /config/<original-yaml-filename>

set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/build-boot-isos.sh --yaml-dir <dir> [--output-dir <dir>] [--manifest <file>] [--quiet]

Options:
  --yaml-dir DIR     Directory containing node YAML files (*.yaml, *.yml). Required.
  --output-dir DIR   Directory where ISO files are written. Default: outputs/boot-isos
  --manifest FILE    Manifest path. Default: <output-dir>/manifest.tsv
  --quiet            Reduce console output.
  -h, --help         Show this help.

Behavior:
  - For each YAML file in --yaml-dir, reads metadata.name.
  - Creates <metadata.name>.iso.
  - ISO payload path is /config/<original-yaml-filename>.
  - Writes manifest columns: metadata_name,source_yaml,iso_path,sha256.
EOF
}

log() {
  local level="$1"
  shift
  if [[ "${QUIET:-0}" -eq 1 && "$level" == "INFO" ]]; then
    return 0
  fi
  printf '[%s] %s\n' "$level" "$*"
}

die() {
  log ERROR "$*"
  exit 1
}

extract_metadata_name() {
  local yaml_file="$1"
  awk '
    BEGIN { in_meta=0 }
    /^[[:space:]]*metadata:[[:space:]]*$/ { in_meta=1; next }
    in_meta==1 {
      if ($0 ~ /^[^[:space:]]/) { exit }
      if ($0 ~ /^[[:space:]]*name:[[:space:]]*/) {
        sub(/^[[:space:]]*name:[[:space:]]*/, "", $0)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
        print $0
        exit
      }
    }
  ' "$yaml_file"
}

sanitize_volume_id() {
  local raw="$1"
  local cleaned
  cleaned="$(printf '%s' "$raw" | tr '[:lower:]' '[:upper:]' | tr -c 'A-Z0-9_' '_' | cut -c1-32)"
  if [[ -z "$cleaned" ]]; then
    cleaned="RKE2CFG"
  fi
  printf '%s\n' "$cleaned"
}

detect_iso_tool() {
  local tool
  for tool in xorriso genisoimage mkisofs; do
    if command -v "$tool" >/dev/null 2>&1; then
      printf '%s\n' "$tool"
      return 0
    fi
  done
  return 1
}

build_iso() {
  local iso_tool="$1"
  local source_yaml="$2"
  local out_iso="$3"
  local volid="$4"
  local source_yaml_bn
  source_yaml_bn="$(basename "$source_yaml")"

  local tmp_root
  tmp_root="$(mktemp -d)"
  mkdir -p "$tmp_root/config"
  cp "$source_yaml" "$tmp_root/config/$source_yaml_bn"

  case "$iso_tool" in
    xorriso)
      xorriso -as mkisofs -quiet -J -R -V "$volid" -o "$out_iso" "$tmp_root" >/dev/null 2>&1
      ;;
    genisoimage|mkisofs)
      "$iso_tool" -quiet -J -r -V "$volid" -o "$out_iso" "$tmp_root" >/dev/null 2>&1
      ;;
    *)
      rm -rf "$tmp_root"
      die "Unsupported ISO builder: $iso_tool"
      ;;
  esac

  rm -rf "$tmp_root"
}

YAML_DIR=""
OUTPUT_DIR="outputs/boot-isos"
MANIFEST_FILE=""
QUIET=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yaml-dir)
      [[ -n "${2:-}" ]] || die "--yaml-dir requires a value"
      YAML_DIR="$2"
      shift 2
      ;;
    --output-dir)
      [[ -n "${2:-}" ]] || die "--output-dir requires a value"
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --manifest)
      [[ -n "${2:-}" ]] || die "--manifest requires a value"
      MANIFEST_FILE="$2"
      shift 2
      ;;
    --quiet)
      QUIET=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1"
      ;;
  esac
done

[[ -n "$YAML_DIR" ]] || {
  usage
  die "--yaml-dir is required"
}

if [[ ! -d "$YAML_DIR" ]]; then
  die "YAML directory does not exist: $YAML_DIR"
fi

if [[ -z "$MANIFEST_FILE" ]]; then
  MANIFEST_FILE="$OUTPUT_DIR/manifest.tsv"
fi

if ! ISO_TOOL="$(detect_iso_tool)"; then
  die "No ISO builder found. Install one of: xorriso, genisoimage, mkisofs"
fi

mkdir -p "$OUTPUT_DIR"
mkdir -p "$(dirname "$MANIFEST_FILE")"

log INFO "ISO builder: $ISO_TOOL"
log INFO "YAML source directory: $YAML_DIR"
log INFO "ISO output directory: $OUTPUT_DIR"
log INFO "Manifest file: $MANIFEST_FILE"

shopt -s nullglob
YAML_FILES=("$YAML_DIR"/*.yaml "$YAML_DIR"/*.yml)
shopt -u nullglob

if (( ${#YAML_FILES[@]} == 0 )); then
  die "No YAML files found in: $YAML_DIR"
fi

declare -A seen_names=()

printf 'metadata_name\tsource_yaml\tiso_path\tsha256\n' > "$MANIFEST_FILE"

built_count=0
for yaml_file in "${YAML_FILES[@]}"; do
  name="$(extract_metadata_name "$yaml_file" || true)"
  if [[ -z "$name" ]]; then
    die "Missing metadata.name in YAML: $yaml_file"
  fi

  if [[ -n "${seen_names[$name]:-}" ]]; then
    die "Duplicate metadata.name '$name' in: $yaml_file and ${seen_names[$name]}"
  fi
  seen_names["$name"]="$yaml_file"

  iso_path="$OUTPUT_DIR/$name.iso"
  volid="$(sanitize_volume_id "$name")"

  log INFO "Building ISO for metadata.name=$name"
  build_iso "$ISO_TOOL" "$yaml_file" "$iso_path" "$volid" || die "Failed to build ISO for $yaml_file"

  hash="$(sha256sum "$iso_path" | awk '{print $1}')"
  printf '%s\t%s\t%s\t%s\n' "$name" "$yaml_file" "$iso_path" "$hash" >> "$MANIFEST_FILE"

  built_count=$((built_count + 1))
done

log INFO "Built $built_count ISO file(s)."
log INFO "Done."
