#!/bin/bash
# Test script to verify interface detection logic without requiring root

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
CONFIG_FILE="$REPO_ROOT/configs/preprod/nodes/dc1manager-ctrl01.yaml"

echo "Testing YAML interface detection..."
echo "=================================="
echo

# Source the interface parsing functions (extract them from the main script)
source <(sed -n '/^yaml_spec_has_list()/,/^}/p' "$REPO_ROOT/bin/rke2nodeinit.sh")
source <(sed -n '/^yaml_spec_interfaces()/,/^PY$/p' "$REPO_ROOT/bin/rke2nodeinit.sh")

# Test yaml_spec_has_list
echo "1. Testing yaml_spec_has_list function:"
if yaml_spec_has_list "$CONFIG_FILE" "interfaces"; then
    echo "   [OK] Detected interfaces as a YAML list"
    yaml_has_interfaces=1
else
    echo "   [FAIL] Failed to detect interfaces list"
    yaml_has_interfaces=0
fi
echo

# Test yaml_spec_interfaces
echo "2. Testing yaml_spec_interfaces function:"
echo "   Parsed interfaces:"
yaml_spec_interfaces "$CONFIG_FILE" | while IFS= read -r line; do
    echo "   - $line"
done
echo

# Test the decision logic
echo "3. Testing prompt skip logic:"
if (( yaml_has_interfaces )); then
    echo "   [OK] Should SKIP interactive prompt (interfaces defined in YAML)"
else
    echo "   [INFO] Would prompt user for additional interfaces"
fi
echo

echo "Test complete!"
