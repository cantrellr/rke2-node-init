#!/usr/bin/env bash
#=============================================================================
# Phase 3 CLI Enhancement Demo
# Purpose: Demonstrate all new CLI features added in Phase 3
# Features:
#   - --help and action-specific help
#   - --version flag
#   - --verbose and --quiet flags
#   - --dry-run mode
#   - Enhanced user experience
#=============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RKE2_SCRIPT="$SCRIPT_DIR/../bin/rke2nodeinit.sh"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

demo_section() {
  echo
  echo -e "${BLUE}========================================${NC}"
  echo -e "${BLUE}$1${NC}"
  echo -e "${BLUE}========================================${NC}"
  echo
}

demo_command() {
  local description="$1"
  shift
  echo -e "${GREEN}Demo: $description${NC}"
  echo -e "${YELLOW}Command: $*${NC}"
  echo
  "$@" || true
  echo
  read -p "Press Enter to continue..." -r
}

# Ensure script exists
if [[ ! -f "$RKE2_SCRIPT" ]]; then
  echo "ERROR: rke2nodeinit.sh not found at: $RKE2_SCRIPT"
  exit 1
fi

echo -e "${BLUE}===============================================${NC}"
echo -e "${BLUE}Phase 3 CLI Enhancement Demo${NC}"
echo -e "${BLUE}===============================================${NC}"
echo
echo "This demo showcases all new CLI features:"
echo "  1. Enhanced help system with action-specific help"
echo "  2. Version information"
echo "  3. Verbosity control (--verbose, --quiet)"
echo "  4. Dry-run mode for safe testing"
echo
read -p "Press Enter to start the demo..." -r

#=============================================================================
# Section 1: Help System
#=============================================================================
demo_section "1. Enhanced Help System"

demo_command "Show general help" \
  "$RKE2_SCRIPT" --help

demo_command "Show version information" \
  "$RKE2_SCRIPT" --version

demo_command "Show help for 'verify' action" \
  "$RKE2_SCRIPT" verify --help

demo_command "Show help for 'image' action" \
  "$RKE2_SCRIPT" image --help

demo_command "Show help for 'push' action" \
  "$RKE2_SCRIPT" push --help

demo_command "Show help for 'custom-ca' action" \
  "$RKE2_SCRIPT" custom-ca --help

demo_command "Show help for 'server' action" \
  "$RKE2_SCRIPT" server --help

demo_command "Show help for 'agent' action" \
  "$RKE2_SCRIPT" agent --help

#=============================================================================
# Section 2: Verbosity Control
#=============================================================================
demo_section "2. Verbosity Control"

# Create a simple test YAML for verify
cat > /tmp/phase3-demo-verify.yaml <<'EOF'
apiVersion: rkeprep/v1
kind: Verify
metadata:
  name: phase3-demo-verify
EOF

demo_command "Normal output (verify action)" \
  "$RKE2_SCRIPT" -f /tmp/phase3-demo-verify.yaml

demo_command "Quiet mode - suppress informational messages" \
  "$RKE2_SCRIPT" --quiet -f /tmp/phase3-demo-verify.yaml

demo_command "Verbose mode - show detailed debug information" \
  "$RKE2_SCRIPT" --verbose -f /tmp/phase3-demo-verify.yaml

#=============================================================================
# Section 3: Dry-Run Mode
#=============================================================================
demo_section "3. Dry-Run Mode"

# Create a minimal image config for dry-run demo
cat > /tmp/phase3-demo-image.yaml <<'EOF'
apiVersion: rkeprep/v1
kind: Image
metadata:
  name: phase3-demo-image
spec:
  rke2Version: v1.31.4+rke2r1
  registry: registry.example.com/rke2
  registryUsername: admin
  registryPassword: changeme
EOF

echo "Creating test image configuration..."
echo "This demonstrates dry-run mode for the 'image' action"
echo

demo_command "Dry-run mode - simulate image preparation without changes" \
  "$RKE2_SCRIPT" --dry-run -f /tmp/phase3-demo-image.yaml

# Create a minimal server config for dry-run demo
cat > /tmp/phase3-demo-server.yaml <<'EOF'
apiVersion: rkeprep/v1
kind: Server
metadata:
  name: phase3-demo-server
spec:
  token: K10test123456789::server:abcdef0123456789
  clusterInit: true
  nodeName: demo-server.example.com
  node-ip: 10.0.1.100
  bind-address: 10.0.1.100
  interfaces:
    - name: eth0
      ip: 10.0.1.100
      prefix: 24
      gateway: 10.0.1.1
      dns: [10.0.1.1, 8.8.8.8]
EOF

demo_command "Dry-run mode - simulate server initialization" \
  "$RKE2_SCRIPT" --dry-run -f /tmp/phase3-demo-server.yaml

#=============================================================================
# Section 4: Combined Flags
#=============================================================================
demo_section "4. Combining Multiple Flags"

demo_command "Dry-run + Verbose - detailed simulation output" \
  "$RKE2_SCRIPT" --dry-run --verbose -f /tmp/phase3-demo-image.yaml

demo_command "Dry-run + Quiet - minimal simulation output" \
  "$RKE2_SCRIPT" --dry-run --quiet -f /tmp/phase3-demo-image.yaml

#=============================================================================
# Section 5: Help System Edge Cases
#=============================================================================
demo_section "5. Help System Flexibility"

demo_command "Action help via --help flag (alternate syntax)" \
  "$RKE2_SCRIPT" --help verify

demo_command "Action help via -h flag" \
  "$RKE2_SCRIPT" verify -h

#=============================================================================
# Cleanup
#=============================================================================
demo_section "Demo Complete"

echo "Cleaning up temporary files..."
rm -f /tmp/phase3-demo-*.yaml

echo
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Phase 3 CLI Enhancement Demo Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo
echo "New features demonstrated:"
echo "  ✓ Comprehensive help system with action-specific documentation"
echo "  ✓ Version information display"
echo "  ✓ Verbose output for debugging and troubleshooting"
echo "  ✓ Quiet mode for scripted/automated usage"
echo "  ✓ Dry-run mode for safe testing and validation"
echo "  ✓ Flexible command-line syntax and flag combinations"
echo
echo "Benefits:"
echo "  • Improved discoverability - users can explore features interactively"
echo "  • Enhanced debugging - verbose mode provides detailed diagnostics"
echo "  • Safer operations - dry-run prevents accidental changes"
echo "  • Better automation - quiet mode ideal for CI/CD pipelines"
echo "  • Professional UX - matches industry-standard CLI patterns"
echo
echo "For more information, see:"
echo "  - docs/PHASE3-IMPLEMENTATION.md"
echo "  - docs/PHASE3-COMPLETION.md"
echo
