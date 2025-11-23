# RKE2 Node Init Script Redesign Analysis

**Date:** November 16, 2025  
**Objective:** Redesign `rke2nodeinit.sh` to incorporate design patterns from `rke2imageprep.sh`

---

## Executive Summary

This analysis compares the architectural patterns, code organization, and design philosophy of `rke2imageprep.sh` (710 lines) against `rke2nodeinit.sh` (6377 lines) to identify redesign opportunities that will improve maintainability, testability, and user experience.

---

## Table of Contents

1. [Current State Analysis](#current-state-analysis)
2. [Target Design Patterns](#target-design-patterns)
3. [Key Differences](#key-differences)
4. [Recommended Redesign Strategy](#recommended-redesign-strategy)
5. [Implementation Roadmap](#implementation-roadmap)
6. [Risk Analysis](#risk-analysis)

---

## Current State Analysis

### rke2nodeinit.sh (Current Implementation)

**Statistics:**
- **Lines:** 6,377
- **Functions:** 95+
- **Actions:** 10 (push, image, server, add-server, agent, verify, airgap, label-node, taint-node, custom-ca)
- **Primary Dependencies:** bash, python3 (optional), curl, apt-get, nerdctl/containerd

**Architecture Strengths:**
- ✅ Comprehensive YAML configuration support (`apiVersion: rkeprep/v1`)
- ✅ Multi-interface networking with complex netplan generation
- ✅ Custom CA integration with certificate chain management
- ✅ Extensive validation and prerequisite checking
- ✅ Detailed logging with structured timestamps
- ✅ Support for both YAML-driven and CLI-driven workflows

**Architecture Weaknesses:**
- ❌ Monolithic structure: single 6K+ line file
- ❌ Heavy reliance on global variables (100+)
- ❌ Inconsistent error handling patterns
- ❌ Mixed concerns: networking, package management, RKE2 installation, registry operations
- ❌ No clear separation between utility functions and business logic
- ❌ Limited dependency management (assumes packages available or fails)

### rke2imageprep.sh (Target Design)

**Statistics:**
- **Lines:** 710
- **Functions:** 4 primary action functions + 2 utility functions
- **Actions:** 3 (--prep, --download, --push)
- **Primary Dependencies:** curl, skopeo, grep (PCRE)

**Architecture Strengths:**
- ✅ **Clear separation of concerns:** Each action is self-contained
- ✅ **Defensive dependency management:** Auto-detect and prompt to install missing tools
- ✅ **Fail-fast error handling:** Comprehensive validation before expensive operations
- ✅ **Minimal global state:** Uses local variables extensively
- ✅ **Explicit parameter passing:** Functions receive inputs rather than reading globals
- ✅ **Comprehensive inline documentation:** Every function has purpose/params/returns
- ✅ **Best practices comments:** Explains *why* not just *what*
- ✅ **Secure credential handling:** Interactive prompts, base64 files, no CLI password exposure
- ✅ **Idempotent operations:** Safe to run multiple times
- ✅ **Progress tracking:** Success/failure counters for batch operations
- ✅ **Actionable error messages:** Clear next steps when failures occur

**Architecture Patterns:**
```bash
# Pattern 1: Function documentation header
#=============================================================================
# Function: action_image_download
# Description: Downloads all RKE2 and CNI plugin images for offline use
# Parameters:
#   $1 - Download directory path (optional, default: ./downloads)
# Returns: 0 if all downloads succeed, 1 if any failures occur
# Usage: action_image_download [/path/to/downloads]
#=============================================================================

# Pattern 2: Dependency checking with user consent
install_dependencies() {
    local missing_deps=()
    # Check for curl, skopeo...
    if [ ${#missing_deps[@]} -eq 0 ]; then
        return 0
    fi
    read -p "Would you like to install missing dependencies now? (y/n): " -n 1 -r
    # Install based on OS detection
}

# Pattern 3: Metrics tracking
local count=0
local success=0
local failed=0
# Process operations...
echo "Total: $total_images, Successful: $success, Failed: $failed"

# Pattern 4: Best practice inline comments
# Best Practice: Use mktemp for race-condition-free temp file creation
local TEMP_DIR=$(mktemp -d)
```

---

## Key Differences

### 1. **Dependency Management**

| Aspect | rke2nodeinit.sh | rke2imageprep.sh |
|--------|-----------------|------------------|
| Missing tools | Hard fail or silent skip | Auto-detect, prompt install with user consent |
| OS detection | Basic apt-get assumptions | Multi-distro support (apt/dnf/yum) |
| Installation | `ensure_installed <pkg>` without consent | Interactive with clear explanation |

**Recommendation:** Adopt interactive dependency installation with OS detection.

### 2. **Error Handling**

| Aspect | rke2nodeinit.sh | rke2imageprep.sh |
|--------|-----------------|------------------|
| Strategy | Global `set -Eeuo pipefail` with ERR trap | Explicit return codes with inline validation |
| Recovery | Immediate exit on any error | Graceful degradation with metrics |
| Feedback | Generic "See log" messages | Specific errors with remediation steps |

**Recommendation:** Maintain strict mode but add graceful error aggregation with summary reports.

### 3. **Function Design**

| Aspect | rke2nodeinit.sh | rke2imageprep.sh |
|--------|-----------------|------------------|
| State | Heavy global variable usage | Local variables, explicit parameter passing |
| Scope | Large multi-purpose functions | Small, single-responsibility functions |
| Documentation | Inline comments, some headers | Comprehensive structured headers |
| Reusability | Limited due to global coupling | High - functions are self-contained |

**Recommendation:** Refactor large functions into focused utilities with explicit interfaces.

### 4. **Code Organization**

| Aspect | rke2nodeinit.sh | rke2imageprep.sh |
|--------|-----------------|------------------|
| Structure | Functions scattered, grouping unclear | Clear sections: utilities → actions → main |
| Length | 6,377 lines in single file | 710 lines in single file |
| Entry point | Bottom of file with complex case statement | Clear main block with sourcing support |

**Recommendation:** Reorganize into clear sections with table of contents comments.

### 5. **User Experience**

| Aspect | rke2nodeinit.sh | rke2imageprep.sh |
|--------|-----------------|------------------|
| Configuration | YAML-first, CLI flags as overrides | CLI flags with clear argument patterns |
| Feedback | Spinner for long ops, basic progress | Comprehensive summaries with metrics |
| Errors | Generic failures | Actionable guidance with examples |
| Help | Comprehensive multi-page help | Concise usage with examples |

**Recommendation:** Maintain YAML support but improve CLI consistency and error messaging.

---

## Target Design Patterns to Adopt

### 1. **Structured Function Documentation**

Every function should have a standardized header:

```bash
#=============================================================================
# Function: <name>
# Description: <one-line purpose>
# Parameters:
#   $1 - <description>
#   $2 - <description> (optional, default: <value>)
# Returns: <exit codes and their meanings>
# Usage: <example invocation>
# Dependencies: <required commands/functions>
# Best Practices: <architectural notes>
#=============================================================================
```

**Benefits:**
- Self-documenting code
- Clear contracts for function interfaces
- Easy to generate API documentation
- Helps identify refactoring candidates

### 2. **Defensive Dependency Management**

```bash
install_dependencies() {
    local missing_deps=()
    local need_<tool>=false
    
    # Check for each required tool
    if ! command -v <tool> &> /dev/null; then
        missing_deps+=("<tool>")
        need_<tool>=true
    fi
    
    # Exit if all satisfied
    if [ ${#missing_deps[@]} -eq 0 ]; then
        return 0
    fi
    
    # Prompt for installation
    echo "Missing dependencies: ${missing_deps[*]}"
    read -p "Install now? (y/n): " -n 1 -r
    [[ ! $REPLY =~ ^[Yy]$ ]] && return 1
    
    # Detect OS and install
    case "$OS" in
        ubuntu|debian) sudo apt-get install -y "${missing_deps[@]}" ;;
        rhel|centos)   sudo dnf install -y "${missing_deps[@]}" ;;
        *) echo "Unsupported OS"; return 1 ;;
    esac
    
    # Verify installation
    for dep in "${missing_deps[@]}"; do
        command -v "$dep" &>/dev/null || return 1
    done
    return 0
}
```

**Benefits:**
- Graceful handling of missing tools
- User consent before system modifications
- Multi-distro support
- Verification of successful installation

### 3. **Operation Metrics Tracking**

```bash
action_<name>() {
    local total_items=<count>
    local count=0
    local success=0
    local failed=0
    
    while <condition>; do
        count=$((count + 1))
        echo "[$count/$total_items] Processing: <item>"
        
        if <operation>; then
            success=$((success + 1))
            echo "  ✓ Success"
        else
            failed=$((failed + 1))
            echo "  ✗ Failed"
        fi
    done
    
    # Summary
    echo "=========================================="
    echo "Operation Summary"
    echo "=========================================="
    echo "Total: $total_items"
    echo "Successful: $success"
    echo "Failed: $failed"
    echo "=========================================="
    
    return $([[ $failed -eq 0 ]] && echo 0 || echo 1)
}
```

**Benefits:**
- Clear progress indicators
- Actionable summaries
- Easy troubleshooting
- Batch operation transparency

### 4. **Explicit Parameter Passing**

**Current (rke2nodeinit.sh):**
```bash
# Reads REGISTRY, REG_USER, REG_PASS from globals
write_registries_yaml_with_fallbacks() {
    local primary="$1"
    # ... uses global REGISTRY, REG_USER, REG_PASS
}
```

**Target (rke2imageprep.sh style):**
```bash
# Explicit parameters
write_registries_yaml() {
    local registry="$1"
    local username="$2"
    local password="$3"
    local ca_file="${4:-}"
    # All state passed explicitly
}
```

**Benefits:**
- Testable in isolation
- Clear dependencies
- No hidden coupling
- Easier refactoring

### 5. **Actionable Error Messages**

**Current:**
```bash
log ERROR "Checksum verification failed. See $LOG_FILE"
exit 3
```

**Target:**
```bash
log ERROR "Checksum verification FAILED"
log ERROR "Expected: $expected_hash"
log ERROR "Computed: $computed_hash"
log ERROR ""
log ERROR "Next steps:"
log ERROR "  1. Delete corrupted file: rm $file"
log ERROR "  2. Re-download: ./script.sh --download"
log ERROR "  3. Verify network integrity"
exit 3
```

**Benefits:**
- Reduces support burden
- Empowers operators
- Speeds troubleshooting
- Improves confidence

---

## Recommended Redesign Strategy

### Phase 1: Foundation (Week 1-2)

**Goal:** Establish core utilities and patterns without breaking existing functionality

#### 1.1 Create Utility Library Section
```bash
# ============================================================================
# SECTION: Core Utilities
# Purpose: Reusable helper functions with no external dependencies
# ============================================================================

# Logging utilities
log_info() { ... }
log_warn() { ... }
log_error() { ... }

# Validation utilities
validate_ipv4() { ... }
validate_prefix() { ... }
validate_yaml_schema() { ... }

# String utilities
trim_whitespace() { ... }
normalize_csv() { ... }
```

#### 1.2 Implement Dependency Manager
```bash
# ============================================================================
# SECTION: Dependency Management
# Purpose: Detect, validate, and install required system packages
# ============================================================================

detect_os() {
    # Returns: ubuntu|debian|rhel|centos|fedora|unknown
}

check_dependencies() {
    local required_deps=("$@")
    local missing_deps=()
    # Returns array of missing dependencies
}

install_dependencies() {
    # Interactive installation with OS detection
}

verify_dependencies() {
    # Post-install verification
}
```

#### 1.3 Add Metrics Infrastructure
```bash
# Metrics tracking utilities
declare -A METRICS=()

metrics_init() {
    METRICS[total]=0
    METRICS[success]=0
    METRICS[failed]=0
}

metrics_increment() {
    local key="$1"
    METRICS[$key]=$((METRICS[$key] + 1))
}

metrics_summary() {
    echo "=========================================="
    echo "Operation Summary"
    echo "=========================================="
    echo "Total:      ${METRICS[total]}"
    echo "Successful: ${METRICS[success]}"
    echo "Failed:     ${METRICS[failed]}"
    echo "=========================================="
}
```

### Phase 2: Action Refactoring (Week 3-4)

**Goal:** Refactor each action into self-contained, well-documented functions

#### 2.1 Template for Action Functions
```bash
#=============================================================================
# Function: action_<name>
# Description: <comprehensive description>
# Parameters:
#   None (reads from CONFIG_FILE global or CLI flags)
# Returns: 
#   0 - Success
#   1 - Validation failure
#   2 - Execution failure
# Usage: action_<name>
# Dependencies: <list required functions/commands>
#=============================================================================
action_<name>() {
    # Initialize context
    initialize_action_context "<name>"
    
    # Validate prerequisites
    validate_prerequisites || return 1
    
    # Initialize metrics
    metrics_init
    
    # Execute operation
    echo "=========================================="
    echo "<Action> Started"
    echo "=========================================="
    
    # Core logic with error handling
    if ! perform_operation; then
        metrics_increment failed
        return 2
    fi
    metrics_increment success
    
    # Summary
    metrics_summary
    
    return 0
}
```

#### 2.2 Priority Order for Refactoring
1. **action_push** - Smallest, good starting point
2. **action_verify** - Read-only, low risk
3. **action_custom_ca** - Self-contained
4. **action_image** - Critical but well-scoped
5. **action_server** - Complex, needs careful handling
6. **action_agent** - Similar to server
7. **action_add_server** - Similar to server

### Phase 3: Configuration & CLI (Week 5-6)

**Goal:** Improve CLI consistency and YAML parsing

#### 3.1 Standardize Flag Handling
```bash
# Consistent long-form flags with optional short forms
--registry=<host>          # -r <host>
--username=<user>          # -u <user>
--password=<pass>          # -p <pass>
--config=<file>            # -f <file>
--version=<tag>            # -v <tag>
--auto-confirm             # -y
--dry-run                  # (no short form)
--help                     # -h
```

#### 3.2 Improve YAML Validation
```bash
validate_yaml_schema() {
    local file="$1"
    local required_fields=()
    local optional_fields=()
    
    # Check apiVersion
    local api
    api=$(yaml_get_api "$file")
    [[ "$api" == "rkeprep/v1" ]] || {
        log_error "Invalid apiVersion: $api (expected: rkeprep/v1)"
        return 1
    }
    
    # Validate kind
    local kind
    kind=$(yaml_get_kind "$file")
    case "$kind" in
        Push|Image|Server|Agent|AddServer|Verify|Airgap|CustomCA) ;;
        *) log_error "Invalid kind: $kind"; return 1 ;;
    esac
    
    # Validate metadata.name (required)
    local name
    name=$(yaml_meta_get "$file" name)
    [[ -n "$name" ]] || {
        log_error "Missing required field: metadata.name"
        return 1
    }
    
    # Kind-specific validation
    validate_kind_specific_fields "$file" "$kind" || return 1
    
    return 0
}
```

### Phase 4: Documentation & Testing (Week 7-8)

**Goal:** Comprehensive documentation and validation

#### 4.1 Generate Function Reference
```bash
# Auto-generate from function headers
./generate-api-docs.sh > docs/API-REFERENCE.md
```

#### 4.2 Add Integration Tests
```bash
tests/
├── test_action_push.sh
├── test_action_verify.sh
├── test_dependency_manager.sh
├── test_yaml_validation.sh
└── test_metrics_tracking.sh
```

#### 4.3 Create Migration Guide
```markdown
# Migration Guide: v0.8 → v1.0

## Breaking Changes
- Removed support for deprecated flag X
- YAML schema changes: ...

## New Features
- Interactive dependency installation
- Improved error messages
- Metrics summaries

## Upgrade Path
1. Backup existing configs
2. Update YAML schemas
3. Test in non-production
```

---

## Implementation Roadmap

### Timeline: 8 Weeks

| Week | Milestone | Deliverables |
|------|-----------|--------------|
| 1-2  | Foundation | Utility library, dependency manager, metrics infrastructure |
| 3-4  | Actions | Refactor 7 action functions with new patterns |
| 5-6  | CLI & Config | Standardize flags, improve YAML validation |
| 7-8  | Polish | Documentation, tests, migration guide |

### Success Criteria

- ✅ All existing actions work without regression
- ✅ Every function has structured documentation
- ✅ Dependency manager handles 3+ distros
- ✅ Metrics tracking in all batch operations
- ✅ Actionable error messages with remediation
- ✅ Reduced global variable usage by 50%+
- ✅ Integration tests for core actions
- ✅ Migration guide for operators

---

## Risk Analysis

### High Risk

| Risk | Impact | Mitigation |
|------|--------|------------|
| Breaking existing workflows | HIGH | Maintain backward compatibility, extensive testing |
| Regression in complex actions | HIGH | Incremental refactoring, feature flags |
| YAML parsing changes | HIGH | Strict validation, clear migration path |

### Medium Risk

| Risk | Impact | Mitigation |
|------|--------|------------|
| Dependency installation failures | MEDIUM | Graceful fallback, clear manual steps |
| Increased complexity | MEDIUM | Comprehensive documentation |
| Performance impact | MEDIUM | Benchmark before/after |

### Low Risk

| Risk | Impact | Mitigation |
|------|--------|------------|
| Documentation drift | LOW | Auto-generation where possible |
| Test coverage gaps | LOW | Prioritize critical paths |

---

## Appendix A: Function Comparison Matrix

| Category | rke2nodeinit.sh | rke2imageprep.sh | Recommendation |
|----------|-----------------|------------------|----------------|
| **Dependency Management** |
| Tool detection | `command -v <tool>` | `command -v <tool> &> /dev/null` | Adopt silent check pattern |
| Installation | `ensure_installed <pkg>` (no consent) | Interactive with OS detection | Adopt interactive pattern |
| Verification | Basic | Explicit post-install checks | Add verification step |
| **Error Handling** |
| Strategy | Global ERR trap | Explicit return codes | Hybrid approach |
| Aggregation | None | Success/failed counters | Add metrics to all actions |
| Recovery | Hard fail | Continue with summary | Add continue-on-error flag |
| **Function Design** |
| Documentation | Inline comments | Structured headers | Adopt structured headers |
| Parameters | Mix of globals + params | Explicit params | Prefer explicit params |
| State | Heavy globals | Local variables | Reduce global usage |
| **User Experience** |
| Progress | Spinner | Progress counters | Add both |
| Summaries | Basic | Comprehensive | Add comprehensive summaries |
| Errors | Generic | Actionable | Improve error messages |

---

## Appendix B: Refactoring Checklist

For each function being refactored:

- [ ] Add structured documentation header
- [ ] Replace global variable reads with parameters
- [ ] Add input validation
- [ ] Implement metrics tracking (if batch operation)
- [ ] Improve error messages with remediation steps
- [ ] Add inline best practice comments
- [ ] Write unit/integration test
- [ ] Update main documentation
- [ ] Verify backward compatibility
- [ ] Benchmark performance impact

---

## Appendix C: Example Refactoring

### Before (rke2nodeinit.sh style):
```bash
cache_rke2_artifacts() {
  mkdir -p "$DOWNLOADS_DIR"
  pushd "$DOWNLOADS_DIR" >/dev/null
  
  if [[ -n "$REQ_VER" ]]; then
    RKE2_VERSION="$REQ_VER"
  else
    detect_latest_rke2_version
  fi
  
  local BASE_URL="https://github.com/rancher/rke2/releases/download/${RKE2_VERSION}"
  
  if [[ -f "$IMAGES_TAR" ]]; then
    log INFO "Already present: $IMAGES_TAR"
  else
    spinner_run "Downloading $IMAGES_TAR" curl -Lf "$BASE_URL/$IMAGES_TAR" -o "$IMAGES_TAR"
  fi
  
  # ... more downloads
  
  popd >/dev/null
}
```

### After (rke2imageprep.sh style):
```bash
#=============================================================================
# Function: cache_rke2_artifacts  
# Description: Downloads and verifies RKE2 release artifacts for offline use
# Parameters:
#   $1 - Download directory (optional, default: ./downloads)
#   $2 - RKE2 version tag (optional, detects latest if omitted)
# Returns: 0 on success, 1 on download failure, 2 on checksum failure
# Usage: cache_rke2_artifacts [/path/to/downloads] [v1.34.1+rke2r1]
# Dependencies: curl, sha256sum
# Best Practices:
#   - Idempotent: Safe to run multiple times
#   - Validates checksums before proceeding
#   - Provides progress feedback for each artifact
#=============================================================================
cache_rke2_artifacts() {
    # Check dependencies before starting expensive operations
    if ! check_dependencies curl sha256sum; then
        echo "Error: Required dependencies not available"
        return 1
    fi
    
    # Parse parameters with defaults
    local download_dir="${1:-./downloads}"
    local version="${2:-}"
    
    # Create download directory with error handling
    mkdir -p "$download_dir" || {
        echo "Error: Failed to create download directory: $download_dir"
        return 1
    }
    
    # Initialize metrics for tracking
    local total_artifacts=4  # images, tarball, sha256, install.sh
    local count=0
    local success=0
    local failed=0
    
    # Detect version if not provided
    if [[ -z "$version" ]]; then
        echo "Detecting latest RKE2 version from GitHub..."
        version=$(detect_latest_rke2_version) || {
            echo "Error: Failed to detect RKE2 version"
            return 1
        }
        echo "Latest stable RKE2 version: $version"
    fi
    
    local base_url="https://github.com/rancher/rke2/releases/download/${version}"
    local arch=$(uname -m)
    case "$arch" in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
    esac
    
    echo "=========================================="
    echo "RKE2 Artifact Download Started"
    echo "Version: $version"
    echo "Architecture: $arch"
    echo "Destination: $download_dir"
    echo "=========================================="
    echo ""
    
    # Download artifacts with progress tracking
    local artifacts=(
        "rke2-images.linux-${arch}.tar.zst"
        "rke2.linux-${arch}.tar.gz"
        "sha256sum-${arch}.txt"
        "install.sh"
    )
    
    for artifact in "${artifacts[@]}"; do
        count=$((count + 1))
        
        # Check if already downloaded
        if [[ -f "$download_dir/$artifact" ]]; then
            echo "[$count/$total_artifacts] Already present: $artifact (skipping)"
            ((success++))
            continue
        fi
        
        echo "[$count/$total_artifacts] Downloading: $artifact"
        
        # Download with error handling
        local url
        if [[ "$artifact" == "install.sh" ]]; then
            url="https://get.rke2.io"
        else
            url="${base_url}/${artifact}"
        fi
        
        if curl -fsSL -o "$download_dir/$artifact" "$url"; then
            local size=$(du -h "$download_dir/$artifact" | awk '{print $1}')
            echo "  ✓ Downloaded successfully ($size)"
            ((success++))
        else
            echo "  ✗ Download failed"
            ((failed++))
        fi
        echo ""
    done
    
    # Verify checksums
    if [[ -f "$download_dir/sha256sum-${arch}.txt" ]]; then
        echo "Verifying checksums..."
        pushd "$download_dir" >/dev/null || return 1
        
        if sha256sum -c "sha256sum-${arch}.txt" 2>&1 | grep -E "rke2-images|rke2\.linux"; then
            echo "  ✓ Checksum verification passed"
        else
            echo "  ✗ Checksum verification failed"
            popd >/dev/null
            return 2
        fi
        
        popd >/dev/null
    fi
    
    # Summary
    echo ""
    echo "=========================================="
    echo "Download Summary"
    echo "=========================================="
    echo "Total artifacts: $total_artifacts"
    echo "Successful: $success"
    echo "Failed: $failed"
    echo "Download directory: $download_dir"
    echo "=========================================="
    
    return $([[ $failed -eq 0 ]] && echo 0 || echo 1)
}
```

### Key Improvements:
1. ✅ Structured documentation header
2. ✅ Explicit parameters with defaults
3. ✅ Dependency validation upfront
4. ✅ Metrics tracking (count/success/failed)
5. ✅ Clear progress indicators
6. ✅ Comprehensive error handling
7. ✅ Actionable success/failure messages
8. ✅ Idempotent (safe to re-run)
9. ✅ Summary report

---

## Conclusion

The redesign strategy focuses on adopting proven patterns from `rke2imageprep.sh` while maintaining the rich functionality of `rke2nodeinit.sh`. The phased approach minimizes risk by:

1. **Building foundations** without touching existing actions
2. **Incrementally refactoring** one action at a time
3. **Maintaining backward compatibility** throughout
4. **Comprehensive testing** before release

**Expected Outcomes:**
- 40-50% reduction in code complexity through better organization
- Improved maintainability via standardized patterns
- Enhanced user experience with better errors and progress tracking
- Reduced support burden through actionable error messages
- Better testability through explicit parameter passing

**Next Steps:**
1. Review and approve redesign strategy
2. Create feature branch for Phase 1
3. Implement utility library
4. Begin action refactoring

---

**Document Version:** 1.0  
**Author:** GitHub Copilot (Claude Sonnet 4.5)  
**Review Status:** DRAFT - Awaiting stakeholder feedback
