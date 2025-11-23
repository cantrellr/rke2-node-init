#!/usr/bin/env bash
#
# Phase 1 Redesign - Demonstration Script
# ========================================
# Purpose: Demonstrate the new utility functions from Phase 1 implementation
# Usage: sudo ./examples/phase1-demo.sh
#

set -euo pipefail

# Source the main script to get access to Phase 1 functions
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
source "$SCRIPT_DIR/../bin/rke2nodeinit.sh" 2>/dev/null || {
  echo "Error: Could not source rke2nodeinit.sh"
  exit 1
}

echo "=========================================="
echo "Phase 1 Redesign - Utility Demonstration"
echo "=========================================="
echo ""

# ==============================================================================
# Demo 1: Enhanced Logging Utilities
# ==============================================================================
echo "=== Demo 1: Enhanced Logging ===" 
echo ""

log_info "This is an informational message"
log_warn "This is a warning message"
log_error "This is an error message (non-fatal for demo)"
log_success "This is a success message"

echo ""
echo "✓ Logging utilities demonstrated"
echo "  Check log file: $LOG_FILE"
echo ""

# ==============================================================================
# Demo 2: OS Detection
# ==============================================================================
echo "=== Demo 2: OS Detection ===" 
echo ""

detected_os=$(detect_os)
echo "Detected OS: $detected_os"

echo ""
echo "✓ OS detection demonstrated"
echo ""

# ==============================================================================
# Demo 3: Dependency Checking (Non-invasive)
# ==============================================================================
echo "=== Demo 3: Dependency Checking ===" 
echo ""

# Check for common tools (should exist)
echo "Checking for common tools (curl, bash, grep)..."
if check_dependencies curl bash grep; then
  echo "✓ All common tools present"
else
  echo "⚠ Missing tools: ${MISSING_DEPS[*]}"
fi

echo ""

# Check for uncommon tool (might not exist)
echo "Checking for specialized tools (skopeo, nerdctl)..."
if check_dependencies skopeo nerdctl; then
  echo "✓ All specialized tools present"
else
  echo "⚠ Missing tools: ${MISSING_DEPS[*]}"
  echo "  (This is expected if not yet installed)"
fi

echo ""
echo "✓ Dependency checking demonstrated"
echo ""

# ==============================================================================
# Demo 4: Metrics Tracking
# ==============================================================================
echo "=== Demo 4: Metrics Tracking ===" 
echo ""

# Initialize metrics for a sample operation
metrics_init "demo_batch_operation"

# Simulate a batch operation
echo "Simulating batch operation with 10 items..."
for i in {1..10}; do
  metrics_increment total
  
  # Simulate random success/failure/skip
  case $((i % 3)) in
    0)
      metrics_increment success
      echo "  Item $i: Success"
      ;;
    1)
      metrics_increment failed
      echo "  Item $i: Failed"
      ;;
    2)
      metrics_increment skipped
      echo "  Item $i: Skipped"
      ;;
  esac
  
  sleep 0.2  # Simulate work
done

# Display summary
metrics_summary "Demo Batch Operation Summary"

# Check if operation should fail
if metrics_should_fail; then
  echo "Result: Operation would return failure (has failed items)"
else
  echo "Result: Operation would return success (no failures)"
fi

echo ""
echo "✓ Metrics tracking demonstrated"
echo ""

# ==============================================================================
# Demo 5: Validation Utilities
# ==============================================================================
echo "=== Demo 5: Validation Utilities ===" 
echo ""

# Test non-empty validation (success case)
echo "Testing validate_non_empty with valid value..."
if validate_non_empty "example-value" "test_parameter"; then
  echo "  ✓ Validation passed"
else
  echo "  ✗ Validation failed (unexpected)"
fi

echo ""

# Test non-empty validation (failure case)
echo "Testing validate_non_empty with empty value..."
if validate_non_empty "" "test_parameter"; then
  echo "  ✓ Validation passed (unexpected)"
else
  echo "  ✗ Validation failed (expected)"
fi

echo ""

# Test file existence (success case)
echo "Testing validate_file_exists with existing file..."
if validate_file_exists "$SCRIPT_DIR/../bin/rke2nodeinit.sh" "main script"; then
  echo "  ✓ File validation passed"
else
  echo "  ✗ File validation failed (unexpected)"
fi

echo ""

# Test file existence (failure case)
echo "Testing validate_file_exists with non-existent file..."
if validate_file_exists "/tmp/nonexistent-file-12345.txt" "test file"; then
  echo "  ✓ File validation passed (unexpected)"
else
  echo "  ✗ File validation failed (expected)"
fi

echo ""

# Test directory writable (success case)
echo "Testing validate_directory_writable with writable directory..."
if validate_directory_writable "/tmp" "temp directory"; then
  echo "  ✓ Directory validation passed"
else
  echo "  ✗ Directory validation failed (unexpected)"
fi

echo ""
echo "✓ Validation utilities demonstrated"
echo ""

# ==============================================================================
# Demo 6: Progress Reporting
# ==============================================================================
echo "=== Demo 6: Progress Reporting ===" 
echo ""

echo "Simulating download operation..."
for i in {1..5}; do
  report_progress $i 5 "Downloading file-${i}.tar.gz"
  
  case $i in
    1|3|5)
      report_item_success "file-${i}.tar.gz" "125MB"
      ;;
    2)
      report_item_skipped "file-${i}.tar.gz" "Already present"
      ;;
    4)
      report_item_failure "file-${i}.tar.gz" "Checksum mismatch"
      ;;
  esac
  
  sleep 0.3
done

echo ""
echo "✓ Progress reporting demonstrated"
echo ""

# ==============================================================================
# Summary
# ==============================================================================
echo "=========================================="
echo "Phase 1 Demonstration Complete"
echo "=========================================="
echo ""
echo "New utilities available:"
echo "  ✓ Enhanced logging (log_info, log_warn, log_error, log_success)"
echo "  ✓ OS detection (detect_os)"
echo "  ✓ Dependency management (check_dependencies, install_dependencies_interactive)"
echo "  ✓ Metrics tracking (metrics_init, metrics_increment, metrics_summary)"
echo "  ✓ Validation (validate_non_empty, validate_file_exists, validate_directory_writable)"
echo "  ✓ Progress reporting (report_progress, report_item_success/failure/skipped)"
echo ""
echo "These utilities are now integrated into rke2nodeinit.sh"
echo "and ready for use in Phase 2 action refactoring."
echo ""
echo "Log file: $LOG_FILE"
echo ""
