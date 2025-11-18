# Phase 1 Quick Reference Card

Quick reference for using Phase 1 utilities in `rke2nodeinit.sh`

---

## Enhanced Logging

```bash
# Information (blue/white)
log_info "Operation started" "Processing 10 items"

# Warning (yellow)
log_warn "Using default credentials" "Override recommended"

# Error (red, to stderr)
log_error "Checksum failed" "Expected: abc123, Got: def456"

# Success (green, with ✓)
log_success "Download completed" "Size: 125MB"
```

---

## Dependency Management

```bash
# Detect OS
os=$(detect_os)  # Returns: ubuntu|debian|rhel|centos|fedora|rocky|almalinux|unknown

# Check dependencies (non-invasive)
if ! check_dependencies curl wget jq; then
  echo "Missing: ${MISSING_DEPS[*]}"
fi

# Interactive installation (prompts user)
install_dependencies_interactive curl wget jq skopeo || exit 1
```

---

## Metrics Tracking

```bash
# Initialize for batch operation
metrics_init "download_images"

# Process items
for item in "${items[@]}"; do
  metrics_increment total
  
  if process_item "$item"; then
    metrics_increment success
  else
    metrics_increment failed
  fi
done

# Display summary
metrics_summary "Download Summary"

# Return appropriate exit code
return $(metrics_should_fail)  # Returns 0 if no failures, 1 otherwise
```

**Available Metrics:**
- `total` - Total items
- `success` - Successful items
- `failed` - Failed items
- `skipped` - Skipped items

---

## Validation

```bash
# Validate non-empty parameter
validate_non_empty "$REGISTRY" "registry" || return 1

# Validate file exists and is readable
validate_file_exists "$CONFIG_FILE" "configuration" || return 1

# Validate directory exists and is writable
validate_directory_writable "$STAGE_DIR" "staging directory" || return 1
```

---

## Progress Reporting

```bash
# Main progress with percentage
report_progress 5 20 "Downloading nginx:latest"
# Output: [5/20 - 25%] Downloading nginx:latest

# Item success
report_item_success "nginx:latest" "245MB"
# Output:   ✓ nginx:latest (245MB)

# Item failure
report_item_failure "nginx:latest" "Checksum mismatch"
# Output:   ✗ nginx:latest (Error: Checksum mismatch)

# Item skipped
report_item_skipped "nginx:latest" "Already present"
# Output:   ⊘ nginx:latest (Skipped: Already present)
```

---

## Complete Example

```bash
action_example() {
  log_info "Starting example operation"
  
  # Validate prerequisites
  validate_non_empty "$REGISTRY" "registry" || return 1
  validate_directory_writable "$STAGE_DIR" "staging directory" || return 1
  
  # Check dependencies
  if ! check_dependencies curl skopeo; then
    install_dependencies_interactive curl skopeo || return 1
  fi
  
  # Initialize metrics
  metrics_init "example_operation"
  
  # Process items
  local items=("item1" "item2" "item3")
  local total=${#items[@]}
  
  for i in "${!items[@]}"; do
    local current=$((i + 1))
    local item="${items[$i]}"
    
    metrics_increment total
    report_progress $current $total "Processing $item"
    
    if process_item "$item"; then
      metrics_increment success
      report_item_success "$item"
    else
      metrics_increment failed
      report_item_failure "$item" "Processing error"
    fi
  done
  
  # Summary
  metrics_summary "Example Operation Summary"
  
  # Return appropriate code
  if metrics_should_fail; then
    log_error "Operation completed with failures"
    return 1
  else
    log_success "Operation completed successfully"
    return 0
  fi
}
```

---

## Best Practices

1. **Always initialize metrics** at start of batch operations
2. **Use validation** at function entry points
3. **Report progress** for long-running operations
4. **Display summaries** at operation completion
5. **Use appropriate logging** levels for different message types
6. **Provide actionable errors** with remediation steps

---

## Testing

```bash
# Run demo script
sudo /rke2/rke2-node-init/examples/phase1-demo.sh

# Interactive testing
source bin/rke2nodeinit.sh
log_info "Test message"
detect_os
```

---

## Documentation

- Full implementation: `docs/PHASE1-IMPLEMENTATION.md`
- Design analysis: `REDESIGN-ANALYSIS.md`
- Function headers: In `bin/rke2nodeinit.sh` (structured documentation)
