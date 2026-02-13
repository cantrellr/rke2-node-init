# Phase 5 Implementation Guide

**Document Version:** 1.0  
**Implementation Date:** November 16, 2025  
**Phase Status:** ✅ COMPLETE

---

## Table of Contents

1. [Overview](#overview)
2. [Objectives](#objectives)
3. [Implementation Summary](#implementation-summary)
4. [Advanced Error Handling](#advanced-error-handling)
5. [Graceful Degradation](#graceful-degradation)
6. [Metrics Dashboard](#metrics-dashboard)
7. [Code Patterns](#code-patterns)
8. [Usage Examples](#usage-examples)
9. [Testing](#testing)
10. [Integration Guide](#integration-guide)

---

## Overview

Phase 5 represents the final enhancement phase of the `rke2nodeinit.sh` script, adding enterprise-grade reliability features. Building on Phases 1-4, Phase 5 implements advanced error handling with trap-based cleanup, error context preservation, graceful degradation patterns, and a comprehensive metrics dashboard with export capabilities.

**Total Code Added:** ~600 lines  
**New Functions:** 17  
**Trap Handlers:** 3  
**Export Formats:** 2 (JSON, CSV)  

---

## Objectives

### Primary Goals

1. **Advanced Error Handling**
   - Trap-based automatic error detection
   - Comprehensive error context preservation
   - Stack trace generation for debugging
   - Automatic cleanup on failures

2. **Graceful Degradation**
   - Non-critical operation failure handling
   - Automatic retry with exponential backoff
   - Configurable criticality levels
   - Operation continuation despite failures

3. **Metrics Dashboard**
   - Session-based metrics tracking
   - Comprehensive dashboard visualization
   - JSON and CSV export capabilities
   - Historical metrics comparison

### Secondary Goals

- Improve operational reliability
- Enhanced debugging capabilities
- Analytics integration
- Production-ready error handling
- Comprehensive metrics for SRE teams

---

## Implementation Summary

### New Functions

| Category | Function | Purpose |
|----------|----------|---------|
| **Error Handling** | `error_handler()` | Global ERR trap handler with stack traces |
| | `cleanup_handler()` | EXIT trap handler executing cleanups |
| | `interrupt_handler()` | INT/TERM trap handler for graceful shutdown |
| | `register_cleanup()` | Register functions for automatic cleanup |
| | `set_error_context()` | Set context for error messages |
| | `clear_error_context()` | Clear error context |
| | `enable_error_handling()` | Enable all trap handlers |
| **Graceful Degradation** | `enable_graceful_degradation()` | Enable degradation mode |
| | `disable_graceful_degradation()` | Disable degradation mode |
| | `try_with_degradation()` | Execute with graceful failure |
| | `retry_with_backoff()` | Retry with exponential backoff |
| **Metrics Dashboard** | `metrics_dashboard_init()` | Initialize dashboard with session ID |
| | `metrics_dashboard_display()` | Display comprehensive dashboard |
| | `metrics_export_json()` | Export metrics to JSON |
| | `metrics_export_csv()` | Export metrics to CSV |
| | `metrics_export_all()` | Export to all formats |
| | `metrics_compare()` | Compare two metric sessions |

### Global Variables

```bash
declare -a ERROR_STACK=()              # Error stack trace
declare -a CLEANUP_FUNCTIONS=()        # Registered cleanup functions
declare -g ERROR_CONTEXT=""            # Current error context
declare -g LAST_ERROR_LINE=0           # Last error line number
declare -g LAST_ERROR_FUNCTION=""      # Last error function name
declare -g GRACEFUL_DEGRADATION_MODE=0 # Degradation mode flag

declare -A METRICS_HISTORY=()          # Metrics history storage
declare -g METRICS_SESSION_ID=""       # Current session ID
declare -g METRICS_EXPORT_DIR=""       # Metrics export directory
```

---

## Advanced Error Handling

### Trap-Based Error Detection

Phase 5 implements comprehensive trap handlers for automatic error detection and cleanup:

```bash
# Enable advanced error handling
enable_error_handling()

# This sets up:
# - ERR trap:  error_handler()
# - EXIT trap: cleanup_handler()
# - INT trap:  interrupt_handler()
# - TERM trap: interrupt_handler()
```

### Error Handler Features

**Automatic Error Detection:**
- Captures exit code, line number, function name
- Builds complete stack trace
- Logs comprehensive error information
- Increments error metrics

**Example Error Output:**

```
[ERROR] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ERROR] ERROR DETECTED
[ERROR] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ERROR] Exit Code: 1
[ERROR] Line: 1234
[ERROR] Function: validate_config
[ERROR] Command: [[ -f "$CONFIG_FILE" ]]
[ERROR] Context: Validating server configuration
[ERROR] 
[ERROR] Stack Trace:
[ERROR]   at validate_config (line 1234)
[ERROR]   at action_server (line 6650)
[ERROR]   at main (line 8000)
[ERROR] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Cleanup Registration

Register functions to be executed automatically on script exit (success or failure):

```bash
# Define cleanup functions
cleanup_temp_files() {
    log_info "Removing temporary files..."
    rm -rf /tmp/deployment-*
}

cleanup_network_config() {
    log_info "Reverting network configuration..."
    netplan revert 2>/dev/null || true
}

cleanup_mounts() {
    log_info "Unmounting temporary filesystems..."
    umount /mnt/staging 2>/dev/null || true
}

# Register cleanups (executed in LIFO order)
register_cleanup cleanup_mounts
register_cleanup cleanup_network_config
register_cleanup cleanup_temp_files
```

**Cleanup Execution:**
- Automatic on script exit (EXIT trap)
- LIFO (Last In, First Out) order
- Error suppression (non-fatal cleanup failures)
- Logged execution

### Error Context

Set contextual information for better error messages:

```bash
# Set context before risky operations
set_error_context "Downloading RKE2 artifacts from upstream"
download_rke2_artifacts || exit 1

set_error_context "Configuring network interfaces"
configure_network || exit 1

# Clear context on success
clear_error_context
```

**Benefits:**
- Immediate understanding of what failed
- Better troubleshooting
- Clear operational context
- Enhanced log analysis

### Interrupt Handling

Graceful handling of user interruption (Ctrl+C):

```bash
# Automatically handled via trap
# User presses Ctrl+C:

[WARN] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[WARN] Operation interrupted by user (Ctrl+C)
[WARN] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[INFO] Executing cleanup handlers...
[DEBUG] Running cleanup function: cleanup_mounts
[DEBUG] Running cleanup function: cleanup_network_config
[DEBUG] Running cleanup function: cleanup_temp_files
[INFO] Cleanup complete
```

---

## Graceful Degradation

### Graceful Degradation Mode

Enable non-critical operations to fail without stopping execution:

```bash
# Enable graceful degradation
enable_graceful_degradation()

# Operations marked as non-critical will log warnings but continue
```

### Try with Degradation

Execute commands with configurable criticality:

```bash
# Non-critical operation (will continue on failure)
try_with_degradation \
    "install_optional_monitoring" \
    "Installing optional Prometheus monitoring" \
    "non-critical"

# Output on failure:
# [WARN] Installing optional Prometheus monitoring failed (non-critical, continuing)

# Critical operation (will fail on error)
try_with_degradation \
    "validate_rke2_config" \
    "Validating RKE2 configuration" \
    "critical"
```

**Criticality Levels:**
- `critical`: Failure stops execution
- `non-critical`: Failure logged as warning, execution continues

**Degraded Operations Metric:**
- Tracks number of non-critical failures
- Visible in metrics dashboard
- Included in exports

### Retry with Exponential Backoff

Automatic retry logic for transient failures:

```bash
# Retry network download up to 5 times, starting with 2s delay
retry_with_backoff \
    "curl -fsSL https://get.rke2.io -o /downloads/install.sh" \
    5 \
    2

# Retry sequence:
# Attempt 1: immediate
# Attempt 2: wait 2s
# Attempt 3: wait 4s
# Attempt 4: wait 8s
# Attempt 5: wait 16s
```

**Exponential Backoff Algorithm:**
```
delay_n = initial_delay * 2^(n-2)

For initial_delay=2:
- Attempt 1: 0s (immediate)
- Attempt 2: 2s
- Attempt 3: 4s
- Attempt 4: 8s
- Attempt 5: 16s
```

**Use Cases:**
- Network downloads
- API calls
- Database connections
- File system operations
- Service health checks

---

## Metrics Dashboard

### Dashboard Initialization

Initialize metrics tracking with session ID:

```bash
# Initialize dashboard for deployment
metrics_dashboard_init "rke2_deployment"

# Generates session ID: rke2_deployment_20251116_143022_12345
# Creates export directory: /rke2/rke2-node-init/outputs/metrics/
```

### Dashboard Display

Comprehensive metrics visualization:

```bash
metrics_dashboard_display "RKE2 Deployment Metrics"
```

**Output:**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RKE2 DEPLOYMENT METRICS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Session ID:                    rke2_deployment_20251116_143022_12345
Operation:                     rke2_deployment
Start Time:                    2025-11-16 14:30:22
End Time:                      2025-11-16 14:35:45
Duration:                      323s

Metrics:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Metric                                    Value
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
site_defaults_loaded                          1
config_loaded                                 1
config_validated                              1
tls_sans_configured                           1
artifacts_staged                              1
hostname_set                                  1
custom_ca_configured                          1
interfaces_configured                         1
token_generated                               1
config_written                                1
netplan_written                               1
rke2_installed                                1
flannel_fix_installed                         1
errors                                        0
degraded_operations                           2
retry_failures                                0
interrupted                                   0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Success Rate:                            92%
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### New Metrics

Phase 5 adds operational metrics:

| Metric | Description |
|--------|-------------|
| `errors` | Number of errors encountered |
| `degraded_operations` | Number of non-critical failures |
| `retry_failures` | Number of operations that failed after all retries |
| `interrupted` | Whether operation was interrupted by user |

### Metrics Export

#### JSON Export

```bash
metrics_export_json "/path/to/metrics.json"
```

**Output Format:**

```json
{
  "session_id": "rke2_deployment_20251116_143022_12345",
  "operation": "rke2_deployment",
  "timestamp": {
    "start": 1700146222,
    "end": 1700146545,
    "duration": 323,
    "start_iso": "2025-11-16T14:30:22-07:00",
    "end_iso": "2025-11-16T14:35:45-07:00"
  },
  "metrics": {
    "site_defaults_loaded": 1,
    "config_loaded": 1,
    "config_validated": 1,
    "tls_sans_configured": 1,
    "artifacts_staged": 1,
    "hostname_set": 1,
    "custom_ca_configured": 1,
    "interfaces_configured": 1,
    "token_generated": 1,
    "config_written": 1,
    "netplan_written": 1,
    "rke2_installed": 1,
    "flannel_fix_installed": 1,
    "errors": 0,
    "degraded_operations": 2,
    "retry_failures": 0
  },
  "hostname": "server01",
    "script_version": "1.2.0",
  "dry_run": false
}
```

#### CSV Export

```bash
metrics_export_csv "/path/to/metrics.csv"
```

**Output Format:**

```csv
session_id,operation,start_time,end_time,duration,metric,value
rke2_deployment_20251116_143022_12345,rke2_deployment,1700146222,1700146545,323,site_defaults_loaded,1
rke2_deployment_20251116_143022_12345,rke2_deployment,1700146222,1700146545,323,config_loaded,1
rke2_deployment_20251116_143022_12345,rke2_deployment,1700146222,1700146545,323,config_validated,1
...
```

#### Export All Formats

```bash
# Export to both JSON and CSV
metrics_export_all

# Output:
# [INFO] Exporting metrics to all formats...
# [SUCCESS] Metrics exported to: /rke2/rke2-node-init/outputs/metrics/rke2_deployment_20251116_143022_12345.json
# [SUCCESS] Metrics exported to: /rke2/rke2-node-init/outputs/metrics/rke2_deployment_20251116_143022_12345.csv
# [SUCCESS] All metrics exported successfully
#   JSON: /rke2/rke2-node-init/outputs/metrics/rke2_deployment_20251116_143022_12345.json
#   CSV:  /rke2/rke2-node-init/outputs/metrics/rke2_deployment_20251116_143022_12345.csv
```

### Metrics Storage

**Default Location:**
```
/rke2/rke2-node-init/outputs/metrics/
```

**Directory Structure:**
```
outputs/metrics/
├── rke2_deployment_20251116_143022_12345.json
├── rke2_deployment_20251116_143022_12345.csv
├── server_deployment_20251116_150000_12346.json
├── server_deployment_20251116_150000_12346.csv
├── agent_deployment_20251116_151500_12347.json
└── agent_deployment_20251116_151500_12347.csv
```

**Custom Location:**
```bash
export METRICS_EXPORT_DIR="/var/log/rke2-metrics"
./rke2nodeinit.sh server
```

---

## Code Patterns

### Standard Error Handling Pattern

```bash
#!/bin/bash
set -euo pipefail

# Enable advanced error handling
enable_error_handling

# Register cleanup functions
cleanup_temp() {
    rm -rf /tmp/myapp-*
}
register_cleanup cleanup_temp

# Set error context and execute
set_error_context "Performing critical operation"
critical_operation || exit 1
clear_error_context

# Graceful degradation for optional features
enable_graceful_degradation
try_with_degradation \
    "optional_feature" \
    "Installing optional feature" \
    "non-critical"
```

### Metrics Dashboard Pattern

```bash
#!/bin/bash
source rke2nodeinit.sh

# Initialize dashboard
metrics_dashboard_init "my_deployment"

# Perform operations with metrics
metrics_increment "config_loaded"
metrics_increment "deployment_steps"

# Display and export
metrics_dashboard_display "Deployment Complete"
metrics_export_all
```

### Retry Pattern

```bash
#!/bin/bash

# Retry network operation
if retry_with_backoff "curl -fsSL $URL" 5 2; then
    log_success "Download successful"
else
    log_error "Download failed after retries"
    exit 1
fi
```

---

## Usage Examples

### Example 1: Server Deployment with Error Handling

```bash
#!/bin/bash
source /rke2/rke2-node-init/bin/rke2nodeinit.sh

# Enable advanced features
enable_error_handling
enable_graceful_degradation
metrics_dashboard_init "server_deployment"

# Register cleanups
register_cleanup cleanup_temp_artifacts

# Deploy with error handling
set_error_context "Deploying RKE2 server"
action_server

# Display metrics
metrics_dashboard_display
metrics_export_all
```

### Example 2: Batch Operations with Retry

```bash
#!/bin/bash

for image in "${IMAGES[@]}"; do
    if retry_with_backoff "download_image $image" 3 2; then
        metrics_increment "images_downloaded"
    else
        metrics_increment "download_failures"
        log_error "Failed to download: $image"
    fi
done
```

### Example 3: Optional Feature Installation

```bash
#!/bin/bash

# Core installation (critical)
try_with_degradation \
    "install_rke2" \
    "Installing RKE2" \
    "critical"

# Monitoring (non-critical)
try_with_degradation \
    "install_prometheus" \
    "Installing Prometheus" \
    "non-critical"

# Documentation (non-critical)
try_with_degradation \
    "generate_docs" \
    "Generating documentation" \
    "non-critical"
```

---

## Testing

### Syntax Validation

```bash
bash -n /rke2/rke2-node-init/bin/rke2nodeinit.sh
# Result: No errors
```

### Error Handler Testing

```bash
# Test error detection
bash -c 'source rke2nodeinit.sh; enable_error_handling; false'
# Should display comprehensive error message
```

### Cleanup Testing

```bash
# Test cleanup registration
bash -c 'source rke2nodeinit.sh; enable_error_handling; register_cleanup "echo cleanup1"; register_cleanup "echo cleanup2"; exit 0'
# Should execute: cleanup2, cleanup1 (LIFO order)
```

### Metrics Export Testing

```bash
# Test metrics export
bash -c 'source rke2nodeinit.sh; metrics_dashboard_init "test"; metrics_increment "test_metric"; metrics_export_all'
# Check outputs/metrics/ directory for JSON and CSV files
```

---

## Integration Guide

### Integrating into Existing Scripts

```bash
#!/bin/bash
# Your existing script

# Add at the beginning
source /rke2/rke2-node-init/bin/rke2nodeinit.sh
enable_error_handling
metrics_dashboard_init "my_operation"

# Add cleanup registration
register_cleanup my_cleanup_function

# Replace error-prone sections
set_error_context "Critical operation"
my_critical_operation
clear_error_context

# Add retry for network operations
retry_with_backoff "download_file" 3 2

# Display metrics at end
metrics_dashboard_display
metrics_export_all
```

### Best Practices

1. **Always enable error handling early**
   ```bash
   enable_error_handling  # First thing after shebang
   ```

2. **Register cleanups immediately**
   ```bash
   register_cleanup cleanup_func  # Right after resource allocation
   ```

3. **Set error context for complex operations**
   ```bash
   set_error_context "Descriptive context"
   risky_operation
   clear_error_context
   ```

4. **Use appropriate criticality levels**
   ```bash
   try_with_degradation "func" "desc" "critical"     # Must succeed
   try_with_degradation "func" "desc" "non-critical" # Optional
   ```

5. **Export metrics for analytics**
   ```bash
   metrics_export_all  # At script completion
   ```

---

## Conclusion

Phase 5 completes the modernization of rke2-node-init with enterprise-grade reliability features:

**✅ Implemented:**
- Trap-based error handling
- Error context preservation
- Automatic cleanup on exit
- Graceful degradation
- Retry with exponential backoff
- Comprehensive metrics dashboard
- JSON and CSV export

**📊 Statistics:**
- Lines added: ~600
- Functions added: 17
- Trap handlers: 3
- Export formats: 2

**🎯 Benefits:**
- Production-ready error handling
- Operational metrics for SRE teams
- Analytics integration capability
- Enhanced reliability
- Better debugging

Phase 5 establishes rke2-node-init as a production-grade, enterprise-ready deployment automation tool.

---

**Document Author:** GitHub Copilot  
**Implementation:** Phase 5 Complete  
**Last Updated:** November 16, 2025
