# Phase 5 Quick Reference

**Version:** 1.0  
**Date:** November 16, 2025  
**Usage:** Command-line reference for Phase 5 functions

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Function Reference](#function-reference)
3. [Common Patterns](#common-patterns)
4. [Troubleshooting](#troubleshooting)
5. [Cheat Sheet](#cheat-sheet)

---

## Quick Start

### Enable All Phase 5 Features

```bash
#!/bin/bash
set -euo pipefail
source /rke2/rke2-node-init/bin/rke2nodeinit.sh

# Enable everything
enable_error_handling
enable_graceful_degradation
metrics_dashboard_init "my_operation"

# Your code here
# ...

# Display and export metrics
metrics_dashboard_display
metrics_export_all
```

---

## Function Reference

### Error Handling

#### `enable_error_handling()`

**Purpose:** Enable trap-based error handling  
**Parameters:** None  
**Returns:** Nothing  

**Usage:**
```bash
enable_error_handling
```

**What It Does:**
- Sets ERR trap → error_handler()
- Sets EXIT trap → cleanup_handler()
- Sets INT/TERM traps → interrupt_handler()
- Enables `set -E` for trap inheritance

---

#### `register_cleanup <function_name>`

**Purpose:** Register cleanup function for automatic execution on exit  
**Parameters:**  
- `function_name` - Name of cleanup function to register  

**Returns:** Nothing  

**Usage:**
```bash
cleanup_temp() {
    rm -rf /tmp/myapp-*
}

register_cleanup cleanup_temp
```

**Notes:**
- Cleanups execute in LIFO order
- Runs on success, failure, or interrupt
- Cleanup errors are suppressed

---

#### `set_error_context <message>`

**Purpose:** Set contextual information for errors  
**Parameters:**  
- `message` - Context description

**Returns:** Nothing  

**Usage:**
```bash
set_error_context "Downloading artifacts from upstream"
download_artifacts
clear_error_context
```

---

#### `clear_error_context()`

**Purpose:** Clear error context  
**Parameters:** None  
**Returns:** Nothing  

**Usage:**
```bash
clear_error_context
```

---

### Graceful Degradation

#### `enable_graceful_degradation()`

**Purpose:** Enable graceful degradation mode  
**Parameters:** None  
**Returns:** Nothing  

**Usage:**
```bash
enable_graceful_degradation
```

**Effect:**
- Non-critical operations can fail without stopping execution

---

#### `disable_graceful_degradation()`

**Purpose:** Disable graceful degradation mode  
**Parameters:** None  
**Returns:** Nothing  

**Usage:**
```bash
disable_graceful_degradation
```

---

#### `try_with_degradation <command> <description> <criticality>`

**Purpose:** Execute command with graceful failure handling  
**Parameters:**  
- `command` - Command or function to execute
- `description` - Human-readable description
- `criticality` - "critical" or "non-critical"

**Returns:** Exit code of command (critical) or 0 (non-critical with degradation)  

**Usage:**
```bash
# Critical operation (must succeed)
try_with_degradation \
    "validate_config" \
    "Validating RKE2 configuration" \
    "critical"

# Non-critical operation (can fail)
try_with_degradation \
    "install_monitoring" \
    "Installing Prometheus" \
    "non-critical"
```

**Behavior:**
- **Critical:** Fails on error (exit code returned)
- **Non-critical + degradation enabled:** Logs warning, returns 0
- **Non-critical + degradation disabled:** Fails on error

---

#### `retry_with_backoff <command> <max_attempts> <initial_delay>`

**Purpose:** Retry command with exponential backoff  
**Parameters:**  
- `command` - Command to retry
- `max_attempts` - Maximum retry attempts (default: 3)
- `initial_delay` - Initial delay in seconds (default: 2)

**Returns:** 0 on success, 1 on failure after all retries  

**Usage:**
```bash
# Retry up to 5 times, starting with 2s delay
retry_with_backoff "curl -fsSL $URL -o file" 5 2

# Use defaults (3 attempts, 2s initial delay)
retry_with_backoff "download_file"
```

**Delay Pattern:**
```
Attempt 1: immediate
Attempt 2: wait initial_delay
Attempt 3: wait initial_delay * 2
Attempt 4: wait initial_delay * 4
Attempt 5: wait initial_delay * 8
```

---

### Metrics Dashboard

#### `metrics_dashboard_init <operation>`

**Purpose:** Initialize metrics dashboard with session ID  
**Parameters:**  
- `operation` - Operation name for session ID

**Returns:** Nothing  

**Usage:**
```bash
metrics_dashboard_init "server_deployment"
```

**Effect:**
- Creates session ID: `{operation}_{YYYYMMDD_HHMMSS}_{PID}`
- Calls `metrics_init`
- Creates export directory

---

#### `metrics_dashboard_display [title]`

**Purpose:** Display formatted metrics dashboard  
**Parameters:**  
- `title` - Optional dashboard title (default: "METRICS DASHBOARD")

**Returns:** Nothing  

**Usage:**
```bash
metrics_dashboard_display "Deployment Complete"
```

**Output:**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DEPLOYMENT COMPLETE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Session ID:     deployment_20251116_143022_12345
Operation:      deployment
Start Time:     2025-11-16 14:30:22
End Time:       2025-11-16 14:35:45
Duration:       323s

Metrics:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
...
```

---

#### `metrics_export_json <file>`

**Purpose:** Export metrics to JSON file  
**Parameters:**  
- `file` - Output file path (optional, auto-generated if omitted)

**Returns:** 0 on success, 1 on failure  

**Usage:**
```bash
# Auto-generate filename
metrics_export_json

# Specify filename
metrics_export_json "/path/to/metrics.json"
```

---

#### `metrics_export_csv <file>`

**Purpose:** Export metrics to CSV file  
**Parameters:**  
- `file` - Output file path (optional, auto-generated if omitted)

**Returns:** 0 on success, 1 on failure  

**Usage:**
```bash
# Auto-generate filename
metrics_export_csv

# Specify filename
metrics_export_csv "/path/to/metrics.csv"
```

---

#### `metrics_export_all()`

**Purpose:** Export metrics to both JSON and CSV  
**Parameters:** None  
**Returns:** 0 if both succeed, 1 otherwise  

**Usage:**
```bash
metrics_export_all
```

**Output:**
```
[INFO] Exporting metrics to all formats...
[SUCCESS] Metrics exported to JSON and CSV:
  JSON: /outputs/metrics/deployment_20251116_143022_12345.json
  CSV:  /outputs/metrics/deployment_20251116_143022_12345.csv
```

---

#### `metrics_compare <file1> <file2>`

**Purpose:** Compare two metrics sessions  
**Parameters:**  
- `file1` - First JSON metrics file
- `file2` - Second JSON metrics file

**Returns:** Nothing (displays comparison info)  

**Usage:**
```bash
metrics_compare \
    "/outputs/metrics/deployment1.json" \
    "/outputs/metrics/deployment2.json"
```

**Requirements:** `jq` command must be installed

---

## Common Patterns

### Pattern 1: Standard Deployment

```bash
#!/bin/bash
set -euo pipefail
source /rke2/rke2-node-init/bin/rke2nodeinit.sh

enable_error_handling
metrics_dashboard_init "deployment"

register_cleanup cleanup_temp_files

set_error_context "Deploying RKE2 server"
action_server
clear_error_context

metrics_dashboard_display
metrics_export_all
```

---

### Pattern 2: Network Operations

```bash
#!/bin/bash
source /rke2/rke2-node-init/bin/rke2nodeinit.sh

enable_error_handling

# Retry download with exponential backoff
if retry_with_backoff "curl -fsSL $URL -o file" 5 2; then
    log_success "Download successful"
else
    log_error "Download failed after retries"
    exit 1
fi
```

---

### Pattern 3: Optional Features

```bash
#!/bin/bash
source /rke2/rke2-node-init/bin/rke2nodeinit.sh

enable_error_handling
enable_graceful_degradation

# Core installation (critical)
try_with_degradation \
    "install_rke2" \
    "Installing RKE2" \
    "critical"

# Monitoring (non-critical)
try_with_degradation \
    "install_monitoring" \
    "Installing Prometheus" \
    "non-critical"
```

---

### Pattern 4: Batch Operations

```bash
#!/bin/bash
source /rke2/rke2-node-init/bin/rke2nodeinit.sh

enable_error_handling
enable_graceful_degradation
metrics_dashboard_init "batch_deployment"

for server in "${SERVERS[@]}"; do
    set_error_context "Deploying to $server"
    
    if retry_with_backoff "deploy_to_server $server" 3 2; then
        metrics_increment "servers_deployed"
    else
        metrics_increment "server_failures"
        log_error "Failed to deploy to $server"
    fi
    
    clear_error_context
done

metrics_dashboard_display "Batch Deployment"
metrics_export_all
```

---

### Pattern 5: Resource Cleanup

```bash
#!/bin/bash
source /rke2/rke2-node-init/bin/rke2nodeinit.sh

enable_error_handling

# Register cleanups in reverse order of creation
register_cleanup cleanup_network
register_cleanup cleanup_mounts
register_cleanup cleanup_temp_files

# Cleanups execute automatically on any exit
```

---

## Troubleshooting

### Error: "command not found: enable_error_handling"

**Cause:** Script not sourced  
**Solution:**
```bash
source /rke2/rke2-node-init/bin/rke2nodeinit.sh
```

---

### Error: Cleanup functions not executing

**Cause:** `enable_error_handling` not called  
**Solution:**
```bash
enable_error_handling  # Must be called before register_cleanup
register_cleanup my_cleanup_function
```

---

### Error: Metrics not exporting

**Cause:** Session ID not initialized  
**Solution:**
```bash
metrics_dashboard_init "my_operation"  # Call before exports
metrics_export_all
```

---

### Error: Graceful degradation not working

**Cause:** Mode not enabled  
**Solution:**
```bash
enable_graceful_degradation  # Call before try_with_degradation
try_with_degradation "cmd" "desc" "non-critical"
```

---

### Error: Stack trace not showing in errors

**Cause:** `set -E` not enabled  
**Solution:**
```bash
enable_error_handling  # This sets 'set -E' automatically
```

---

### Warning: Cleanup executed multiple times

**Cause:** Multiple trap registrations  
**Solution:**
```bash
# Only call enable_error_handling once at script start
enable_error_handling
```

---

## Cheat Sheet

### Initialization

```bash
# Minimal
source /rke2/rke2-node-init/bin/rke2nodeinit.sh
enable_error_handling

# Full
source /rke2/rke2-node-init/bin/rke2nodeinit.sh
enable_error_handling
enable_graceful_degradation
metrics_dashboard_init "operation"
```

### Error Handling

```bash
# Set context
set_error_context "Operation description"
risky_operation
clear_error_context

# Register cleanup
register_cleanup cleanup_function
```

### Graceful Degradation

```bash
# Enable mode
enable_graceful_degradation

# Try with degradation
try_with_degradation "cmd" "description" "critical|non-critical"

# Retry with backoff
retry_with_backoff "command" max_attempts initial_delay
```

### Metrics

```bash
# Initialize
metrics_dashboard_init "operation_name"

# Increment
metrics_increment "metric_name"

# Display
metrics_dashboard_display "Title"

# Export
metrics_export_json
metrics_export_csv
metrics_export_all

# Compare
metrics_compare file1.json file2.json
```

### Common Commands

```bash
# Standard deployment
enable_error_handling
metrics_dashboard_init "deployment"
register_cleanup cleanup_temp
set_error_context "Deploying"
action_server
clear_error_context
metrics_dashboard_display
metrics_export_all

# Network operation with retry
retry_with_backoff "curl -fsSL $URL" 5 2

# Optional feature
enable_graceful_degradation
try_with_degradation "install_monitoring" "Installing monitoring" "non-critical"
```

### Metric Names (New in Phase 5)

| Metric | Description |
|--------|-------------|
| `errors` | Number of errors encountered |
| `degraded_operations` | Number of non-critical failures |
| `retry_failures` | Operations that failed after all retries |
| `interrupted` | Whether interrupted by user |

### Export Locations

**Default Directory:**
```
/rke2/rke2-node-init/outputs/metrics/
```

**Custom Directory:**
```bash
export METRICS_EXPORT_DIR="/custom/path"
```

**File Naming:**
```
{operation}_{YYYYMMDD_HHMMSS}_{PID}.{json|csv}
```

**Example:**
```
server_deployment_20251116_143022_12345.json
server_deployment_20251116_143022_12345.csv
```

---

## Quick Examples

### Example 1: Minimal Error Handling

```bash
#!/bin/bash
source /rke2/rke2-node-init/bin/rke2nodeinit.sh
enable_error_handling
./bin/rke2nodeinit.sh server
```

### Example 2: With Cleanup

```bash
#!/bin/bash
source /rke2/rke2-node-init/bin/rke2nodeinit.sh
enable_error_handling
register_cleanup "rm -rf /tmp/deployment-*"
./bin/rke2nodeinit.sh server
```

### Example 3: With Metrics

```bash
#!/bin/bash
source /rke2/rke2-node-init/bin/rke2nodeinit.sh
enable_error_handling
metrics_dashboard_init "deployment"
./bin/rke2nodeinit.sh server
metrics_dashboard_display
metrics_export_all
```

### Example 4: Full Featured

```bash
#!/bin/bash
set -euo pipefail
source /rke2/rke2-node-init/bin/rke2nodeinit.sh

enable_error_handling
enable_graceful_degradation
metrics_dashboard_init "production_deployment"

register_cleanup cleanup_temp
register_cleanup cleanup_network

set_error_context "Deploying RKE2 server"
action_server
clear_error_context

try_with_degradation "install_monitoring" "Installing monitoring" "non-critical"

metrics_dashboard_display "Production Deployment Complete"
metrics_export_all
```

---

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `METRICS_EXPORT_DIR` | Metrics export directory | `${SCRIPT_DIR}/outputs/metrics` |
| `ERROR_CONTEXT` | Current error context | (empty) |
| `GRACEFUL_DEGRADATION_MODE` | Degradation mode flag | `0` |
| `METRICS_SESSION_ID` | Current session ID | (auto-generated) |

---

## Version Compatibility

**Minimum Requirements:**
- Bash 4.0+ (associative arrays)
- GNU coreutils
- `jq` (for metrics_compare only)

**Tested On:**
- Ubuntu 24.04 LTS
- Rocky Linux 9
- RHEL 9

---

**Document Author:** GitHub Copilot  
**Last Updated:** November 16, 2025  
**Phase:** 5 (Complete)
