#!/bin/bash
# Phase 5 Demo Script
# Demonstrates Phase 5 advanced error handling and metrics dashboard features

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Demo configuration
readonly SCRIPT_PATH="/rke2/rke2-node-init/bin/rke2nodeinit.sh"
readonly DEMO_TEMP_DIR="/tmp/phase5-demo-$$"

# ============================================
# Helper Functions
# ============================================

print_header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${GREEN}▶ $1${NC}"
    echo ""
}

print_info() {
    echo -e "${CYAN}ℹ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_code() {
    echo -e "${YELLOW}$1${NC}"
}

pause_demo() {
    echo ""
    read -p "Press ENTER to continue..." -r
    echo ""
}

# ============================================
# Setup and Cleanup
# ============================================

setup_demo_env() {
    mkdir -p "$DEMO_TEMP_DIR"
    print_success "Demo environment created: $DEMO_TEMP_DIR"
}

cleanup_demo_env() {
    if [[ -d "$DEMO_TEMP_DIR" ]]; then
        rm -rf "$DEMO_TEMP_DIR"
        print_success "Demo environment cleaned up"
    fi
}

trap cleanup_demo_env EXIT

# ============================================
# Demo Scenarios
# ============================================

demo_error_handling_overview() {
    print_header "Demo 1: Advanced Error Handling Overview"
    
    print_info "Phase 5 introduces comprehensive error handling with:"
    echo ""
    echo "  1. Trap-Based Handlers"
    echo "     • ERR trap for automatic error detection"
    echo "     • EXIT trap for cleanup on script termination"
    echo "     • INT/TERM traps for graceful interruption"
    echo ""
    echo "  2. Error Context Preservation"
    echo "     • Stack trace generation"
    echo "     • Line number and function tracking"
    echo "     • Contextual error messages"
    echo ""
    echo "  3. Cleanup Registration"
    echo "     • Register cleanup functions"
    echo "     • Automatic execution on exit"
    echo "     • LIFO (Last In, First Out) execution order"
    
    pause_demo
    
    print_section "Example: Error Handler Output"
    cat <<'EOF'
[ERROR] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ERROR] ERROR DETECTED
[ERROR] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ERROR] Exit Code: 1
[ERROR] Line: 1234
[ERROR] Function: deploy_server
[ERROR] Command: validate_config "$CONFIG_FILE"
[ERROR] Context: Validating server configuration
[ERROR] 
[ERROR] Stack Trace:
[ERROR]   at deploy_server (line 1234)
[ERROR]   at action_server (line 6650)
[ERROR]   at main (line 8000)
[ERROR] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
    
    print_success "Error handling overview complete"
}

demo_trap_handlers() {
    print_header "Demo 2: Trap-Based Error Handling"
    
    print_info "Demonstrating trap handlers and cleanup registration"
    
    print_section "Code Example: Enabling Error Handling"
    print_code "enable_error_handling"
    echo ""
    
    print_section "Code Example: Registering Cleanup Functions"
    cat <<'EOF'
cleanup_temp_files() {
    log_info "Removing temporary files..."
    rm -rf /tmp/deployment-*
}

cleanup_network_config() {
    log_info "Reverting network configuration..."
    netplan revert
}

# Register cleanup functions (executed in LIFO order)
register_cleanup cleanup_network_config
register_cleanup cleanup_temp_files
EOF
    
    pause_demo
    
    print_section "Trap Handler Functions"
    echo ""
    echo "  • error_handler()       - Captures errors with full context"
    echo "  • cleanup_handler()     - Executes all registered cleanups"
    echo "  • interrupt_handler()   - Handles Ctrl+C gracefully"
    echo "  • register_cleanup()    - Registers cleanup functions"
    echo "  • set_error_context()   - Sets context for error messages"
    
    print_success "Trap handlers demonstration complete"
}

demo_error_context() {
    print_header "Demo 3: Error Context Preservation"
    
    print_info "Error context provides detailed information about what was happening when an error occurred"
    
    print_section "Setting Error Context"
    cat <<'EOF'
# Set context before risky operations
set_error_context "Downloading RKE2 artifacts from upstream"
download_artifacts || handle_error

set_error_context "Applying network configuration"
netplan apply || handle_error

# Clear context when operation succeeds
clear_error_context
EOF
    
    pause_demo
    
    print_section "Error Context in Action"
    echo ""
    echo "Without context:"
    print_code "  [ERROR] Command failed with exit code 1"
    echo ""
    echo "With context:"
    print_code "  [ERROR] Exit Code: 1"
    print_code "  [ERROR] Context: Downloading RKE2 artifacts from upstream"
    print_code "  [ERROR] Line: 1234"
    print_code "  [ERROR] Function: action_image"
    
    print_success "Error context demonstration complete"
}

demo_graceful_degradation() {
    print_header "Demo 4: Graceful Degradation"
    
    print_info "Graceful degradation allows non-critical operations to fail without stopping execution"
    
    print_section "Enabling Graceful Degradation"
    print_code "enable_graceful_degradation"
    echo ""
    
    print_section "Example: Try with Degradation"
    cat <<'EOF'
# Attempt optional feature installation
try_with_degradation \
    "install_optional_tools" \
    "Installing optional monitoring tools" \
    "non-critical"

# Output if fails:
# [WARN] Installing optional monitoring tools failed (non-critical, continuing)

# Critical operations still fail
try_with_degradation \
    "validate_config" \
    "Validating RKE2 configuration" \
    "critical"
EOF
    
    pause_demo
    
    print_section "Use Cases for Graceful Degradation"
    echo ""
    echo "  ✓ Optional feature installation"
    echo "  ✓ Non-essential validation checks"
    echo "  ✓ Monitoring/telemetry setup"
    echo "  ✓ Documentation generation"
    echo "  ✓ Best practice warnings"
    
    print_success "Graceful degradation demonstration complete"
}

demo_retry_logic() {
    print_header "Demo 5: Retry with Exponential Backoff"
    
    print_info "Automatic retry logic for transient failures"
    
    print_section "Retry Function Signature"
    print_code "retry_with_backoff <command> <max_attempts> <initial_delay>"
    echo ""
    
    print_section "Example: Network Operations"
    cat <<'EOF'
# Retry network download up to 5 times with 2-second initial delay
retry_with_backoff \
    "curl -fsSL https://get.rke2.io -o /downloads/install.sh" \
    5 \
    2

# Retry behavior:
# Attempt 1: fails → wait 2s
# Attempt 2: fails → wait 4s
# Attempt 3: fails → wait 8s
# Attempt 4: fails → wait 16s
# Attempt 5: fails → give up
EOF
    
    pause_demo
    
    print_section "Exponential Backoff Benefits"
    echo ""
    echo "  • Handles transient network issues"
    echo "  • Reduces load on remote servers"
    echo "  • Increases success rate for flaky operations"
    echo "  • Configurable retry attempts and delays"
    
    print_success "Retry logic demonstration complete"
}

demo_metrics_dashboard() {
    print_header "Demo 6: Comprehensive Metrics Dashboard"
    
    print_info "Phase 5 introduces an advanced metrics dashboard with session tracking and export"
    
    print_section "Initializing Metrics Dashboard"
    print_code "metrics_dashboard_init \"rke2_deployment\""
    echo ""
    
    print_section "Sample Metrics Dashboard Output"
    cat <<'EOF'
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
METRICS DASHBOARD
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
config_loaded                                 1
config_validated                              1
artifacts_staged                              1
rke2_installed                                1
errors                                        0
degraded_operations                           2
retry_failures                                0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Success Rate:                         100%
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
    
    pause_demo
    
    print_section "Dashboard Features"
    echo ""
    echo "  • Unique session ID for tracking"
    echo "  • Timestamp tracking (start/end/duration)"
    echo "  • All metrics displayed in formatted table"
    echo "  • Automatic success rate calculation"
    echo "  • New metrics: errors, degraded_operations, retry_failures"
    
    print_success "Metrics dashboard demonstration complete"
}

demo_metrics_export() {
    print_header "Demo 7: Metrics Export (JSON & CSV)"
    
    print_info "Export metrics for external analytics and reporting"
    
    print_section "Export Functions"
    echo ""
    echo "  • metrics_export_json()   - Export to JSON format"
    echo "  • metrics_export_csv()    - Export to CSV format"
    echo "  • metrics_export_all()    - Export to all formats"
    
    pause_demo
    
    print_section "JSON Export Example"
    cat <<'EOF'
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
    "config_loaded": 1,
    "config_validated": 1,
    "artifacts_staged": 1,
    "rke2_installed": 1,
    "errors": 0,
    "degraded_operations": 2
  },
  "hostname": "server01",
    "script_version": "1.2.0",
  "dry_run": false
}
EOF
    
    pause_demo
    
    print_section "CSV Export Example"
    cat <<'EOF'
session_id,operation,start_time,end_time,duration,metric,value
rke2_deployment_20251116_143022_12345,rke2_deployment,1700146222,1700146545,323,config_loaded,1
rke2_deployment_20251116_143022_12345,rke2_deployment,1700146222,1700146545,323,config_validated,1
rke2_deployment_20251116_143022_12345,rke2_deployment,1700146222,1700146545,323,artifacts_staged,1
rke2_deployment_20251116_143022_12345,rke2_deployment,1700146222,1700146545,323,rke2_installed,1
EOF
    
    pause_demo
    
    print_section "Export Usage"
    print_code "# Export to all formats"
    print_code "metrics_export_all"
    echo ""
    print_code "# Export to specific format"
    print_code "metrics_export_json /path/to/metrics.json"
    print_code "metrics_export_csv /path/to/metrics.csv"
    
    print_success "Metrics export demonstration complete"
}

demo_metrics_location() {
    print_header "Demo 8: Metrics Storage Location"
    
    print_info "Metrics are automatically stored in a structured directory"
    
    print_section "Default Export Directory"
    print_code "METRICS_EXPORT_DIR=\"/rke2/rke2-node-init/outputs/metrics\""
    echo ""
    
    print_section "Directory Structure"
    cat <<'EOF'
outputs/metrics/
├── rke2_deployment_20251116_143022_12345.json
├── rke2_deployment_20251116_143022_12345.csv
├── server_deployment_20251116_150000_12346.json
├── server_deployment_20251116_150000_12346.csv
├── agent_deployment_20251116_151500_12347.json
└── agent_deployment_20251116_151500_12347.csv
EOF
    
    pause_demo
    
    print_section "Customizing Export Location"
    print_code "export METRICS_EXPORT_DIR=\"/var/log/rke2-metrics\""
    print_code "./rke2nodeinit.sh server"
    
    print_success "Metrics location demonstration complete"
}

demo_real_world_usage() {
    print_header "Demo 9: Real-World Usage Example"
    
    print_info "Complete example integrating all Phase 5 features"
    
    print_section "Production Deployment Script"
    cat <<'EOF'
#!/bin/bash
source /rke2/rke2-node-init/bin/rke2nodeinit.sh

# Enable advanced error handling
enable_error_handling

# Enable graceful degradation for non-critical operations
enable_graceful_degradation

# Initialize metrics dashboard
metrics_dashboard_init "production_deployment"

# Register cleanup functions
cleanup_temp_artifacts() {
    log_info "Cleaning temporary artifacts..."
    rm -rf /tmp/rke2-deploy-*
}
register_cleanup cleanup_temp_artifacts

# Set error context
set_error_context "Loading deployment configuration"

# Load and validate config with retry
if ! retry_with_backoff "load_config /etc/rke2/deploy.yaml" 3 2; then
    log_error "Failed to load configuration after retries"
    exit 1
fi

metrics_increment "config_loaded"
clear_error_context

# Deploy server with graceful degradation
set_error_context "Deploying RKE2 server"
action_server

# Optional: Install monitoring (non-critical)
try_with_degradation \
    "install_monitoring_stack" \
    "Installing Prometheus monitoring" \
    "non-critical"

# Display comprehensive dashboard
metrics_dashboard_display "Production Deployment Complete"

# Export metrics for analytics
metrics_export_all

log_success "Deployment completed successfully!"
EOF
    
    pause_demo
    
    print_section "Key Benefits Demonstrated"
    echo ""
    echo "  ✓ Automatic error handling and cleanup"
    echo "  ✓ Retry logic for transient failures"
    echo "  ✓ Graceful degradation for optional features"
    echo "  ✓ Comprehensive metrics tracking"
    echo "  ✓ Automated metrics export"
    echo "  ✓ Detailed error context on failures"
    
    print_success "Real-world usage example complete"
}

demo_phase5_summary() {
    print_header "Demo 10: Phase 5 Summary & Benefits"
    
    print_info "Phase 5 enhances the rke2-node-init script with production-grade reliability"
    
    print_section "New Functions Added (15 total)"
    echo ""
    echo "Error Handling:"
    echo "  1. error_handler()                 - Global error trap handler"
    echo "  2. cleanup_handler()               - Exit cleanup handler"
    echo "  3. interrupt_handler()             - Interrupt signal handler"
    echo "  4. register_cleanup()              - Register cleanup functions"
    echo "  5. set_error_context()             - Set error context string"
    echo "  6. clear_error_context()           - Clear error context"
    echo "  7. enable_error_handling()         - Enable all error traps"
    echo ""
    echo "Graceful Degradation:"
    echo "  8. enable_graceful_degradation()   - Enable degradation mode"
    echo "  9. disable_graceful_degradation()  - Disable degradation mode"
    echo "  10. try_with_degradation()         - Try with graceful fail"
    echo "  11. retry_with_backoff()           - Retry with exp. backoff"
    echo ""
    echo "Metrics Dashboard:"
    echo "  12. metrics_dashboard_init()       - Initialize dashboard"
    echo "  13. metrics_dashboard_display()    - Display dashboard"
    echo "  14. metrics_export_json()          - Export to JSON"
    echo "  15. metrics_export_csv()           - Export to CSV"
    echo "  16. metrics_export_all()           - Export all formats"
    echo "  17. metrics_compare()              - Compare sessions"
    
    pause_demo
    
    print_section "Code Statistics"
    echo ""
    printf "  %-30s %10s\n" "Lines Added:" "~600"
    printf "  %-30s %10s\n" "New Functions:" "17"
    printf "  %-30s %10s\n" "Global Variables:" "6"
    printf "  %-30s %10s\n" "Trap Handlers:" "3"
    echo ""
    
    pause_demo
    
    print_section "Benefits for Operators"
    echo ""
    echo "  ✓ Automatic cleanup on failures or interruption"
    echo "  ✓ Detailed error messages with stack traces"
    echo "  ✓ Non-critical operations won't block deployments"
    echo "  ✓ Automatic retry of transient failures"
    echo "  ✓ Comprehensive metrics for troubleshooting"
    echo "  ✓ Metrics export for analytics and reporting"
    
    pause_demo
    
    print_section "Benefits for Developers"
    echo ""
    echo "  ✓ Consistent error handling patterns"
    echo "  ✓ Easy cleanup registration"
    echo "  ✓ Reusable retry logic"
    echo "  ✓ Graceful degradation framework"
    echo "  ✓ Structured metrics collection"
    
    pause_demo
    
    print_section "Production Readiness"
    echo ""
    echo "  ✓ Enterprise-grade error handling"
    echo "  ✓ Operational metrics and dashboards"
    echo "  ✓ Analytics-ready export formats"
    echo "  ✓ Graceful failure handling"
    echo "  ✓ Comprehensive logging and tracing"
    
    print_success "Phase 5 summary complete!"
}

# ============================================
# Interactive Menu
# ============================================

show_menu() {
    clear
    print_header "Phase 5 Feature Demonstration Menu"
    
    echo "Error Handling:"
    echo "  1) Error Handling Overview"
    echo "  2) Trap-Based Handlers"
    echo "  3) Error Context Preservation"
    echo ""
    
    echo "Graceful Degradation:"
    echo "  4) Graceful Degradation"
    echo "  5) Retry with Exponential Backoff"
    echo ""
    
    echo "Metrics Dashboard:"
    echo "  6) Metrics Dashboard"
    echo "  7) Metrics Export (JSON/CSV)"
    echo "  8) Metrics Storage Location"
    echo ""
    
    echo "Integration:"
    echo "  9) Real-World Usage Example"
    echo " 10) Phase 5 Summary & Benefits"
    echo ""
    
    echo "Other Options:"
    echo " 11) Run All Demos (Sequential)"
    echo "  0) Exit"
    echo ""
}

run_interactive() {
    while true; do
        show_menu
        read -p "Select demo number (0-11): " -r choice
        
        case $choice in
            1) demo_error_handling_overview ;;
            2) demo_trap_handlers ;;
            3) demo_error_context ;;
            4) demo_graceful_degradation ;;
            5) demo_retry_logic ;;
            6) demo_metrics_dashboard ;;
            7) demo_metrics_export ;;
            8) demo_metrics_location ;;
            9) demo_real_world_usage ;;
            10) demo_phase5_summary ;;
            11)
                demo_error_handling_overview
                demo_trap_handlers
                demo_error_context
                demo_graceful_degradation
                demo_retry_logic
                demo_metrics_dashboard
                demo_metrics_export
                demo_metrics_location
                demo_real_world_usage
                demo_phase5_summary
                print_success "All demos complete!"
                ;;
            0)
                echo ""
                print_info "Exiting demo..."
                exit 0
                ;;
            *)
                print_error "Invalid selection. Please choose 0-11."
                sleep 2
                ;;
        esac
        
        echo ""
        read -p "Press ENTER to return to menu..." -r
    done
}

# ============================================
# Main Execution
# ============================================

main() {
    setup_demo_env
    
    print_header "Phase 5 Demonstration Script"
    print_info "This script demonstrates Phase 5 advanced error handling and metrics features"
    print_info "Including: trap handlers, error context, graceful degradation, and metrics dashboard"
    echo ""
    
    # Check for auto-run mode
    if [[ "${AUTO_RUN:-false}" == "true" ]]; then
        print_info "Auto-run mode enabled - running all demos"
        demo_error_handling_overview
        demo_trap_handlers
        demo_error_context
        demo_graceful_degradation
        demo_retry_logic
        demo_metrics_dashboard
        demo_metrics_export
        demo_metrics_location
        demo_real_world_usage
        demo_phase5_summary
        print_success "All demos complete!"
    else
        run_interactive
    fi
}

# Run main function
main "$@"
