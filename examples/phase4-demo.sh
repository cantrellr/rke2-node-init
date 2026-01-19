#!/bin/bash
# Phase 4 Demo Script
# Demonstrates Phase 4 refactored deployment actions with metrics and progress reporting

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Demo configuration
readonly SCRIPT_PATH="/rke2/rke2-node-init/bin/rke2nodeinit.sh"
readonly DEMO_CONFIGS="/rke2/rke2-node-init/configs"

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
    echo -e "${YELLOW}ℹ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

pause_demo() {
    echo ""
    read -p "Press ENTER to continue..." -r
    echo ""
}

run_command() {
    local description="$1"
    local command="$2"
    
    print_section "$description"
    echo -e "${YELLOW}Command:${NC} $command"
    echo ""
    
    if [[ "${AUTO_RUN:-false}" != "true" ]]; then
        pause_demo
    fi
    
    eval "$command"
}

# ============================================
# Demo Scenarios
# ============================================

demo_help_system() {
    print_header "Demo 1: Phase 3 Help System"
    
    print_info "Demonstrating enhanced help system with action-specific guidance"
    
    run_command "Show general help" \
        "$SCRIPT_PATH --help"
    
    run_command "Show server action help" \
        "$SCRIPT_PATH --help server"
    
    run_command "Show version" \
        "$SCRIPT_PATH --version"
    
    print_success "Help system demo complete"
}

demo_server_dry_run() {
    print_header "Demo 2: Server Deployment - Dry Run Mode"
    
    print_info "Demonstrating server action with dry-run validation"
    print_info "This shows all 8 progress phases and metrics tracking"
    
    run_command "Validate server deployment (dry-run)" \
        "sudo $SCRIPT_PATH --dry-run server 2>&1 | head -100"
    
    print_success "Server dry-run demo complete"
}

demo_agent_verbose() {
    print_header "Demo 3: Agent Deployment - Verbose Mode"
    
    print_info "Demonstrating agent action with verbose logging"
    print_info "Shows detailed debug information throughout deployment"
    
    run_command "Agent deployment with verbose output (first 80 lines)" \
        "sudo $SCRIPT_PATH --dry-run --verbose agent 2>&1 | head -80"
    
    print_success "Agent verbose demo complete"
}

demo_add_server_progress() {
    print_header "Demo 4: Add-Server Deployment - Progress Reporting"
    
    print_info "Demonstrating add-server action with progress phases"
    print_info "Highlights 8-phase progress reporting pattern"
    
    run_command "Extract progress phases from add-server" \
        "sudo $SCRIPT_PATH --dry-run add-server 2>&1 | grep '^\[PROGRESS\]'"
    
    print_success "Add-server progress demo complete"
}

demo_metrics_comparison() {
    print_header "Demo 5: Metrics Comparison Across Actions"
    
    print_info "Comparing metrics tracked by different deployment actions"
    
    print_section "Server Metrics (13 total)"
    cat <<EOF
• site_defaults_loaded
• config_loaded
• config_validated
• tls_sans_configured
• artifacts_staged
• hostname_set
• custom_ca_configured
• interfaces_configured
• token_generated
• config_written
• netplan_written
• rke2_installed
• flannel_fix_installed
EOF
    
    pause_demo
    
    print_section "Agent Metrics (10 total)"
    cat <<EOF
• site_defaults_loaded
• config_loaded
• config_validated
• artifacts_staged
• hostname_set
• interfaces_configured
• token_configured
• config_written
• netplan_written
• rke2_installed
• flannel_fix_installed
EOF
    
    pause_demo
    
    print_section "Add-Server Metrics (13 total)"
    cat <<EOF
• site_defaults_loaded
• config_loaded
• config_validated
• tls_sans_configured
• artifacts_staged
• hostname_set
• custom_ca_configured
• interfaces_configured
• token_configured
• config_written
• netplan_written
• rke2_installed
• flannel_fix_installed
EOF
    
    print_success "Metrics comparison complete"
}

demo_error_handling() {
    print_header "Demo 6: Enhanced Error Handling"
    
    print_info "Demonstrating error messages with remediation guidance"
    print_info "This will intentionally trigger validation errors"
    
    print_section "Example: Missing configuration file"
    cat <<'EOF'
[ERROR] File not found: /configs/missing-config.yaml
[ERROR] Remediation: Create configuration file:
[ERROR]   cp /examples/config/server-example.yaml /configs/missing-config.yaml
[ERROR]   Edit /configs/missing-config.yaml with your settings
EOF
    
    pause_demo
    
    print_section "Example: Missing required variable"
    cat <<'EOF'
[ERROR] NODE_NAME is not set
[ERROR] Remediation: Add 'NODE_NAME: hostname' to /configs/server.yaml
[ERROR] Example:
[ERROR]   NODE_NAME: "server01"
EOF
    
    pause_demo
    
    print_section "Example: Invalid cluster token"
    cat <<'EOF'
[ERROR] CLUSTER_TOKEN is not set
[ERROR] Remediation: Get token from first server:
[ERROR]   cat /var/lib/rancher/rke2/server/node-token
[ERROR] Then add to configuration:
[ERROR]   CLUSTER_TOKEN: "K10xxxxxxxxxxxxx::server:xxxxxxxxxxxxx"
EOF
    
    print_success "Error handling demo complete"
}

demo_airgap_workflow() {
    print_header "Demo 7: Airgap Deployment Workflow"
    
    print_info "Demonstrating airgap action (leverages action_image)"
    
    print_section "Airgap workflow steps:"
    cat <<EOF
1. Runs action_image with NO_REBOOT=1
   - Stages RKE2 container images
   - Prepares airgap-ready filesystem
   
2. Syncs filesystems
   - Ensures data consistency
   
3. Powers off VM
   - Prepares for template conversion
   - Safe state for cloning

Note: In dry-run mode, poweroff is skipped
EOF
    
    pause_demo
    
    run_command "Airgap preparation (dry-run, first 50 lines)" \
        "sudo $SCRIPT_PATH --dry-run airgap 2>&1 | head -50"
    
    print_success "Airgap workflow demo complete"
}

demo_quiet_mode() {
    print_header "Demo 8: Quiet Mode Operation"
    
    print_info "Demonstrating quiet mode with minimal output"
    
    run_command "Server deployment in quiet mode" \
        "sudo $SCRIPT_PATH --dry-run --quiet server 2>&1"
    
    print_info "Note: Quiet mode shows only errors and critical messages"
    
    print_success "Quiet mode demo complete"
}

demo_metrics_summary() {
    print_header "Demo 9: Metrics Summary Display"
    
    print_info "Demonstrating metrics summary at deployment completion"
    
    run_command "Extract metrics summary from server deployment" \
        "sudo $SCRIPT_PATH --dry-run server 2>&1 | tail -30"
    
    print_info "Metrics summary provides complete deployment audit trail"
    
    print_success "Metrics summary demo complete"
}

demo_phase_progression() {
    print_header "Demo 10: 8-Phase Deployment Progression"
    
    print_info "Visualizing complete 8-phase deployment pattern"
    
    print_section "Standard 8-Phase Pattern"
    cat <<EOF
Phase 1/8: Load Configuration
  ↓
Phase 2/8: Validate Configuration
  ↓
Phase 3/8: Configure Network / Stage Artifacts
  ↓
Phase 4/8: Stage Artifacts / Configure System
  ↓
Phase 5/8: Configure System
  ↓
Phase 6/8: Configure Interfaces / Cluster Join
  ↓
Phase 7/8: Write RKE2 Configuration
  ↓
Phase 8/8: Install RKE2 Service
EOF
    
    pause_demo
    
    run_command "Show actual phase progression (server)" \
        "sudo $SCRIPT_PATH --dry-run server 2>&1 | grep -E '^\[PROGRESS\]|^✓'"
    
    print_success "Phase progression demo complete"
}

# ============================================
# Interactive Menu
# ============================================

show_menu() {
    clear
    print_header "Phase 4 Feature Demonstration Menu"
    
    echo "Phase 3 Features:"
    echo "  1) Help System (--help, --version)"
    echo ""
    
    echo "Phase 4 Deployment Actions:"
    echo "  2) Server Deployment (dry-run)"
    echo "  3) Agent Deployment (verbose)"
    echo "  4) Add-Server Deployment (progress)"
    echo "  7) Airgap Workflow"
    echo ""
    
    echo "Advanced Features:"
    echo "  5) Metrics Comparison"
    echo "  6) Error Handling & Remediation"
    echo "  8) Quiet Mode"
    echo "  9) Metrics Summary"
    echo " 10) 8-Phase Progression"
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
            1) demo_help_system ;;
            2) demo_server_dry_run ;;
            3) demo_agent_verbose ;;
            4) demo_add_server_progress ;;
            5) demo_metrics_comparison ;;
            6) demo_error_handling ;;
            7) demo_airgap_workflow ;;
            8) demo_quiet_mode ;;
            9) demo_metrics_summary ;;
            10) demo_phase_progression ;;
            11)
                demo_help_system
                demo_server_dry_run
                demo_agent_verbose
                demo_add_server_progress
                demo_metrics_comparison
                demo_error_handling
                demo_airgap_workflow
                demo_quiet_mode
                demo_metrics_summary
                demo_phase_progression
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
    # Check if script exists
    if [[ ! -f "$SCRIPT_PATH" ]]; then
        print_error "rke2nodeinit.sh not found at $SCRIPT_PATH"
        exit 1
    fi
    
    # Check if running as root for certain demos
    if [[ $EUID -ne 0 ]] && [[ "${SKIP_ROOT_CHECK:-false}" != "true" ]]; then
        print_error "Some demos require root privileges"
        print_info "Run with: sudo $0"
        print_info "Or set SKIP_ROOT_CHECK=true to skip root-only demos"
        exit 1
    fi
    
    print_header "Phase 4 Demonstration Script"
    print_info "This script demonstrates Phase 4 refactored deployment actions"
    print_info "Including: metrics tracking, progress reporting, and error handling"
    echo ""
    
    # Check for auto-run mode
    if [[ "${AUTO_RUN:-false}" == "true" ]]; then
        print_info "Auto-run mode enabled - running all demos"
        demo_help_system
        demo_server_dry_run
        demo_agent_verbose
        demo_add_server_progress
        demo_metrics_comparison
        demo_error_handling
        demo_airgap_workflow
        demo_quiet_mode
        demo_metrics_summary
        demo_phase_progression
        print_success "All demos complete!"
    else
        run_interactive
    fi
}

# Run main function
main "$@"
