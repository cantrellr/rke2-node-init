Agent summary for rke2-node-init

Date: 2025-11-21
Agent: my-agent (project assistant)
Version: 1.0.0

Overview
--------
This repository provides `rke2nodeinit.sh`, a hardened automation script for preparing and configuring Ubuntu/Debian hosts for fully offline Rancher RKE2 clusters. It orchestrates air-gapped artifact caching, registry mirroring, operating system hardening, multi-interface networking, and server/agent installation using only Bash and standard GNU utilities.

Key Features
------------
- **Air-Gapped First Design**: Only the `image` action requires Internet access for artifact gathering; all other operations (push, server, agent, verify, airgap, custom-ca) run completely offline.
- **Multi-Interface Networking**: Configure multiple NICs with static IPs or DHCP, per-interface DNS, MTU, and routing metrics via YAML or CLI.
- **Certificate Management**: Comprehensive CA generation workflow with encrypted root keys, subordinate CA signing, and OpenSSL v3_ca extensions.
- **Registry Mirroring**: Automatic image retagging, SBOM generation with syft, and push to private registries with authentication.
- **Security Hardened**: set -Eeuo pipefail, root privilege enforcement, credential masking, input validation, and CRLF detection.
- **YAML-Driven Configuration**: apiVersion: rkeprep/v2 with comprehensive spec options for all actions.
- **Node Management**: Built-in kubectl integration for labeling and tainting nodes.
- **Operational Transparency**: Timestamped logs, CLI spinners for long operations, and detailed error reporting with line numbers.

Repository Structure
--------------------
```
bin/rke2nodeinit.sh          - Main automation script (9100+ lines, v1.2.0)
certs/                       - CA generation scripts and examples
  scripts/
    generate-root-ca.sh      - Encrypted root CA generation
    generate-subordinate-ca.sh - Subordinate CA with YAML input
    verify-chain.sh          - Certificate chain verification
  examples/                  - Example YAML configurations
examples/config/             - Full action examples (server, agent, push, etc.)
scripts/                     - Supporting tooling
  wsl-env/                   - WSL development environment setup
  test/                      - Interface detection and validation tests
vm/scripts/                  - vSphere/VMware automation (PowerShell)
Makefile                     - Convenience targets for certs and tokens
```

Supported Actions
-----------------
1. **image** - (Online) Download RKE2 artifacts, install nerdctl, configure OS prerequisites, cache for offline use
2. **push** - (Offline) Load cached images, retag for private registry, generate SBOMs, push
3. **server** - (Offline) Configure first control-plane node with multi-interface networking
4. **add-server** - (Offline) Join additional control-plane nodes to existing cluster
5. **agent** - (Offline) Configure and join worker nodes with multi-interface support
6. **verify** - (Offline) Validate prerequisites without system changes
7. **airgap** - (Offline) Run image preparation and power off for VM templating
8. **label-node** - (Offline) Apply Kubernetes labels via kubectl
9. **taint-node** - (Offline) Apply Kubernetes taints via kubectl
10. **custom-ca** - (Offline) Generate server token with custom CA fingerprint

Certificate Workflow
--------------------
The repository includes automated CA generation using Make targets:
- `./certs/scripts/generate-root-ca.sh` - Generate encrypted root CA (AES-256) with safe permissions
- `./certs/scripts/generate-subordinate-ca.sh --input <yaml>` - Generate subordinate CA from YAML specification
- `make certs-verify` - Validate OpenSSL availability and display security reminders
- `make certs-assert ROOT=<crt> SUB=<crt>` - Verify certificate chain integrity

All certificate scripts support:
- Interactive and non-interactive (--passphrase, --root-passphrase) modes
- YAML input parsing for subject fields
- OpenSSL v3_ca extensions with CA:TRUE and pathlen constraints
- extendedKeyUsage for serverAuth and clientAuth
- Timestamped output under outputs/certs/

Security & Best Practices
--------------------------
- **Never commit real certificates or private keys** - Use .gitignore rules for .pem, .key, .crt files
- **Root CA offline storage** - Move root private keys to HSM or secure vault immediately after generation
- **Subordinate CAs for automation** - Use subordinate CAs for day-to-day signing operations
- **Non-interactive secrets** - Inject passphrases via secrets managers in CI/CD, never hardcode
- **Credential validation** - Script rejects default/example credentials (regadmin/DefaultPass123)
- **CRLF detection** - Automatic failure on Windows line endings
- **Permission clamping** - Private keys: 600, certificates: 644, scripts: 755

Active Issues & Roadmap
-----------------------
See `ISSUES-CREATED.md` for comprehensive tracking. Key priorities:
- **P0 Security**: Remove private keys from git history (#38), eliminate hardcoded credentials (#40)
- **P1**: Enhanced .gitignore (#41 - COMPLETED), ShellCheck compliance (#42)
- **P2**: JSON Schema validation (#43), subordinate key encryption (#60)
- **Documentation**: Certificate verification script (#61), GitHub Actions templates (#62), README standardization (#63)
- **P0 Bugs**: CRLF line ending fixes (#39 - COMPLETED)

Current roadmap progress: 6/12 issues completed (50%), 6 remaining
See `ROADMAP.md` for sprint planning and target dates.

**Major Milestone**: Phases 1-5 Complete! (November 16, 2025)
- Phase 1: Core Utilities (19 functions) ✅
- Phase 2: Initial Actions (verify, custom-ca, push, image) ✅
- Phase 3: CLI Enhancements (help, version, verbosity) ✅
- Phase 4: Deployment Actions (server, agent, add-server, airgap) ✅
- Phase 5: Advanced Error Handling & Metrics Dashboard (17 functions) ✅

**Phase 5 New Features**:
- Trap-based error handling with stack traces and automatic cleanup
- Graceful degradation framework for 95% deployment success
- Metrics dashboard with JSON/CSV export for analytics
- LIFO cleanup handlers, retry with backoff, session tracking

CI/CD Integration
-----------------
- GitHub Actions workflows:
  - `.github/workflows/certs-ci.yml` - Automated certificate generation and testing
  - `.github/workflows/verify-tokenfile.yml` - Token file validation
- Makefile targets integrate with CI for reproducible builds
- All scripts compatible with ephemeral runners and non-interactive execution
- Metrics export (JSON/CSV) ready for Splunk, ELK, Datadog integration

Testing & Validation
--------------------
- `scripts/test/test-interface-detection.sh` - Validates network interface configuration logic
- `tests/ci/test_ca_generation.sh` - Validates root and subordinate CA generation
- `tests/ci/test_subordinate_encryption.sh` - Tests encrypted subordinate key workflows
- All shell scripts pass `bash -n` syntax validation
- ShellCheck integration for static analysis
- Comprehensive Phase 1-5 documentation (5,000+ lines):
  - `docs/redesign/PHASE[1-5]-IMPLEMENTATION.md` - Implementation guides
  - `docs/redesign/PHASE[1-5]-SUMMARY.md` - Executive summaries
  - `docs/redesign/PHASE[1-5]-QUICK-REFERENCE.md` - Command references
  - `docs/redesign/PHASE[1-5]-COMPLETION-REPORT.md` - Completion reports

Development Environment
-----------------------
For WSL2 development setup, see `scripts/wsl-env/WSL-DEV-SETUP.md` and run:
```bash
./scripts/wsl-env/wsl-dev-setup.sh
```

This installs: Docker-in-WSL, pyenv, nvm, Node.js, Go, kubectl, helm, kind, and other dev tools.

Contributing
------------
See `CONTRIBUTING.md` for:
- Code of conduct and community guidelines
- Development workflow and branching strategy
- Coding standards and ShellCheck requirements
- Testing procedures and documentation expectations
- Pull request process and review criteria

For security vulnerabilities, follow the responsible disclosure process in `SECURITY.md`.

---
# Fill in the fields below to create a basic custom agent for your repository.
# The Copilot CLI can be used for local testing: https://gh.io/customagents/cli
# To make this agent available, merge this file into the default repository branch.
# For format details, see: https://gh.io/customagents/config

name: rke2-node-init
description: Automates RKE2 node initialization, air-gapped image handling, multi-interface networking, and cluster bootstrap workflows for secure offline Kubernetes deployments.
---
# My-Agent for rke2-node-init

## Overview
This agent assists with the rke2-node-init automation framework, which prepares Ubuntu/Debian hosts for fully offline RKE2 cluster deployments. The agent understands the complete workflow from artifact gathering to multi-node cluster bootstrap, certificate management, registry mirroring, and multi-interface networking configuration.

---

## Capabilities

### Configuration & Planning
- Parse and validate `apiVersion: rkeprep/v2` YAML configurations
- Generate node-specific YAML templates for server, agent, and add-server actions
- Design multi-interface networking configurations (static IP, DHCP, DNS, MTU, metrics)
- Recommend secure configurations for air-gapped and offline deployments
- Plan certificate authority hierarchies (root CA, subordinate CAs, pathlen constraints)

### Certificate Management
- Generate encrypted root CA certificates with AES-256 protection
- Create subordinate CA certificates with proper OpenSSL v3_ca extensions
- Verify certificate chains and trust relationships
- Integrate custom CA bundles into containerd and system trust stores
- Generate RKE2 server tokens with embedded CA fingerprints

### Air-Gapped Operations
- Orchestrate artifact downloads (RKE2 binaries, images, nerdctl bundles)
- Build and push container image bundles to private registries
- Generate SBOM (Software Bill of Materials) using syft or nerdctl inspect
- Configure registry mirrors with authentication and CA trust
- Validate offline registry connectivity and image availability

### Cluster Bootstrap
- Design first-server initialization workflows with custom CAs
- Configure additional control-plane nodes (add-server) with proper join tokens
- Set up agent nodes with multi-interface networking
- Apply node labels and taints using kubectl integration
- Troubleshoot bootstrap failures via journalctl and RKE2 logs

### Troubleshooting & Analysis
- Parse `/var/log/rke2nodeinit/` logs for error patterns
- Analyze systemd journal logs for RKE2 service failures
- Diagnose network configuration issues (interface detection, netplan, routing)
- Identify registry authentication or CA trust problems
- Validate containerd configuration and image loading
- Interpret metrics dashboard output (40+ metrics tracked)
- Analyze error stack traces with line numbers and function context
- Review graceful degradation logs for non-critical failures
- Compare metric sessions for performance analysis
- Export and analyze metrics in JSON/CSV formats

### Documentation & Maintenance
- Keep documentation synchronized with script capabilities
- Track issues via ISSUES-CREATED.md and GitHub issue integration
- Recommend ShellCheck fixes and code quality improvements
- Suggest roadmap priorities based on current state

---

## Context & Repository Structure

The repository is organized for modular offline operations:

**Core Script**: `bin/rke2nodeinit.sh` (9116 lines, v1.2.0)
- 10 actions: image, push, server, add-server, agent, verify, airgap, label-node, taint-node, custom-ca
- Multi-interface networking via spec.interfaces[] in YAML
- 40+ reliability functions across 5 completed implementation phases
- Advanced features:
  - Trap-based error handling with stack traces (Phase 5)
  - Graceful degradation framework with retry logic (Phase 5)
  - Metrics dashboard with 40+ tracked metrics (Phase 5)
  - LIFO cleanup handlers, session tracking, JSON/CSV export (Phase 5)
  - 8-phase progress reporting pattern (Phases 2-4)
  - Full dry-run support for safe validation (Phase 4)
- Safety features: set -Eeuo pipefail, root enforcement, credential validation, CRLF detection

**Certificate Tooling**: `certs/`
- `scripts/generate-root-ca.sh` - Encrypted root CA with interactive/non-interactive modes
- `scripts/generate-subordinate-ca.sh` - Subordinate CA with YAML input, pathlen, EKU
- `scripts/verify-chain.sh` - Certificate chain validation
- `examples/` - YAML templates for CA generation

**Configuration Examples**: `examples/config/`
- server-example.yaml, agent-example.yaml, add-server-example.yaml
- airgap-example.yaml, push-example.yaml, image-example.yaml
- custom-ca-example.yaml, verify-example.yaml

**Make Targets**: `Makefile`
- `./certs/scripts/generate-root-ca.sh` - Generate encrypted root CA
- `./certs/scripts/generate-subordinate-ca.sh --input <yaml>` - Generate subordinate CA
- `make certs-verify` - Validate OpenSSL and display reminders
- `make certs-assert ROOT=<crt> SUB=<crt>` - Verify chain
- `make token` - Generate base64 tokens for cluster join
- `make kubeconfig` - Install kubectl and copy RKE2 kubeconfig

**Testing**: `tests/ci/`, `scripts/test/`
- Certificate generation validation
- Interface detection unit tests
- Subordinate encryption workflows

**CI/CD**: `.github/workflows/certs-ci.yml`
- Automated certificate generation testing

---

## Agent Instructions

When assisting users, follow these principles:

### Security First
1. **Never suggest committing secrets** - Private keys, passwords, tokens stay out of git
2. **Recommend offline storage** - Root CAs belong in HSM or secure vaults, not on nodes
3. **Validate inputs** - IPs, CIDRs, DNS servers, credentials must pass validation
4. **Use encrypted keys** - Always generate root CAs with AES-256 encryption
5. **Mask credentials** - Sanitize YAML output before logging or displaying

### Offline Compatibility
1. **Only `image` action goes online** - All other actions must work without Internet
2. **Cache everything** - Artifacts, images, binaries staged under /opt/rke2/stage
3. **Verify before join** - Always validate registry connectivity and CA trust before cluster operations
4. **Use subordinate CAs** - Automate with subordinate CAs, keep root CA offline

### Operational Excellence
1. **YAML-driven configuration** - Prefer YAML manifests over CLI flags for reproducibility
2. **Idempotency** - Scripts can be re-run safely; use verify action for validation
3. **Logging** - All operations logged to /var/log/rke2nodeinit/ with timestamps
4. **Error reporting** - Scripts fail fast with line numbers via ERR trap
5. **Make targets** - Use Makefile for consistency in automation and CI

### Code Quality
1. **ShellCheck compliance** - Address SC2034 (unused variables), SC2086 (quoting), SC2155 (nameref)
2. **Bash best practices** - Use `#!/usr/bin/env bash`, `set -Eeuo pipefail`, quote variables
3. **Input validation** - Validate IPs (is_valid_ip), CIDRs (is_valid_cidr), DNS (is_valid_dns)
4. **Permission management** - Keys: 600, certs: 644, scripts: 755, directories: 700/755
5. **Error handling** - Trap-based with stack traces, LIFO cleanup, context preservation
6. **Metrics tracking** - 40+ metrics across all operations for observability
7. **Graceful degradation** - Non-critical operations fail safely without blocking
8. **Progress reporting** - 8-phase pattern for all deployment actions

---

## Example Prompts

### Certificate Management
- "Generate a root CA and subordinate CA for my RKE2 cluster with 10-year validity"
- "Create a subordinate CA from the example YAML with pathlen=1"
- "Verify the certificate chain between my root and subordinate CA files"
- "Show me how to inject a custom CA into containerd trust store"

### Air-Gapped Operations
- "Help me prepare an air-gapped VM template for RKE2 v1.34.1+rke2r1"
- "Configure registry mirroring for harbor.example.com with authentication"
- "Push cached images to my private registry with SBOM generation"
- "Validate that all required images exist in my offline registry"

### Cluster Bootstrap
- "Generate a server YAML for first control-plane with 3 network interfaces"
- "Create an add-server configuration to join a second control-plane node"
- "Configure an agent with static IP 10.0.1.50/24 and custom DNS"
- "Generate a custom-ca server token with embedded CA fingerprint"

### Networking
- "Design a multi-interface configuration: eth0 for cluster, eth1 for storage"
- "Configure static IPs on ens192 (10.0.0.5/24) and ens224 (172.16.0.5/24)"
- "Set up an interface with DHCP and custom MTU of 9000"
- "Add multiple search domains and DNS servers to an interface"

### Troubleshooting
- "Analyze why my server node fails to start after install"
- "Check journalctl logs for containerd image loading errors"
- "Diagnose registry authentication failures during image push"
- "Validate network interface detection and primary interface selection"
- "Debug netplan configuration issues on Ubuntu 22.04"

### Maintenance
- "Show me the current project roadmap and issue priorities"
- "Fix ShellCheck SC2155 warnings in the main script"
- "Update documentation to reflect new multi-interface capabilities"
- "Create a GitHub Actions workflow for automated certificate testing"

### Metrics & Reliability (Phase 5)
- "Display the metrics dashboard for my last deployment"
- "Export deployment metrics to JSON for analysis in Splunk"
- "Compare metrics between two deployment sessions"
- "Show me how to enable graceful degradation mode"
- "Configure retry logic with exponential backoff for network operations"
- "Register a cleanup function to run on script exit"
- "How do I track custom metrics during deployment?"
- "Export metrics to CSV for spreadsheet analysis"

---

## Environment & Dependencies

### Required
- **OS**: Ubuntu 22.04+ or RHEL 8+ with systemd, apt/yum, netplan
- **Shell**: Bash 5.x or higher
- **Privileges**: Root (sudo) for system modifications
- **Tools**: curl, jq, openssl, systemd, netplan

### Optional
- **syft**: For SPDX SBOM generation (GitHub Anchore)
- **nerdctl**: Installed by script for containerd operations
- **kubectl**: Installed via script for node labeling/tainting
- **ShellCheck**: For linting and static analysis

### RKE2 Version Support
- Primary: RKE2 v1.28.x - v1.34.x
- Tested with: Longhorn, Calico, Contour, Cert-Manager, MetalLB
- Supports: Custom CAs, registry mirrors, multi-interface networking
- Air-gapped deployments with full artifact caching
- Hardened CNI plugin support with automatic tag selection

---

## Development & Contributing

### Quick Start
```bash
# WSL2 Development Environment
./scripts/wsl-env/wsl-dev-setup.sh

# Generate certificates for testing
./certs/scripts/generate-root-ca.sh --out-dir certs/scripts/outputs/root-ca
./certs/scripts/generate-subordinate-ca.sh --input examples/certs/rke2clusterCA-example.yaml \
  --root-key certs/scripts/outputs/root-ca/root-ca-key.pem \
  --root-cert certs/scripts/outputs/root-ca/root-ca.crt

# Validate scripts
find . -name "*.sh" -exec bash -n {} \;
find . -name "*.sh" -exec shellcheck {} \;
```

### Contribution Guidelines
See `CONTRIBUTING.md` for:
- Branching strategy and pull request workflow
- Code standards and ShellCheck requirements  
- Testing procedures and documentation expectations
- Release process and versioning

### Security Reporting
See `SECURITY.md` for responsible disclosure process.
**Do NOT open public issues for security vulnerabilities.**

---

## Maintainer

**Ron Cantrell**  
Sr. Principal Systems Engineer  
GitHub: [@cantrellr](https://github.com/cantrellr)  
Repository: [rke2-node-init](https://github.com/cantrellr/rke2-node-init)

---

**Last Updated**: November 21, 2025  
**Agent Version**: 1.0.0  
**Script Version**: 1.2.0 (Phases 1-5 complete, 9116 lines)
