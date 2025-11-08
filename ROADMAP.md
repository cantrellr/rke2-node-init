# 🗺️ RKE2 Node Init - Project Roadmap

**Last Updated:** November 8, 2025  
**Status:** Active Development  
**GitHub Issues:** [View All Issues](https://github.com/cantrellr/rke2-node-init/issues)

---

## 📊 Progress Overview

- **Total Issues:** 12
- **Completed:** 2/12 (17%)
- **In Progress:** 0/12
- **Not Started:** 10/12

---

## 🔴 Sprint 1: Immediate (This Week) - CRITICAL

**Target:** Complete by November 15, 2025  
**Progress:** 2/4 completed (50%)

### ✅ Issue #39: Fix CRLF Line Endings
- **Status:** ✅ **COMPLETED**
- **Priority:** P0 - Critical Bug
- **File:** `test-interface-detection.sh`
- **Completed:** November 8, 2025
- **Solution:** Converted CRLF to LF using PowerShell

### ✅ Issue #41: Create .gitignore
- **Status:** ✅ **COMPLETED**
- **Priority:** P1 - Security
- **File:** `.gitignore`
- **Completed:** November 8, 2025
- **Solution:** Enhanced existing .gitignore with comprehensive security rules

### ⏳ Issue #38: Remove Private Key from Repository
- **Status:** ⏳ **TODO** - BLOCKING
- **Priority:** P0 - Critical Security
- **Effort:** 2-4 hours
- **Assignee:** Security Team
- **Labels:** `P0`, `security`
- **Link:** [#38](https://github.com/cantrellr/rke2-node-init/issues/38)
- **Action Required:**
  1. Verify if `certs/rke2ca-cert-key.pem` is production key
  2. If yes: REVOKE certificate immediately
  3. Remove from repository and git history
  4. Update documentation with key generation guide

### ⏳ Issue #40: Remove Hardcoded Credentials
- **Status:** ⏳ **TODO**
- **Priority:** P0 - Security
- **Effort:** 1-2 hours
- **Labels:** `P0`, `security`
- **Link:** [#40](https://github.com/cantrellr/rke2-node-init/issues/40)
- **Files:** `rke2nodeinit.sh` (lines 136-138)
- **Action:** Remove default credentials, add validation

---

## 🟡 Sprint 2: Short Term (This Month)

**Target:** Complete by December 8, 2025  
**Progress:** 0/4 started

### ⏳ Issue #42: Fix ShellCheck Warnings
- **Status:** ⏳ **TODO**
- **Priority:** P2 - Quality
- **Effort:** 1-2 hours
- **Labels:** `P2`, `quality`
- **Link:** [#42](https://github.com/cantrellr/rke2-node-init/issues/42)
- **Files:** Lines 1193, 1276, 1286
- **Action:** Separate declare and assign statements

### ⏳ Issue #43: Add JSON Schema Validation
- **Status:** ⏳ **TODO**
- **Priority:** P2 - Feature
- **Effort:** 4-6 hours
- **Labels:** `P2`, `feature`
- **Link:** [#43](https://github.com/cantrellr/rke2-node-init/issues/43)
- **Deliverables:**
  - JSON Schema for `apiVersion: rkeprep/v1`
  - Validation function
  - IDE autocomplete support

### ⏳ Issue #44: Implement Testing Framework
- **Status:** ⏳ **TODO**
- **Priority:** P2 - Testing
- **Effort:** 1-2 weeks
- **Labels:** `P2`, `testing`
- **Link:** [#44](https://github.com/cantrellr/rke2-node-init/issues/44)
- **Framework:** ShellSpec (recommended)
- **Coverage:** Input validation, YAML parsing, network config

### ⏳ Issue #45: Add CHANGELOG and CONTRIBUTING
- **Status:** ⏳ **TODO**
- **Priority:** P2 - Documentation
- **Effort:** 2-3 hours
- **Labels:** `P2`, `documentation`
- **Link:** [#45](https://github.com/cantrellr/rke2-node-init/issues/45)
- **Files to Create:**
  - `CHANGELOG.md`
  - `CONTRIBUTING.md`
  - `CODE_OF_CONDUCT.md`

---

## 🟢 Sprint 3: Long Term (This Quarter)

**Target:** Complete by February 8, 2026  
**Progress:** 0/4 started

### ⏳ Issue #46: Build CI/CD Pipeline
- **Status:** ⏳ **TODO**
- **Priority:** P3 - Infrastructure
- **Effort:** 1 week
- **Labels:** `P3`, `infrastructure`
- **Link:** [#46](https://github.com/cantrellr/rke2-node-init/issues/46)
- **Workflows:**
  - `.github/workflows/test.yml` - Testing
  - `.github/workflows/security.yml` - Security scanning
  - `.github/workflows/release.yml` - Release automation

### ⏳ Issue #47: Add Health Check & Backup Actions
- **Status:** ⏳ **TODO**
- **Priority:** P3 - Feature
- **Effort:** 1-2 weeks
- **Labels:** `P3`, `feature`
- **Link:** [#47](https://github.com/cantrellr/rke2-node-init/issues/47)
- **New Actions:**
  - `healthcheck` - Monitor system status
  - `backup` - Backup configurations
  - `restore` - Restore from backup

### ⏳ Issue #48: Implement Audit Logging
- **Status:** ⏳ **TODO**
- **Priority:** P3 - Feature
- **Effort:** 3-5 days
- **Labels:** `P3`, `feature`
- **Link:** [#48](https://github.com/cantrellr/rke2-node-init/issues/48)
- **Compliance:** SOC 2, HIPAA audit trails

### ⏳ Issue #49: Add Certificate Expiration Monitoring
- **Status:** ⏳ **TODO**
- **Priority:** P3 - Feature
- **Effort:** 2-3 days
- **Labels:** `P3`, `feature`
- **Link:** [#49](https://github.com/cantrellr/rke2-node-init/issues/49)
- **Monitoring:** CA certs, RKE2 certs, registry certs

---

## 📈 Metrics & KPIs

### Code Quality
- **ShellCheck Warnings:** 3 (down from 3)
- **Documentation Coverage:** 95% (excellent)
- **Test Coverage:** 0% (target: 80%)

### Security Posture
- **Critical Vulnerabilities:** 2 open (Issues #38, #40)
- **High Priority:** 0
- **Medium Priority:** 0
- **Secrets in Code:** 2 instances (to be removed)

### Project Health
- **Issue Velocity:** 2 closed/week (current)
- **Mean Time to Resolution:** TBD
- **Active Contributors:** 1

---

## 🎯 Milestones

### Milestone 1: Security Hardening (November 2025)
- ✅ Create .gitignore
- ⏳ Remove private keys
- ⏳ Remove hardcoded credentials
- ⏳ Fix CRLF issues

**Progress:** 2/4 (50%)

### Milestone 2: Quality & Testing (December 2025)
- ⏳ Fix ShellCheck warnings
- ⏳ Add JSON Schema validation
- ⏳ Implement testing framework
- ⏳ Add documentation

**Progress:** 0/4 (0%)

### Milestone 3: Automation & Monitoring (Q1 2026)
- ⏳ Build CI/CD pipeline
- ⏳ Add operational features
- ⏳ Implement audit logging
- ⏳ Add monitoring

**Progress:** 0/4 (0%)

---

## 🔄 Recent Updates

### November 8, 2025
- ✅ Created 12 GitHub issues from code review
- ✅ Fixed CRLF line endings in test-interface-detection.sh (Issue #39)
- ✅ Enhanced .gitignore with security rules (Issue #41)
- ✅ Created GitHub labels (P0-P3, security, bug, feature, etc.)
- ✅ Applied labels to all issues
- ✅ Created project tracking documentation

---

## 📝 Notes

### Dependencies
- Issue #44 (Testing) should be completed before #46 (CI/CD)
- Issue #42 (ShellCheck) can be done in parallel
- Security issues (#38, #40) are blocking for production use

### Risks
- Private key (#38) may require certificate rotation across entire infrastructure
- Testing framework (#44) requires significant time investment
- CI/CD (#46) requires GitHub Actions expertise

### Decisions Needed
- [ ] Choose testing framework (ShellSpec vs BATS)
- [ ] Define code coverage targets
- [ ] Establish release versioning strategy

---

## 🚀 Quick Commands

```bash
# View all issues
gh issue list

# View P0 issues only
gh issue list --label P0

# View current sprint
gh issue list --label P0,P1

# View your assigned issues
gh issue list --assignee @me

# Close an issue
gh issue close 39 --comment "Fixed CRLF line endings"
```

---

**Next Review:** November 15, 2025  
**Team:** RKE2 DevOps  
**Repository:** [cantrellr/rke2-node-init](https://github.com/cantrellr/rke2-node-init)
