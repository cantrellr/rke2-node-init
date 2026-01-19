## 📝 Description

<!-- Provide a clear description of your changes -->

## 🎯 Related Issue

<!-- Link to the issue this PR addresses -->

Fixes #
Closes #
Relates to #

## 🔄 Type of Change

<!-- Select all that apply -->

- [ ] 🐛 Bug fix (non-breaking change that fixes an issue)
- [ ] ✨ New feature (non-breaking change that adds functionality)
- [ ] 💥 Breaking change (fix or feature that changes existing functionality)
- [ ] 📚 Documentation update
- [ ] 🧹 Code cleanup/refactoring
- [ ] 🔒 Security fix
- [ ] ⚡ Performance improvement
- [ ] 🧪 Test addition/improvement

## 🧪 Testing Performed

<!-- Describe how you tested these changes -->

**Test Environment:**
- OS/Distribution: <!-- e.g., Ubuntu 22.04 -->
- RKE2 Version: <!-- e.g., v1.28.5+rke2r1 -->
- Test Method: <!-- e.g., manual, automated, ShellSpec -->

**Test Scenarios:**
- [ ] Fresh RKE2 installation
- [ ] Upgrade from previous version
- [ ] Multiple node types (control/worker)
- [ ] Various network configurations
- [ ] Error handling

**Test Results:**
```bash
# Paste test output or screenshots
```

## 📋 Checklist

**Code Quality:**
- [ ] My code follows the project's style guidelines
- [ ] I've run ShellCheck and fixed all warnings
- [ ] I've added/updated comments for complex logic
- [ ] I've removed debugging/console.log statements

**Testing:**
- [ ] I've tested my changes locally
- [ ] I've added tests that prove my fix/feature works
- [ ] Existing tests pass with my changes
- [ ] I've tested edge cases and error conditions

**Documentation:**
- [ ] I've updated README.md (if applicable)
- [ ] I've updated YAML schema documentation (if applicable)
- [ ] I've added/updated function documentation
- [ ] I've updated CHANGELOG.md

**Security:**
- [ ] No hardcoded credentials added
- [ ] No sensitive data in logs
- [ ] Input validation added where needed
- [ ] No new ShellCheck security warnings

**Breaking Changes:**
- [ ] This PR introduces breaking changes
- [ ] I've documented the migration path
- [ ] I've updated the version number appropriately

## 🔍 Code Review Focus Areas

<!-- Point reviewers to specific areas that need extra attention -->

**Please review carefully:**
1. <!-- e.g., Line 345: New YAML parsing logic -->
2. <!-- e.g., Function `configure_network()`: Complex regex -->
3. <!-- e.g., Error handling in certificate validation -->

## 📸 Screenshots/Logs

<!-- If applicable, add screenshots or log output -->

**Before:**
```
# Original behavior
```

**After:**
```
# New behavior
```

## 🚀 Deployment Notes

<!-- Any special considerations for deploying this change -->

**Migration Required:**
- [ ] Yes - see instructions below
- [ ] No

**Migration Instructions:**
```bash
# Steps to migrate from old version
```

**Rollback Plan:**
```bash
# How to revert if issues occur
```

## 💭 Additional Context

<!-- Any other information reviewers should know -->

## 🔗 References

<!-- Links to documentation, RFCs, related PRs, etc. -->

- RKE2 Documentation: <!-- link -->
- Related PR: <!-- link -->
- Design Document: <!-- link -->

---

**Reviewer Notes:**

<!-- For maintainers -->

**Merge Strategy:**
- [ ] Squash and merge
- [ ] Create merge commit
- [ ] Rebase and merge

**Post-Merge Actions:**
- [ ] Update CHANGELOG.md
- [ ] Create release notes
- [ ] Update documentation site
- [ ] Notify users of breaking changes
