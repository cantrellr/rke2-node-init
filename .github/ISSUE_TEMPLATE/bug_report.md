---
name: Bug Report
about: Report a bug or unexpected behavior in rke2nodeinit.sh
title: '[BUG] '
labels: bug
assignees: ''
---

## 🐛 Bug Description

<!-- A clear and concise description of what the bug is -->

## 📋 Environment

- **OS/Distribution:** <!-- e.g., Ubuntu 22.04, RHEL 9 -->
- **RKE2 Version:** <!-- e.g., v1.28.5+rke2r1 -->
- **Script Version/Commit:** <!-- e.g., main branch, commit abc123 -->
- **VMware vSphere Version:** <!-- if applicable -->

## 🔄 Steps to Reproduce

1. Run command: `...`
2. With config file: `...`
3. See error at: `...`

## ❌ Expected Behavior

<!-- What you expected to happen -->

## ✅ Actual Behavior

<!-- What actually happened -->

## 📝 Configuration File (YAML)

```yaml
# Paste your sanitized YAML config here (remove sensitive data)
apiVersion: rkeprep/v1
kind: NodeConfig
# ...
```

## 📊 Log Output

```
# Paste relevant log output here
# Include errors and context around the failure
```

## 💡 Additional Context

<!-- Any other information about the problem -->
<!-- Screenshots, network diagrams, etc. -->

## 🔍 Possible Solution

<!-- Optional: If you have ideas on how to fix this -->

---

**Checklist:**
- [ ] I've checked existing issues for duplicates
- [ ] I've sanitized my config file (no IPs/passwords)
- [ ] I've included relevant log output
- [ ] I've tested with the latest version
