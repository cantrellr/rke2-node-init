**STIG Manual Checklist**

Purpose: A concise, reusable checklist template for manual STIG items requiring human application or review. Use one checklist entry per STIG control. Record verification steps, evidence, reviewer, and date.

How to use:
- Complete one entry per control.
- Mark the checkboxes when steps are done.
- Attach collected evidence (logs, screenshots, command output) to the ticket or compliance record.

---

**Checklist Template (copy per control)**

- **Control ID / Name:** 
- **Description:** Brief description of the control and required state.
- **System/Scope:** e.g., OS, RKE2 node, Kubernetes API, CNI, host network
- **Remediation Steps (what to do):**
  - [ ] Step 1: (exact command or config edit)
  - [ ] Step 2: (exact command or config edit)
  - [ ] Step 3: (notes)
- **Verification Steps (how a reviewer confirms):**
  - [ ] Verify config: command/example — e.g., `sshd -T | grep permitrootlogin` or `kubectl get pods -A`
  - [ ] Check logs: command — e.g., `journalctl -u rke2-server --since "1 hour ago"`
  - [ ] Inspect files: path(s) — e.g., `/etc/ssh/sshd_config`, `/etc/audit/rules.d/audit.rules`
- **Expected Result:** Short factual statement of expected outcome (pass/fail criteria).
- **Evidence to Collect:** List of files, command outputs, screenshots to attach.
  - Example: `/etc/ssh/sshd_config` (snapshot), `ssh -vvv` test output, screenshot of hardened UI
- **Reviewer:** Name / initials
- **Review Date:** YYYY-MM-DD
- **Notes:** Any deviations, mitigations, or exceptions

---

**Common Manual STIG Items & Suggested Remediation/Verification**

1) **SSH Hardening**
   - Description: Ensure SSH is configured per STIG (no root login, no password auth, protocol, ciphers).
   - Remediation steps:
     - [ ] Set `PermitRootLogin no` in `/etc/ssh/sshd_config` and restart SSH (`systemctl restart sshd`).
     - [ ] Set `PasswordAuthentication no` and reload SSH.
   - Verification:
     - [ ] `sshd -T | grep -E "permitrootlogin|passwordauthentication"`
   - Evidence: `sshd -T` output, `/etc/ssh/sshd_config` snapshot.

2) **Local Accounts & Passwords**
   - Description: Remove/lock unused accounts; verify password policies and shadow file settings.
   - Remediation:
     - [ ] Lock or remove accounts: `usermod -L <user>` or `passwd -l <user>`.
     - [ ] Ensure `PASS_MAX_DAYS`/`PASS_MIN_LEN` in `/etc/login.defs` or use PAM.
   - Verification:
     - [ ] `awk -F: '$2=="!"||$2=="*"{print $1" locked"}' /etc/shadow` and `chage -l <user>`.
   - Evidence: `/etc/shadow` excerpt, `chage` outputs.

3) **Host Patching & Packages**
   - Description: Apply latest OS security patches and remove unused packages.
   - Remediation:
     - [ ] Run package updates: `apt update && apt upgrade -y` or `yum update -y`.
     - [ ] Remove unused packages: `apt remove --purge <pkg>`.
   - Verification:
     - [ ] `apt list --upgradable` (should be empty) or `yum check-update`.
   - Evidence: Update logs, package manager history (`/var/log/apt/history.log`).

4) **Auditd / Syslog / Logging**
   - Description: Ensure auditd rules present, log retention and remote forwarding configured.
   - Remediation:
     - [ ] Add required rules to `/etc/audit/rules.d/` and restart `auditd`.
     - [ ] Configure remote syslog if required.
   - Verification:
     - [ ] `auditctl -l` shows expected rules.
     - [ ] Check `/var/log/audit/audit.log` for timestamped entries.
   - Evidence: `auditctl -l` output, sample lines from audit log.

5) **Time Synchronization (NTP/Chrony)**
   - Remediation:
     - [ ] Ensure `chronyd` or `ntpd` is installed and configured to approved servers.
     - [ ] `systemctl enable --now chronyd`.
   - Verification:
     - [ ] `chronyc sources -v` or `ntpq -p` shows configured servers and synchronization.
   - Evidence: `chronyc sources -v` output.

6) **RKE2 / Kubernetes Specific**
   - Control examples: token handling, TLS, static pod configs, manifest permissions.
   - Remediation:
     - [ ] Ensure token files are stored in secure path with correct perms: `chmod 600 /var/lib/rancher/rke2/server/node-token`.
     - [ ] Ensure `rke2` configs contain hardened flags (verify manifest in `/etc/rancher/rke2/config.yaml`).
   - Verification:
     - [ ] `ls -l /var/lib/rancher/rke2/server/` and `cat /etc/rancher/rke2/config.yaml`.
     - [ ] `kubectl get componentstatuses` and `kubectl get nodes -o wide` for cluster readiness.
   - Evidence: config snapshots, `kubectl` outputs.

7) **Network & Firewall**
   - Remediation:
     - [ ] Configure `firewalld`/`iptables` rules according to STIG.
     - [ ] Harden CNI plugin configuration.
   - Verification:
     - [ ] `ss -tuln` to list listening ports; `iptables -L -v -n` or `nft list ruleset`.
   - Evidence: firewall rules export, CNI config files.

8) **Services & Daemons**
   - Remediation:
     - [ ] Disable/remove unused services: `systemctl disable --now <service>`.
   - Verification:
     - [ ] `systemctl list-unit-files --type=service | grep enabled` (confirm only allowed services enabled).
   - Evidence: `systemctl status` for key services.

9) **File System & Storage (encryption, mounts)**
   - Remediation:
     - [ ] Ensure sensitive volumes are encrypted and mount options include `nodev,nosuid,noexec` where applicable.
   - Verification:
     - [ ] `mount | grep <mount>` and `lsblk --fs` to confirm encryption.
   - Evidence: `fstab` entries, `cryptsetup status` output.

10) **Backups & Recovery**
    - Remediation:
      - [ ] Ensure backup jobs are configured and tested.
    - Verification:
      - [ ] Show last successful backup logs and recovery test results.
    - Evidence: Backup logs, test restore evidence.

11) **Vulnerability Scanning & Remediation Tracking**
    - Remediation:
      - [ ] Run approved scanner, address findings or document exceptions.
    - Verification:
      - [ ] Attach scan report and remediation tickets.

12) **Documentation, Exceptions & Authorization**
    - Remediation:
      - [ ] If deviation from STIG is necessary, record an exception with mitigation and approval.
    - Verification:
      - [ ] Exception paperwork and approver signature.

---

Tips for reviewers:
- Always collect command output (not screenshots only).
- Use precise commands listed in the Remediation/Verification sections.
- When a control requires manual file edits, include a before/after snapshot.

Record of changes to this checklist:
- Created: 2026-02-09
