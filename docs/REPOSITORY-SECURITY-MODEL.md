# Repository Security Model

Last updated: 2026-06-24

This document describes the intended access, contribution, and repository hardening model for `cantrellr/rke2-node-init`.

## Goals

The repository should remain publicly readable while protecting the upstream repository from unauthorized changes.

The desired model is:

- Public cloning is allowed.
- Public forking is allowed unless a future operational reason requires disabling forks.
- Public issues are allowed for non-security bugs, questions, and enhancement requests.
- Public pull requests are allowed from forks.
- Upstream branch creation and direct commits are restricted to the owner, explicitly approved maintainers, and approved automation.
- Changes to `main` are made through pull requests with CI, review, and rollback notes.
- Vulnerabilities are reported privately, not through public issues.

## Current Observed Status

The following settings were visible through the GitHub connector when this document was created:

| Area | Observed value |
| --- | --- |
| Repository visibility | Public |
| Default branch | `main` |
| Repository owner | `cantrellr` |
| Authenticated connector permission | admin, maintain, push, triage, pull |
| Auto-merge | Disabled |
| Merge methods enabled | Merge commit, squash merge, and rebase merge |
| Branch update button | Disabled |
| Archived | No |

The connector did not expose all repository security controls, including branch protection rules, repository rulesets, private vulnerability reporting state, Dependabot settings, CodeQL/code scanning settings, secret scanning settings, or current collaborator list. Those must be verified in the GitHub web UI.

## Important GitHub Behavior

For a public repository, public users can clone and usually fork the repository. That does not grant them write access to the upstream repository. Upstream branches and direct commits require repository write-level permission or higher.

A public contribution model normally uses forks and pull requests:

1. Contributor forks the repository.
2. Contributor pushes a branch to their fork.
3. Contributor opens a pull request into `cantrellr/rke2-node-init:main`.
4. Maintainer reviews, validates, and merges when approved.

## Recommended Repository Settings

### 1. Collaborators And Access

GitHub UI path:

`Settings` → `Collaborators and teams`

Recommended state:

- Keep `cantrellr` as repository owner/admin.
- Remove any unknown or stale collaborators.
- Grant `Write`, `Maintain`, or `Admin` only to explicitly approved maintainers or trusted automation.
- Use `Read` or no direct access for everyone else.
- Review access after major project changes or every 90 days.

### 2. Branch Protection Or Ruleset For `main`

GitHub UI path:

`Settings` → `Branches` → `Branch protection rules`

Create or update a rule for:

```text
main
```

Recommended settings:

- Require a pull request before merging.
- Require at least one approval.
- Require review from Code Owners.
- Dismiss stale pull request approvals when new commits are pushed.
- Require conversation resolution before merging.
- Require status checks before merging.
- Require branches to be up to date before merging when feasible.
- Require signed commits if your local workflow supports GPG, SSH, or S/MIME signing consistently.
- Require linear history if you want squash/rebase-only history.
- Do not allow force pushes.
- Do not allow deletions.
- Apply restrictions to administrators if you want the owner/admin to follow the same PR process.

Recommended required checks:

- `Validate RKE2 Configs (rkeprep/v2)`
- `CI — verify token-file uniqueness`
- `certs-ci`
- `Validate VM Configs`, if VM manifests are in scope for the PR
- `ipam-app-ci`, if `apps/ipam/` is in scope for the PR

If GitHub offers `Restrict who can push to matching branches` for this repository/account type, enable it for `main` and allow only `cantrellr` and approved automation. Note that this setting depends on account type and repository ownership model.

### 3. CODEOWNERS

This repository includes `.github/CODEOWNERS` so branch protection can request owner review automatically.

Recommended settings:

- Keep `.github/CODEOWNERS` on `main`.
- Protect `.github/CODEOWNERS` itself with ownership by `@cantrellr`.
- Enable `Require review from Code Owners` in the `main` branch protection rule.
- Add additional maintainers only after granting them appropriate repository access.

### 4. Pull Request Merge Strategy

GitHub UI path:

`Settings` → `General` → `Pull Requests`

Recommended state:

- Allow squash merge: enabled.
- Allow rebase merge: optional.
- Allow merge commits: optional; disable if you want linear history.
- Automatically delete head branches: enabled for upstream branches.
- Allow auto-merge: optional; keep disabled if every merge should be manual.
- Allow update branch: optional; currently observed as disabled.

For this repository, squash merge is usually the cleanest default because many changes are operational and should be summarized as one rollback unit.

### 5. Security And Analysis

GitHub UI path:

`Settings` → `Code security and analysis`

Recommended state:

- Enable private vulnerability reporting.
- Enable Dependabot alerts.
- Enable Dependabot security updates.
- Enable dependency graph.
- Enable secret scanning.
- Enable push protection.
- Enable CodeQL/code scanning for shell, Python, and workflow-relevant content where practical.
- Review security alerts at least monthly.

### 6. GitHub Actions Permissions

GitHub UI path:

`Settings` → `Actions` → `General`

Recommended state:

- Allow GitHub Actions for this repository.
- Prefer selected/verified actions where practical.
- Set workflow permissions to read-only by default.
- Grant write permissions only to workflows that require it.
- Require approval for workflows from fork pull requests.
- Do not expose sensitive secrets to forked pull request workflows.

### 7. Issues And Pull Requests

This repository includes issue templates and a pull request template.

Recommended state:

- Keep issues enabled for non-security reports.
- Keep pull requests enabled.
- Keep blank issues disabled unless there is a strong reason to allow free-form reports.
- Direct vulnerability reporters to GitHub Security Advisories.
- Keep the PR template focused on validation evidence, security checklist, docs, and rollback.

## Contributor Instructions

### Public Clone

```bash
git clone https://github.com/cantrellr/rke2-node-init.git
cd rke2-node-init
```

### External Contribution

External contributors should not push branches to the upstream repository. Use a fork:

```bash
# 1. Fork the repository in GitHub.
# 2. Clone your fork.
git clone https://github.com/<your-user>/rke2-node-init.git
cd rke2-node-init

# 3. Add upstream for syncing.
git remote add upstream https://github.com/cantrellr/rke2-node-init.git

# 4. Create a feature branch in your fork.
git checkout -b feature/my-change

# 5. Commit and push to your fork.
git push -u origin feature/my-change

# 6. Open a PR to cantrellr/rke2-node-init:main.
```

### Maintainer Contribution

Approved maintainers may create upstream branches only for authorized work:

```bash
git clone https://github.com/cantrellr/rke2-node-init.git
cd rke2-node-init
git checkout -b maint/my-change
# make changes, validate, push, and open PR
git push -u origin maint/my-change
```

Do not push directly to `main` unless break-glass maintenance is required and the change is documented afterward.

## Security Reporting Instructions

Use private reporting for suspected vulnerabilities:

<https://github.com/cantrellr/rke2-node-init/security/advisories/new>

Do not open public issues for vulnerabilities.

Include:

- Affected path or component.
- Affected version, branch, commit, or tag.
- Safe reproduction steps.
- Impact assessment.
- Required privileges or access.
- Suggested fix or mitigation.
- Whether public credit is desired.

## Issue Reporting Instructions

Use public issues only for non-security topics:

- Bugs.
- Feature requests.
- Operational questions.
- Documentation fixes.

Before posting, remove:

- Passwords.
- Tokens.
- Private keys.
- Kubeconfigs.
- Registry credentials.
- Production-only hostnames, IPs, topology, and certificate material.

## Pull Request Instructions

A pull request should include:

- Problem statement.
- Technical summary.
- Validation evidence.
- Documentation updated list.
- Security and sensitive-data checklist.
- Operational risk and rollback notes.

PRs that affect runtime behavior, systemd units, CI, scripts, networking, certificates, registry behavior, or manifests should receive careful maintainer review before merge.

## Review Cadence

Recommended periodic review:

| Frequency | Review item |
| --- | --- |
| Monthly | Open security alerts, stale PRs, failed CI, new dependency alerts |
| Quarterly | Collaborator list, branch protection/rulesets, GitHub Actions permissions |
| After major change | Required checks, CODEOWNERS coverage, issue/PR templates, SECURITY.md |

## Limitations

This document describes the desired and recommended model. Some controls require GitHub UI configuration and cannot be fully represented in repository files.
