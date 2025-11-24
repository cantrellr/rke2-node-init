# GitHub Actions Workflows - Documentation

This directory contains automated workflows for maintaining documentation quality and consistency.

## Workflows

### 1. Documentation Validation (`docs-validation.yml`)

**Trigger:** On PR commit (when documentation or script files change)

**Purpose:** Comprehensive validation and quality checks for all documentation

**Features:**
- ✅ Validates all YAML configuration files
- ✅ Extracts and verifies help text from script
- ✅ Checks markdown formatting with markdownlint
- ✅ Validates all markdown links
- ✅ Verifies documentation completeness
- ✅ Ensures all actions are documented
- ✅ Auto-updates version references
- ✅ Generates validation report
- ✅ Posts results as PR comment

**Checks Performed:**

1. **YAML Validation**
   - Validates `apiVersion: rkeprep/v1`
   - Checks for valid `kind` values
   - Ensures `metadata.name` is present
   - Validates field types and structure

2. **Help Text Extraction**
   - Extracts script version
   - Parses main help text
   - Identifies all action-specific help sections
   - Validates CLI flags

3. **Markdown Quality**
   - Formatting checks (markdownlint)
   - Link validation (markdown-link-check)
   - Checks for broken internal/external links

4. **Documentation Completeness**
   - Verifies README.md has essential sections
   - Checks for CONTRIBUTING.md and SECURITY.md
   - Validates examples directory structure
   - Ensures all actions are documented

5. **Version Consistency**
   - Updates version references in documentation
   - Syncs script version across files

**Output:**
- Validation report (JSON artifact)
- PR comment with results summary
- Auto-commits documentation fixes

---

### 2. Documentation Sync (`docs-sync.yml`)

**Trigger:** On PR commit (when script files change)

**Purpose:** Auto-generate documentation from script source code

**Features:**
- 📝 Extracts help text from `bin/rke2nodeinit.sh`
- 📝 Generates `docs/CLI-HELP.md` with current help text
- 📝 Generates `docs/YAML-SCHEMA.md` with configuration schema
- 📝 Auto-commits generated documentation
- 📝 Posts PR comment when documentation is updated

**Generated Documentation:**

1. **CLI-HELP.md**
   - Main help text
   - Action-specific help sections
   - Usage examples
   - CLI flags and options

2. **YAML-SCHEMA.md**
   - Supported YAML kinds
   - Common spec fields
   - Required fields
   - Example configurations

**Workflow:**
```
Script Change → Extract Help → Generate Docs → Commit → PR Comment
```

---

## Configuration Files

### `.markdownlint.json`

Markdown linting rules for consistent formatting:
- ATX-style headers (`#`)
- 2-space indentation for lists
- 120-character line length (excluding code/tables)
- Allows duplicate headers at different nesting levels
- Permits specific HTML elements

### `.github/markdown-link-check.json`

Link validation configuration:
- Ignores localhost URLs
- Ignores example/local registry URLs
- 5-second timeout per link
- Retry on 429 (rate limit)
- Treats auth-required (401/403) as valid

---

## Usage

### For Contributors

The workflows run automatically on PR commits. You don't need to do anything special.

**When you:**
- Modify `bin/rke2nodeinit.sh` help text → docs sync workflow runs
- Add/modify YAML configs → validation workflow runs
- Update markdown files → validation workflow runs

**What happens:**
1. Workflows validate your changes
2. Auto-generate/update documentation if needed
3. Commit changes back to your PR
4. Post validation results as PR comment

### For Maintainers

**Review the PR comments:**
- Check validation results
- Review auto-generated documentation
- Ensure all checks pass before merging

**If validation fails:**
- Review the workflow logs
- Fix the reported issues
- Push fixes to the PR branch

---

## Best Practices

### When Modifying Script Help Text

1. Update help text in `bin/rke2nodeinit.sh`
2. Follow existing format:
   ```bash
   action_name)
     cat <<'HELPEOF'
   Action: action-name
   ====================
   Purpose: Description
   
   Usage:
     sudo bin/rke2nodeinit.sh action-name -f config.yaml
   
   ...
   HELPEOF
     ;;
   ```
3. Commit the script change
4. The workflow will auto-generate `docs/CLI-HELP.md`

### When Adding New Actions

1. Implement the action in `bin/rke2nodeinit.sh`
2. Add help section to `show_action_help()`
3. Add to case statement for action dispatch
4. Add example YAML config to `examples/`
5. Workflows will validate and document automatically

### When Adding YAML Configurations

1. Use `apiVersion: rkeprep/v1`
2. Include valid `kind` value
3. Always include `metadata.name`
4. Place in `configs/` or `examples/`
5. Workflow will validate schema compliance

---

## Troubleshooting

### Validation Failures

**YAML validation fails:**
- Check `apiVersion: rkeprep/v1` is present
- Verify `kind` is one of: Push, Image, Airgap, Server, AddServer, Agent, Verify, CustomCA
- Ensure `metadata.name` exists and is not empty

**Markdown lint fails:**
- Run locally: `markdownlint '**/*.md'`
- Fix formatting issues reported
- Common issues: trailing spaces, inconsistent list indentation

**Link check fails:**
- Verify external links are accessible
- Check internal links point to existing files
- Add exceptions to `.github/markdown-link-check.json` if needed

### Workflow Not Running

**Check trigger paths:**
```yaml
paths:
  - '**.md'
  - 'bin/rke2nodeinit.sh'
  - 'scripts/**'
  - 'configs/**'
  - 'examples/**'
```

Only files matching these patterns trigger the workflows.

---

## Manual Testing

### Test Locally Before Push

**Validate YAML files:**
```bash
python3 -c "
import yaml
import sys
with open('configs/your-config.yaml') as f:
    yaml.safe_load(f)
print('✓ YAML is valid')
"
```

**Check markdown formatting:**
```bash
npx markdownlint '**/*.md' --ignore node_modules
```

**Extract help text:**
```bash
grep -A 50 'print_help()' bin/rke2nodeinit.sh | head -50
```

---

## Metrics and Reporting

Each workflow run generates:
- **Validation report** (JSON artifact, retained 30 days)
- **Extracted help data** (JSON artifact)
- **PR comment** with validation summary

### Report Format

```json
{
  "timestamp": "2025-11-24T12:00:00Z",
  "script_version": "1.0.0",
  "actions_count": 10,
  "yaml_kinds_count": 8,
  "markdown_files": 25,
  "checks": {
    "yaml_validation": "passed",
    "help_extraction": "passed",
    "completeness": "passed"
  }
}
```

---

## Maintenance

### Updating Workflows

1. Edit workflow files in `.github/workflows/`
2. Test changes in a PR branch
3. Review workflow run results
4. Merge when tests pass

### Adding New Validations

1. Add Python script to validation step
2. Update PR comment template
3. Add to validation report
4. Document in this README

---

## References

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [markdownlint Rules](https://github.com/DavidAnson/markdownlint/blob/main/doc/Rules.md)
- [markdown-link-check](https://github.com/tcort/markdown-link-check)
- [YAML Specification](https://yaml.org/spec/1.2/spec.html)

---

**Last Updated:** 2025-11-24  
**Maintainer:** GitHub Actions Bot
