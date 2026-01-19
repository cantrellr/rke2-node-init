README Standardization Plan

Date: November 9, 2025

Purpose:
This document lists README files to standardize across the repository and the small patchset plan to apply consistent headings, quick-start commands, and cross-references to the canonical Makefile cert targets.

Scope:
- root README.md
- certs/README.md (already updated)
- configs/examples/README.md (already updated)
- scripts/WSL-DEV-SETUP.md (already updated)
- vm/docs/README.md
- any other README.md found under subfolders

Standard README structure (template):
1. Short summary (1-2 lines)
2. Table of Contents (anchors)
3. Quick start (copyable commands)
4. Examples (link to examples/*)
5. Security notes (if applicable)
6. Files & layout
7. Getting help / Contributing

Planned changes (patchset):
1. Identify all README files
2. Create a minimal patch for each file: inject Quick Start and Security notes, ensure certs references use Make targets
3. Run grep checks to verify updated references ("make certs-root-ca", "make certs-sub-ca")
4. Commit changes in a small batch

Checklist (to be executed):
- [ ] Find README files across repo
- [ ] Draft per-file patches
- [ ] Apply patches and validate links/references
- [ ] Commit and push

Notes:
- Keep edits minimal and safe; avoid rewriting large documentation content in a single change.
- For docs that require large rewrites (root README), propose a follow-up PR for review.

