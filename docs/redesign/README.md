# Redesign Archive Notes

This directory contains historical phase-by-phase redesign artifacts retained for implementation history.

Current-state clarifications:
- Canonical runtime behavior is documented in ../../README.md and ../HYPERV-VM-NAME-SETUP.md.
- Boot service behavior is ISO-based: attach virtual CD media containing /config/<yaml>; first boot selects the first YAML under /config.
- Current script invocation is ./bin/rke2nodeinit.sh, and file-based action runs use -f <manifest>.

Some historical snippets may still show legacy field names from in-progress redesign stages (for example NODE_NAME or CLUSTER_TOKEN). Treat those snippets as historical context, not current rkeprep/v2 schema guidance.

Use these documents for architecture history and rationale; use current top-level docs for operational runbooks.
