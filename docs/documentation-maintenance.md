# RKE2 Node Init Documentation Maintenance

This guide defines how documentation is maintained after the docs condensation pass.

---

## 1. Canonical Document Set

The active documentation set is intentionally small:

| File | Owner purpose |
| --- | --- |
| `docs/README.md` | Operator-facing documentation index and reading order. |
| `docs/System-Design-Document.md` | Current architecture, workflow, trust boundary, and diagram source of truth. |
| `docs/operator-runbook.md` | Current operational commands, validation steps, and troubleshooting. |
| `docs/hardening-checklist.md` | Security, staging, registry, OS, CA, and documentation controls. |
| `docs/documentation-maintenance.md` | Rules for maintaining the docs and diagram workflow. |

Older uppercase docs, `docs/redesign/`, `docs/report/`, and `docs/stigs/` are retained as legacy/reference material. Do not expand them as the main operator path.

---

## 2. Change Order

When code behavior changes, update docs in this order:

1. `docs/System-Design-Document.md`
2. `diagrams/mermaid-source/*`
3. `docs/operator-runbook.md`
4. `docs/hardening-checklist.md`
5. `docs/README.md`, if the navigation or canonical set changes
6. Top-level `README.md`, if the public entrypoint changes

---

## 3. Diagram Source Contract

Mermaid source files live in:

```text
diagrams/mermaid-source/
```

Rendered exports are written to:

```text
diagrams/svg/
diagrams/png/
```

The system design document embeds Mermaid blocks and links to generated SVG/PNG files using this pattern:

```markdown
Diagram export: [SVG](../diagrams/svg/system-design-document-diagram-01.svg) | [PNG](../diagrams/png/system-design-document-diagram-01.png)
```

Do not create fake placeholder PNG/SVG files. Use the renderer.

---

## 4. Local Render Workflow

From the repo root:

```bash
./diagrams/apply-diagram-updates.sh . --install-deps --install-browser-deps
./diagrams/apply-diagram-updates.sh .
```

The first command installs local Mermaid tooling and Puppeteer browser dependencies when needed. The second command is the normal repeat run.

The renderer stores local Node tooling under `.diagram-tools/`, which is ignored by Git.

---

## 5. Commit Unit

A diagram/documentation change should normally commit these together:

- Markdown document updates;
- Mermaid source updates;
- diagram index updates;
- rendered SVG exports;
- rendered PNG exports;
- any runbook or checklist changes tied to behavior.

Do not commit:

- `.diagram-tools/`;
- `.diagram-sync-updated-files.txt`;
- runtime logs;
- downloads;
- outputs;
- secrets;
- generated private keys;
- production kubeconfigs.

---

## 6. Legacy Docs Handling

When useful content is found in an older doc:

1. Move the current behavior into the canonical document set.
2. Leave the old document in place as historical reference unless it is actively harmful.
3. Update `docs/README.md` only if the legacy document remains important enough to call out.
4. Avoid creating new uppercase one-off docs.

---

## 7. Validation Checklist

Before pushing documentation changes:

```bash
grep -c '```mermaid' docs/System-Design-Document.md
grep -c 'Diagram export:' docs/System-Design-Document.md
./diagrams/apply-diagram-updates.sh .
git status --short
git diff --check
```

Expected result: Mermaid block count and export-line count should match.
