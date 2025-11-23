PR Proposal: Integrate vulnerability scanner into image action

Goal
----
Add an optional vulnerability scanning step (e.g., Trivy) to the `image` action that:

- Scans staged/downloaded artifacts (tarballs, installers) and optionally image layers.
- Emits a machine-readable vulnerability report (JSON) into `outputs/sbom/<SPEC_NAME>-vuln.json`.
- Augments the SBOM summary/security_score with scanner results (e.g., high/critical counts reduce score).
- Is opt-in (controlled via YAML spec e.g., `spec.scanVulnerabilities: true` or CLI flag `--scan-vulns`).

Design notes
------------
- Use Trivy when available (widely used, supports filesystem and archive scanning).
- Fallback: if Trivy is absent, log a WARN and skip scan.
- Place scanner output in `outputs/sbom/<SPEC_NAME>-vuln.json` and provide a short text summary in the same directory.
- The security_score calculation will be extended conservatively:
  - Subtract 30 points if any Critical vulns found
  - Subtract 20 points if any High vulns found
  - Add 10 points if Trivy ran and returned no vulns
  - Cap score between 0 and 100

Implementation plan (what this PR will add)
-------------------------------------------
1. New script `scripts/run_vuln_scan.sh` that:
   - Accepts a list of file paths or a directory to scan
   - Invokes `trivy fs --security-checks vuln --format json -o <out>` for each target
   - Aggregates results into a single JSON report and returns summary counts
2. Extend `action_image()` to:
   - Honor a new YAML key `spec.scanVulnerabilities` (default: false)
   - If enabled, call `scripts/run_vuln_scan.sh` against staged/downloaded artifacts
   - Merge results into SBOM JSON and adjust security_score using the heuristic above
3. CI changes (optional for follow-up):
   - Add a test that runs the vulnerability scan script against a small synthetic artifact and verifies JSON output.

Why not include the scanner unconditionally?
-------------------------------------------
- Scanning can be slow and requires a network cache or local DB for certain scanners; keep it opt-in to preserve `image` action latency for operators who don't want scanning.

Notes for reviewers
-------------------
- This PR provides a clear opt-in path and does not change default behavior.
- It is designed to be low-risk and easily disabled in environments without Trivy.

Next steps
----------
If you'd like, I can open a PR branch with these changes (scaffold + script + tests) ready for review. The PR will include the changes described here and a small demonstration using a synthetic file in `tests/` to validate output.
