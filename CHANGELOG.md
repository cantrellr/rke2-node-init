# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Repository structure refactoring for better organization
- New directory structure with `bin/`, `scripts/`, `docs/`, and `tests/`
- Standard open-source project files:
  - `SECURITY.md` - Security policy and vulnerability reporting
  - `CONTRIBUTING.md` - Contribution guidelines
  - `CODE_OF_CONDUCT.md` - Community code of conduct
  - `CHANGELOG.md` - Project changelog
- Tool configuration files:
  - `.editorconfig` - Code style consistency
  - `.shellcheckrc` - ShellCheck linting configuration
  - `.markdownlint.json` - Markdown linting rules
  - `.yamllint.yml` - YAML validation rules
- Reorganized VM utilities into `vm/scripts/`, `vm/templates/`, and `vm/docs/`
- Test infrastructure directories: `tests/unit/`, `tests/integration/`, `tests/fixtures/`
- Documentation structure: `docs/` directory for comprehensive guides
 

### Changed
- Moved `rke2nodeinit.sh` to `bin/rke2nodeinit.sh`
- Moved `rke2nodeinit-unused-functions.sh` to `scripts/archived/`
- Moved `test-interface-detection.sh` to `scripts/test/`
- Reorganized VM directory structure for better separation of concerns
- Updated `.gitignore` with production configuration paths
 - Docs: aligned example paths to `examples/` and updated examples to prefer kebab-case keys; clarified that camelCase aliases are supported
 - CI: added example YAML validation and duplicate-token-file verification workflow
 - `bin/rke2nodeinit.sh` enhanced with OCI manifest fallback parsing and
   post-staging verification improvements: architecture detection, tarball
   integrity checks, and optional deep layer verification via `--verify-layers`.
 - Help text updated to document new `--verify-layers` flag and its behavior.
 - Added `PHASES-1-2-IMPLEMENTATION.md` documenting the OCI parsing and
   layer verification implementation details and test notes.

### Testing

- To validate staged artifacts and exercise the new features locally, run:

```bash
# Standard post-staging checks (Docker or OCI manifest parsing)
sudo ./bin/rke2nodeinit.sh -f config.yaml image

# Enable deep layer checksum verification (may take significant time)
sudo ./bin/rke2nodeinit.sh -f config.yaml --verify-layers image

# Verify OCI parsing by inspecting sample images reported by the script
sudo ./bin/rke2nodeinit.sh -f config.yaml image | sed -n '/Sample images/,/Post-staging/p'
```

### Deprecated
- Direct path to `rke2nodeinit.sh` in repository root (use `bin/rke2nodeinit.sh`)
  - Temporary symlink provided for backward compatibility
  - Will be removed in a future release

### Security
- Enhanced `.gitignore` to prevent committing production configurations
- Added comprehensive security policy in `SECURITY.md`
- Separated examples from production configuration paths

### Migration Guide
If you have scripts or automation referencing the old paths:

**Old Path:**
```bash
./rke2nodeinit.sh --action server
```

**New Path (recommended):**
```bash
./bin/rke2nodeinit.sh --action server
```

**Temporary Compatibility:**
A symlink is provided at the repository root for backward compatibility:
```bash
./rke2nodeinit.sh -> bin/rke2nodeinit.sh
```

This symlink will be removed in a future release. Please update your scripts.

---

## [0.2.0] - 2025-11-12

### Added
- OCI image index parsing for staged images (`parse_oci_image_index`) to support
  OCI layout formatted tarballs in addition to Docker `manifest.json`.
- Deep image layer checksum verification (`verify_image_layer_checksums`) to
  optionally validate individual layer SHA256 digests inside staged image
  tarballs (opt-in via `--verify-layers`).
- CLI flag `--verify-layers` to enable deep layer verification during the
  `image` action (off by default to avoid extra processing time).

### Changed
- `bin/rke2nodeinit.sh` enhanced with OCI manifest fallback parsing and
  post-staging verification improvements: architecture detection, tarball
  integrity checks, and optional deep layer verification via `--verify-layers`.
- Help text updated to document new `--verify-layers` flag and its behavior.
- Added `PHASES-1-2-IMPLEMENTATION.md` documenting the OCI parsing and
  layer verification implementation details and test notes.

### Notes
- This release primarily adds artifact verification and OCI-format support
  to improve reliability in air-gapped deployments. The new `--verify-layers`
  flag is intentionally opt-in because it performs an exhaustive hash check
  of every image layer.

## [1.0.0] - TBD

### Initial Release
- Full air-gapped RKE2 cluster deployment automation
- Support for offline artifact caching and registry mirroring
- Network configuration with multi-interface support
- Certificate authority trust chain management
- Server and agent node initialization
- Comprehensive logging and error handling
- YAML-based configuration with CLI override support

[Unreleased]: https://github.com/cantrellr/rke2-node-init/compare/v1.0.0...HEAD
[0.2.0]: https://github.com/cantrellr/rke2-node-init/releases/tag/v0.2.0
[1.0.0]: https://github.com/cantrellr/rke2-node-init/releases/tag/v1.0.0
