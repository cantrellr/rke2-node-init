# Contributing to rke2-node-init

Thank you for your interest in contributing to rke2-node-init! This document provides guidelines and instructions for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) to keep our community welcoming and inclusive.

## Getting Started

### Prerequisites

- Bash 5.x or higher
- Ubuntu 22.04+ or RHEL 8+ (for testing)
- Git for version control
- ShellCheck for linting Bash scripts
- Basic understanding of RKE2 and Kubernetes

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/rke2-node-init.git
   cd rke2-node-init
   ```

3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/cantrellr/rke2-node-init.git
   ```

4. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Workflow

### Repository Structure

```
.
├── bin/                    # Main executable scripts
├── configs/
│   └── examples/          # Example configuration files
├── certs/                 # Certificate management
│   ├── examples/          # Example certificates
│   └── scripts/           # Certificate generation scripts
├── docs/                  # Documentation
├── scripts/               # Utility scripts
│   ├── archived/          # Deprecated/unused scripts
│   ├── test/              # Test scripts
│   └── utils/             # Utility scripts
├── tests/                 # Test suite
│   ├── unit/              # Unit tests
│   ├── integration/       # Integration tests
│   └── fixtures/          # Test data
└── vm/                    # VM management utilities
    ├── scripts/           # PowerShell scripts
    ├── templates/         # VM templates
    └── docs/              # VM documentation
```

### Making Changes

1. **Update your fork** before starting work:
   ```bash
   git fetch upstream
   git merge upstream/main
   ```

2. **Make your changes** following our coding standards

3. **Test your changes** thoroughly

4. **Lint your code**:
   ```bash
   # Shell scripts
   shellcheck bin/rke2nodeinit.sh
   
   # Markdown files
   markdownlint README.md
   
   # YAML files
   yamllint configs/examples/
   ```

5. **Commit your changes** with descriptive messages:
   ```bash
   git add .
   git commit -m "feat: add new feature X"
   ```

## Coding Standards

### Shell Scripts

- **Bash Version**: Target Bash 5.x+
- **Error Handling**: Use `set -Eeuo pipefail` at the start of scripts
- **Indentation**: 2 spaces (no tabs)
- **Line Length**: Prefer max 120 characters
- **Naming**:
  - Functions: `snake_case` or `action_verb` pattern
  - Variables: `UPPER_CASE` for constants, `lower_case` for local variables
- **Comments**: Use descriptive comments for complex logic
- **Quotes**: Always quote variables: `"${variable}"`

### Example

```bash
#!/usr/bin/env bash
set -Eeuo pipefail

# Function to perform action
action_example() {
  local input="${1:-default}"
  local readonly CONSTANT="value"
  
  echo "Processing: ${input}"
}
```

### PowerShell Scripts

- **Indentation**: 4 spaces
- **Naming**: PascalCase for functions and parameters
- **Error Handling**: Use `-ErrorAction Stop` where appropriate

### Documentation

- **Markdown**: Follow [markdownlint](https://github.com/DavidAnson/markdownlint) rules
- **Code Blocks**: Always specify language for syntax highlighting
- **Links**: Use relative links for internal documentation

## Testing

### Manual Testing

Before submitting:

1. Test the main script in a clean environment
2. Verify all actions work as expected
3. Test with both online and offline scenarios
4. Validate error handling and edge cases

### Test Structure

```bash
# tests/unit/test_function.sh
#!/usr/bin/env bash

test_function_name() {
  # Arrange
  local input="test"
  
  # Act
  local result
  result=$(function_name "${input}")
  
  # Assert
  [[ "${result}" == "expected" ]] || return 1
}
```

### Running Tests

```bash
# Run unit tests (when available)
bash tests/unit/run_tests.sh

# Run integration tests (when available)
bash tests/integration/run_tests.sh
```

## Documentation

### README Updates

- Update README.md for new features or changes
- Include usage examples
- Update the Table of Contents if adding new sections

### Documentation Files

- **Architecture**: Update `docs/architecture.md` for structural changes
- **Network Config**: Update `docs/network-config.md` for network-related changes
- **Troubleshooting**: Add common issues to `docs/troubleshooting.md`

### Code Comments

- Comment complex logic
- Use inline comments sparingly
- Prefer self-documenting code with descriptive names

## Submitting Changes

### Pull Request Process

1. **Update documentation** related to your changes

2. **Ensure all tests pass** and code is linted

3. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

4. **Create a Pull Request** on GitHub:
   - Use a descriptive title
   - Reference related issues
   - Provide a detailed description of changes
   - Include testing steps

### Pull Request Template

```markdown
## Description
Brief description of changes

## Related Issues
Fixes #123

## Changes Made
- Change 1
- Change 2

## Testing
- [ ] Manual testing completed
- [ ] Linting passed
- [ ] Documentation updated

## Breaking Changes
Yes/No - Description if yes
```

### Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc.)
- `refactor:` Code refactoring
- `test:` Adding or updating tests
- `chore:` Maintenance tasks

Examples:
```
feat: add support for custom CA bundles
fix: resolve network interface detection issue
docs: update README with new configuration options
```

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. Update CHANGELOG.md
2. Update version references in documentation
3. Tag the release
4. Create GitHub release with notes

## Questions?

If you have questions:

1. Check existing [documentation](README.md)
2. Search [existing issues](https://github.com/cantrellr/rke2-node-init/issues)
3. Open a new issue with the `question` label

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (see [LICENSE](LICENSE)).

---

Thank you for contributing to rke2-node-init!
