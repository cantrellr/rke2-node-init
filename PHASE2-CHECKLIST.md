# Phase 2 Preparation Checklist

**Target Start:** Week of November 18, 2025  
**Duration:** 2 weeks  
**Scope:** Refactor action functions to use Phase 1 utilities

---

## Pre-Phase 2 Validation

### Phase 1 Completion Checklist

- [x] All Phase 1 utilities implemented
- [x] Syntax validation passed
- [x] Demo script runs successfully
- [x] Documentation complete
- [x] Backward compatibility verified
- [x] Performance impact measured (<1%)

**Status:** ✅ Ready for Phase 2

---

## Phase 2 Action Priority

### Week 1 (Nov 18-22)

#### Action 1: action_verify ⭐ (Low Risk)
- [ ] Read current implementation
- [ ] Design refactored version with metrics
- [ ] Implement changes
- [ ] Add comprehensive error messages
- [ ] Test thoroughly
- [ ] Update documentation
- [ ] Commit with detailed message

**Rationale:** Read-only operation, lowest risk, good learning opportunity

#### Action 2: action_custom_ca ⭐ (Self-Contained)
- [ ] Read current implementation
- [ ] Design refactored version
- [ ] Add validation utilities
- [ ] Improve error messages
- [ ] Test with various CA configurations
- [ ] Update documentation
- [ ] Commit with detailed message

**Rationale:** Self-contained, clear scope, moderate complexity

### Week 2 (Nov 25-29)

#### Action 3: action_push ⭐⭐ (Metrics Showcase)
- [ ] Read current implementation
- [ ] Design refactored version
- [ ] Add metrics tracking for image operations
- [ ] Add progress reporting
- [ ] Improve error messages
- [ ] Test with various registries
- [ ] Update documentation
- [ ] Commit with detailed message

**Rationale:** Good use case for metrics, batch operation benefits

#### Action 4: action_image ⭐⭐⭐ (Critical Path)
- [ ] Read current implementation (large function)
- [ ] Break down into smaller functions
- [ ] Add dependency checking
- [ ] Add metrics for download operations
- [ ] Add progress reporting
- [ ] Improve error messages with remediation
- [ ] Extensive testing (most critical action)
- [ ] Update documentation
- [ ] Commit with detailed message

**Rationale:** Most important action, requires careful handling

---

## Refactoring Template

For each action, follow this template:

### 1. Analysis Phase

```markdown
## Current Implementation Analysis

**Lines:** <count>
**Dependencies:** <list>
**Global Variables Used:** <list>
**Validation Present:** <yes/no>
**Error Handling:** <description>
**Exit Points:** <count>

## Refactoring Opportunities

1. Add metrics tracking
2. Use validation utilities
3. Improve error messages
4. Add progress reporting
5. Reduce global variable usage
```

### 2. Design Phase

```bash
#=============================================================================
# Function: action_<name>
# Description: <updated description>
# Parameters:
#   None (reads from CONFIG_FILE global or CLI flags)
# Returns: 
#   0 - Success
#   1 - Validation failure
#   2 - Execution failure
# Usage: action_<name>
# Dependencies: <list Phase 1 utilities used>
# Changes from Original:
#   - Added metrics tracking
#   - Added validation utilities
#   - Improved error messages
#   - Added progress reporting
#=============================================================================
action_<name>() {
  log_info "Starting <action> operation"
  
  # Validate prerequisites
  validate_non_empty "$REQUIRED_VAR" "required_var" || return 1
  
  # Check dependencies
  if ! check_dependencies required_tool; then
    install_dependencies_interactive required_tool || return 1
  fi
  
  # Initialize metrics
  metrics_init "<action>_operation"
  
  # Core logic with metrics
  # ... existing logic refactored ...
  
  # Summary
  metrics_summary "<Action> Summary"
  
  # Return based on metrics
  if metrics_should_fail; then
    log_error "Operation completed with failures"
    return 1
  else
    log_success "Operation completed successfully"
    return 0
  fi
}
```

### 3. Implementation Phase

- [ ] Create backup of original function
- [ ] Implement refactored version
- [ ] Test with existing YAML configs
- [ ] Test with CLI arguments
- [ ] Verify backward compatibility
- [ ] Run integration tests

### 4. Testing Phase

```bash
# Test 1: Basic functionality
sudo bin/rke2nodeinit.sh <action> -f examples/<action>-example.yaml

# Test 2: Error handling
# (deliberately misconfigure and verify error messages)

# Test 3: Metrics output
# (verify summary displays correctly)

# Test 4: Backward compatibility
# (test with old-style invocations)
```

### 5. Documentation Phase

- [ ] Update function header comments
- [ ] Update main README if needed
- [ ] Add to CHANGELOG
- [ ] Create example YAML if needed
- [ ] Update Phase 2 progress tracker

---

## Testing Strategy

### Unit Testing

For each refactored action:

```bash
# Create test script
cat > tests/test_action_<name>.sh << 'EOF'
#!/usr/bin/env bash
source bin/rke2nodeinit.sh

# Test 1: Success case
test_success() {
  # Setup
  # Execute
  # Assert
}

# Test 2: Failure case
test_failure() {
  # Setup
  # Execute
  # Assert
}

# Run tests
test_success
test_failure
EOF
```

### Integration Testing

Test complete workflows:

```bash
# Test image + server workflow
sudo bin/rke2nodeinit.sh image -f configs/test-image.yaml
sudo bin/rke2nodeinit.sh server -f configs/test-server.yaml

# Verify no regressions
diff <expected> <actual>
```

### Regression Testing

```bash
# Run all existing test scripts
for test in tests/test_*.sh; do
  echo "Running $test..."
  bash "$test" || echo "FAILED: $test"
done
```

---

## Commit Strategy

### Commit Message Template

```
refactor(action_<name>): adopt Phase 1 utilities

Changes:
- Added metrics tracking with success/failure counts
- Replaced manual validation with utility functions
- Improved error messages with remediation steps
- Added progress reporting for batch operations
- Reduced global variable coupling

Benefits:
- More transparent operations with comprehensive summaries
- Consistent error messaging across actions
- Better debugging with structured logs
- Improved user experience with progress indicators

Testing:
- Verified backward compatibility with existing configs
- Tested error handling with invalid inputs
- Validated metrics accuracy with batch operations

Closes: #<issue>
Part of: Phase 2 redesign (action refactoring)
```

### Git Workflow

```bash
# Create feature branch for each action
git checkout -b refactor/action-<name>

# Make changes
# Test thoroughly
# Commit with detailed message

# Push and create PR
git push origin refactor/action-<name>

# After review, merge to feat/stage-artifact-path
```

---

## Success Criteria per Action

Each refactored action must meet:

- [ ] **Functionality:** All existing features work identically
- [ ] **Backward Compatibility:** Old configs/CLI invocations still work
- [ ] **Metrics:** Batch operations have success/failure tracking
- [ ] **Validation:** Use Phase 1 validation utilities
- [ ] **Error Messages:** Actionable with remediation steps
- [ ] **Progress:** Long operations show progress indicators
- [ ] **Documentation:** Function headers updated, examples added
- [ ] **Testing:** Pass all existing tests + new tests
- [ ] **Performance:** No measurable degradation (<5%)
- [ ] **Code Quality:** Reduced complexity, improved readability

---

## Risk Mitigation

### High-Risk Actions

For complex actions (image, server, agent):

1. **Create experimental branch first**
2. **Extensive testing in non-production**
3. **Feature flag for new implementation**
4. **Rollback plan documented**
5. **Peer review before merge**

### Medium-Risk Actions

For moderate complexity (push, add-server):

1. **Thorough testing with various inputs**
2. **Verify edge cases**
3. **Document breaking changes (if any)**

### Low-Risk Actions

For simple actions (verify, custom-ca):

1. **Standard testing**
2. **Quick review**
3. **Fast iteration**

---

## Progress Tracking

### Week 1 Progress

| Day | Action | Task | Status |
|-----|--------|------|--------|
| Mon | verify | Analysis | ⬜ |
| Mon | verify | Design | ⬜ |
| Tue | verify | Implementation | ⬜ |
| Tue | verify | Testing | ⬜ |
| Wed | custom-ca | Analysis | ⬜ |
| Wed | custom-ca | Design | ⬜ |
| Thu | custom-ca | Implementation | ⬜ |
| Fri | custom-ca | Testing | ⬜ |

### Week 2 Progress

| Day | Action | Task | Status |
|-----|--------|------|--------|
| Mon | push | Analysis | ⬜ |
| Mon | push | Design | ⬜ |
| Tue | push | Implementation | ⬜ |
| Tue | push | Testing | ⬜ |
| Wed | image | Analysis | ⬜ |
| Wed | image | Design | ⬜ |
| Thu | image | Implementation | ⬜ |
| Fri | image | Testing | ⬜ |

---

## Documentation Requirements

For each refactored action, create/update:

1. **Function Documentation**
   - Update structured header
   - Document changes from original
   - List Phase 1 utilities used

2. **Example YAML**
   - Ensure example configs still work
   - Add comments for new features

3. **CHANGELOG Entry**
   - List breaking changes (if any)
   - Document new features
   - Note improvements

4. **Migration Guide** (if needed)
   - How to update configs
   - Deprecated patterns
   - Recommended practices

---

## Phase 2 Completion Criteria

Phase 2 will be considered complete when:

- [ ] 4 priority actions refactored (verify, custom-ca, push, image)
- [ ] All actions use metrics tracking where appropriate
- [ ] All actions use validation utilities
- [ ] All actions have improved error messages
- [ ] All actions maintain backward compatibility
- [ ] All tests pass (existing + new)
- [ ] Documentation updated
- [ ] Demo scripts updated
- [ ] Performance benchmarks show <5% impact
- [ ] Code review completed
- [ ] Merged to main branch

**Target Completion:** November 29, 2025

---

## Resources

### Reference Documents
- `REDESIGN-ANALYSIS.md` - Overall strategy
- `docs/PHASE1-IMPLEMENTATION.md` - Utility documentation
- `docs/PHASE1-QUICK-REFERENCE.md` - Quick reference
- `PHASE1-SUMMARY.md` - Phase 1 summary

### Example Code
- `examples/phase1-demo.sh` - Working examples
- `bin/rke2nodeinit.sh` - Function definitions

### Testing Tools
- `bash -n` - Syntax validation
- `shellcheck` - Linting (if available)
- Integration test scripts

---

**Phase 2: READY TO START** 🎯  
**Phase 1: COMPLETE** ✅  
**Overall Progress:** 25% (2/8 weeks)
