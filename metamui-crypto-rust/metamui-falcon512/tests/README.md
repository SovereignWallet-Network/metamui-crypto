# Falcon-512 Test Structure

This directory contains the test suite for Falcon-512, organized into categories based on runtime and complexity.

## Test Categories

### Quick Tests (`quick_tests.rs`)
- **Runtime**: < 1 second
- **Purpose**: Basic functionality verification
- **When to run**: Every build, CI/CD pipeline
- **Command**: `cargo test -p metamui-falcon512`

### Integration Tests (`integration_tests.rs`)
- **Runtime**: 1-10 seconds
- **Purpose**: Component integration and moderate scenarios
- **When to run**: Before commits, nightly builds
- **Command**: `cargo test -p metamui-falcon512`

### Stress Tests (`stress_tests.rs`)
- **Runtime**: > 10 seconds
- **Purpose**: Statistical analysis, performance benchmarks
- **When to run**: Release validation, performance testing
- **Command**: `cargo test -p metamui-falcon512 -- --ignored`

## Running Tests

```bash
# Run all quick and integration tests (default)
cargo test -p metamui-falcon512

# Run only quick tests
cargo test -p metamui-falcon512 quick_tests

# Run only integration tests
cargo test -p metamui-falcon512 integration_tests

# Run stress tests (marked with #[ignore])
cargo test -p metamui-falcon512 -- --ignored

# Run all tests including stress tests
cargo test -p metamui-falcon512 -- --include-ignored

# Run with output
cargo test -p metamui-falcon512 -- --nocapture
```

## Test Configuration

The `common/mod.rs` module provides test configurations:
- `quick_config()`: Minimal attempts for fast testing
- `integration_config()`: Balanced configuration
- `stress_config()`: Full configuration for comprehensive testing

## Adding New Tests

1. **Quick tests**: Add to `quick_tests.rs` if runtime < 1s
2. **Integration tests**: Add to `integration_tests.rs` if runtime 1-10s
3. **Stress tests**: Add to `stress_tests.rs` with `#[ignore]` if runtime > 10s

## Notes

- Falcon-512 uses rejection sampling, so some operations may fail and need retries
- Test configurations reduce retry attempts to speed up testing
- Stress tests use full retry counts for accurate statistics