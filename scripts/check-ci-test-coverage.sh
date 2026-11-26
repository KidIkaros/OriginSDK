#!/usr/bin/env bash
# Drift guard: every tests/*.rs file must be referenced in .github/workflows/ci.yml,
# or covered by a catch-all `cargo test --tests` step.
# Exits nonzero and names the offenders otherwise.
set -euo pipefail
cd "$(dirname "$0")/.."

CI=.github/workflows/ci.yml
missing=0
for f in tests/*.rs; do
    name=$(basename "$f" .rs)
    if ! grep -q "$name" "$CI"; then
        echo "NOT IN CI: tests/$name.rs"
        missing=1
    fi
done
# bin tests need an explicit --bins invocation (--lib does not run them)
if ls src/bin/*.rs >/dev/null 2>&1 && ! grep -q -- '--bins' "$CI"; then
    echo "NOT IN CI: src/bin tests (no 'cargo test --bins' step)"
    missing=1
fi
if [ "$missing" -ne 0 ]; then
    echo "error: test files exist that CI never runs — wire them in or document exclusion" >&2
    exit 1
fi
echo "ci test coverage: all test files referenced"
