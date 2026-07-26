## [0.6.0] — 2026-XX-XX

### Removed (BREAKING)
- **`pub mod signing_legacy`** — entire module deleted. Pre-0.4 flat `signing_*` API was deprecated at `0.4.0` with a promise of removal in `0.5`; that removal was deferred once at `0.5.1` and is now honored in `0.6.0`. See [MIGRATION.md](MIGRATION.md#0.5x--06) for migration instructions.
- **Crate-root re-exports**: `HybridSignatureOutput`, `HybridSigningKey`, `HybridVerifyingKey`. Deprecated at `0.5.1` (`#[deprecated(since = "0.5.1")]`); removed in `0.6.0`. Use `signing::hybrid::HybridSigningKeyBundle` instead — the canonical surface has been available at `origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle` since `0.4.0`.

### Added (tooling)
- **`scripts/audit_signing_legacy.sh`** — downstream consumers can run this against their own repos to find pre-0.6 uses of the removed symbols. Default scan is `*.rs` only; pass `--include-toml` and/or `--include-md` to widen; `--json` emits machine-readable findings. Exit codes: `0` clean, `1` matches found, `2` argument error. See `bash scripts/audit_signing_legacy.sh --help` for usage.

