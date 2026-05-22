# Maintenance Policy — The Geomys Standard of Care

## Philosophy

This document establishes the maintenance standards for the `origin-crypto-sdk` cryptographic library, inspired by Filippo Valsorda's "The Geomys Standard of Care" (words.filippo.io/geomys/).

Cryptographic libraries require a higher standard of care than typical software. Every change must be justified, documented, and reviewed with the understanding that a single bug can compromise the security of all downstream users.

---

## Version Support

| Version | Status | End of Support |
|---------|--------|----------------|
| 0.1.x   | Active | Not before 2027-12-31 |

### Support Levels

- **Active**: Full support. Security patches, bug fixes, and feature updates.
- **Maintenance**: Security patches and critical bug fixes only.
- **End-of-Life**: No updates. Users must upgrade.

---

## Security Response

### Severity Classification

| Severity | Description | Response Time |
|----------|-------------|---------------|
| Critical | Key recovery, message forgery, timing leaks | 48 hours |
| High | DoS, incorrect verification, non-constant-time ops | 7 days |
| Medium | API misuse, documentation errors | 30 days |
| Low | Code quality, test coverage | Next release |

### Disclosure Process

1. **Discovery**: Report received via security@origincrypto.com
2. **Acknowledgment**: Within 24 hours
3. **Investigation**: Severity assessment and fix development
4. **Notification**: Affected users notified privately (if applicable)
5. **Release**: Public disclosure with patch

---

## Change Management

### Prohibited Without RFC

- New cryptographic primitives
- Changes to constant-time properties
- Modifications to RNG sources
- Breaking API changes

### Required for All Changes

- [ ] Test coverage ≥ 80%
- [ ] No `unsafe` blocks without justification
- [ ] Documentation updated
- [ ] CHANGELOG.md entry

---

## Testing Requirements

### Continuous Integration

All pull requests must pass:

```bash
cargo test --lib
cargo clippy -- -D warnings
cargo fmt --check
```

### Cryptographic Verification

- Accumulated test vectors for all primitives
- Cross-validation with reference implementations
- Fuzzing for input parsing and deserialization

---

## Dependencies

### Approved Cryptographic Primitives

| Primitive | Implementation | Status |
|-----------|---------------|--------|
| secp256k1 | Native (this crate) | Active |
| ChaCha20  | chacha20poly1305 | External |
| BLAKE3    | blake3 | External |
| Falcon    | falcon-rust | External |

### Dependency Updates

- Security updates: Within 7 days of release
- Feature updates: Evaluated quarterly
- Unused dependencies: Removed immediately

---

## Incident Response

### Security Incident Checklist

1. Isolate affected code paths
2. Assess scope of impact
3. Develop minimal patch
4. Coordinate disclosure with downstream users
5. Release patched version
6. Post-incident review

---

## Contact

- **Security**: security@origincrypto.com
- **General**: support@origincrypto.com

---

## References

- [The Geomys Standard of Care](https://words.filippo.io/geomys/)
- [Cryptographic Right Answers](https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
