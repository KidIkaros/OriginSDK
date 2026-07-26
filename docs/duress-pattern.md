# Duress Passphrase Patterns: Application-Level Guidance for `origin-crypto-sdk`

*Current as of 2026-07-26.*

## Audience and Scope

This document is written for **application developers integrating `origin-crypto-sdk`** — wallet authors, encrypted-messenger backends, password-manager UIs, identity and recovery tools that wrap the SDK. It is **not** written for the end users of those applications.

The scope is **application-level composition of existing SDK primitives** (`create_blob`, `recover_seed`, `SeedHandle::with_tier`, `MemoryTier::Standard` / `MemoryTier::Sovereign`) to support users in jurisdictions where physical compulsion or legally compelled disclosure is foreseeable.

`origin-crypto-sdk` does **not** ship a duress primitive, a self-destruct primitive, a hidden-volume helper, or any "active-wipe" affordance. This document therefore teaches composition only.

Treat the patterns below as a checklist, **not** a recipe; jurisdictional specifics differ and change.

## TL;DR

- The SDK deliberately ships **no duress primitive**. You compose from primitives you already have.
- The canonical pattern is **operational deniability** — keep sensitive state off the device your user carries.
- The conditional pattern is **distinguishable decoy routing** — three vaults, one passphrase-routed decoy, no destruction, no audit signal.
- The hard problem is operational: which vault routed to which seed, what your application does on failure, and what the user can plausibly answer when compelled.
- **None of this is legal advice.** Consult local counsel. Cross-border applications must publish per-jurisdiction guidance.

## What This Document Is Not

- **NOT** legal advice. Jurisdiction-specific law differs; this document is informational as of 2026-07-26.
- **NOT** a security guarantee. A duress pattern that you can verify on your test device is not a duress pattern that will survive an adversary trained in forensic analysis.
- **NOT** an SDK API surface. Every symbol referenced here (`create_blob`, `recover_seed`, `SeedHandle::with_tier`, `MemoryTier::*`) is part of the existing public API of `origin-crypto-sdk` 0.4.x / 0.5.x.
- **NOT** a substitute for understanding the jurisdiction(s) your users live in. If your users live across borders, write per-jurisdiction guidance inside your application.

## Threat Model

| Adversary | Capability | SDK exposure | Mitigation in this document |
|---|---|---|---|
| **A1: legal compulsion at border** | Forensic tool + subpoena for in-app disclosure | None — the SDK has no backdoor | Pattern P1, Pattern P2 |
| **A2: device confiscation + offline analysis** | Take device for weeks; offline crypto attack; SSD forensics | `MemoryTier::Sovereign` (mlock) reduces swap exposure | Pattern P1, Pattern P2, short-lived `SeedHandle` |
| **A3: physical compulsion ("rubber-hose")** | In-person threats; compelled speech | None | Pattern P1 only — no technical fix exists |

Pattern P2 protects against A1 and A2.
Pattern P3 protects against A1 only.
Pattern P1 protects against all three by removing the data from the device.

**No technical pattern protects against A3 except by absence of data.** This is the cheapest and most reliable mitigation; it is also the one most applications ignore because it is operationally inconvenient.

## Architectural Patterns

### Pattern P1 — Recommended Operational Posture (Recommended Default)

**Principle.** Don't have the data on you.

> **Framing note.** P1 is a *deployment posture*, not a software-composition
> pattern. Patterns P2 and P3 are software patterns built atop the SDK; Pattern
> P1 is operational advice that **no software can replace**. Treat P1 and P2/P3
> as different axes, not alternative options to choose from on technical merit.

- Sensitive blobs live on a stationary device (a server at home, a hardware token in a safe).
- The device the user travels with is a thin client: it pulls plaintext only when needed, over a connection the adversary cannot intercept.
- If the device is examined, no cryptographic state is present to recover.

This is the **EFF Surveillance Self-Defense** recommendation: a clean traveler device is more predictable than any software deniability.

For most application authors, **P1 is the only recommended pattern in v1.0**. Add P2 and P3 only when your user population explicitly asks for them and after retain-counsel review.

### Pattern P2 — Distinguishable Decoy Vault (Conditional)

**Principle.** Three vaults share the unlock screen; wrong passphrase returns decoy plaintext; the duress passphrase routes to the decoy.

This is **mathematically distinct** from a self-destruct feature:

- **No destruction occurs.** A wrong passphrase yields valid decoy plaintext under Argon2id-stretched KDF.
- **No state change.** No log entry, no audit trail, no panicking process, no dropped frame, no SSD TRIM sequence.
- **No third-party-verifiable wipe.** A forensic analyst can run the duress passphrase against the real blob and observe decryption failure, but cannot distinguish between "user does not have real passphrase" and "user used duress passphrase against real blob".

**Required for Pattern P2:**

1. Two blobs (real + decoy) stored at different on-disk paths, produced via independent `create_blob` calls.
2. A route-key prefix attached to the user-entered passphrase.
3. Memory hygiene: zeroize-on-drop via `SeedHandle::with_tier(..., MemoryTier::Sovereign)`.

**Recommended only when:**

- Your users explicitly understand the legal consequence under their jurisdiction.
- You can document the routing scheme to your users inside the application.
- You can test it against a non-target build before deployment.

### Pattern P3 — Indistinguishable Plausible Deniability (High Risk)

**Principle.** Multiple passwords yield indistinguishable volumes; adversary cannot prove a hidden volume exists.

This is the **VeraCrypt Hidden Volume** model. It is the most academically elegant of the three and the most operationally fragile.

- SSD TRIM patterns leak volume geometry.
- OS logs (last-mounted timestamp, swap, etc.) leak user activity.
- File-system timestamps leak writes.
- Behavioral tells — the user "did not react" when asked for a second volume — are inadmissible but operationally decisive.

We recommend P3 only when **all** of the following hold:

- Your user population is trained in operational deniability.
- The device sits on a fully-encrypted volume (LUKS / FileVault / BitLocker).
- Operational hygiene is in place: no notices, no application logs, no swap, no crash dumps, no OS-level leak channels.

## Legal Context — Why Active-Wipe Is Out of Scope

`origin-crypto-sdk` deliberatively does not expose an `unsafe_wipe` / `destroy_blob` API.

The reason is concrete. Several border incidents in 2025-2026 have resulted in **18 U.S.C. §2232** charges — the federal statute addressing destruction of property to prevent seizure — after users entered a "duress PIN" configured to factory-reset a device on entry (publicized via TechCrunch 2026-07-24).

**Implications for SDK design:**

- A duress button that **actively destroys data** is provable. Forensic examiners can detect the wipe: deleted-block TRIM markers, reboot logs, SSD wear-leveling records persist in non-volatile storage after the wipe. That provability **crystallizes prosecutable intent** under statutes modelled on §2232.
- A duress route under **Pattern P2** is **not** an act of destruction. No data was destroyed: a valid Argon2id decryption occurred, the user merely supplied the wrong route key, and the application yielded decoy plaintext. Forensics can prove "the user did not supply the real-passphrase result"; forensics cannot prove "the user intended to destroy evidence" because no destruction event occurred.

The SDK cannot ship a general "destroy" API because doing so would invite application developers to wire it to UI controls that expose end users to potential destruction-of-evidence prosecution.

Pattern P2 instead pushes the routing decision into the application's UX layer, where per-jurisdiction UX choices belong.

## Jurisdictional Guidance

This guidance is informational. Consult retained counsel.

| Jurisdiction | Recommendation |
|---|---|
| **US** | Pattern P1 over Pattern P2 over Pattern P3. Acknowledge 18 U.S.C. §2232 risk explicitly inside your application's privacy / threat-model documentation. Refuse to ship active-wipe UI affordances. |
| **UK** | Investigatory Powers Act 2016 (IPA; successor to RIPA Part III) compels single-passphrase disclosure. Pattern P1 / P2 protect against forensic analysis but **do not** protect against a compelled IPA disclosure notice. Document explicitly that a duress passphrase does not rescue a user from a compelled-disclosure offense. |
| **EU** | No uniform EU-wide decryption obligation exists as of 2026-07-26. Member-state obligations differ (e.g. France LCEN art. 230-1; Germany §100a StPO; Spain art. 588 LECrim). Surface jurisdiction to the user inside the application. The EU CSA / "Chat Control" proposal remains in legislative deadlock; no E2EE-breaking mandate has been enacted. |
| **Five Eyes cross-border MLAT requests** | Encrypted backups held server-side and decryptable by the provider are subject to MLAT. End-to-end encrypted backups are not. Pattern P1 with a stationary non-US / non-Five-Eyes host is a common redaction pattern; this is an operational choice, not a cryptographic guarantee. |
| **Authoritarian regimes** | Pattern P1 only. No technical pattern is sufficient against rubber-hose + compelled-access adversaries. Train users to keep state off the device that may be inspected. |

## Implementation Blueprint

The following Rust sketch illustrates **Pattern P2** using only existing public API of `origin-crypto-sdk`. The fence is `rust,no_run` — the snippet is illustrative, not a runnable program; bind against actual SDK signatures in your application.

```rust,no_run
use origin_crypto_sdk::blob::{create_blob, recover_seed, MemoryTier};
use origin_crypto_sdk::seed::SeedHandle;
use origin_crypto_sdk::error::CryptoError;

const ROUTE_REAL:   &[u8] = b"R\0";
const ROUTE_DECOY:  &[u8] = b"D\0";
const ROUTE_DURESS: &[u8] = b"X\0";

// Route classification is an impl detail of this module. Both duress and
// decoy routes decrypt the *decoy* blob — live adversaries cannot tell a
// decoy-routed unlock from a duress-routed unlock. The `Route` enum is
// exposed only via the public `classify_route` UX-layer helper below;
// the cryptographic core's `unlock` does not return it.
#[derive(Debug, PartialEq, Eq)]
enum Route { Real, Decoy }

// Cryptographic core: take a passphrase + the (real, decoy) blobs, return a
// `SeedHandle`. The Route variant stays internal; only the SeedHandle
// (real or decoy seed material, mlock()'d under MemoryTier::Sovereign)
// leaks out, and the application layer cannot distinguish them without
// inspecting the seed material itself. **This function never returns the
// Route enum**, by deliberate design — see §“Operational Pitfalls” below.
fn unlock(
    user_passphrase: &[u8],
    real_blob:  &[u8],
    decoy_blob: &[u8],
) -> Result<SeedHandle, CryptoError> {
    let target_blob = match user_passphrase {
        p if p.starts_with(ROUTE_REAL)   => real_blob,
        p if p.starts_with(ROUTE_DECOY)  => decoy_blob,
        p if p.starts_with(ROUTE_DURESS) => decoy_blob,
        _ => return Err(CryptoError::AuthenticationFailed),
    };

    // recover_seed returns raw [u8; 32] — explicitly NOT zeroize-on-drop.
    // Wrap immediately in SeedHandle::with_tier so the bytes are
    // mlock()'d under MemoryTier::Sovereign and zeroize()'d on Drop.
    //
    // NOTE: Use `.get(2..)` instead of `[2..]` so a too-short passphrase
    // returns AuthenticationFailed (indistinguishable from wrong-prefix /
    // wrong-secret) rather than panicking with an index-out-of-bounds, which
    // would itself be a side-channel signal to the forensic adversary.
    let tail = user_passphrase
        .get(2..)
        .ok_or(CryptoError::AuthenticationFailed)?;
    let raw = recover_seed(target_blob, tail, MemoryTier::Standard)?;
    Ok(SeedHandle::with_tier(&raw, None, MemoryTier::Sovereign))
}

// Public UX-layer helper. Callers MAY invoke this to determine whether the
// user unlocked the real vault (`Route::Real`) or the decoy class
// (`Route::Decoy`, which both the deliberate decoy and the duress
// passphrase route into — they are observably identical by design). Useful
// for example to render different status text in the UI based on the
// Real-vs-Decoy class.
//
// **This function collapses duress and decoy routes intentionally.** If your
// UI genuinely needs duress-vs-decoy distinction, do that on the prefix
// bytes directly — NOT on this function's return value, which loses that
// information by design (preserving observational indistinguishability against
// the forensic adversary).
//
// MUST NOT be called from audit, log, or forensic-persistence paths (this
// includes `tracing::*!`, `log::*!`, metrics emission, structured observability
// frameworks, and any audit/fraud-detection subsystems). On those paths,
// callers MUST treat all three prefixes uniformly.
fn classify_route(user_passphrase: &[u8]) -> Result<Route, CryptoError> {
    if user_passphrase.starts_with(ROUTE_REAL)   { return Ok(Route::Real); }
    if user_passphrase.starts_with(ROUTE_DECOY)  { return Ok(Route::Decoy); }
    if user_passphrase.starts_with(ROUTE_DURESS) { return Ok(Route::Decoy); }
    Err(CryptoError::AuthenticationFailed)
}

fn create_real_blob(passphrase: &[u8], seed: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    // Pattern P2 requires three independent blobs. The real blob embeds the real
    // seed; the decoy blob embeds a different seed whose plaintext is a
    // plausible decoy (e.g., a low-value wallet, an empty inbox).
    create_blob(passphrase, MemoryTier::Standard, Some(seed))
}
```

**Critical points from this blueprint:**

- The route prefix is **never** stored separately. The user enters `R\0<secret>` or `D\0<secret>`; the application does not learn the route until it sees the prefix.
- A wrong passphrase, a wrong route, or a wrong-prefix login **all return** the same `Err(CryptoError::AuthenticationFailed)`. **No application log may distinguish them.**
- Recovery is keyed to the unwrapped secret only; the prefix is sliced off after routing.
- `MemoryTier::Sovereign` is the right tier for Pattern P2. `MemoryTier::Standard` allows the recovered plaintext bytes to be paged to swap-backed virtual memory and survive a crash dump.

## Operational Pitfalls and Memory Hygiene

- **Do not** let the route branch be observable by the forensic adversary. This means: do not log the route taken (`dbg!()`, `eprintln!()`, `tracing::info!()`, `log::warn!()` — all forbidden on the routing path), and do not store the route decision in the same process memory as the passphrase itself. A memory snapshot that contains both the route variable and the passphrase bytes is itself a leak.
- **Do not** include an `expect("real", ...)` or `assert_eq!(route, Route::Real)` that panics on duress routes. A panic is a side-channel signal.
- **Do not** retain the unwrapped secret bytes beyond the `SeedHandle` scope. Let `Drop` zeroize them.
- **Do** use `MemoryTier::Sovereign` for the `SeedHandle` returned by your Pattern P2 path. `MemoryTier::Standard` permits plaintext bytes to be paged to swap.
- **Do** handle `MemoryTier::Sovereign` `mlock` failure as a hard authentication failure (do **not** fall back to `Standard`). A degraded `Sovereign` path is more dangerous than a clean failure.
- **Do** test Pattern P2 with a non-target device before deploying it to your users.
- **Do not** reuse passphrase bodies between vaults. The route prefix is part of the secret: changing the route means a different secret, full stop.

## Counter-Recommendation — Clean Traveler Devices

For high-risk users — activists in jurisdictions where data possession is proscribed; journalists under state-level protection regimes; civil-society organizers under surveillance order — the most reliable approach is **not** software deniability at all. It is:

- A clean traveler device, wiped before travel, used only at the inspection point, brought home uninspectably.
- Sensitive work performed on a device that **never crosses a border**.
- Sensitive blobs held on infrastructure the user does not personally carry.

Independent resources (referenced for advisory only; not part of `origin-crypto-sdk`):

- EFF Surveillance Self-Defense: <https://ssd.eff.org/>
- Access Now Digital Security Helpline: <https://www.accessnow.org/help/>
- Freedom of the Press Foundation: <https://freedom.press/>
- Tactical Tech Holistic Security: <https://holistic-security.tacticaltech.org/>

These resources are independent of this SDK. Application authors who serve high-risk users should treat them as required reading, not optional.

---

*The information in this document is current as of 2026-07-26. Jurisdiction-specific statute and case law (including the Tunick matter) is in active litigation; consult retained counsel before relying on any specific claim. This document is informational and does not constitute legal advice, a security guarantee, or a warranty of fitness for any particular purpose.*
