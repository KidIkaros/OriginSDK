// SPDX-License-Identifier: Apache-2.0

//! Memory tier configuration for Argon2id KDF.
//!
//! Three tiers prove viability across the device spectrum:
//! - **Nano**: IoT / edge / RPi Zero (8 MB, 2 iter, 1 thread)
//! - **Standard**: Mid-tier laptop (64 MB, 3 iter, 2 threads)
//! - **Sovereign**: Datacenter / high-security (256 MB, 5 iter, 4 threads)
//!
//! The quantum pipeline (SHAKE-256 + KMAC-256 + hybrid keys) is identical
//! across all tiers. Only the Argon2id password-to-seed cost changes.

use argon2::Params;

/// Device memory tier — gates only the Argon2id KDF cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemoryTier {
    /// IoT / Edge / RPi Zero: 8 MB, 2 iterations, 1 lane.
    Nano,
    /// Mid-tier laptop / server: 64 MB, 3 iterations, 2 lanes.
    #[default]
    Standard,
    /// Datacenter / high-security: 256 MB, 5 iterations, 4 lanes.
    Sovereign,
}

impl MemoryTier {
    /// Return Argon2id parameters for this tier.
    pub fn argon2_params(self, output_len: usize) -> Params {
        let (m_cost, t_cost, p_cost) = match self {
            MemoryTier::Nano => (8 * 1024, 2, 1),        // 8 MB
            MemoryTier::Standard => (64 * 1024, 3, 2),   // 64 MB
            MemoryTier::Sovereign => (256 * 1024, 5, 4), // 256 MB
        };
        Params::new(m_cost, t_cost, p_cost, Some(output_len)).expect("valid Argon2 params")
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            MemoryTier::Nano => "nano",
            MemoryTier::Standard => "standard",
            MemoryTier::Sovereign => "sovereign",
        }
    }

    /// Get the recommended buffer size for this tier
    pub fn buffer_size(&self) -> usize {
        match self {
            MemoryTier::Nano => 1024,
            MemoryTier::Standard => 4096,
            MemoryTier::Sovereign => 4096,
        }
    }

    /// Whether memory should be locked (mlock)
    pub fn should_lock(&self) -> bool {
        matches!(self, MemoryTier::Sovereign)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nano_params_valid() {
        let p = MemoryTier::Nano.argon2_params(32);
        assert_eq!(p.m_cost(), 8 * 1024);
        assert_eq!(p.t_cost(), 2);
        assert_eq!(p.p_cost(), 1);
    }

    #[test]
    fn standard_params_valid() {
        let p = MemoryTier::Standard.argon2_params(32);
        assert_eq!(p.m_cost(), 64 * 1024);
    }

    #[test]
    fn sovereign_params_valid() {
        let p = MemoryTier::Sovereign.argon2_params(32);
        assert_eq!(p.m_cost(), 256 * 1024);
        assert_eq!(p.t_cost(), 5);
        assert_eq!(p.p_cost(), 4);
    }

    #[test]
    fn default_tier_is_standard() {
        let tier: MemoryTier = Default::default();
        assert_eq!(tier, MemoryTier::Standard);
    }

    #[test]
    fn tier_labels() {
        assert_eq!(MemoryTier::Nano.label(), "nano");
        assert_eq!(MemoryTier::Standard.label(), "standard");
        assert_eq!(MemoryTier::Sovereign.label(), "sovereign");
    }

    #[test]
    fn buffer_sizes() {
        assert_eq!(MemoryTier::Nano.buffer_size(), 1024);
        assert_eq!(MemoryTier::Standard.buffer_size(), 4096);
        assert_eq!(MemoryTier::Sovereign.buffer_size(), 4096);
    }

    #[test]
    fn should_lock_only_for_sovereign() {
        assert!(!MemoryTier::Nano.should_lock());
        assert!(!MemoryTier::Standard.should_lock());
        assert!(MemoryTier::Sovereign.should_lock());
    }

    #[test]
    fn tier_equality() {
        assert_eq!(MemoryTier::Nano, MemoryTier::Nano);
        assert_ne!(MemoryTier::Nano, MemoryTier::Standard);
    }

    #[test]
    fn argon2_params_different_output_lens() {
        for &len in &[16, 32, 64] {
            let p = MemoryTier::Nano.argon2_params(len);
            assert_eq!(p.output_len(), Some(len));
        }
    }
}
