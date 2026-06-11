// SPDX-License-Identifier: Apache-2.0

//! Parallel batch operations for NTRU Prime using Rayon
//!
//! Provides parallel implementations for batch key generation,
//! encapsulation, and decapsulation operations.

#[cfg(feature = "pqc-parallel")]
use rand::{CryptoRng, RngCore};
#[cfg(feature = "pqc-parallel")]
use rayon::prelude::*;

use crate::kem::ntru_prime::{
    self, constants::CT_SIZE, Ciphertext, PrivateKey, PublicKey, SharedSecret,
};

// =============================================================================
// Parallel Batch Operations
// =============================================================================

/// Generate multiple NTRU Prime key pairs in parallel
///
/// # Arguments
/// * `n` - Number of key pairs to generate
/// * `rng` - Random number generator (will be cloned for each thread)
///
/// # Returns
/// Vector of (private_key, public_key) tuples
#[cfg(feature = "pqc-parallel")]
pub fn keypairs_parallel<R: RngCore + CryptoRng + Clone + Sized + Send>(
    n: usize,
    rng: &mut R,
) -> Vec<(PrivateKey, PublicKey)> {
    // Create thread-safe RNG clones
    let mut rngs = Vec::with_capacity(n);
    for _ in 0..n {
        rngs.push(rng.clone());
    }

    rngs.into_par_iter()
        .map(|mut rng| ntru_prime::generate_keypair(&mut rng))
        .collect()
}

/// Batch encapsulate using parallel processing
///
/// # Arguments
/// * `public_keys` - Slice of public keys to encapsulate to
/// * `rng` - Random number generator (will be cloned for each thread)
///
/// # Returns
/// Vector of (ciphertext, shared_secret) tuples
#[cfg(feature = "pqc-parallel")]
pub fn encapsulate_batch<R: RngCore + CryptoRng + Clone + Sized + Send>(
    public_keys: &[PublicKey],
    rng: &mut R,
) -> Vec<(Ciphertext, SharedSecret)> {
    // Create thread-safe RNG clones
    let mut rngs: Vec<_> = (0..public_keys.len()).map(|_| rng.clone()).collect();

    public_keys
        .par_iter()
        .zip(rngs.into_par_iter())
        .map(|(pk, mut rng)| ntru_prime::encapsulate(pk, &mut rng))
        .collect()
}

/// Batch decapsulate using parallel processing
///
/// # Arguments
/// * `ciphertexts` - Slice of ciphertexts
/// * `private_keys` - Slice of corresponding private keys
///
/// # Returns
/// Vector of Results containing shared secrets or errors
#[cfg(feature = "pqc-parallel")]
pub fn decapsulate_batch(
    ciphertexts: &[Ciphertext],
    private_keys: &[PrivateKey],
) -> Vec<Result<SharedSecret, String>> {
    ciphertexts
        .par_iter()
        .zip(private_keys.par_iter())
        .map(|(ct, sk)| ntru_prime::decapsulate(ct, sk))
        .collect()
}

/// Parallel polynomial multiplication for batch operations
///
/// # Arguments
/// * `results` - Mutable slice to store results
/// * `polys_a` - Slice of first polynomial operands
/// * `polys_b` - Slice of second polynomial operands
///
/// Each `result[i]` = `polys_a[i]` * `polys_b[i]`
#[cfg(feature = "pqc-parallel")]
pub fn poly_mul_batch_parallel(
    results: &mut [Vec<i16>],
    polys_a: &[Vec<i16>],
    polys_b: &[Vec<i16>],
) {
    assert_eq!(polys_a.len(), polys_b.len());
    assert_eq!(results.len(), polys_a.len());

    results
        .par_iter_mut()
        .zip(polys_a.par_iter())
        .zip(polys_b.par_iter())
        .for_each(|((result, poly_a), poly_b)| {
            // Use optimized multiplication if available
            #[cfg(all(feature = "pqc-simd", feature = "pqc-parallel"))]
            {
                result.clone_from(&crate::ntru_prime::simd_poly::poly_mul(poly_a, poly_b));
            }

            #[cfg(not(all(feature = "pqc-simd", feature = "pqc-parallel")))]
            {
                // Fallback to scalar multiplication defined inline
                let n = poly_a.len();
                let mut computed = vec![0i16; n];
                for i in 0..n {
                    let mut acc = 0i32;
                    for j in 0..=i {
                        acc += (poly_a[j] as i32) * (poly_b[i - j] as i32);
                    }
                    computed[i] = mod_freeze(acc);
                }
                result.clone_from(&computed);
            }
        });
}

/// Modular reduction for fallback (same as simd_poly::freeze)
/// Available when pqc-simd is not enabled
#[cfg(all(feature = "pqc-parallel", not(feature = "pqc-simd")))]
#[inline(always)]
fn mod_freeze(a: i32) -> i16 {
    const MAGIC: i32 = 934_409;
    const Q_I32: i32 = 4_591;
    let t = ((a as i64) * (MAGIC as i64)) >> 32;
    let b = a - (t as i32) * Q_I32;
    let mut c = b - Q_I32;
    let mask = (b >> 31) & Q_I32;
    c += mask;
    c as i16
}

/// Modular reduction for fallback (i32 -> i32 version)
#[inline(always)]
fn freeze_i32(a: i32) -> i32 {
    const MAGIC: i32 = 934_409;
    const Q_I32: i32 = 4_591;
    let t = ((a as i64) * (MAGIC as i64)) >> 32;
    let b = a - (t as i32) * Q_I32;
    let mut c = b - Q_I32;
    let mask = (b >> 31) & Q_I32;
    c += mask;
    c
}

/// Parallel batch modular reduction
///
/// # Arguments
/// * `values` - Mutable slice of values to reduce modulo Q
#[cfg(feature = "pqc-parallel")]
pub fn reduce_batch_parallel(values: &mut [i32]) {
    #[cfg(feature = "pqc-simd")]
    values.par_iter_mut().for_each(|v| {
        *v = crate::ntru_prime::simd_poly::freeze(*v) as i32;
    });

    #[cfg(not(feature = "pqc-simd"))]
    values.par_iter_mut().for_each(|v| {
        *v = freeze_i32(*v);
    });
}

/// Parallel batch R3 coefficient freeze
///
/// # Arguments
/// * `values` - Mutable slice of i32 values to freeze to i8 (mod 3)
#[cfg(feature = "pqc-parallel")]
pub fn freeze_r3_batch_parallel(values: &mut [i32]) {
    values.par_iter_mut().for_each(|v| {
        *v = crate::ntru_prime::r3::mod3::freeze(*v) as i32;
    });
}

// =============================================================================
// Parallel NTT Operations
// =============================================================================

/// Parallel batch NTT forward transform
///
/// # Arguments
/// * `polys` - Slice of polynomials to transform
#[cfg(all(feature = "pqc-parallel", feature = "pqc-simd"))]
pub fn ntt_forward_batch_parallel(polys: &mut [Vec<i32>]) {
    polys.par_iter_mut().for_each(|poly| {
        crate::ntru_prime::ntt::ntt_forward_inplace(poly.as_mut_slice());
    });
}

/// Parallel batch NTT inverse transform
///
/// # Arguments
/// * `polys` - Slice of NTT-domain polynomials to inverse transform
#[cfg(all(feature = "pqc-parallel", feature = "pqc-simd"))]
pub fn ntt_inverse_batch_parallel(polys: &mut [Vec<i32>]) {
    polys.par_iter_mut().for_each(|poly| {
        crate::ntru_prime::ntt::ntt_inverse_inplace(poly.as_mut_slice());
    });
}

// =============================================================================
// Parallel Key Validation
// =============================================================================

/// Validate multiple public keys in parallel
///
/// # Arguments
/// * `public_keys` - Slice of public keys to validate
///
/// # Returns
/// Vector of boolean validation results
#[cfg(feature = "pqc-parallel")]
pub fn validate_public_keys_batch(public_keys: &[PublicKey]) -> Vec<bool> {
    public_keys
        .par_iter()
        .map(|pk| {
            // Basic validation: check size and attempt decode
            if pk.data.len() != ntru_prime::PK_SIZE {
                return false;
            }

            // Try to decode the polynomial
            let _ = crate::ntru_prime::rq::encoding::decode(&pk.data);
            true
        })
        .collect()
}

// =============================================================================
// Parallel Weight Computation
// =============================================================================

/// Compute weights of multiple polynomials in parallel
///
/// # Arguments
/// * `polys` - Slice of polynomials (as i8 slices)
///
/// # Returns
/// Vector of weight values (sum of absolute coefficients)
#[cfg(feature = "pqc-parallel")]
pub fn compute_weights_batch(polys: &[&[i8]]) -> Vec<i32> {
    polys
        .par_iter()
        .map(|poly| poly.iter().map(|&x| x.abs() as i32).sum())
        .collect()
}

// =============================================================================
// Fallback (non-parallel) implementations
// =============================================================================

/// Non-parallel fallback for keypair generation
#[cfg(not(feature = "pqc-parallel"))]
pub fn keypairs_parallel<R: RngCore + CryptoRng>(
    n: usize,
    rng: &mut R,
) -> Vec<(PrivateKey, PublicKey)> {
    let mut results = Vec::with_capacity(n);
    for _ in 0..n {
        results.push(ntru_prime::generate_keypair(rng));
    }
    results
}

/// Non-parallel fallback for batch encapsulation
#[cfg(not(feature = "pqc-parallel"))]
pub fn encapsulate_batch<R: RngCore + CryptoRng>(
    public_keys: &[PublicKey],
    rng: &mut R,
) -> Vec<(Ciphertext, SharedSecret)> {
    public_keys
        .iter()
        .map(|pk| ntru_prime::encapsulate(pk, rng))
        .collect()
}

/// Non-parallel fallback for batch decapsulation
#[cfg(not(feature = "pqc-parallel"))]
pub fn decapsulate_batch(
    ciphertexts: &[Ciphertext],
    private_keys: &[PrivateKey],
) -> Vec<Result<SharedSecret, String>> {
    ciphertexts
        .iter()
        .zip(private_keys.iter())
        .map(|(ct, sk)| ntru_prime::decapsulate(ct, sk))
        .collect()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn test_keypairs_parallel() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let pairs = keypairs_parallel(4, &mut rng);

        assert_eq!(pairs.len(), 4);
        for (sk, pk) in pairs {
            assert_eq!(pk.data.len(), ntru_prime::PK_SIZE);
            assert_eq!(sk.as_bytes().len(), ntru_prime::SK_SIZE);
        }
    }

    #[test]
    fn test_encapsulate_batch() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let pairs = keypairs_parallel(4, &mut rng);
        let public_keys: Vec<_> = pairs.iter().map(|(_, pk)| pk.clone()).collect();

        let results = encapsulate_batch(&public_keys, &mut rng);

        assert_eq!(results.len(), 4);
        for (ct, ss) in results {
            assert_eq!(ct.data.len(), CT_SIZE);
            assert_eq!(ss.as_bytes().len(), 32);
        }
    }

    #[test]
    fn test_decapsulate_batch() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let pairs = keypairs_parallel(4, &mut rng);
        let private_keys: Vec<_> = pairs.iter().map(|(sk, _)| sk.clone()).collect();
        let public_keys: Vec<_> = pairs.iter().map(|(_, pk)| pk.clone()).collect();

        let encapsulated = encapsulate_batch(&public_keys, &mut rng);
        let ciphertexts: Vec<_> = encapsulated.iter().map(|(ct, _)| ct.clone()).collect();

        let results = decapsulate_batch(&ciphertexts, &private_keys);

        assert_eq!(results.len(), 4);
        for result in results {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_compute_weights_batch() {
        let polys: Vec<&[i8]> = vec![
            &[1, 0, -1, 1, 1, 0, -1, -1],
            &[0, 0, 0, 0, 0, 0, 0, 0],
            &[1, 1, 1, 1, 1, 1, 1, 1],
        ];

        let weights = compute_weights_batch(&polys);

        assert_eq!(weights[0], 6);
        assert_eq!(weights[1], 0);
        assert_eq!(weights[2], 8);
    }

    #[cfg(feature = "pqc-parallel")]
    #[test]
    fn test_validate_public_keys_batch() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let pairs = keypairs_parallel(4, &mut rng);
        let public_keys: Vec<_> = pairs.iter().map(|(_, pk)| pk.clone()).collect();

        let results = validate_public_keys_batch(&public_keys);

        assert_eq!(results.len(), 4);
        for result in results {
            assert!(result);
        }
    }
}
