//! Protected hasher with state in guarded memory.

use core::fmt;
use core::mem;
use digest::{FixedOutputReset, Output, OutputSizeUser, Update};
use zeroize::Zeroize;

use crate::alloc::ProtectedAlloc;
use crate::error::{Result, ShroudError};
use crate::policy::Policy;
use crate::types::{ShroudedArray, ShroudedBytes};

/// A hasher that keeps its internal state in protected memory.
///
/// `ShroudedHasher<D>` wraps any `digest`-compatible hasher in protected memory
/// that is:
/// - Locked to RAM (prevents swapping to disk)
/// - Optionally surrounded by guard pages (catches buffer overflows)
/// - Excluded from core dumps (on Linux)
/// - Automatically zeroized on drop
///
/// # Security
///
/// When calling `finalize_reset()`, the output is briefly in a `GenericArray`
/// on the stack before being copied to protected memory. The temporary is
/// zeroized immediately after copying. This is unavoidable with the current
/// `digest` API.
///
/// # Example
///
/// ```ignore
/// use shroud::{ShroudedSha256, Expose};
///
/// let mut hasher = ShroudedSha256::new().unwrap();
/// hasher.update(b"hello world");
/// let hash = hasher.finalize_reset_array::<32>().unwrap();
///
/// // Hash is now in protected memory
/// assert_eq!(hash.expose().len(), 32);
/// ```
pub struct ShroudedHasher<D>
where
    D: FixedOutputReset + Update + Default,
{
    alloc: ProtectedAlloc,
    _marker: core::marker::PhantomData<D>,
}

impl<D> ShroudedHasher<D>
where
    D: FixedOutputReset + Update + Default,
{
    /// Creates a new `ShroudedHasher` with the default policy.
    pub fn new() -> Result<Self> {
        Self::new_with_policy(Policy::default())
    }

    /// Creates a new `ShroudedHasher` with a specific policy.
    pub fn new_with_policy(policy: Policy) -> Result<Self> {
        let size = mem::size_of::<D>();
        let align = mem::align_of::<D>();

        if size == 0 {
            return Err(ShroudError::AllocationFailed(
                "cannot shroud zero-sized hasher".to_string(),
            ));
        }

        let mut alloc = ProtectedAlloc::new_aligned(size, align, policy)?;

        // Initialize the hasher in protected memory
        let value = D::default();
        // SAFETY: alloc is properly sized and aligned for D
        unsafe {
            let ptr = alloc.as_mut_slice().as_mut_ptr() as *mut D;
            ptr.write(value);
        }

        Ok(Self {
            alloc,
            _marker: core::marker::PhantomData,
        })
    }

    /// Returns a mutable reference to the inner hasher.
    #[inline]
    fn inner_mut(&mut self) -> &mut D {
        // SAFETY: The memory was properly initialized with a D value
        unsafe { &mut *(self.alloc.as_mut_slice().as_mut_ptr() as *mut D) }
    }

    /// Updates the hasher with input data.
    pub fn update(&mut self, data: &[u8]) {
        self.inner_mut().update(data);
    }

    /// Updates the hasher with input data, returning self for chaining.
    pub fn chain_update(mut self, data: &[u8]) -> Self {
        self.update(data);
        self
    }

    /// Writes the hash output to the provided buffer and resets the hasher.
    ///
    /// This is the most efficient method when you need to store the output
    /// in your own buffer.
    pub fn finalize_into_reset(&mut self, out: &mut Output<D>) {
        self.inner_mut().finalize_into_reset(out);
    }

    /// Computes the hash and returns it in protected memory.
    ///
    /// The hasher is reset and can be reused for additional computations.
    ///
    /// # Security Note
    ///
    /// The hash output is briefly on the stack before being copied to
    /// protected memory. The stack copy is zeroized immediately after.
    pub fn finalize_reset(&mut self) -> Result<ShroudedBytes> {
        let mut output = Output::<D>::default();
        self.finalize_into_reset(&mut output);

        // Copy to protected memory, then zeroize the stack copy
        let result = ShroudedBytes::from_slice(output.as_mut_slice());
        output.zeroize();
        result
    }

    /// Computes the hash and returns it as a fixed-size protected array.
    ///
    /// # Panics
    ///
    /// Panics if `N` does not match the digest output size.
    ///
    /// # Security Note
    ///
    /// The hash output is briefly on the stack before being copied to
    /// protected memory. The stack copy is zeroized immediately after.
    pub fn finalize_reset_array<const N: usize>(&mut self) -> Result<ShroudedArray<N>> {
        let mut output = Output::<D>::default();
        self.finalize_into_reset(&mut output);

        assert_eq!(
            output.len(),
            N,
            "output size {} does not match requested array size {}",
            output.len(),
            N
        );

        // Copy to protected memory, then zeroize the stack copy
        let array: [u8; N] = output.as_slice().try_into().expect("size already verified");
        output.zeroize();
        ShroudedArray::from_array(array)
    }

    /// Resets the hasher to its initial state without producing output.
    pub fn reset(&mut self) {
        // Create a new default hasher and write it over the old one
        // The old state will be overwritten (effectively zeroized by the new state)
        let new_hasher = D::default();
        // SAFETY: The memory is properly sized and aligned for D
        unsafe {
            let ptr = self.alloc.as_mut_slice().as_mut_ptr() as *mut D;
            // Drop the old value (important for types with non-trivial Drop)
            core::ptr::drop_in_place(ptr);
            // Write the new value
            ptr.write(new_hasher);
        }
    }
}

impl<D> Drop for ShroudedHasher<D>
where
    D: FixedOutputReset + Update + Default,
{
    fn drop(&mut self) {
        // Drop the hasher value before ProtectedAlloc zeroizes the raw bytes
        // SAFETY: The memory contains a valid D value
        unsafe {
            let ptr = self.alloc.as_mut_slice().as_mut_ptr() as *mut D;
            core::ptr::drop_in_place(ptr);
        }
        // ProtectedAlloc will zeroize the memory when it drops
    }
}

impl<D> fmt::Debug for ShroudedHasher<D>
where
    D: FixedOutputReset + Update + Default + OutputSizeUser,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShroudedHasher")
            .field("algorithm", &core::any::type_name::<D>())
            .field("output_size", &D::output_size())
            .field("state", &"[REDACTED]")
            .finish()
    }
}

// Type aliases for common hash algorithms

/// SHA-1 hasher with protected state.
///
/// # Security Warning
///
/// SHA-1 is cryptographically broken and should only be used for legacy
/// compatibility (e.g., HIBP k-anonymity API). Do not use for new designs.
#[cfg(feature = "sha1")]
pub type ShroudedSha1 = ShroudedHasher<sha1::Sha1>;

/// SHA-256 hasher with protected state.
#[cfg(feature = "sha2")]
pub type ShroudedSha256 = ShroudedHasher<sha2::Sha256>;

/// SHA-384 hasher with protected state.
#[cfg(feature = "sha2")]
pub type ShroudedSha384 = ShroudedHasher<sha2::Sha384>;

/// SHA-512 hasher with protected state.
#[cfg(feature = "sha2")]
pub type ShroudedSha512 = ShroudedHasher<sha2::Sha512>;

// ============================================================================
// Test utilities
// ============================================================================

#[cfg(all(test, feature = "digest"))]
mod test_utils {
    use super::*;
    use digest::Digest;

    /// Helper to compute hash using standard digest crate and compare with ShroudedHasher
    pub fn compare_with_standard<D>(input: &[u8])
    where
        D: Digest + FixedOutputReset + Update + Default,
    {
        use crate::Expose;

        // Compute using standard digest
        let expected = D::digest(input);

        // Compute using ShroudedHasher
        let mut shrouded = ShroudedHasher::<D>::new().unwrap();
        shrouded.update(input);
        let actual = shrouded.finalize_reset().unwrap();

        assert_eq!(
            actual.expose(),
            expected.as_slice(),
            "Hash mismatch for input of length {}",
            input.len()
        );
    }

    /// Helper to test incremental hashing matches single-shot
    pub fn compare_incremental_vs_single<D>(chunks: &[&[u8]])
    where
        D: Digest + FixedOutputReset + Update + Default,
    {
        use crate::Expose;

        // Compute single-shot
        let combined: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        let mut single_shot = ShroudedHasher::<D>::new().unwrap();
        single_shot.update(&combined);
        let expected = single_shot.finalize_reset().unwrap();

        // Compute incrementally
        let mut incremental = ShroudedHasher::<D>::new().unwrap();
        for chunk in chunks {
            incremental.update(chunk);
        }
        let actual = incremental.finalize_reset().unwrap();

        assert_eq!(
            actual.expose(),
            expected.expose(),
            "Incremental hashing mismatch"
        );
    }
}

// ============================================================================
// SHA-256 Tests
// ============================================================================

#[cfg(all(test, feature = "sha2"))]
mod sha256_tests {
    use super::*;
    use crate::Expose;
    use digest::Digest;

    // ------------------------------------------------------------------------
    // Known Answer Tests (KATs)
    // ------------------------------------------------------------------------

    #[test]
    fn test_empty_string() {
        let mut hasher = ShroudedSha256::new().unwrap();
        let hash = hasher.finalize_reset_array::<32>().unwrap();
        assert_eq!(
            hex::encode(hash.expose()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_single_char_a() {
        super::test_utils::compare_with_standard::<sha2::Sha256>(b"a");
    }

    #[test]
    fn test_abc() {
        let mut hasher = ShroudedSha256::new().unwrap();
        hasher.update(b"abc");
        let hash = hasher.finalize_reset_array::<32>().unwrap();
        // NIST test vector
        assert_eq!(
            hex::encode(hash.expose()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_448_bits() {
        // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let mut hasher = ShroudedSha256::new().unwrap();
        hasher.update(input);
        let hash = hasher.finalize_reset_array::<32>().unwrap();
        // NIST test vector
        assert_eq!(
            hex::encode(hash.expose()),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn test_896_bits() {
        // "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        let input = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let mut hasher = ShroudedSha256::new().unwrap();
        hasher.update(input);
        let hash = hasher.finalize_reset_array::<32>().unwrap();
        // NIST test vector
        assert_eq!(
            hex::encode(hash.expose()),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
    }

    #[test]
    fn test_password() {
        let mut hasher = ShroudedSha256::new().unwrap();
        hasher.update(b"password");
        let hash = hasher.finalize_reset_array::<32>().unwrap();
        assert_eq!(
            hex::encode(hash.expose()),
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        );
    }

    // ------------------------------------------------------------------------
    // Comparison with standard digest crate
    // ------------------------------------------------------------------------

    #[test]
    fn test_compare_standard_empty() {
        super::test_utils::compare_with_standard::<sha2::Sha256>(b"");
    }

    #[test]
    fn test_compare_standard_single_byte() {
        for byte in 0u8..=255 {
            super::test_utils::compare_with_standard::<sha2::Sha256>(&[byte]);
        }
    }

    #[test]
    fn test_compare_standard_various_lengths() {
        for len in [
            1, 2, 31, 32, 33, 55, 56, 57, 63, 64, 65, 100, 128, 256, 512, 1000,
        ] {
            let input: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            super::test_utils::compare_with_standard::<sha2::Sha256>(&input);
        }
    }

    #[test]
    fn test_compare_standard_block_boundaries() {
        // SHA-256 has 64-byte blocks
        for len in 62..=66 {
            let input: Vec<u8> = vec![0x42; len];
            super::test_utils::compare_with_standard::<sha2::Sha256>(&input);
        }
        for len in 126..=130 {
            let input: Vec<u8> = vec![0x42; len];
            super::test_utils::compare_with_standard::<sha2::Sha256>(&input);
        }
    }

    #[test]
    fn test_compare_standard_all_zeros() {
        for len in [0, 1, 32, 64, 100, 1024] {
            let input = vec![0u8; len];
            super::test_utils::compare_with_standard::<sha2::Sha256>(&input);
        }
    }

    #[test]
    fn test_compare_standard_all_ones() {
        for len in [0, 1, 32, 64, 100, 1024] {
            let input = vec![0xffu8; len];
            super::test_utils::compare_with_standard::<sha2::Sha256>(&input);
        }
    }

    // ------------------------------------------------------------------------
    // Incremental hashing tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_incremental_single_bytes() {
        let input = b"hello world";
        let chunks: Vec<&[u8]> = input.iter().map(std::slice::from_ref).collect();
        super::test_utils::compare_incremental_vs_single::<sha2::Sha256>(&chunks);
    }

    #[test]
    fn test_incremental_various_chunk_sizes() {
        let input: Vec<u8> = (0..256).map(|i| i as u8).collect();

        // Split into chunks of varying sizes
        let chunks: Vec<&[u8]> = vec![
            &input[0..10],
            &input[10..15],
            &input[15..64],
            &input[64..65],
            &input[65..200],
            &input[200..],
        ];
        super::test_utils::compare_incremental_vs_single::<sha2::Sha256>(&chunks);
    }

    #[test]
    fn test_incremental_empty_chunks() {
        let chunks: Vec<&[u8]> = vec![b"", b"hello", b"", b" ", b"", b"world", b""];
        super::test_utils::compare_incremental_vs_single::<sha2::Sha256>(&chunks);
    }

    // ------------------------------------------------------------------------
    // Hasher reuse tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_reuse_after_finalize() {
        let mut hasher = ShroudedSha256::new().unwrap();

        hasher.update(b"first");
        let h1 = hasher.finalize_reset_array::<32>().unwrap();

        hasher.update(b"second");
        let h2 = hasher.finalize_reset_array::<32>().unwrap();

        // Verify both are correct independent hashes
        assert_eq!(
            hex::encode(h1.expose()),
            hex::encode(sha2::Sha256::digest(b"first"))
        );
        assert_eq!(
            hex::encode(h2.expose()),
            hex::encode(sha2::Sha256::digest(b"second"))
        );
    }

    #[test]
    fn test_reuse_many_times() {
        let mut hasher = ShroudedSha256::new().unwrap();

        for i in 0..100 {
            let input = format!("input_{}", i);
            hasher.update(input.as_bytes());
            let hash = hasher.finalize_reset().unwrap();

            let expected = sha2::Sha256::digest(input.as_bytes());
            assert_eq!(
                hash.expose(),
                expected.as_slice(),
                "Mismatch at iteration {}",
                i
            );
        }
    }

    #[test]
    fn test_reset() {
        let mut hasher = ShroudedSha256::new().unwrap();
        hasher.update(b"some data that will be discarded");
        hasher.reset();
        let hash = hasher.finalize_reset_array::<32>().unwrap();

        // Should be hash of empty string
        assert_eq!(
            hex::encode(hash.expose()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // ------------------------------------------------------------------------
    // Output format tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_finalize_reset_vs_finalize_reset_array() {
        let mut hasher1 = ShroudedSha256::new().unwrap();
        let mut hasher2 = ShroudedSha256::new().unwrap();

        hasher1.update(b"test");
        hasher2.update(b"test");

        let bytes = hasher1.finalize_reset().unwrap();
        let array = hasher2.finalize_reset_array::<32>().unwrap();

        assert_eq!(bytes.expose(), array.expose().as_slice());
    }

    #[test]
    fn test_finalize_into_reset() {
        let mut hasher = ShroudedSha256::new().unwrap();
        hasher.update(b"test");

        let mut output = digest::Output::<sha2::Sha256>::default();
        hasher.finalize_into_reset(&mut output);

        let expected = sha2::Sha256::digest(b"test");
        assert_eq!(output.as_slice(), expected.as_slice());
    }

    // ------------------------------------------------------------------------
    // Chain update tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_chain_update() {
        let hash = ShroudedSha256::new()
            .unwrap()
            .chain_update(b"hello")
            .chain_update(b" ")
            .chain_update(b"world")
            .finalize_reset_array::<32>()
            .unwrap();

        let expected = sha2::Sha256::digest(b"hello world");
        assert_eq!(hash.expose().as_slice(), expected.as_slice());
    }

    // ------------------------------------------------------------------------
    // Debug output tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_debug_redacted() {
        let hasher = ShroudedSha256::new().unwrap();
        let debug_str = format!("{:?}", hasher);

        assert!(debug_str.contains("[REDACTED]"));
        assert!(debug_str.contains("ShroudedHasher"));
        assert!(debug_str.contains("output_size"));
    }
}

// ============================================================================
// SHA-384 Tests
// ============================================================================

#[cfg(all(test, feature = "sha2"))]
mod sha384_tests {
    use super::*;
    use crate::Expose;
    use digest::Digest;

    #[test]
    fn test_empty_string() {
        let mut hasher = ShroudedSha384::new().unwrap();
        let hash = hasher.finalize_reset_array::<48>().unwrap();
        let expected = sha2::Sha384::digest(b"");
        assert_eq!(hash.expose().as_slice(), expected.as_slice());
    }

    #[test]
    fn test_abc() {
        let mut hasher = ShroudedSha384::new().unwrap();
        hasher.update(b"abc");
        let hash = hasher.finalize_reset_array::<48>().unwrap();
        // NIST test vector
        assert_eq!(
            hex::encode(hash.expose()),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn test_compare_standard_various_lengths() {
        for len in [0, 1, 64, 128, 256, 512, 1000] {
            let input: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            super::test_utils::compare_with_standard::<sha2::Sha384>(&input);
        }
    }

    #[test]
    fn test_compare_standard_block_boundaries() {
        // SHA-384 has 128-byte blocks
        for len in 126..=130 {
            let input: Vec<u8> = vec![0x42; len];
            super::test_utils::compare_with_standard::<sha2::Sha384>(&input);
        }
    }

    #[test]
    fn test_incremental() {
        let chunks: Vec<&[u8]> = vec![b"hello", b" ", b"world"];
        super::test_utils::compare_incremental_vs_single::<sha2::Sha384>(&chunks);
    }

    #[test]
    fn test_reuse() {
        let mut hasher = ShroudedSha384::new().unwrap();

        for i in 0..20 {
            let input = format!("test_{}", i);
            hasher.update(input.as_bytes());
            let hash = hasher.finalize_reset().unwrap();

            let expected = sha2::Sha384::digest(input.as_bytes());
            assert_eq!(hash.expose(), expected.as_slice());
        }
    }
}

// ============================================================================
// SHA-512 Tests
// ============================================================================

#[cfg(all(test, feature = "sha2"))]
mod sha512_tests {
    use super::*;
    use crate::Expose;
    use digest::Digest;

    #[test]
    fn test_empty_string() {
        let mut hasher = ShroudedSha512::new().unwrap();
        let hash = hasher.finalize_reset_array::<64>().unwrap();
        let expected = sha2::Sha512::digest(b"");
        assert_eq!(hash.expose().as_slice(), expected.as_slice());
    }

    #[test]
    fn test_abc() {
        let mut hasher = ShroudedSha512::new().unwrap();
        hasher.update(b"abc");
        let hash = hasher.finalize_reset_array::<64>().unwrap();
        // NIST test vector
        assert_eq!(
            hex::encode(hash.expose()),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn test_compare_standard_various_lengths() {
        for len in [0, 1, 64, 128, 256, 512, 1000] {
            let input: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            super::test_utils::compare_with_standard::<sha2::Sha512>(&input);
        }
    }

    #[test]
    fn test_compare_standard_block_boundaries() {
        // SHA-512 has 128-byte blocks
        for len in 126..=130 {
            let input: Vec<u8> = vec![0x42; len];
            super::test_utils::compare_with_standard::<sha2::Sha512>(&input);
        }
    }

    #[test]
    fn test_incremental() {
        let chunks: Vec<&[u8]> = vec![b"hello", b" ", b"world"];
        super::test_utils::compare_incremental_vs_single::<sha2::Sha512>(&chunks);
    }

    #[test]
    fn test_reuse() {
        let mut hasher = ShroudedSha512::new().unwrap();

        for i in 0..20 {
            let input = format!("test_{}", i);
            hasher.update(input.as_bytes());
            let hash = hasher.finalize_reset().unwrap();

            let expected = sha2::Sha512::digest(input.as_bytes());
            assert_eq!(hash.expose(), expected.as_slice());
        }
    }
}

// ============================================================================
// SHA-1 Tests
// ============================================================================

#[cfg(all(test, feature = "sha1"))]
mod sha1_tests {
    use super::*;
    use crate::Expose;
    use digest::Digest;

    #[test]
    fn test_empty_string() {
        let mut hasher = ShroudedSha1::new().unwrap();
        let hash = hasher.finalize_reset_array::<20>().unwrap();
        // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        assert_eq!(
            hex::encode(hash.expose()),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn test_abc() {
        let mut hasher = ShroudedSha1::new().unwrap();
        hasher.update(b"abc");
        let hash = hasher.finalize_reset_array::<20>().unwrap();
        // NIST test vector
        assert_eq!(
            hex::encode(hash.expose()),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn test_password() {
        let mut hasher = ShroudedSha1::new().unwrap();
        hasher.update(b"password");
        let hash = hasher.finalize_reset_array::<20>().unwrap();
        assert_eq!(
            hex::encode(hash.expose()),
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
        );
    }

    #[test]
    fn test_448_bits() {
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let mut hasher = ShroudedSha1::new().unwrap();
        hasher.update(input);
        let hash = hasher.finalize_reset_array::<20>().unwrap();
        // NIST test vector
        assert_eq!(
            hex::encode(hash.expose()),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn test_compare_standard_empty() {
        super::test_utils::compare_with_standard::<sha1::Sha1>(b"");
    }

    #[test]
    fn test_compare_standard_single_byte() {
        for byte in 0u8..=255 {
            super::test_utils::compare_with_standard::<sha1::Sha1>(&[byte]);
        }
    }

    #[test]
    fn test_compare_standard_various_lengths() {
        for len in [
            1, 2, 31, 32, 33, 55, 56, 57, 63, 64, 65, 100, 128, 256, 512, 1000,
        ] {
            let input: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            super::test_utils::compare_with_standard::<sha1::Sha1>(&input);
        }
    }

    #[test]
    fn test_compare_standard_block_boundaries() {
        // SHA-1 has 64-byte blocks
        for len in 62..=66 {
            let input: Vec<u8> = vec![0x42; len];
            super::test_utils::compare_with_standard::<sha1::Sha1>(&input);
        }
    }

    #[test]
    fn test_incremental_single_bytes() {
        let input = b"hello world";
        let chunks: Vec<&[u8]> = input.iter().map(std::slice::from_ref).collect();
        super::test_utils::compare_incremental_vs_single::<sha1::Sha1>(&chunks);
    }

    #[test]
    fn test_incremental_various_chunk_sizes() {
        let input: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let chunks: Vec<&[u8]> = vec![
            &input[0..10],
            &input[10..15],
            &input[15..64],
            &input[64..65],
            &input[65..200],
            &input[200..],
        ];
        super::test_utils::compare_incremental_vs_single::<sha1::Sha1>(&chunks);
    }

    #[test]
    fn test_reuse() {
        let mut hasher = ShroudedSha1::new().unwrap();

        for i in 0..50 {
            let input = format!("test_{}", i);
            hasher.update(input.as_bytes());
            let hash = hasher.finalize_reset().unwrap();

            let expected = sha1::Sha1::digest(input.as_bytes());
            assert_eq!(
                hash.expose(),
                expected.as_slice(),
                "Mismatch at iteration {}",
                i
            );
        }
    }

    #[test]
    fn test_reset() {
        let mut hasher = ShroudedSha1::new().unwrap();
        hasher.update(b"discard this");
        hasher.reset();
        let hash = hasher.finalize_reset_array::<20>().unwrap();

        assert_eq!(
            hex::encode(hash.expose()),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }
}

// ============================================================================
// Property-based / Fuzz Tests
// ============================================================================

#[cfg(all(test, feature = "sha2"))]
mod proptest_sha2 {
    use super::*;
    use crate::Expose;
    use digest::Digest;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn fuzz_sha256_matches_standard(input in prop::collection::vec(any::<u8>(), 0..4096)) {
            let expected = sha2::Sha256::digest(&input);
            let mut shrouded = ShroudedSha256::new().unwrap();
            shrouded.update(&input);
            let actual = shrouded.finalize_reset().unwrap();
            prop_assert_eq!(actual.expose(), expected.as_slice());
        }

        #[test]
        fn fuzz_sha384_matches_standard(input in prop::collection::vec(any::<u8>(), 0..4096)) {
            let expected = sha2::Sha384::digest(&input);
            let mut shrouded = ShroudedSha384::new().unwrap();
            shrouded.update(&input);
            let actual = shrouded.finalize_reset().unwrap();
            prop_assert_eq!(actual.expose(), expected.as_slice());
        }

        #[test]
        fn fuzz_sha512_matches_standard(input in prop::collection::vec(any::<u8>(), 0..4096)) {
            let expected = sha2::Sha512::digest(&input);
            let mut shrouded = ShroudedSha512::new().unwrap();
            shrouded.update(&input);
            let actual = shrouded.finalize_reset().unwrap();
            prop_assert_eq!(actual.expose(), expected.as_slice());
        }

        #[test]
        fn fuzz_sha256_incremental_matches_single_shot(
            chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..512), 1..10)
        ) {
            let combined: Vec<u8> = chunks.iter().flatten().copied().collect();

            // Single-shot
            let mut single = ShroudedSha256::new().unwrap();
            single.update(&combined);
            let expected = single.finalize_reset().unwrap();

            // Incremental
            let mut incremental = ShroudedSha256::new().unwrap();
            for chunk in &chunks {
                incremental.update(chunk);
            }
            let actual = incremental.finalize_reset().unwrap();

            prop_assert_eq!(actual.expose(), expected.expose());
        }

        #[test]
        fn fuzz_sha256_reuse_consistency(inputs in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..256), 1..20)) {
            let mut hasher = ShroudedSha256::new().unwrap();

            for input in inputs {
                hasher.update(&input);
                let actual = hasher.finalize_reset().unwrap();
                let expected = sha2::Sha256::digest(&input);
                prop_assert_eq!(actual.expose(), expected.as_slice());
            }
        }

        #[test]
        fn fuzz_sha256_reset_produces_empty_hash(garbage in prop::collection::vec(any::<u8>(), 1..1024)) {
            let mut hasher = ShroudedSha256::new().unwrap();
            hasher.update(&garbage);
            hasher.reset();
            let actual = hasher.finalize_reset().unwrap();
            let expected = sha2::Sha256::digest(b"");
            prop_assert_eq!(actual.expose(), expected.as_slice());
        }
    }
}

#[cfg(all(test, feature = "sha1"))]
mod proptest_sha1 {
    use super::*;
    use crate::Expose;
    use digest::Digest;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn fuzz_sha1_matches_standard(input in prop::collection::vec(any::<u8>(), 0..4096)) {
            let expected = sha1::Sha1::digest(&input);
            let mut shrouded = ShroudedSha1::new().unwrap();
            shrouded.update(&input);
            let actual = shrouded.finalize_reset().unwrap();
            prop_assert_eq!(actual.expose(), expected.as_slice());
        }

        #[test]
        fn fuzz_sha1_incremental_matches_single_shot(
            chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..512), 1..10)
        ) {
            let combined: Vec<u8> = chunks.iter().flatten().copied().collect();

            // Single-shot
            let mut single = ShroudedSha1::new().unwrap();
            single.update(&combined);
            let expected = single.finalize_reset().unwrap();

            // Incremental
            let mut incremental = ShroudedSha1::new().unwrap();
            for chunk in &chunks {
                incremental.update(chunk);
            }
            let actual = incremental.finalize_reset().unwrap();

            prop_assert_eq!(actual.expose(), expected.expose());
        }

        #[test]
        fn fuzz_sha1_reuse_consistency(inputs in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..256), 1..20)) {
            let mut hasher = ShroudedSha1::new().unwrap();

            for input in inputs {
                hasher.update(&input);
                let actual = hasher.finalize_reset().unwrap();
                let expected = sha1::Sha1::digest(&input);
                prop_assert_eq!(actual.expose(), expected.as_slice());
            }
        }
    }
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[cfg(all(test, feature = "sha2"))]
mod edge_case_tests {
    use super::*;
    use crate::Expose;
    use digest::Digest;

    #[test]
    fn test_large_input() {
        // 1 MB of data
        let input: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

        let expected = sha2::Sha256::digest(&input);
        let mut shrouded = ShroudedSha256::new().unwrap();
        shrouded.update(&input);
        let actual = shrouded.finalize_reset().unwrap();

        assert_eq!(actual.expose(), expected.as_slice());
    }

    #[test]
    fn test_many_small_updates() {
        let mut shrouded = ShroudedSha256::new().unwrap();
        let mut standard = sha2::Sha256::new();

        // 10,000 single-byte updates
        for i in 0..10_000u16 {
            let byte = (i % 256) as u8;
            shrouded.update(&[byte]);
            Digest::update(&mut standard, [byte]);
        }

        let actual = shrouded.finalize_reset().unwrap();
        let expected = standard.finalize();

        assert_eq!(actual.expose(), expected.as_slice());
    }

    #[test]
    fn test_alternating_empty_and_data() {
        let mut shrouded = ShroudedSha256::new().unwrap();
        let mut standard = sha2::Sha256::new();

        for i in 0..100 {
            shrouded.update(b"");
            Digest::update(&mut standard, b"");
            let data = format!("{}", i);
            shrouded.update(data.as_bytes());
            Digest::update(&mut standard, data.as_bytes());
            shrouded.update(b"");
            Digest::update(&mut standard, b"");
        }

        let actual = shrouded.finalize_reset().unwrap();
        let expected = standard.finalize();

        assert_eq!(actual.expose(), expected.as_slice());
    }

    #[test]
    fn test_binary_patterns() {
        // Test various binary patterns that might cause issues
        let patterns: Vec<Vec<u8>> = vec![
            vec![0x00; 100],                     // all zeros
            vec![0xff; 100],                     // all ones
            vec![0x80; 100],                     // high bit set
            vec![0x7f; 100],                     // high bit clear
            (0..256).map(|i| i as u8).collect(), // all byte values
            [0x00, 0xff].repeat(50),             // alternating
        ];

        for pattern in patterns {
            let expected = sha2::Sha256::digest(&pattern);
            let mut shrouded = ShroudedSha256::new().unwrap();
            shrouded.update(&pattern);
            let actual = shrouded.finalize_reset().unwrap();
            assert_eq!(actual.expose(), expected.as_slice());
        }
    }

    #[test]
    fn test_exactly_one_block() {
        // SHA-256 block size is 64 bytes
        let input = vec![0x42u8; 64];
        super::test_utils::compare_with_standard::<sha2::Sha256>(&input);
    }

    #[test]
    fn test_exactly_two_blocks() {
        let input = vec![0x42u8; 128];
        super::test_utils::compare_with_standard::<sha2::Sha256>(&input);
    }

    #[test]
    fn test_padding_boundary() {
        // SHA-256 adds 9 bytes of padding (1 byte 0x80 + 8 bytes length)
        // So 55 bytes of data + 9 bytes padding = 64 bytes (exactly one block)
        // And 56 bytes of data needs 2 blocks
        for len in 54..=58 {
            let input = vec![0x42u8; len];
            super::test_utils::compare_with_standard::<sha2::Sha256>(&input);
        }
    }
}
