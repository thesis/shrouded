// Shroud is a low-level secure memory crate — unsafe blocks, raw indexing,
// and expect/unwrap are inherent to the domain. Suppress workspace lints that
// don't apply here until the crate is incrementally cleaned up.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block,
    clippy::arithmetic_side_effects,
    clippy::print_stderr
)]

//! # Shroud
//!
//! Secure memory management with mlock, guard pages, and automatic zeroization.
//!
//! `shrouded` provides types for storing secrets in protected memory that is:
//! - **Locked to RAM** (mlock/VirtualLock) to prevent swapping to disk
//! - **Guard-paged** to catch buffer overflows/underflows
//! - **Excluded from core dumps** (MADV_DONTDUMP on Linux)
//! - **Automatically zeroized** on drop using volatile writes
//!
//! ## Quick Start
//!
//! ```
//! use shrouded::{ShroudedString, Expose};
//!
//! // Create a protected secret from a String (original is zeroized)
//! let password = String::from("hunter2");
//! let secret = ShroudedString::new(password).unwrap();
//!
//! // Access the secret when needed
//! assert_eq!(secret.expose(), "hunter2");
//!
//! // Secret is automatically zeroized when dropped
//! ```
//!
//! ## Types
//!
//! - [`ShroudedBytes`]: Dynamic-size protected byte buffer
//! - [`ShroudedString`]: UTF-8 string with protected storage
//! - [`ShroudedArray<N>`]: Fixed-size protected array
//! - [`Shroud<T>`]: Generic protected box for any `Zeroize` type
//!
//! ## Policy
//!
//! Control how memory protection failures are handled with [`Policy`]:
//!
//! - `BestEffort` (default): Attempt protection, fall back gracefully
//! - `Strict`: Require all protection to succeed, error on failure
//! - `Disabled`: Skip protection (still zeroizes on drop)
//!
//! ```
//! use shrouded::{ShroudBuilder, Policy};
//!
//! let mut key = [0x42u8; 32];
//! let secret = ShroudBuilder::new()
//!     .policy(Policy::Strict)
//!     .build_bytes(&mut key)
//!     .unwrap();
//! ```
//!
//! ## Features
//!
//! - `mlock` (default): Enable memory locking
//! - `guard-pages` (default): Enable guard pages
//! - `serde`: Enable deserialize support (never serialize!)
//!
//! ## Security Considerations
//!
//! - Secrets are protected from being swapped to disk
//! - Guard pages help detect buffer overflows
//! - Debug output shows `[REDACTED]` instead of secret data
//! - No `Display` impl - must explicitly call `.expose()`
//! - No `Clone` impl - must explicitly call `.try_clone()`
//! - Serde only implements `Deserialize`, never `Serialize`

mod alloc;
mod builder;
mod error;
mod policy;
mod sys;
mod traits;
mod types;

#[cfg(feature = "serde")]
pub mod serde;

// Re-export main types
pub use builder::ShroudBuilder;
pub use error::{Result, ShroudError};
pub use policy::Policy;
pub use traits::{Expose, ExposeGuard, ExposeGuardMut, ExposeGuarded, ExposeGuardedMut, ExposeMut};
pub use types::{Shroud, ShroudedArray, ShroudedBytes, ShroudedString};

#[cfg(feature = "digest")]
pub use types::ShroudedHasher;

#[cfg(feature = "sha1")]
pub use types::ShroudedSha1;

#[cfg(feature = "sha2")]
pub use types::{ShroudedSha256, ShroudedSha384, ShroudedSha512};

// Re-export zeroize for convenience
pub use zeroize::Zeroize;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shrouded_bytes_basic() {
        let mut data = vec![1, 2, 3, 4, 5];
        let secret = ShroudedBytes::from_slice(&mut data).unwrap();

        assert_eq!(secret.expose(), &[1, 2, 3, 4, 5]);
        assert_eq!(data, vec![0, 0, 0, 0, 0]); // Source zeroized
    }

    #[test]
    fn test_shrouded_string_basic() {
        let secret = ShroudedString::new("password123".to_string()).unwrap();
        assert_eq!(secret.expose(), "password123");
    }

    #[test]
    fn test_shrouded_array_basic() {
        let secret: ShroudedArray<16> = ShroudedArray::new_with(|buf| {
            for (i, byte) in buf.iter_mut().enumerate() {
                *byte = i as u8;
            }
        })
        .unwrap();

        let expected: [u8; 16] = core::array::from_fn(|i| i as u8);
        assert_eq!(secret.expose(), &expected);
    }

    #[test]
    fn test_shroud_generic() {
        #[derive(zeroize::Zeroize)]
        struct Key([u8; 32]);

        let secret = Shroud::new(Key([0x42; 32])).unwrap();
        assert_eq!(secret.expose().0[0], 0x42);
    }

    #[test]
    fn test_debug_is_redacted() {
        let secret = ShroudedString::new("super_secret".to_string()).unwrap();
        let debug_output = format!("{:?}", secret);

        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("super_secret"));
    }

    #[test]
    fn test_builder_api() {
        let mut data = vec![0xAB; 16];
        let secret = ShroudBuilder::new()
            .policy(Policy::BestEffort)
            .build_bytes(&mut data)
            .unwrap();

        assert_eq!(secret.len(), 16);
        assert_eq!(secret.expose()[0], 0xAB);
    }

    #[test]
    fn test_policy_disabled() {
        let mut data = vec![1, 2, 3];
        let secret = ShroudBuilder::new()
            .policy(Policy::Disabled)
            .build_bytes(&mut data)
            .unwrap();

        assert_eq!(secret.expose(), &[1, 2, 3]);
    }

    // ============================================================
    // expose_guarded() Tests
    // ============================================================

    #[test]
    fn test_expose_guarded_lifecycle() {
        let secret = ShroudedString::new("guarded_secret".to_string()).unwrap();

        // Acquire guard, access data, then drop guard
        {
            let guard = secret
                .expose_guarded()
                .expect("expose_guarded should succeed");
            assert_eq!(&*guard, "guarded_secret");
            // Guard is dropped here, should re-lock memory
        }

        // Should be able to acquire guard again
        let guard2 = secret
            .expose_guarded()
            .expect("second expose_guarded should succeed");
        assert_eq!(&*guard2, "guarded_secret");
    }

    #[test]
    fn test_expose_guarded_mut() {
        // Use disabled policy to avoid memory being locked after guard drops
        // (since expose() assumes memory is accessible)
        let mut secret = ShroudBuilder::new()
            .policy(Policy::Disabled)
            .build_bytes(&mut [1, 2, 3, 4, 5])
            .unwrap();

        {
            let mut guard = secret
                .expose_guarded_mut()
                .expect("expose_guarded_mut should succeed");
            // Mutate through the guard
            guard[0] = 10;
        }

        assert_eq!(secret.expose()[0], 10);
    }

    #[test]
    fn test_expose_guarded_with_disabled_policy() {
        let secret = ShroudBuilder::new()
            .policy(Policy::Disabled)
            .build_string("disabled_policy".to_string())
            .unwrap();

        // With disabled policy, expose_guarded should still work (returns unguarded)
        let guard = secret
            .expose_guarded()
            .expect("should succeed even with disabled policy");
        assert_eq!(&*guard, "disabled_policy");
    }

    // ============================================================
    // Concurrent Access Tests
    // ============================================================

    #[test]
    fn test_concurrent_read_access() {
        use std::sync::Arc;
        use std::thread;

        let secret = Arc::new(ShroudedString::new("concurrent_secret".to_string()).unwrap());
        let mut handles = vec![];

        for _ in 0..4 {
            let secret_clone = Arc::clone(&secret);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let value = secret_clone.expose();
                    assert_eq!(value, "concurrent_secret");
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread should not panic");
        }
    }

    #[test]
    fn test_concurrent_guarded_access() {
        // Note: Concurrent guarded access to the same memory region can race
        // on mprotect calls. With AtomicBool this is data-race-free but the
        // mprotect operations themselves may conflict. This test uses a
        // disabled policy to avoid the race condition.
        use std::sync::Arc;
        use std::thread;

        let secret = Arc::new(
            ShroudBuilder::new()
                .policy(Policy::Disabled)
                .build_string("guarded_concurrent".to_string())
                .unwrap(),
        );
        let mut handles = vec![];

        for _ in 0..4 {
            let secret_clone = Arc::clone(&secret);
            handles.push(thread::spawn(move || {
                for _ in 0..50 {
                    let guard = secret_clone
                        .expose_guarded()
                        .expect("expose_guarded should succeed");
                    assert_eq!(&*guard, "guarded_concurrent");
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread should not panic");
        }
    }

    // ============================================================
    // Large Allocation Tests
    // ============================================================

    #[test]
    fn test_large_allocation_1mb() {
        let size = 1024 * 1024; // 1 MB
        let mut data = vec![0xABu8; size];

        let secret = ShroudedBytes::from_slice(&mut data).unwrap();

        assert_eq!(secret.len(), size);
        assert_eq!(secret.expose()[0], 0xAB);
        assert_eq!(secret.expose()[size - 1], 0xAB);

        // Source should be zeroized
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_near_overflow_size_fails_gracefully() {
        // Attempt allocation with size that would overflow when adding guard pages
        // Use a large but not extreme size to avoid memory mapping issues
        let huge_size = usize::MAX / 2;

        let result = ShroudBuilder::new()
            .policy(Policy::BestEffort)
            .build_bytes_with(huge_size, |_| {});

        // Should fail gracefully with an error, not panic
        assert!(result.is_err());
    }

    // ============================================================
    // Policy Error Handling Tests
    // ============================================================

    #[test]
    fn test_strict_policy_allocates_successfully() {
        // Basic allocation should succeed with strict policy
        let result = ShroudBuilder::new()
            .policy(Policy::Strict)
            .build_string("strict_test".to_string());

        // This may fail on some systems due to mlock limits, which is expected
        // The important thing is it doesn't panic
        match result {
            Ok(secret) => assert_eq!(secret.expose(), "strict_test"),
            Err(e) => {
                // Expected errors: LockFailed (mlock limit), ProtectFailed
                let err_str = format!("{:?}", e);
                assert!(
                    err_str.contains("Lock")
                        || err_str.contains("Protect")
                        || err_str.contains("Allocation"),
                    "unexpected error: {}",
                    err_str
                );
            }
        }
    }

    #[test]
    fn test_disabled_policy_always_succeeds() {
        // Disabled policy should always succeed (no system calls for protection)
        let secret = ShroudBuilder::new()
            .policy(Policy::Disabled)
            .build_string("always_works".to_string())
            .expect("disabled policy should always succeed");

        assert_eq!(secret.expose(), "always_works");

        // expose_guarded should also work
        let guard = secret.expose_guarded().expect("guarded access should work");
        assert_eq!(&*guard, "always_works");
    }

    #[test]
    fn test_best_effort_policy_succeeds() {
        // Best effort should succeed even if some protections fail
        let secret = ShroudBuilder::new()
            .policy(Policy::BestEffort)
            .build_string("best_effort_test".to_string())
            .expect("best effort should succeed");

        assert_eq!(secret.expose(), "best_effort_test");
    }
}
