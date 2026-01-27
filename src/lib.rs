//! # Shroud
//!
//! Secure memory management with mlock, guard pages, and automatic zeroization.
//!
//! `shroud` provides types for storing secrets in protected memory that is:
//! - **Locked to RAM** (mlock/VirtualLock) to prevent swapping to disk
//! - **Guard-paged** to catch buffer overflows/underflows
//! - **Excluded from core dumps** (MADV_DONTDUMP on Linux)
//! - **Automatically zeroized** on drop using volatile writes
//!
//! ## Quick Start
//!
//! ```
//! use shroud::{ShroudedString, Expose};
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
//! use shroud::{ShroudBuilder, Policy};
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

mod error;
mod policy;
mod traits;
mod alloc;
mod builder;
mod types;
mod sys;

#[cfg(feature = "serde")]
pub mod serde;

// Re-export main types
pub use error::{Result, ShroudError};
pub use policy::Policy;
pub use traits::{Expose, ExposeGuard, ExposeGuardMut, ExposeGuarded, ExposeGuardedMut, ExposeMut};
pub use builder::ShroudBuilder;
pub use types::{Shroud, ShroudedArray, ShroudedBytes, ShroudedString};

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
        }).unwrap();

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
}
