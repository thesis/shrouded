//! Builder pattern for configuring shrouded types.

use crate::error::Result;
use crate::policy::Policy;
use crate::types::{ShroudedArray, ShroudedBytes, ShroudedString};

/// A builder for creating shrouded types with custom configuration.
///
/// # Example
///
/// ```
/// use shrouded::{ShroudBuilder, Policy, Expose};
///
/// let mut data = vec![0x42u8; 32];
/// let secret = ShroudBuilder::new()
///     .policy(Policy::Strict)
///     .build_bytes(&mut data)
///     .unwrap();
///
/// assert_eq!(secret.expose()[0], 0x42);
/// ```
#[derive(Debug, Clone)]
pub struct ShroudBuilder {
    policy: Policy,
}

impl Default for ShroudBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ShroudBuilder {
    /// Creates a new builder with default settings.
    pub fn new() -> Self {
        Self {
            policy: Policy::default(),
        }
    }

    /// Sets the memory protection policy.
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// Builds a `ShroudedBytes` from a slice, zeroizing the source.
    pub fn build_bytes(self, source: &mut [u8]) -> Result<ShroudedBytes> {
        ShroudedBytes::from_slice_with_policy(source, self.policy)
    }

    /// Builds a `ShroudedBytes` of the given length, initialized with a closure.
    pub fn build_bytes_with<F>(self, len: usize, f: F) -> Result<ShroudedBytes>
    where
        F: FnOnce(&mut [u8]),
    {
        ShroudedBytes::new_with_policy(len, self.policy, f)
    }

    /// Builds a `ShroudedString` from a String, consuming and zeroizing it.
    pub fn build_string(self, source: String) -> Result<ShroudedString> {
        ShroudedString::new_with_policy(source, self.policy)
    }

    /// Builds a `ShroudedString` from a mutable string slice, zeroizing the source.
    pub fn build_string_from_str(self, source: &mut str) -> Result<ShroudedString> {
        ShroudedString::from_str_mut_with_policy(source, self.policy)
    }

    /// Builds a `ShroudedArray` of the given size, zero-initialized.
    pub fn build_array<const N: usize>(self) -> Result<ShroudedArray<N>> {
        ShroudedArray::new_with_policy(self.policy)
    }

    /// Builds a `ShroudedArray` from a fixed-size array, zeroizing the source.
    pub fn build_array_from<const N: usize>(self, source: [u8; N]) -> Result<ShroudedArray<N>> {
        ShroudedArray::from_array_with_policy(source, self.policy)
    }

    /// Builds a `ShroudedArray` initialized with a closure.
    pub fn build_array_with<const N: usize, F>(self, f: F) -> Result<ShroudedArray<N>>
    where
        F: FnOnce(&mut [u8; N]),
    {
        ShroudedArray::new_with_policy_and_init(self.policy, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Expose;

    #[test]
    fn test_builder_bytes() {
        let mut data = vec![1, 2, 3, 4, 5];
        let secret = ShroudBuilder::new()
            .policy(Policy::BestEffort)
            .build_bytes(&mut data)
            .unwrap();

        assert_eq!(secret.expose(), &[1, 2, 3, 4, 5]);
        assert_eq!(data, vec![0, 0, 0, 0, 0]); // Source zeroized
    }

    #[test]
    fn test_builder_bytes_with() {
        let secret = ShroudBuilder::new()
            .build_bytes_with(10, |buf| {
                for (i, byte) in buf.iter_mut().enumerate() {
                    *byte = i as u8;
                }
            })
            .unwrap();

        assert_eq!(secret.expose(), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_builder_string() {
        let secret = ShroudBuilder::new()
            .policy(Policy::Disabled)
            .build_string("password".to_string())
            .unwrap();

        assert_eq!(secret.expose(), "password");
    }

    #[test]
    fn test_builder_array() {
        let secret: ShroudedArray<32> = ShroudBuilder::new()
            .policy(Policy::Strict)
            .build_array()
            .unwrap();

        assert_eq!(secret.expose(), &[0u8; 32]);
    }

    #[test]
    fn test_builder_array_with() {
        let secret: ShroudedArray<8> = ShroudBuilder::new()
            .build_array_with(|buf| buf.fill(0x42))
            .unwrap();

        assert_eq!(secret.expose(), &[0x42u8; 8]);
    }
}
