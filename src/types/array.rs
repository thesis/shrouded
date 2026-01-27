//! Fixed-size protected array.

use core::fmt;
use crate::alloc::ProtectedAlloc;
use crate::error::Result;
use crate::policy::Policy;
use crate::traits::{Expose, ExposeGuard, ExposeGuardMut, ExposeGuarded, ExposeGuardedMut, ExposeMut};

/// A fixed-size protected byte array.
///
/// `ShroudedArray<N>` stores exactly `N` bytes in protected memory that is:
/// - Locked to RAM (prevents swapping to disk)
/// - Optionally surrounded by guard pages (catches buffer overflows)
/// - Excluded from core dumps (on Linux)
/// - Automatically zeroized on drop
///
/// # Example
///
/// ```
/// use shroud::{ShroudedArray, Expose};
///
/// // Create a 32-byte secret key
/// let key: ShroudedArray<32> = ShroudedArray::new_with(|buf| {
///     buf.fill(0x42);
/// }).unwrap();
///
/// assert_eq!(key.expose()[0], 0x42);
/// ```
pub struct ShroudedArray<const N: usize> {
    alloc: ProtectedAlloc,
    policy: Policy,
}

impl<const N: usize> ShroudedArray<N> {
    /// Creates a new zero-initialized `ShroudedArray`.
    pub fn new() -> Result<Self> {
        Self::new_with_policy(Policy::default())
    }

    /// Creates a new zero-initialized `ShroudedArray` with a specific policy.
    pub fn new_with_policy(policy: Policy) -> Result<Self> {
        let alloc = ProtectedAlloc::new(N, policy)?;
        Ok(Self { alloc, policy })
    }

    /// Creates a new `ShroudedArray` from a fixed-size array, zeroizing the source.
    pub fn from_array(source: [u8; N]) -> Result<Self> {
        Self::from_array_with_policy(source, Policy::default())
    }

    /// Creates a new `ShroudedArray` from a fixed-size array with a specific policy.
    pub fn from_array_with_policy(mut source: [u8; N], policy: Policy) -> Result<Self> {
        let mut alloc = ProtectedAlloc::new(N, policy)?;
        alloc.write_and_zeroize_source(&mut source)?;
        Ok(Self { alloc, policy })
    }

    /// Creates a new `ShroudedArray` initialized with a closure.
    ///
    /// The closure receives a mutable reference to the array to initialize.
    ///
    /// # Example
    ///
    /// ```
    /// use shroud::ShroudedArray;
    ///
    /// let key: ShroudedArray<16> = ShroudedArray::new_with(|buf| {
    ///     for (i, byte) in buf.iter_mut().enumerate() {
    ///         *byte = i as u8;
    ///     }
    /// }).unwrap();
    /// ```
    pub fn new_with<F>(f: F) -> Result<Self>
    where
        F: FnOnce(&mut [u8; N]),
    {
        Self::new_with_policy_and_init(Policy::default(), f)
    }

    /// Creates a new `ShroudedArray` with a specific policy, initialized with a closure.
    pub fn new_with_policy_and_init<F>(policy: Policy, f: F) -> Result<Self>
    where
        F: FnOnce(&mut [u8; N]),
    {
        let mut alloc = ProtectedAlloc::new(N, policy)?;

        // Get a reference to the buffer as an array
        let slice = alloc.as_mut_slice();
        // SAFETY: We know the allocation is exactly N bytes
        let array_ref: &mut [u8; N] = slice.try_into().expect("allocation size mismatch");
        f(array_ref);

        Ok(Self { alloc, policy })
    }

    /// Returns the size of the array.
    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns true if the array has zero size.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Creates a clone of this `ShroudedArray`.
    ///
    /// Note: This is an explicit method rather than implementing `Clone` to
    /// make cloning secrets a deliberate choice.
    pub fn try_clone(&self) -> Result<Self> {
        let mut alloc = ProtectedAlloc::new(N, self.policy)?;
        alloc.as_mut_slice().copy_from_slice(self.alloc.as_slice());
        Ok(Self {
            alloc,
            policy: self.policy,
        })
    }
}

impl<const N: usize> Expose for ShroudedArray<N> {
    type Target = [u8; N];

    #[inline]
    fn expose(&self) -> &[u8; N] {
        // SAFETY: We know the allocation is exactly N bytes
        self.alloc.as_slice().try_into().expect("allocation size mismatch")
    }
}

impl<const N: usize> ExposeMut for ShroudedArray<N> {
    #[inline]
    fn expose_mut(&mut self) -> &mut [u8; N] {
        // SAFETY: We know the allocation is exactly N bytes
        self.alloc.as_mut_slice().try_into().expect("allocation size mismatch")
    }
}

impl<const N: usize> ExposeGuarded for ShroudedArray<N> {
    fn expose_guarded(&self) -> Result<ExposeGuard<'_, [u8; N]>> {
        let array_ref: &[u8; N] = self.alloc.as_slice().try_into().expect("allocation size mismatch");
        Ok(ExposeGuard::unguarded(array_ref))
    }
}

impl<const N: usize> ExposeGuardedMut for ShroudedArray<N> {
    fn expose_guarded_mut(&mut self) -> Result<ExposeGuardMut<'_, [u8; N]>> {
        let array_ref: &mut [u8; N] = self.alloc.as_mut_slice().try_into().expect("allocation size mismatch");
        Ok(ExposeGuardMut::unguarded(array_ref))
    }
}

impl<const N: usize> fmt::Debug for ShroudedArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShroudedArray")
            .field("size", &N)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

// Explicitly do NOT implement Display to force users to use .expose()

impl<const N: usize> PartialEq for ShroudedArray<N> {
    fn eq(&self, other: &Self) -> bool {
        self.expose() == other.expose()
    }
}

impl<const N: usize> Eq for ShroudedArray<N> {}

impl<const N: usize> Default for ShroudedArray<N> {
    fn default() -> Self {
        Self::new().expect("failed to allocate ShroudedArray")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let arr: ShroudedArray<32> = ShroudedArray::new().unwrap();
        assert_eq!(arr.len(), 32);
        assert_eq!(arr.expose(), &[0u8; 32]);
    }

    #[test]
    fn test_from_array() {
        let source = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let arr = ShroudedArray::from_array(source).unwrap();

        assert_eq!(arr.expose(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_new_with() {
        let arr: ShroudedArray<16> = ShroudedArray::new_with(|buf| {
            for (i, byte) in buf.iter_mut().enumerate() {
                *byte = i as u8;
            }
        })
        .unwrap();

        let expected: [u8; 16] = core::array::from_fn(|i| i as u8);
        assert_eq!(arr.expose(), &expected);
    }

    #[test]
    fn test_try_clone() {
        let arr: ShroudedArray<8> = ShroudedArray::new_with(|buf| buf.fill(0x42)).unwrap();
        let cloned = arr.try_clone().unwrap();

        assert_eq!(arr.expose(), cloned.expose());
    }

    #[test]
    fn test_debug_redacted() {
        let arr: ShroudedArray<32> = ShroudedArray::new_with(|buf| buf.fill(0x42)).unwrap();
        let debug_str = format!("{:?}", arr);

        assert!(debug_str.contains("[REDACTED]"));
        assert!(debug_str.contains("32"));
    }

    #[test]
    fn test_expose_mut() {
        let mut arr: ShroudedArray<4> = ShroudedArray::new().unwrap();
        arr.expose_mut()[0] = 99;
        assert_eq!(arr.expose()[0], 99);
    }

    #[test]
    fn test_zero_size() {
        let arr: ShroudedArray<0> = ShroudedArray::new().unwrap();
        assert!(arr.is_empty());
        assert_eq!(arr.len(), 0);
    }
}
