//! Dynamic-size protected byte buffer.

use crate::alloc::ProtectedAlloc;
use crate::error::Result;
use crate::policy::Policy;
use crate::traits::{
    Expose, ExposeGuard, ExposeGuardMut, ExposeGuarded, ExposeGuardedMut, ExposeMut,
};
use core::fmt;

/// A dynamic-size protected byte buffer.
///
/// `ShroudedBytes` stores arbitrary binary data in protected memory that is:
/// - Locked to RAM (prevents swapping to disk)
/// - Optionally surrounded by guard pages (catches buffer overflows)
/// - Excluded from core dumps (on Linux)
/// - Automatically zeroized on drop
///
/// # Example
///
/// ```
/// use shroud::{ShroudedBytes, Expose};
///
/// // Create from a slice (source is zeroized)
/// let mut key_data = vec![0x42u8; 32];
/// let secret = ShroudedBytes::from_slice(&mut key_data).unwrap();
///
/// // Access the protected data
/// assert_eq!(secret.expose()[0], 0x42);
///
/// // Original data was zeroized
/// assert!(key_data.iter().all(|&b| b == 0));
/// ```
pub struct ShroudedBytes {
    alloc: ProtectedAlloc,
    len: usize,
    policy: Policy,
}

impl ShroudedBytes {
    /// Creates a new `ShroudedBytes` by copying from a slice and zeroizing the source.
    ///
    /// The source slice is zeroized after the data is copied to protected memory.
    pub fn from_slice(source: &mut [u8]) -> Result<Self> {
        Self::from_slice_with_policy(source, Policy::default())
    }

    /// Creates a new `ShroudedBytes` with a specific policy.
    pub fn from_slice_with_policy(source: &mut [u8], policy: Policy) -> Result<Self> {
        let len = source.len();
        let mut alloc = ProtectedAlloc::new(len, policy)?;
        alloc.write_and_zeroize_source(source)?;
        Ok(Self { alloc, len, policy })
    }

    /// Creates a new `ShroudedBytes` of the given length, initialized with a closure.
    ///
    /// The closure receives a mutable slice of the protected memory to initialize.
    ///
    /// # Example
    ///
    /// ```
    /// use shroud::ShroudedBytes;
    ///
    /// let secret = ShroudedBytes::new_with(32, |buf| {
    ///     // Initialize with some pattern
    ///     for (i, byte) in buf.iter_mut().enumerate() {
    ///         *byte = i as u8;
    ///     }
    /// }).unwrap();
    /// ```
    pub fn new_with<F>(len: usize, f: F) -> Result<Self>
    where
        F: FnOnce(&mut [u8]),
    {
        Self::new_with_policy(len, Policy::default(), f)
    }

    /// Creates a new `ShroudedBytes` with a specific policy, initialized with a closure.
    pub fn new_with_policy<F>(len: usize, policy: Policy, f: F) -> Result<Self>
    where
        F: FnOnce(&mut [u8]),
    {
        let mut alloc = ProtectedAlloc::new(len, policy)?;
        f(alloc.as_mut_slice());
        Ok(Self { alloc, len, policy })
    }

    /// Creates an empty `ShroudedBytes`.
    pub fn empty() -> Result<Self> {
        Ok(Self {
            alloc: ProtectedAlloc::new(0, Policy::default())?,
            len: 0,
            policy: Policy::default(),
        })
    }

    /// Returns the length of the protected data in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the protected data is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Creates a clone of this `ShroudedBytes`.
    ///
    /// Returns `Err(ShroudError::RegionLocked)` if the memory is currently
    /// protected. Use `expose_guarded()` to access protected data instead.
    ///
    /// Note: This is an explicit method rather than implementing `Clone` to
    /// make cloning secrets a deliberate choice.
    pub fn try_clone(&self) -> Result<Self> {
        if self.alloc.is_protected() {
            return Err(crate::error::ShroudError::RegionLocked);
        }
        let mut alloc = ProtectedAlloc::new(self.len, self.policy)?;
        alloc.as_mut_slice().copy_from_slice(self.alloc.as_slice());
        Ok(Self {
            alloc,
            len: self.len,
            policy: self.policy,
        })
    }
}

impl Expose for ShroudedBytes {
    type Target = [u8];

    #[inline]
    fn expose(&self) -> &[u8] {
        &self.alloc.as_slice()[..self.len]
    }
}

impl ExposeMut for ShroudedBytes {
    #[inline]
    fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.alloc.as_mut_slice()[..self.len]
    }
}

impl ExposeGuarded for ShroudedBytes {
    fn expose_guarded(&self) -> Result<ExposeGuard<'_, [u8]>> {
        if self.policy.protection_enabled() {
            self.alloc.make_readable()?;
            let alloc_ref = &self.alloc;
            let data = &self.alloc.as_slice()[..self.len];

            Ok(ExposeGuard::new(data, move || {
                let _ = alloc_ref.make_inaccessible();
            }))
        } else {
            Ok(ExposeGuard::unguarded(&self.alloc.as_slice()[..self.len]))
        }
    }
}

impl ExposeGuardedMut for ShroudedBytes {
    fn expose_guarded_mut(&mut self) -> Result<ExposeGuardMut<'_, [u8]>> {
        if self.policy.protection_enabled() {
            self.alloc.make_writable()?;
            let alloc_ptr = &self.alloc as *const ProtectedAlloc;
            let data = &mut self.alloc.as_mut_slice()[..self.len];

            Ok(ExposeGuardMut::new(data, move || {
                // SAFETY: The guard holds a mutable borrow of self, so alloc is still alive
                unsafe {
                    let _ = (*alloc_ptr).make_inaccessible();
                }
            }))
        } else {
            Ok(ExposeGuardMut::unguarded(
                &mut self.alloc.as_mut_slice()[..self.len],
            ))
        }
    }
}

impl fmt::Debug for ShroudedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShroudedBytes")
            .field("len", &self.len)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

// Explicitly do NOT implement Display to force users to use .expose()

impl PartialEq for ShroudedBytes {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        if self.len != other.len {
            return false;
        }
        self.expose().ct_eq(other.expose()).into()
    }
}

impl Eq for ShroudedBytes {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_slice() {
        let mut data = vec![1, 2, 3, 4, 5];
        let secret = ShroudedBytes::from_slice(&mut data).unwrap();

        assert_eq!(secret.len(), 5);
        assert_eq!(secret.expose(), &[1, 2, 3, 4, 5]);

        // Source should be zeroized
        assert_eq!(data, vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_new_with() {
        let secret = ShroudedBytes::new_with(10, |buf| {
            for (i, byte) in buf.iter_mut().enumerate() {
                *byte = i as u8;
            }
        })
        .unwrap();

        assert_eq!(secret.len(), 10);
        assert_eq!(secret.expose(), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_empty() {
        let secret = ShroudedBytes::empty().unwrap();
        assert!(secret.is_empty());
        assert_eq!(secret.len(), 0);
    }

    #[test]
    fn test_try_clone() {
        let mut data = vec![42u8; 16];
        let secret = ShroudedBytes::from_slice(&mut data).unwrap();
        let cloned = secret.try_clone().unwrap();

        assert_eq!(secret.expose(), cloned.expose());
    }

    #[test]
    fn test_try_clone_fails_on_protected_memory() {
        let mut data = vec![42u8; 16];
        let secret = ShroudedBytes::from_slice(&mut data).unwrap();

        // expose_guarded() makes memory inaccessible when the guard drops
        {
            let _guard = secret.expose_guarded().unwrap();
        }

        // try_clone must return Err, not bypass protection
        let result = secret.try_clone();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::error::ShroudError::RegionLocked
        ));
    }

    #[test]
    fn test_debug_redacted() {
        let mut data = vec![0x42u8; 32];
        let secret = ShroudedBytes::from_slice(&mut data).unwrap();
        let debug_str = format!("{:?}", secret);

        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("42"));
    }

    #[test]
    fn test_expose_mut() {
        let mut secret = ShroudedBytes::new_with(5, |buf| {
            buf.fill(0);
        })
        .unwrap();

        secret.expose_mut()[0] = 99;
        assert_eq!(secret.expose()[0], 99);
    }
}
