//! UTF-8 string with protected storage.

use core::fmt;
use crate::error::{Result, ShroudError};
use crate::policy::Policy;
use crate::traits::{Expose, ExposeGuard, ExposeGuardMut, ExposeGuarded, ExposeGuardedMut, ExposeMut};
use crate::alloc::ProtectedAlloc;

/// A UTF-8 string stored in protected memory.
///
/// `ShroudedString` stores string data in protected memory that is:
/// - Locked to RAM (prevents swapping to disk)
/// - Optionally surrounded by guard pages (catches buffer overflows)
/// - Excluded from core dumps (on Linux)
/// - Automatically zeroized on drop
///
/// # Example
///
/// ```
/// use shroud::{ShroudedString, Expose};
///
/// // Create from a String (consumes and zeroizes the original)
/// let password = String::from("hunter2");
/// let secret = ShroudedString::new(password).unwrap();
///
/// assert_eq!(secret.expose(), "hunter2");
/// ```
pub struct ShroudedString {
    alloc: ProtectedAlloc,
    len: usize,
    policy: Policy,
}

impl ShroudedString {
    /// Creates a new `ShroudedString` from a `String`, consuming and zeroizing it.
    ///
    /// The original `String` is zeroized after copying to protected memory.
    pub fn new(source: String) -> Result<Self> {
        Self::new_with_policy(source, Policy::default())
    }

    /// Creates a new `ShroudedString` with a specific policy.
    pub fn new_with_policy(mut source: String, policy: Policy) -> Result<Self> {
        let len = source.len();
        let mut alloc = ProtectedAlloc::new(len, policy)?;

        // SAFETY: String's underlying bytes are valid for mutation.
        // Use write_and_zeroize_source to atomically copy and zeroize,
        // avoiding a window where the secret exists in both locations.
        unsafe {
            let bytes = source.as_bytes_mut();
            alloc.write_and_zeroize_source(bytes)?;
        }
        drop(source);

        Ok(Self { alloc, len, policy })
    }

    /// Creates a new `ShroudedString` from a mutable string slice, zeroizing the source.
    pub fn from_str_mut(source: &mut str) -> Result<Self> {
        Self::from_str_mut_with_policy(source, Policy::default())
    }

    /// Creates a new `ShroudedString` from a mutable string slice with a specific policy.
    pub fn from_str_mut_with_policy(source: &mut str, policy: Policy) -> Result<Self> {
        let len = source.len();
        let mut alloc = ProtectedAlloc::new(len, policy)?;

        // SAFETY: Zeroizing the string is safe, all zeros is valid UTF-8.
        // Use write_and_zeroize_source to atomically copy and zeroize,
        // avoiding a window where the secret exists in both locations.
        unsafe {
            let bytes = source.as_bytes_mut();
            alloc.write_and_zeroize_source(bytes)?;
        }

        Ok(Self { alloc, len, policy })
    }

    /// Creates a new `ShroudedString` by copying from an immutable string slice.
    ///
    /// Use this when the source is in memory you don't control (e.g., from another
    /// crate like `keepass`). The source cannot be zeroized since it's immutable,
    /// but this avoids creating an intermediate heap allocation that `.to_string()`
    /// would require.
    ///
    /// # Example
    ///
    /// ```
    /// use shroud::{ShroudedString, Expose};
    ///
    /// // Copy from a &str without intermediate allocation
    /// let secret = ShroudedString::from_str("password").unwrap();
    /// assert_eq!(secret.expose(), "password");
    /// ```
    pub fn from_str(source: &str) -> Result<Self> {
        Self::from_str_with_policy(source, Policy::default())
    }

    /// Creates a new `ShroudedString` by copying from an immutable string slice
    /// with a specific policy.
    ///
    /// The source cannot be zeroized since it's immutable. Use this when copying
    /// from memory you don't control.
    pub fn from_str_with_policy(source: &str, policy: Policy) -> Result<Self> {
        let len = source.len();
        let mut alloc = ProtectedAlloc::new(len, policy)?;
        alloc.as_mut_slice()[..len].copy_from_slice(source.as_bytes());
        Ok(Self { alloc, len, policy })
    }

    /// Creates an empty `ShroudedString`.
    pub fn empty() -> Result<Self> {
        Ok(Self {
            alloc: ProtectedAlloc::new(0, Policy::default())?,
            len: 0,
            policy: Policy::default(),
        })
    }

    /// Returns the length of the string in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the string is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Creates a clone of this `ShroudedString`.
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
        alloc.as_mut_slice().copy_from_slice(&self.alloc.as_slice()[..self.len]);
        Ok(Self {
            alloc,
            len: self.len,
            policy: self.policy,
        })
    }

    /// Returns the string as bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.alloc.as_slice()[..self.len]
    }
}

impl Expose for ShroudedString {
    type Target = str;

    #[inline]
    fn expose(&self) -> &str {
        // SAFETY: We validated UTF-8 on construction
        unsafe { core::str::from_utf8_unchecked(&self.alloc.as_slice()[..self.len]) }
    }
}

impl ExposeMut for ShroudedString {
    #[inline]
    fn expose_mut(&mut self) -> &mut str {
        // SAFETY: We validated UTF-8 on construction
        unsafe { core::str::from_utf8_unchecked_mut(&mut self.alloc.as_mut_slice()[..self.len]) }
    }
}

impl ExposeGuarded for ShroudedString {
    fn expose_guarded(&self) -> Result<ExposeGuard<'_, str>> {
        if self.policy.protection_enabled() {
            self.alloc.make_readable()?;
            let alloc_ref = &self.alloc;
            // SAFETY: We validated UTF-8 on construction
            let s = unsafe { core::str::from_utf8_unchecked(&self.alloc.as_slice()[..self.len]) };

            Ok(ExposeGuard::new(s, move || {
                let _ = alloc_ref.make_inaccessible();
            }))
        } else {
            // SAFETY: We validated UTF-8 on construction
            let s = unsafe { core::str::from_utf8_unchecked(&self.alloc.as_slice()[..self.len]) };
            Ok(ExposeGuard::unguarded(s))
        }
    }
}

impl ExposeGuardedMut for ShroudedString {
    fn expose_guarded_mut(&mut self) -> Result<ExposeGuardMut<'_, str>> {
        if self.policy.protection_enabled() {
            self.alloc.make_writable()?;
            let alloc_ptr = &self.alloc as *const ProtectedAlloc;
            // SAFETY: We validated UTF-8 on construction
            let s = unsafe {
                core::str::from_utf8_unchecked_mut(&mut self.alloc.as_mut_slice()[..self.len])
            };

            Ok(ExposeGuardMut::new(s, move || {
                // SAFETY: The guard holds a mutable borrow of self, so alloc is still alive
                unsafe {
                    let _ = (*alloc_ptr).make_inaccessible();
                }
            }))
        } else {
            // SAFETY: We validated UTF-8 on construction
            let s = unsafe {
                core::str::from_utf8_unchecked_mut(&mut self.alloc.as_mut_slice()[..self.len])
            };
            Ok(ExposeGuardMut::unguarded(s))
        }
    }
}

impl fmt::Debug for ShroudedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShroudedString")
            .field("len", &self.len)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

// Explicitly do NOT implement Display to force users to use .expose()

impl PartialEq for ShroudedString {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        if self.len != other.len {
            return false;
        }
        self.as_bytes().ct_eq(other.as_bytes()).into()
    }
}

impl Eq for ShroudedString {}

impl TryFrom<String> for ShroudedString {
    type Error = ShroudError;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<&str> for ShroudedString {
    type Error = ShroudError;

    fn try_from(value: &str) -> Result<Self> {
        // Note: This creates a copy since we can't zeroize a &str
        Self::new(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let password = String::from("hunter2");
        let secret = ShroudedString::new(password).unwrap();

        assert_eq!(secret.expose(), "hunter2");
        assert_eq!(secret.len(), 7);
    }

    #[test]
    fn test_empty() {
        let secret = ShroudedString::empty().unwrap();
        assert!(secret.is_empty());
        assert_eq!(secret.expose(), "");
    }

    #[test]
    fn test_from_str() {
        // This copies directly without intermediate String allocation
        let secret = ShroudedString::from_str("hunter2").unwrap();
        assert_eq!(secret.expose(), "hunter2");
        assert_eq!(secret.len(), 7);
    }

    #[test]
    fn test_from_str_empty() {
        let secret = ShroudedString::from_str("").unwrap();
        assert!(secret.is_empty());
        assert_eq!(secret.expose(), "");
    }

    #[test]
    fn test_from_str_equals_new() {
        // Verify from_str produces same result as new()
        let from_str = ShroudedString::from_str("test").unwrap();
        let from_new = ShroudedString::new("test".to_string()).unwrap();
        assert_eq!(from_str, from_new);
    }

    #[test]
    fn test_try_clone() {
        let secret = ShroudedString::new("secret".to_string()).unwrap();
        let cloned = secret.try_clone().unwrap();

        assert_eq!(secret.expose(), cloned.expose());
    }

    #[test]
    fn test_debug_redacted() {
        let secret = ShroudedString::new("password123".to_string()).unwrap();
        let debug_str = format!("{:?}", secret);

        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("password123"));
    }

    #[test]
    fn test_as_bytes() {
        let secret = ShroudedString::new("hello".to_string()).unwrap();
        assert_eq!(secret.as_bytes(), b"hello");
    }

    #[test]
    fn test_try_from_string() {
        let secret: ShroudedString = String::from("test").try_into().unwrap();
        assert_eq!(secret.expose(), "test");
    }

    #[test]
    fn test_equality() {
        let a = ShroudedString::new("same".to_string()).unwrap();
        let b = ShroudedString::new("same".to_string()).unwrap();
        let c = ShroudedString::new("different".to_string()).unwrap();

        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
