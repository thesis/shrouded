//! Generic protected box for any Zeroize type.

use core::fmt;
use core::mem;
use zeroize::Zeroize;
use crate::alloc::ProtectedAlloc;
use crate::error::{Result, ShroudError};
use crate::policy::Policy;
use crate::traits::{Expose, ExposeGuard, ExposeGuardMut, ExposeGuarded, ExposeGuardedMut, ExposeMut};

/// A generic protected box for any type implementing `Zeroize`.
///
/// `Shroud<T>` stores a value of type `T` in protected memory that is:
/// - Locked to RAM (prevents swapping to disk)
/// - Optionally surrounded by guard pages (catches buffer overflows)
/// - Excluded from core dumps (on Linux)
/// - Automatically zeroized on drop (via `Zeroize` trait)
///
/// # Heap Limitations
///
/// The value is moved into protected memory. If the value was originally
/// on the heap (e.g., `Vec`, `String`), the original heap allocation may
/// still contain remnants of the data. For maximum security with heap types,
/// prefer:
/// - `ShroudedBytes` for byte vectors
/// - `ShroudedString` for strings
/// - `ShroudedArray<N>` for fixed-size data
///
/// `Shroud<T>` is best for stack-allocated types like:
/// - Fixed-size arrays: `[u8; 32]`
/// - Structs containing only stack data
/// - Primitive types
///
/// # Example
///
/// ```
/// use shroud::{Shroud, Expose};
/// use zeroize::Zeroize;
///
/// #[derive(Zeroize)]
/// struct SecretKey {
///     key: [u8; 32],
///     nonce: [u8; 12],
/// }
///
/// let secret = Shroud::new(SecretKey {
///     key: [0x42; 32],
///     nonce: [0x00; 12],
/// }).unwrap();
///
/// assert_eq!(secret.expose().key[0], 0x42);
/// ```
pub struct Shroud<T: Zeroize> {
    alloc: ProtectedAlloc,
    #[allow(dead_code)]
    policy: Policy,
    _marker: core::marker::PhantomData<T>,
}

impl<T: Zeroize> Shroud<T> {
    /// Creates a new `Shroud<T>` containing the given value.
    ///
    /// The value is moved into protected memory. See struct documentation
    /// for heap limitations.
    pub fn new(value: T) -> Result<Self> {
        Self::new_with_policy(value, Policy::default())
    }

    /// Creates a new `Shroud<T>` with a specific policy.
    pub fn new_with_policy(value: T, policy: Policy) -> Result<Self> {
        let size = mem::size_of::<T>();
        let align = mem::align_of::<T>();
        if size == 0 {
            return Err(ShroudError::AllocationFailed(
                "cannot shroud zero-sized types".to_string(),
            ));
        }

        let mut alloc = ProtectedAlloc::new_aligned(size, align, policy)?;

        // Copy the value into protected memory
        // SAFETY: alloc is properly sized and aligned for T
        unsafe {
            let ptr = alloc.as_mut_slice().as_mut_ptr() as *mut T;
            ptr.write(value);
        }

        Ok(Self {
            alloc,
            policy,
            _marker: core::marker::PhantomData,
        })
    }

    /// Creates a new `Shroud<T>` initialized with a closure.
    ///
    /// This avoids ever having the value on the stack, providing maximum
    /// security for sensitive data.
    ///
    /// # Example
    ///
    /// ```
    /// use shroud::Shroud;
    /// use zeroize::Zeroize;
    ///
    /// #[derive(Zeroize, Default)]
    /// struct Key([u8; 32]);
    ///
    /// let secret = Shroud::new_with(|| Key([0x42; 32])).unwrap();
    /// ```
    pub fn new_with<F>(f: F) -> Result<Self>
    where
        F: FnOnce() -> T,
    {
        Self::new_with_policy_and_init(Policy::default(), f)
    }

    /// Creates a new `Shroud<T>` with a specific policy, initialized with a closure.
    pub fn new_with_policy_and_init<F>(policy: Policy, f: F) -> Result<Self>
    where
        F: FnOnce() -> T,
    {
        let size = mem::size_of::<T>();
        let align = mem::align_of::<T>();
        if size == 0 {
            return Err(ShroudError::AllocationFailed(
                "cannot shroud zero-sized types".to_string(),
            ));
        }

        let mut alloc = ProtectedAlloc::new_aligned(size, align, policy)?;

        // Initialize the value directly in protected memory
        // This minimizes the time the value exists on the stack
        let value = f();
        unsafe {
            let ptr = alloc.as_mut_slice().as_mut_ptr() as *mut T;
            ptr.write(value);
        }

        Ok(Self {
            alloc,
            policy,
            _marker: core::marker::PhantomData,
        })
    }

    /// Returns the size of the contained type in bytes.
    #[inline]
    pub const fn size(&self) -> usize {
        mem::size_of::<T>()
    }

    /// Performs a constant-time byte comparison of the underlying memory.
    ///
    /// This is safe for types where byte equality implies value equality
    /// (e.g., arrays, simple structs without padding). For types with padding
    /// or non-trivial representations, use the `PartialEq` implementation instead.
    ///
    /// # Warning
    /// This compares raw bytes and may not be appropriate for types with padding
    /// bytes or platform-dependent representations.
    pub fn ct_eq(&self, other: &Self) -> subtle::Choice {
        use subtle::ConstantTimeEq;
        self.alloc.as_slice().ct_eq(other.alloc.as_slice())
    }
}

impl<T: Zeroize> Expose for Shroud<T> {
    type Target = T;

    #[inline]
    fn expose(&self) -> &T {
        // SAFETY: The memory was properly initialized with a T value
        unsafe { &*(self.alloc.as_slice().as_ptr() as *const T) }
    }
}

impl<T: Zeroize> ExposeMut for Shroud<T> {
    #[inline]
    fn expose_mut(&mut self) -> &mut T {
        // SAFETY: The memory was properly initialized with a T value
        unsafe { &mut *(self.alloc.as_mut_slice().as_mut_ptr() as *mut T) }
    }
}

impl<T: Zeroize> ExposeGuarded for Shroud<T> {
    fn expose_guarded(&self) -> Result<ExposeGuard<'_, T>> {
        // SAFETY: The memory was properly initialized with a T value
        let value_ref = unsafe { &*(self.alloc.as_slice().as_ptr() as *const T) };
        Ok(ExposeGuard::unguarded(value_ref))
    }
}

impl<T: Zeroize> ExposeGuardedMut for Shroud<T> {
    fn expose_guarded_mut(&mut self) -> Result<ExposeGuardMut<'_, T>> {
        // SAFETY: The memory was properly initialized with a T value
        let value_ref = unsafe { &mut *(self.alloc.as_mut_slice().as_mut_ptr() as *mut T) };
        Ok(ExposeGuardMut::unguarded(value_ref))
    }
}

impl<T: Zeroize> Drop for Shroud<T> {
    fn drop(&mut self) {
        // Call Zeroize on the value before the ProtectedAlloc zeroizes the raw bytes
        // SAFETY: The memory contains a valid T value
        unsafe {
            let ptr = self.alloc.as_mut_slice().as_mut_ptr() as *mut T;
            (*ptr).zeroize();
        }
    }
}

impl<T: Zeroize> fmt::Debug for Shroud<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shroud")
            .field("type", &core::any::type_name::<T>())
            .field("size", &mem::size_of::<T>())
            .field("data", &"[REDACTED]")
            .finish()
    }
}

// Explicitly do NOT implement Clone - cloning secrets should be deliberate
// Explicitly do NOT implement Display - force users to use .expose()

impl<T: Zeroize + PartialEq> PartialEq for Shroud<T> {
    fn eq(&self, other: &Self) -> bool {
        self.expose() == other.expose()
    }
}

impl<T: Zeroize + Eq> Eq for Shroud<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Zeroize, PartialEq, Eq, Debug)]
    struct TestKey {
        data: [u8; 32],
    }

    #[test]
    fn test_new() {
        let key = TestKey { data: [0x42; 32] };
        let secret = Shroud::new(key).unwrap();

        assert_eq!(secret.expose().data[0], 0x42);
        assert_eq!(secret.size(), mem::size_of::<TestKey>());
    }

    #[test]
    fn test_new_with() {
        let secret = Shroud::new_with(|| TestKey { data: [0x42; 32] }).unwrap();
        assert_eq!(secret.expose().data[0], 0x42);
    }

    #[test]
    fn test_expose_mut() {
        let mut secret = Shroud::new(TestKey { data: [0x00; 32] }).unwrap();
        secret.expose_mut().data[0] = 0x99;
        assert_eq!(secret.expose().data[0], 0x99);
    }

    #[test]
    fn test_debug_redacted() {
        let secret = Shroud::new(TestKey { data: [0x42; 32] }).unwrap();
        let debug_str = format!("{:?}", secret);

        assert!(debug_str.contains("[REDACTED]"));
        assert!(debug_str.contains("TestKey"));
    }

    #[test]
    fn test_equality() {
        let a = Shroud::new(TestKey { data: [0x42; 32] }).unwrap();
        let b = Shroud::new(TestKey { data: [0x42; 32] }).unwrap();
        let c = Shroud::new(TestKey { data: [0x00; 32] }).unwrap();

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_primitive_array() {
        let secret: Shroud<[u8; 16]> = Shroud::new([0x42u8; 16]).unwrap();
        assert_eq!(secret.expose()[0], 0x42);
    }
}
