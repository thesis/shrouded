//! Traits for exposing protected secret data.

use crate::error::Result;

/// A guard that provides temporary access to protected memory.
///
/// When dropped, the guard re-locks the memory region (sets PROT_NONE on Unix),
/// preventing any access until another guard is acquired.
pub struct ExposeGuard<'a, T: ?Sized> {
    data: &'a T,
    /// Called on drop to re-lock the memory region.
    relock: Option<Box<dyn FnOnce() + 'a>>,
}

impl<'a, T: ?Sized> ExposeGuard<'a, T> {
    /// Creates a new expose guard.
    ///
    /// # Safety
    /// The caller must ensure that calling `relock` is safe after the guard
    /// is dropped and that the data reference remains valid.
    pub(crate) fn new(data: &'a T, relock: impl FnOnce() + 'a) -> Self {
        Self {
            data,
            relock: Some(Box::new(relock)),
        }
    }

    /// Creates a guard without re-locking behavior.
    pub(crate) fn unguarded(data: &'a T) -> Self {
        Self { data, relock: None }
    }
}

impl<T: ?Sized> core::ops::Deref for ExposeGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.data
    }
}

impl<T: ?Sized> Drop for ExposeGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(relock) = self.relock.take() {
            relock();
        }
    }
}

/// A mutable guard that provides temporary write access to protected memory.
pub struct ExposeGuardMut<'a, T: ?Sized> {
    data: &'a mut T,
    /// Called on drop to re-lock the memory region.
    relock: Option<Box<dyn FnOnce() + 'a>>,
}

impl<'a, T: ?Sized> ExposeGuardMut<'a, T> {
    /// Creates a new mutable expose guard.
    pub(crate) fn new(data: &'a mut T, relock: impl FnOnce() + 'a) -> Self {
        Self {
            data,
            relock: Some(Box::new(relock)),
        }
    }

    /// Creates a guard without re-locking behavior.
    pub(crate) fn unguarded(data: &'a mut T) -> Self {
        Self { data, relock: None }
    }
}

impl<T: ?Sized> core::ops::Deref for ExposeGuardMut<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.data
    }
}

impl<T: ?Sized> core::ops::DerefMut for ExposeGuardMut<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data
    }
}

impl<T: ?Sized> Drop for ExposeGuardMut<'_, T> {
    fn drop(&mut self) {
        if let Some(relock) = self.relock.take() {
            relock();
        }
    }
}

/// Trait for types that can expose their protected contents as an immutable reference.
pub trait Expose {
    /// The type of the exposed data.
    type Target: ?Sized;

    /// Exposes the protected data as an immutable reference.
    ///
    /// This is the most convenient API but provides no automatic re-locking.
    /// For maximum security, prefer `expose_guarded()` when available.
    fn expose(&self) -> &Self::Target;
}

/// Trait for types that can expose their protected contents as a mutable reference.
pub trait ExposeMut: Expose {
    /// Exposes the protected data as a mutable reference.
    fn expose_mut(&mut self) -> &mut Self::Target;
}

/// Trait for types that support guarded access with automatic re-locking.
///
/// The returned guard temporarily unlocks memory protection (if supported) and
/// automatically re-locks it when dropped. This provides the highest security
/// by minimizing the window during which secrets are readable.
pub trait ExposeGuarded: Expose {
    /// Exposes the protected data with a guard that re-locks on drop.
    ///
    /// Returns an error if the memory region cannot be unlocked.
    fn expose_guarded(&self) -> Result<ExposeGuard<'_, Self::Target>>;
}

/// Trait for types that support mutable guarded access with automatic re-locking.
pub trait ExposeGuardedMut: ExposeGuarded + ExposeMut {
    /// Exposes the protected data mutably with a guard that re-locks on drop.
    fn expose_guarded_mut(&mut self) -> Result<ExposeGuardMut<'_, Self::Target>>;
}
