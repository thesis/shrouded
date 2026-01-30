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
///
/// # Why `expose()` is infallible
///
/// The `expose()` method returns a direct reference without calling `mprotect()`.
/// This is intentional: by default, protected memory is allocated with read/write
/// permissions (PROT_READ | PROT_WRITE). The memory is always accessible unless
/// you explicitly call `make_inaccessible()` or use `expose_guarded()`.
///
/// This design provides ergonomic access for common cases where you just need
/// to read the secret value. For maximum security with automatic re-locking,
/// use [`ExposeGuarded::expose_guarded()`] instead.
pub trait Expose {
    /// The type of the exposed data.
    type Target: ?Sized;

    /// Exposes the protected data as an immutable reference.
    ///
    /// This method is infallible because it assumes the memory is already
    /// accessible (the default state after allocation). It does not call
    /// `mprotect()` or modify memory permissions.
    ///
    /// For maximum security, prefer [`ExposeGuarded::expose_guarded()`] which
    /// temporarily unlocks memory and automatically re-locks it when done.
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
///
/// # Why `expose_guarded()` is fallible
///
/// Unlike [`Expose::expose()`], this method must call `mprotect()` to change
/// memory permissions from PROT_NONE to readable. This system call can fail
/// due to:
///
/// - Invalid memory region (shouldn't happen with proper use)
/// - Kernel resource limits
/// - Memory already unmapped
///
/// The guard automatically calls `mprotect()` again on drop to restore
/// PROT_NONE protection, minimizing the exposure window.
///
/// # When to use guarded vs unguarded access
///
/// - Use `expose()` when you need quick access and acceptable security
/// - Use `expose_guarded()` when you want memory to be inaccessible except
///   during the brief access window (defense against memory inspection attacks)
pub trait ExposeGuarded: Expose {
    /// Exposes the protected data with a guard that re-locks on drop.
    ///
    /// This method calls `mprotect()` to make the memory readable, then returns
    /// a guard that will call `mprotect()` again to make it inaccessible when
    /// dropped.
    ///
    /// Returns an error if the memory protection cannot be changed.
    fn expose_guarded(&self) -> Result<ExposeGuard<'_, Self::Target>>;
}

/// Trait for types that support mutable guarded access with automatic re-locking.
pub trait ExposeGuardedMut: ExposeGuarded + ExposeMut {
    /// Exposes the protected data mutably with a guard that re-locks on drop.
    fn expose_guarded_mut(&mut self) -> Result<ExposeGuardMut<'_, Self::Target>>;
}
