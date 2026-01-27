//! Platform-specific memory protection implementations.

use crate::error::Result;
use crate::policy::Policy;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
mod fallback;

/// Page size for the current platform.
#[allow(dead_code)]
pub fn page_size() -> usize {
    platform_impl::page_size()
}

/// Allocates a protected memory region.
///
/// The returned region will have:
/// - Memory locked to physical RAM (mlock) if enabled
/// - Guard pages before and after (if enabled)
/// - Core dump exclusion (MADV_DONTDUMP on Linux)
pub fn allocate(size: usize, policy: Policy) -> Result<MemoryRegion> {
    platform_impl::allocate(size, policy)
}

/// A protected memory region.
///
/// This struct manages the lifecycle of protected memory, including:
/// - Page-aligned allocation with optional guard pages
/// - Memory locking (mlock/VirtualLock)
/// - Core dump exclusion
/// - Zeroization and cleanup on drop
pub struct MemoryRegion {
    /// Pointer to the usable data area (after the leading guard page, if any).
    ptr: *mut u8,
    /// Size of the usable data area in bytes.
    len: usize,
    /// Pointer to the start of the entire allocation (including guard pages).
    alloc_ptr: *mut u8,
    /// Total size of the allocation (including guard pages).
    alloc_len: usize,
    /// Whether memory is currently locked with mlock.
    is_locked: bool,
    /// Whether guard pages are present.
    #[allow(dead_code)]
    has_guard_pages: bool,
    /// Whether memory is currently set to PROT_NONE (inaccessible).
    is_protected: bool,
}

// SAFETY: MemoryRegion manages its own memory and synchronization.
// The data it points to is not shared across threads without external synchronization.
unsafe impl Send for MemoryRegion {}
unsafe impl Sync for MemoryRegion {}

impl MemoryRegion {
    /// Returns the pointer to the usable data area.
    #[inline]
    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    /// Returns a mutable pointer to the usable data area.
    #[inline]
    #[allow(dead_code)]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    /// Returns the size of the usable data area in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the region has zero length.
    #[inline]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the data as a byte slice.
    ///
    /// # Safety
    /// The memory must not be protected (PROT_NONE). Use `make_readable()` first.
    #[inline]
    pub unsafe fn as_slice(&self) -> &[u8] {
        core::slice::from_raw_parts(self.ptr, self.len)
    }

    /// Returns the data as a mutable byte slice.
    ///
    /// # Safety
    /// The memory must not be protected (PROT_NONE). Use `make_writable()` first.
    #[inline]
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        core::slice::from_raw_parts_mut(self.ptr, self.len)
    }

    /// Returns whether the memory is currently set to PROT_NONE.
    #[inline]
    pub fn is_protected(&self) -> bool {
        self.is_protected
    }

    /// Makes the memory region readable (PROT_READ).
    #[allow(dead_code)]
    pub fn make_readable(&mut self) -> Result<()> {
        if !self.is_protected {
            return Ok(());
        }
        platform_impl::protect(self.ptr, self.len, Protection::Read)?;
        self.is_protected = false;
        Ok(())
    }

    /// Makes the memory region readable and writable (PROT_READ | PROT_WRITE).
    pub fn make_writable(&mut self) -> Result<()> {
        if !self.is_protected {
            return Ok(());
        }
        platform_impl::protect(self.ptr, self.len, Protection::ReadWrite)?;
        self.is_protected = false;
        Ok(())
    }

    /// Makes the memory region inaccessible (PROT_NONE).
    pub fn make_inaccessible(&mut self) -> Result<()> {
        if self.is_protected {
            return Ok(());
        }
        platform_impl::protect(self.ptr, self.len, Protection::None)?;
        self.is_protected = true;
        Ok(())
    }

    /// Zeroizes the memory contents using volatile writes.
    fn zeroize(&mut self) {
        if self.len == 0 {
            return;
        }

        // Temporarily make memory writable if protected
        let was_protected = self.is_protected;
        if was_protected {
            let _ = self.make_writable();
        }

        // Use volatile writes to prevent optimizer from eliding the zeroization
        unsafe {
            let slice = core::slice::from_raw_parts_mut(self.ptr, self.len);
            for byte in slice.iter_mut() {
                core::ptr::write_volatile(byte, 0);
            }
        }
        // Memory barrier to ensure the writes complete
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        // Restore protection if it was set
        if was_protected {
            let _ = self.make_inaccessible();
        }
    }
}

impl Drop for MemoryRegion {
    fn drop(&mut self) {
        // 1. Zeroize the data
        self.zeroize();

        // 2. Unlock the memory (munlock)
        if self.is_locked {
            let _ = platform_impl::unlock(self.alloc_ptr, self.alloc_len);
        }

        // 3. Deallocate (munmap/VirtualFree)
        let _ = platform_impl::deallocate(self.alloc_ptr, self.alloc_len);
    }
}

/// Memory protection level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Protection {
    /// No access allowed (PROT_NONE).
    None,
    /// Read-only access (PROT_READ).
    Read,
    /// Read and write access (PROT_READ | PROT_WRITE).
    ReadWrite,
}

// Select the appropriate platform implementation
#[cfg(unix)]
use unix as platform_impl;

#[cfg(windows)]
use windows as platform_impl;

#[cfg(not(any(unix, windows)))]
use fallback as platform_impl;
