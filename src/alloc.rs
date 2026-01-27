//! Protected memory allocator.
//!
//! This module provides the core `ProtectedAlloc` type that manages
//! protected memory regions with automatic zeroization on drop.

use crate::error::{Result, ShroudError};
use crate::policy::Policy;
use crate::sys::{self, MemoryRegion};

/// A protected memory allocator managing a single memory region.
///
/// `ProtectedAlloc` wraps a `MemoryRegion` and provides safe access to
/// protected memory. It handles:
///
/// - Page-aligned allocation with optional guard pages
/// - Memory locking (mlock/VirtualLock) to prevent swapping
/// - Core dump exclusion (MADV_DONTDUMP on Linux)
/// - Automatic zeroization on drop
///
/// # Security Properties
///
/// - Memory is locked to RAM (if enabled) to prevent swapping to disk
/// - Guard pages catch buffer overflows/underflows (if enabled)
/// - Memory is excluded from core dumps on Linux
/// - Contents are zeroized using volatile writes before deallocation
pub struct ProtectedAlloc {
    region: MemoryRegion,
}

impl ProtectedAlloc {
    /// Creates a new protected allocation of the given size.
    ///
    /// The memory is allocated and protected according to the given policy.
    pub fn new(size: usize, policy: Policy) -> Result<Self> {
        Self::new_aligned(size, 1, policy)
    }

    /// Creates a new protected allocation of the given size with the specified alignment.
    ///
    /// The memory is allocated and protected according to the given policy.
    /// The alignment must be a power of 2 and not exceed the system page size.
    pub fn new_aligned(size: usize, alignment: usize, policy: Policy) -> Result<Self> {
        let region = sys::allocate_aligned(size, alignment, policy)?;
        Ok(Self { region })
    }

    /// Returns the size of the usable data area in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.region.len()
    }

    /// Returns true if the allocation has zero length.
    #[inline]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.region.is_empty()
    }

    /// Returns true if the memory is currently protected (inaccessible).
    #[inline]
    #[allow(dead_code)]
    pub fn is_protected(&self) -> bool {
        self.region.is_protected()
    }

    /// Returns the data as a byte slice.
    ///
    /// # Panics
    /// Panics if the memory is protected. Call `make_readable()` first.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        assert!(
            !self.region.is_protected(),
            "cannot read protected memory - call make_readable() first"
        );
        // SAFETY: We've verified the memory is not protected
        unsafe { self.region.as_slice() }
    }

    /// Returns the data as a mutable byte slice.
    ///
    /// # Panics
    /// Panics if the memory is protected. Call `make_writable()` first.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        assert!(
            !self.region.is_protected(),
            "cannot write protected memory - call make_writable() first"
        );
        // SAFETY: We've verified the memory is not protected
        unsafe { self.region.as_mut_slice() }
    }

    /// Makes the memory region readable.
    #[allow(dead_code)]
    pub fn make_readable(&self) -> Result<()> {
        self.region.make_readable()
    }

    /// Makes the memory region readable and writable.
    pub fn make_writable(&self) -> Result<()> {
        self.region.make_writable()
    }

    /// Makes the memory region inaccessible (PROT_NONE).
    #[allow(dead_code)]
    pub fn make_inaccessible(&self) -> Result<()> {
        self.region.make_inaccessible()
    }

    /// Writes data from a source slice, zeroizing the source afterward.
    ///
    /// This is the recommended way to initialize protected memory from
    /// existing data, as it ensures the source is zeroized.
    pub fn write_and_zeroize_source(&mut self, source: &mut [u8]) -> Result<()> {
        if source.len() > self.len() {
            return Err(ShroudError::CapacityOverflow {
                requested: source.len(),
                maximum: self.len(),
            });
        }

        // Ensure memory is writable
        if self.region.is_protected() {
            self.make_writable()?;
        }

        // Copy the data
        let dest = self.as_mut_slice();
        dest[..source.len()].copy_from_slice(source);

        // Zeroize the source using volatile writes
        zeroize_slice(source);

        Ok(())
    }
}

/// Zeroizes a slice using volatile writes to prevent optimizer elision.
#[inline]
pub(crate) fn zeroize_slice(data: &mut [u8]) {
    // Use volatile writes to prevent the optimizer from eliding the zeroization
    for byte in data.iter_mut() {
        // SAFETY: Volatile writes to valid memory are safe
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    // Memory barrier to ensure the writes complete before we return
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_allocation() {
        let alloc = ProtectedAlloc::new(100, Policy::BestEffort).unwrap();
        assert_eq!(alloc.len(), 100);
        assert!(!alloc.is_empty());
    }

    #[test]
    fn test_empty_allocation() {
        let alloc = ProtectedAlloc::new(0, Policy::BestEffort).unwrap();
        assert!(alloc.is_empty());
    }

    #[test]
    fn test_write_and_read() {
        let mut alloc = ProtectedAlloc::new(100, Policy::BestEffort).unwrap();

        {
            let data = alloc.as_mut_slice();
            data[0] = 42;
            data[99] = 255;
        }

        let data = alloc.as_slice();
        assert_eq!(data[0], 42);
        assert_eq!(data[99], 255);
    }

    #[test]
    fn test_write_and_zeroize_source() {
        let mut alloc = ProtectedAlloc::new(10, Policy::BestEffort).unwrap();
        let mut source = vec![1, 2, 3, 4, 5];

        alloc.write_and_zeroize_source(&mut source).unwrap();

        // Verify data was copied
        assert_eq!(&alloc.as_slice()[..5], &[1, 2, 3, 4, 5]);

        // Verify source was zeroized
        assert_eq!(source, vec![0, 0, 0, 0, 0]);
    }
}
