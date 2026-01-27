//! Fallback implementation for platforms without specialized memory protection.
//!
//! This implementation uses standard allocation with zeroization on drop.
//! It provides no mlock, guard pages, or PROT_NONE protection.

#![allow(dead_code)]

use crate::error::{Result, ShroudError};
use crate::policy::Policy;
use super::{MemoryRegion, Protection};

/// Returns the page size (uses a common default of 4096).
pub fn page_size() -> usize {
    4096
}

/// Allocates a memory region using standard allocation.
pub fn allocate(size: usize, policy: Policy) -> Result<MemoryRegion> {
    allocate_aligned(size, 1, policy)
}

/// Allocates a memory region using standard allocation with the specified alignment.
///
/// # Arguments
/// * `size` - Size of the data region in bytes
/// * `alignment` - Required alignment in bytes (must be a power of 2)
/// * `_policy` - Memory protection policy (ignored in fallback)
pub fn allocate_aligned(size: usize, alignment: usize, _policy: Policy) -> Result<MemoryRegion> {
    // Validate alignment
    debug_assert!(alignment.is_power_of_two(), "alignment must be a power of 2");

    if size == 0 {
        return Ok(MemoryRegion {
            ptr: core::ptr::NonNull::dangling().as_ptr(),
            len: 0,
            alloc_ptr: core::ptr::NonNull::dangling().as_ptr(),
            alloc_len: 0,
            alloc_align: alignment,
            is_locked: false,
            has_guard_pages: false,
            is_protected: false,
        });
    }

    // Use requested alignment, minimum 1
    let align = alignment.max(1);

    // Allocate with requested alignment
    let layout = std::alloc::Layout::from_size_align(size, align)
        .map_err(|e| ShroudError::AllocationFailed(e.to_string()))?;

    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };

    if ptr.is_null() {
        return Err(ShroudError::AllocationFailed(
            "standard allocator returned null".to_string(),
        ));
    }

    // Verify alignment
    debug_assert!(
        ptr as usize % alignment == 0,
        "allocated pointer {:p} is not aligned to {} bytes",
        ptr,
        alignment
    );

    Ok(MemoryRegion {
        ptr,
        len: size,
        alloc_ptr: ptr,
        alloc_len: size,
        alloc_align: align,
        is_locked: false,
        has_guard_pages: false,
        is_protected: false,
    })
}

/// Changes memory protection (no-op in fallback).
pub fn protect(_ptr: *mut u8, _len: usize, _protection: Protection) -> Result<()> {
    // Fallback cannot change memory protection
    Ok(())
}

/// Unlocks memory (no-op in fallback).
pub fn unlock(_ptr: *mut u8, _len: usize) -> Result<()> {
    Ok(())
}

/// Deallocates memory.
pub fn deallocate(ptr: *mut u8, len: usize, alignment: usize) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    let align = alignment.max(1);
    let layout = std::alloc::Layout::from_size_align(len, align)
        .map_err(|e| ShroudError::DeallocationFailed(e.to_string()))?;

    unsafe {
        std::alloc::dealloc(ptr, layout);
    }

    Ok(())
}
