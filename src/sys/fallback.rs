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
pub fn allocate(size: usize, _policy: Policy) -> Result<MemoryRegion> {
    if size == 0 {
        return Ok(MemoryRegion {
            ptr: core::ptr::NonNull::dangling().as_ptr(),
            len: 0,
            alloc_ptr: core::ptr::NonNull::dangling().as_ptr(),
            alloc_len: 0,
            is_locked: false,
            has_guard_pages: false,
            is_protected: false,
        });
    }

    // Allocate with standard layout
    let layout = std::alloc::Layout::from_size_align(size, 8)
        .map_err(|e| ShroudError::AllocationFailed(e.to_string()))?;

    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };

    if ptr.is_null() {
        return Err(ShroudError::AllocationFailed(
            "standard allocator returned null".to_string(),
        ));
    }

    Ok(MemoryRegion {
        ptr,
        len: size,
        alloc_ptr: ptr,
        alloc_len: size,
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
pub fn deallocate(ptr: *mut u8, len: usize) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    let layout = std::alloc::Layout::from_size_align(len, 8)
        .map_err(|e| ShroudError::DeallocationFailed(e.to_string()))?;

    unsafe {
        std::alloc::dealloc(ptr, layout);
    }

    Ok(())
}
