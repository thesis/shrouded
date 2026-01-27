//! Windows implementation using VirtualAlloc, VirtualLock, and VirtualProtect.

use crate::error::{Result, ShroudError};
use crate::policy::Policy;
use super::{MemoryRegion, Protection};

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualLock, VirtualProtect, VirtualUnlock,
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

/// Returns the system page size.
pub fn page_size() -> usize {
    unsafe {
        let mut info: SYSTEM_INFO = core::mem::zeroed();
        GetSystemInfo(&mut info);
        info.dwPageSize as usize
    }
}

/// Rounds up to the nearest page boundary.
fn round_up_to_page(size: usize, page_size: usize) -> usize {
    (size + page_size - 1) & !(page_size - 1)
}

/// Allocates a protected memory region using VirtualAlloc.
pub fn allocate(size: usize, policy: Policy) -> Result<MemoryRegion> {
    allocate_aligned(size, 1, policy)
}

/// Allocates a protected memory region using VirtualAlloc with the specified alignment.
///
/// # Arguments
/// * `size` - Size of the data region in bytes
/// * `alignment` - Required alignment in bytes (must be a power of 2 and <= page_size)
/// * `policy` - Memory protection policy
pub fn allocate_aligned(size: usize, alignment: usize, policy: Policy) -> Result<MemoryRegion> {
    let page_sz = page_size();

    // Validate alignment
    debug_assert!(alignment.is_power_of_two(), "alignment must be a power of 2");
    debug_assert!(
        alignment <= page_sz,
        "alignment ({}) cannot exceed page size ({})",
        alignment,
        page_sz
    );

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

    let data_pages = round_up_to_page(size, page_sz);

    // Calculate total allocation size with optional guard pages
    let use_guard_pages = cfg!(feature = "guard-pages") && policy.protection_enabled();
    let guard_size = if use_guard_pages { page_sz } else { 0 };
    let total_size = guard_size + data_pages + guard_size;

    // Allocate memory with VirtualAlloc
    let alloc_ptr = unsafe {
        VirtualAlloc(
            core::ptr::null(),
            total_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if alloc_ptr.is_null() {
        return Err(ShroudError::AllocationFailed(format!(
            "VirtualAlloc failed: error code {}",
            unsafe { GetLastError() }
        )));
    }

    let alloc_ptr = alloc_ptr as *mut u8;
    let data_ptr = unsafe { alloc_ptr.add(guard_size) };

    // Verify alignment - VirtualAlloc returns page-aligned memory, so any alignment <= page_size is satisfied
    debug_assert!(
        data_ptr as usize % alignment == 0,
        "data pointer {:p} is not aligned to {} bytes",
        data_ptr,
        alignment
    );

    // Set up guard pages (PAGE_NOACCESS)
    let has_guard_pages = if use_guard_pages {
        let leading_guard_ok = set_protection(alloc_ptr, page_sz, Protection::None).is_ok();
        let trailing_guard_ptr = unsafe { alloc_ptr.add(guard_size + data_pages) };
        let trailing_guard_ok = set_protection(trailing_guard_ptr, page_sz, Protection::None).is_ok();

        if policy.is_strict() && (!leading_guard_ok || !trailing_guard_ok) {
            // Clean up and return error
            unsafe { VirtualFree(alloc_ptr as *mut _, 0, MEM_RELEASE) };
            return Err(ShroudError::ProtectFailed(
                "failed to set up guard pages".to_string(),
            ));
        }

        leading_guard_ok && trailing_guard_ok
    } else {
        false
    };

    // Lock memory (VirtualLock)
    let use_mlock = cfg!(feature = "mlock") && policy.protection_enabled();
    let is_locked = if use_mlock {
        let result = unsafe { VirtualLock(data_ptr as *const _, data_pages) };
        if result != 0 {
            true
        } else if policy.is_strict() {
            // Clean up and return error
            unsafe { VirtualFree(alloc_ptr as *mut _, 0, MEM_RELEASE) };
            return Err(ShroudError::LockFailed(format!(
                "VirtualLock failed: error code {}",
                unsafe { GetLastError() }
            )));
        } else {
            false
        }
    } else {
        false
    };

    Ok(MemoryRegion {
        ptr: data_ptr,
        len: size,
        alloc_ptr,
        alloc_len: total_size,
        alloc_align: alignment,
        is_locked,
        has_guard_pages,
        is_protected: false,
    })
}

/// Sets memory protection on a region.
fn set_protection(ptr: *mut u8, len: usize, protection: Protection) -> Result<()> {
    let prot = match protection {
        Protection::None => PAGE_NOACCESS,
        Protection::Read => PAGE_READONLY,
        Protection::ReadWrite => PAGE_READWRITE,
    };

    let mut old_protect = 0u32;
    let result = unsafe { VirtualProtect(ptr as *const _, len, prot, &mut old_protect) };

    if result != 0 {
        Ok(())
    } else {
        Err(ShroudError::ProtectFailed(format!(
            "VirtualProtect failed: error code {}",
            unsafe { GetLastError() }
        )))
    }
}

/// Changes memory protection.
pub fn protect(ptr: *mut u8, len: usize, protection: Protection) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    // Round up to page boundary for VirtualProtect
    let page_sz = page_size();
    let len_rounded = round_up_to_page(len, page_sz);

    set_protection(ptr, len_rounded, protection)
}

/// Unlocks memory (VirtualUnlock).
pub fn unlock(ptr: *mut u8, len: usize) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    let result = unsafe { VirtualUnlock(ptr as *const _, len) };

    if result != 0 {
        Ok(())
    } else {
        // VirtualUnlock can fail if the memory wasn't locked, which is OK
        let error = unsafe { GetLastError() };
        if error == 158 {
            // ERROR_NOT_LOCKED
            Ok(())
        } else {
            Err(ShroudError::UnlockFailed(format!(
                "VirtualUnlock failed: error code {}",
                error
            )))
        }
    }
}

/// Deallocates memory (VirtualFree).
///
/// Note: The `_alignment` parameter is unused for VirtualAlloc-based allocation
/// but included for API consistency with the fallback allocator.
pub fn deallocate(ptr: *mut u8, _len: usize, _alignment: usize) -> Result<()> {
    if ptr.is_null() {
        return Ok(());
    }

    let result = unsafe { VirtualFree(ptr as *mut _, 0, MEM_RELEASE) };

    if result != 0 {
        Ok(())
    } else {
        Err(ShroudError::DeallocationFailed(format!(
            "VirtualFree failed: error code {}",
            unsafe { GetLastError() }
        )))
    }
}
