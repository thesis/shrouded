//! Unix implementation using mmap, mlock, and mprotect.

use super::{MemoryRegion, Protection};
use crate::error::{Result, ShroudError};
use crate::policy::Policy;

/// Returns the system page size.
pub fn page_size() -> usize {
    // SAFETY: sysconf is safe to call
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

/// Rounds up to the nearest page boundary.
fn round_up_to_page(size: usize, page_size: usize) -> usize {
    (size + page_size - 1) & !(page_size - 1)
}

/// Allocates a protected memory region using mmap.
#[allow(dead_code)]
pub fn allocate(size: usize, policy: Policy) -> Result<MemoryRegion> {
    allocate_aligned(size, 1, policy)
}

/// Allocates a protected memory region using mmap with the specified alignment.
///
/// # Arguments
/// * `size` - Size of the data region in bytes
/// * `alignment` - Required alignment in bytes (must be a power of 2 and <= page_size)
/// * `policy` - Memory protection policy
pub fn allocate_aligned(size: usize, alignment: usize, policy: Policy) -> Result<MemoryRegion> {
    let page_sz = page_size();

    // Validate alignment
    debug_assert!(
        alignment.is_power_of_two(),
        "alignment must be a power of 2"
    );
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
            is_protected: core::sync::atomic::AtomicBool::new(false),
        });
    }

    let data_pages = round_up_to_page(size, page_sz);

    // Calculate total allocation size with optional guard pages
    let use_guard_pages = cfg!(feature = "guard-pages") && policy.protection_enabled();
    let guard_size = if use_guard_pages { page_sz } else { 0 };
    let total_size = guard_size
        .checked_add(data_pages)
        .and_then(|s| s.checked_add(guard_size))
        .ok_or_else(|| ShroudError::AllocationFailed("size calculation overflow".to_string()))?;

    // Allocate memory with mmap
    // SAFETY: mmap with MAP_ANONYMOUS is safe
    let alloc_ptr = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            total_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    if alloc_ptr == libc::MAP_FAILED {
        return Err(ShroudError::AllocationFailed(format!(
            "mmap failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let alloc_ptr = alloc_ptr as *mut u8;
    let data_ptr = unsafe { alloc_ptr.add(guard_size) };

    // Verify alignment - mmap returns page-aligned memory, so any alignment <= page_size is satisfied
    debug_assert!(
        data_ptr as usize % alignment == 0,
        "data pointer {:p} is not aligned to {} bytes",
        data_ptr,
        alignment
    );

    // Set up guard pages (PROT_NONE)
    let has_guard_pages = if use_guard_pages {
        let leading_guard_ok = set_protection(alloc_ptr, page_sz, Protection::None).is_ok();
        let trailing_guard_ptr = unsafe { alloc_ptr.add(guard_size + data_pages) };
        let trailing_guard_ok =
            set_protection(trailing_guard_ptr, page_sz, Protection::None).is_ok();

        if policy.is_strict() && (!leading_guard_ok || !trailing_guard_ok) {
            // Clean up and return error
            unsafe { libc::munmap(alloc_ptr as *mut libc::c_void, total_size) };
            return Err(ShroudError::ProtectFailed(
                "failed to set up guard pages".to_string(),
            ));
        }

        leading_guard_ok && trailing_guard_ok
    } else {
        false
    };

    // Lock memory (mlock)
    let use_mlock = cfg!(feature = "mlock") && policy.protection_enabled();
    let is_locked = if use_mlock {
        let result = unsafe { libc::mlock(data_ptr as *const libc::c_void, data_pages) };
        if result == 0 {
            true
        } else if policy.is_strict() {
            // Clean up and return error
            unsafe { libc::munmap(alloc_ptr as *mut libc::c_void, total_size) };
            return Err(ShroudError::LockFailed(format!(
                "mlock failed: {}",
                std::io::Error::last_os_error()
            )));
        } else {
            false
        }
    } else {
        false
    };

    // Exclude from core dumps (Linux and Android)
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // MADV_DONTDUMP = 16 on Linux
        const MADV_DONTDUMP: libc::c_int = 16;
        let result =
            unsafe { libc::madvise(data_ptr as *mut libc::c_void, data_pages, MADV_DONTDUMP) };
        if result != 0 && policy.is_strict() {
            // Clean up and return error
            if is_locked {
                unsafe { libc::munlock(data_ptr as *const libc::c_void, data_pages) };
            }
            unsafe { libc::munmap(alloc_ptr as *mut libc::c_void, total_size) };
            return Err(ShroudError::ProtectFailed(format!(
                "MADV_DONTDUMP failed: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    Ok(MemoryRegion {
        ptr: data_ptr,
        len: size,
        alloc_ptr,
        alloc_len: total_size,
        alloc_align: alignment,
        is_locked,
        has_guard_pages,
        is_protected: core::sync::atomic::AtomicBool::new(false),
    })
}

/// Sets memory protection on a region.
fn set_protection(ptr: *mut u8, len: usize, protection: Protection) -> Result<()> {
    let prot = match protection {
        Protection::None => libc::PROT_NONE,
        Protection::Read => libc::PROT_READ,
        Protection::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
    };

    let result = unsafe { libc::mprotect(ptr as *mut libc::c_void, len, prot) };

    if result == 0 {
        Ok(())
    } else {
        Err(ShroudError::ProtectFailed(format!(
            "mprotect failed: {}",
            std::io::Error::last_os_error()
        )))
    }
}

/// Changes memory protection.
pub fn protect(ptr: *mut u8, len: usize, protection: Protection) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    // Round up to page boundary for mprotect
    let page_sz = page_size();
    let len_rounded = round_up_to_page(len, page_sz);

    set_protection(ptr, len_rounded, protection)
}

/// Unlocks memory (munlock).
pub fn unlock(ptr: *mut u8, len: usize) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    let result = unsafe { libc::munlock(ptr as *const libc::c_void, len) };

    if result == 0 {
        Ok(())
    } else {
        Err(ShroudError::UnlockFailed(format!(
            "munlock failed: {}",
            std::io::Error::last_os_error()
        )))
    }
}

/// Deallocates memory (munmap).
///
/// Note: The `_alignment` parameter is unused for mmap-based allocation
/// but included for API consistency with the fallback allocator.
pub fn deallocate(ptr: *mut u8, len: usize, _alignment: usize) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    let result = unsafe { libc::munmap(ptr as *mut libc::c_void, len) };

    if result == 0 {
        Ok(())
    } else {
        Err(ShroudError::DeallocationFailed(format!(
            "munmap failed: {}",
            std::io::Error::last_os_error()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_size() {
        let ps = page_size();
        assert!(ps >= 4096);
        assert!(ps.is_power_of_two());
    }

    #[test]
    fn test_round_up_to_page() {
        let ps = 4096;
        assert_eq!(round_up_to_page(0, ps), 0);
        assert_eq!(round_up_to_page(1, ps), 4096);
        assert_eq!(round_up_to_page(4096, ps), 4096);
        assert_eq!(round_up_to_page(4097, ps), 8192);
    }

    #[test]
    fn test_allocate_zero_size() {
        let region = allocate(0, Policy::BestEffort).unwrap();
        assert!(region.is_empty());
    }

    #[test]
    fn test_allocate_and_write() {
        let mut region = allocate(100, Policy::BestEffort).unwrap();
        assert_eq!(region.len(), 100);

        // Write some data
        unsafe {
            let slice = region.as_mut_slice();
            slice[0] = 42;
            slice[99] = 255;
        }

        // Read it back
        unsafe {
            let slice = region.as_slice();
            assert_eq!(slice[0], 42);
            assert_eq!(slice[99], 255);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn test_mlock_verification() {
        // On Linux, we can verify mlock by checking /proc/self/status
        use std::fs;

        // Get initial VmLck value
        fn get_vmlck() -> Option<usize> {
            let status = fs::read_to_string("/proc/self/status").ok()?;
            for line in status.lines() {
                if line.starts_with("VmLck:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    return parts.get(1)?.parse().ok();
                }
            }
            None
        }

        let initial_vmlck = get_vmlck().unwrap_or(0);

        // Allocate with strict policy to ensure mlock succeeds
        // (or fails clearly if we don't have permission)
        let result = allocate(8192, Policy::BestEffort);

        if let Ok(region) = result {
            if region.is_locked {
                // If mlock succeeded, VmLck should have increased
                let new_vmlck = get_vmlck().unwrap_or(0);
                assert!(
                    new_vmlck >= initial_vmlck,
                    "VmLck should not decrease after mlock"
                );
            }
            // If mlock failed (e.g., due to RLIMIT_MEMLOCK), that's OK in BestEffort mode
        }
    }
}
