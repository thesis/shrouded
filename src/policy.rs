//! Memory protection policy configuration.

/// Policy controlling how memory protection failures are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Policy {
    /// Best effort: attempt protection, fall back gracefully on failure.
    ///
    /// This is the recommended default for most applications. Memory will be
    /// protected when possible, but the application will continue to function
    /// even if mlock or guard pages are unavailable (e.g., due to resource
    /// limits or platform restrictions).
    #[default]
    BestEffort,

    /// Strict: require all protection features to succeed.
    ///
    /// Operations will return an error if memory cannot be locked or guard
    /// pages cannot be created. Use this in high-security contexts where
    /// degraded protection is unacceptable.
    Strict,

    /// Disabled: skip all platform-specific protection.
    ///
    /// Memory is still zeroized on drop, but mlock, guard pages, and
    /// MADV_DONTDUMP are not used. This is useful for testing or when
    /// running in restricted environments like WASM.
    Disabled,
}

impl Policy {
    /// Returns true if protection failures should be treated as errors.
    #[inline]
    pub fn is_strict(self) -> bool {
        matches!(self, Policy::Strict)
    }

    /// Returns true if memory protection should be attempted.
    #[inline]
    pub fn protection_enabled(self) -> bool {
        !matches!(self, Policy::Disabled)
    }
}
