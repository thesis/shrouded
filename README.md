# shroud

Secure memory management with mlock, guard pages, and automatic zeroization.

## Overview

`shroud` provides types for storing secrets in protected memory that is:

- **Locked to RAM** (`mlock`/`VirtualLock`) to prevent swapping to disk
- **Guard-paged** to catch buffer overflows/underflows
- **Excluded from core dumps** (`MADV_DONTDUMP` on Linux)
- **Automatically zeroized** on drop using volatile writes

## Design Goals

1. **Secrecy-style ergonomics**: Simple `.expose()` API to access protected data
2. **Memsec-level protection**: Platform-specific memory protection with graceful degradation
3. **Defense in depth**: Multiple layers of protection (mlock + guard pages + zeroization)
4. **Explicit operations**: No automatic `Clone`, `Display`, or `Serialize`

## Types

| Type | Description |
|------|-------------|
| `ShroudedBytes` | Dynamic-size protected byte buffer |
| `ShroudedString` | UTF-8 string with protected storage |
| `ShroudedArray<N>` | Fixed-size protected array |
| `Shroud<T>` | Generic protected box for any `Zeroize` type |

## Usage

```rust
use shroud::{ShroudedString, ShroudedBytes, ShroudedArray, Expose};

// Strings - original is consumed and zeroized
let password = String::from("hunter2");
let secret = ShroudedString::new(password).unwrap();
assert_eq!(secret.expose(), "hunter2");

// Bytes - source slice is zeroized
let mut key_data = vec![0x42u8; 32];
let key = ShroudedBytes::from_slice(&mut key_data).unwrap();
assert!(key_data.iter().all(|&b| b == 0)); // Source zeroized

// Fixed arrays - initialized in protected memory
let nonce: ShroudedArray<12> = ShroudedArray::new_with(|buf| {
    // Initialize directly in protected memory
    getrandom::getrandom(buf).unwrap();
}).unwrap();
```

## Policy

Control how memory protection failures are handled:

```rust
use shroud::{ShroudBuilder, Policy};

// BestEffort (default): Attempt protection, fall back gracefully
let secret = ShroudBuilder::new()
    .policy(Policy::BestEffort)
    .build_string("secret".to_string())?;

// Strict: Error if protection fails
let secret = ShroudBuilder::new()
    .policy(Policy::Strict)
    .build_string("secret".to_string())?;

// Disabled: No protection (still zeroizes on drop)
let secret = ShroudBuilder::new()
    .policy(Policy::Disabled)
    .build_string("secret".to_string())?;
```

## Security Properties

### What shroud protects against

- **Swap attacks**: Secrets locked to RAM cannot be swapped to disk
- **Core dump leaks**: Secrets excluded from core dumps on Linux
- **Buffer overflows**: Guard pages cause immediate crash on out-of-bounds access
- **Memory remnants**: Volatile zeroization prevents optimizer from eliding cleanup
- **Accidental logging**: Debug output shows `[REDACTED]`
- **Accidental serialization**: No `Serialize` impl (only `Deserialize`)

### What shroud does NOT protect against

- **Root access**: A privileged attacker can read process memory directly
- **Memory snapshots**: VM snapshots or hibernation may capture secrets
- **Side channels**: Timing attacks, speculative execution, etc.
- **Heap remnants**: For heap types like `Vec`, consider using `ShroudedBytes` directly

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `mlock` | ✓ | Enable memory locking |
| `guard-pages` | ✓ | Enable guard pages |
| `serde` | ✗ | Enable deserialize support |

## Platform Support

| Platform | mlock | Guard Pages | Core Dump Exclusion |
|----------|-------|-------------|---------------------|
| Linux | ✓ | ✓ | ✓ (`MADV_DONTDUMP`) |
| macOS | ✓ | ✓ | ✗ |
| Windows | ✓ | ✓ | ✗ |
| WASM/Other | ✗ | ✗ | ✗ |

On unsupported platforms, `shroud` falls back to standard allocation with zeroization on drop.

## Comparison with Similar Crates

| Feature | shroud | secrecy | memsec |
|---------|--------|---------|--------|
| Zeroize on drop | ✓ | ✓ | ✓ |
| mlock | ✓ | ✗ | ✓ |
| Guard pages | ✓ | ✗ | ✓ |
| Expose API | ✓ | ✓ | ✗ |
| Policy control | ✓ | ✗ | ✗ |
| Debug redaction | ✓ | ✓ | ✗ |
| No Serialize | ✓ | ✓ | N/A |

## License

MIT
