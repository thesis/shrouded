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
| `ShroudedHasher<D>` | Hasher with protected internal state (requires `digest` feature) |

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

## Protected Hashing

The `ShroudedHasher<D>` type keeps hasher internal state in protected memory, useful when hashing sensitive data like passwords. Enable with the `sha1` or `sha2` features.

```rust
use shroud::{ShroudedSha256, Expose};

// Create a protected hasher
let mut hasher = ShroudedSha256::new().unwrap();

// Hash sensitive data - hasher state is in protected memory
hasher.update(b"sensitive password");

// Get the hash in protected memory
let hash = hasher.finalize_reset_array::<32>().unwrap();
println!("Hash: {}", hex::encode(hash.expose()));

// Hasher is automatically reset and can be reused
hasher.update(b"another password");
let hash2 = hasher.finalize_reset_array::<32>().unwrap();
```

### Available Hashers

| Type | Feature | Output Size |
|------|---------|-------------|
| `ShroudedSha1` | `sha1` | 20 bytes |
| `ShroudedSha256` | `sha2` | 32 bytes |
| `ShroudedSha384` | `sha2` | 48 bytes |
| `ShroudedSha512` | `sha2` | 64 bytes |

### Security Note

SHA-1 is cryptographically broken and should only be used for legacy compatibility (e.g., HIBP k-anonymity API). Use SHA-256 or stronger for new designs.

When calling `finalize_reset()`, the hash output is briefly on the stack before being copied to protected memory. The temporary is zeroized immediately after copying.

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
| `digest` | ✗ | Enable `ShroudedHasher<D>` for custom digest algorithms |
| `sha1` | ✗ | Enable `ShroudedSha1` (includes `digest`) |
| `sha2` | ✗ | Enable `ShroudedSha256`, `ShroudedSha384`, `ShroudedSha512` (includes `digest`) |

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

### Detailed Comparison: shroud vs secstr

The `secstr` crate is commonly used for protected memory (e.g., by the `keepass` crate). Here's how it compares:

#### Memory Protection

| Feature | shroud | secstr |
|---------|--------|--------|
| mlock (prevent swap) | ✓ | ✓ |
| Guard pages (PROT_NONE) | ✓ | ✗ |
| mprotect (read/write control) | ✓ | ✗ |
| Core dump exclusion | ✓ | ✓ |
| Zeroing on drop | ✓ | ✓ |
| Auto re-lock after access | ✓ (`ExposeGuard`) | ✗ |

#### API & Types

| Aspect | shroud | secstr |
|--------|--------|--------|
| String type | `ShroudedString` | `SecStr` |
| Bytes type | `ShroudedBytes` | `SecVec` |
| Fixed-size array | `ShroudedArray<N>` | ✗ |
| Generic wrapper | `Shroud<T>` | ✗ |
| Access pattern | `.expose()` | `.unsecure()` |
| Guarded access | `.expose_guarded()` | ✗ |
| Cloning | `.try_clone()` (explicit) | Not Clone |

#### Error Handling

| Aspect | shroud | secstr |
|--------|--------|--------|
| Policy control | `BestEffort` / `Strict` / `Disabled` | None (silent fallback) |
| mlock failure | Configurable | Silent fallback |

#### Pros & Cons

**shroud:**
- ✅ Guard pages detect buffer overflows
- ✅ Auto re-locking via `ExposeGuard`
- ✅ Per-allocation policy control
- ✅ Native Windows support (no libsodium dependency)
- ❌ More complex API
- ❌ Higher memory overhead (guard pages)

**secstr:**
- ✅ Simple API
- ✅ Lower overhead
- ✅ Mature, battle-tested
- ❌ No guard pages
- ❌ No automatic re-locking
- ❌ Silent failures on mlock errors

## Usage Notes

Some behaviors may be surprising if you're used to standard Rust types:

1. **No `Clone` trait**: Use `try_clone()` explicitly to copy protected values. This returns `Result` because each clone allocates new protected memory (with mlock).

2. **No `Serialize` trait**: Only `Deserialize` is implemented. To serialize, explicitly call `.expose()` and serialize the inner value. This prevents accidental serialization of secrets.

3. **`expose()` vs `expose_guarded()` - why one is fallible**:

   - `expose()` is **infallible** because it returns a direct reference without changing memory permissions. Memory is allocated with read/write access by default.

   - `expose_guarded()` **returns `Result`** because it must call `mprotect()` to change permissions from PROT_NONE to readable, then back to PROT_NONE when the guard is dropped. System calls can fail.

   ```rust
   // Quick access (memory stays accessible)
   let value = password.expose();

   // Guarded access (memory locked except during access)
   let guard = password.expose_guarded()?;
   do_something(guard.as_bytes());
   // Memory automatically re-locked when guard is dropped
   ```

   Use `expose()` for convenience; use `expose_guarded()` for maximum security when you want memory inaccessible except during brief access windows.

4. **Constant-time comparison**: `PartialEq` uses constant-time comparison to prevent timing attacks. Comparing two `ShroudedString` values is safe.

5. **`try_clone()` allocates new protected memory**: Each clone gets its own mlock'd region with guard pages. This is intentional for security but has performance implications.

6. **Source data is zeroized**: When creating a `ShroudedString` from a `String`, the original `String` is zeroized. The data now lives only in protected memory.
