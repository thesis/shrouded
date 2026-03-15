# shroud

Secure memory management in Rust with mlock, guard pages, and automatic
zeroization.

## Overview

`shroud` provides types for storing secrets in protected memory that is:

- **Locked to RAM** (`mlock`/`VirtualLock`) to prevent swapping to disk.
- **Guard-paged** to catch buffer overflows/underflows.
- **Excluded from core dumps** to avoid writes to disk.
- **Automatically zeroized** on drop using volatile writes to minimize exposure.

## Design goals

1. **`secrecy`-style ergonomics**: Simple `.expose()` API to access protected
   data
2. **`memsec`-level protection**: Platform-specific memory protection with
   graceful degradation
3. **Defense in depth**: Multiple layers of protection (mlock + guard pages +
   zeroization)
4. **Explicit operations**: No automatic `Clone`, `Display`, or `Serialize`

## Types

| Type                | Description                                                      |
| ------------------- | ---------------------------------------------------------------- |
| `ShroudedBytes`     | Dynamic-size protected byte buffer                               |
| `ShroudedString`    | UTF-8 string with protected storage                              |
| `ShroudedArray<N>`  | Fixed-size protected array                                       |
| `Shroud<T>`         | Generic protected box for any `Zeroize` type                     |
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

## Threat model

### What shroud aims to protect against

- **Swap attacks**: Secrets locked to RAM cannot be swapped to disk
- **Core dump leaks**: Secrets excluded from core dumps on Linux
- **Buffer overflows**: Guard pages cause immediate crash on out-of-bounds
  access
- **Memory remnants**: Volatile zeroization prevents optimizer from eliding
  cleanup
- **Accidental logging**: Debug output shows `[REDACTED]`
- **Accidental serialization**: No `Serialize` impl (only `Deserialize`)

### What shroud does NOT protect against

- **Root access**: A privileged attacker can read process memory directly
- **Memory snapshots**: VM snapshots or hibernation may capture secrets
- **Side channels**: Timing attacks, speculative execution, etc.
- **Heap remnants**: For heap types like `Vec`, consider using `ShroudedBytes`
  directly

## Performance

`shroud` prioritizes security over performance. Each allocation uses `mmap` (not
`malloc`) to obtain page-aligned memory for guard pages, making allocation
significantly slower than a normal heap allocation. With guard pages enabled, a
single-byte secret occupies at least 3 memory pages (~12KB on most systems).

This also affects `mlock` budgets. The kernel limits locked memory per process
([`RLIMIT_MEMLOCK`](https://www.rdocumentation.org/packages/RAppArmor/versions/0.8.3/topics/rlimit_memlock),
often 64–256KB by default), and guard pages inflate each allocation's footprint.
`expose_guarded()` adds two `mprotect` syscalls per access; `expose()` avoids
this at the cost of keeping memory readable between accesses.

We believe these costs are worthwhile in the typical case, handling a handful of
API keys or passwords. If you're handling many secrets concurrently, though, or
create them in a hot loop, the performance cost is real.

## Features

| Feature       | Default | Description                                                                     |
| ------------- | ------- | ------------------------------------------------------------------------------- |
| `mlock`       | ✓       | Enable memory locking                                                           |
| `guard-pages` | ✓       | Enable guard pages                                                              |
| `serde`       | ✗       | Enable deserialize support                                                      |
| `digest`      | ✗       | Enable `ShroudedHasher<D>` for custom digest algorithms                         |
| `sha1`        | ✗       | Enable `ShroudedSha1` (includes `digest`)                                       |
| `sha2`        | ✗       | Enable `ShroudedSha256`, `ShroudedSha384`, `ShroudedSha512` (includes `digest`) |

## Platform support

| Platform   | mlock | Guard Pages | Core Dump Exclusion                                                         |
| ---------- | ----- | ----------- | --------------------------------------------------------------------------- |
| Linux      | ✓     | ✓           | ✓ ([`MADV_DONTDUMP`](https://man7.org/linux/man-pages/man2/madvise.2.html)) |
| macOS      | ✓     | ✓           | ✗                                                                           |
| Windows    | ✓     | ✓           | ✗                                                                           |
| WASM/Other | ✗     | ✗           | ✗                                                                           |

On unsupported platforms, `shroud` falls back to standard allocation with
zeroization on drop.

## Comparison with similar crates

| Feature                           | shroud      | secrecy            | memsec | secstr        |
| --------------------------------- | ----------- | ------------------ | ------ | ------------- |
| Zeroize on drop                   | yes         | yes                | yes    | yes           |
| `mlock`                           | yes         | no                 | yes    | yes           |
| Guard pages                       | yes         | no                 | yes    | no            |
| `mprotect` (re-lock after access) | yes         | no                 | no     | no            |
| Core dump exclusion               | yes         | no                 | no     | yes           |
| Expose-style API                  | `.expose()` | `.expose_secret()` | —      | `.unsecure()` |
| Policy control                    | yes         | no                 | no     | no            |
| Debug redaction                   | yes         | yes                | no     | no            |
| No implicit `Serialize`           | yes         | yes                | N/A    | N/A           |
| Optional serde                    | deser only  | ser + deser        | no     | ser + deser   |
| Fixed-size array type             | yes         | no                 | yes    | no            |
| Windows support                   | yes         | yes                | no     | yes           |

Migrating from another crate? See the [migration guide](docs/migration.md).

## Usage notes

Some behaviors may be surprising if you're used to standard Rust types:

1. **No `Clone` trait**: Use `try_clone()` explicitly to copy protected values.
   This returns `Result` because each clone allocates new protected memory (with
   mlock).

2. **No `Serialize` trait**: Only `Deserialize` is implemented. To serialize,
   explicitly call `.expose()` and serialize the inner value. This prevents
   accidental serialization of secrets.

3. **`expose()` vs `expose_guarded()` - why one is fallible**:
   - `expose()` is **infallible** because it returns a direct reference without
     changing memory permissions. Memory is allocated with read/write access by
     default.

   - `expose_guarded()` **returns `Result`** because it must call
     [`mprotect()`](https://man7.org/linux/man-pages/man2/mprotect.2.html) to
     change permissions from `PROT_NONE` to readable, then back to `PROT_NONE`
     when the guard is dropped. System calls can fail.

   ```rust
   // Quick access (memory stays accessible)
   let value = password.expose();

   // Guarded access (memory locked except during access)
   let guard = password.expose_guarded()?;
   do_something(guard.as_bytes());
   // Memory automatically re-locked when guard is dropped
   ```

   Use `expose()` for convenience; use `expose_guarded()` for maximum security
   when you want memory inaccessible except during brief access windows.

4. **Constant-time comparison**: `PartialEq` uses constant-time comparison to
   prevent timing attacks. Comparing two `ShroudedString` values is safe.

5. **`try_clone()` allocates new protected memory**: Each clone gets its own
   mlock'd region with guard pages. This is intentional for security but has
   performance implications.

6. **Source data is zeroized**: When creating a `ShroudedString` from a
   `String`, the original `String` is zeroized. The data now lives only in
   protected memory.
