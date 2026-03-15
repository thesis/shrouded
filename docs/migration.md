# Migrating to shroud

## From secrecy

### Concept mapping

| secrecy | shroud | notes |
|---------|--------|-------|
| `Secret<String>` | `ShroudedString` | dedicated type |
| `Secret<Vec<u8>>` | `ShroudedBytes` | dedicated type |
| `Secret<T>` | `Shroud<T>` | generic wrapper |
| `.expose_secret()` | `.expose()` | shorter name |
| `CloneableSecret` | `.try_clone()` | returns `Result` |
| `SerializableSecret` | `.expose()` + manual ser | no Serialize impl |

### Before / after

secrecy:

```rust
use secrecy::{Secret, ExposeSecret};

let password = Secret::new("hunter2".to_string());
let value: &str = password.expose_secret().as_str();
```

shroud:

```rust
use shroud::{ShroudedString, Expose};

let password = ShroudedString::new("hunter2".to_string()).unwrap();
let value: &str = password.expose();
```

### Behavioral differences

- **Fallible constructors.** `ShroudedString::new()` returns `Result` because memory protection (mlock, guard pages) can fail. `Secret::new()` is infallible.
- **No Serialize.** secrecy allows opt-in serialization via `SerializableSecret`. shroud has no `Serialize` impl at all — call `.expose()` and serialize the inner value explicitly.
- **Fallible clone.** `try_clone()` returns `Result` because each clone allocates new protected memory with mlock. secrecy's `Clone` (via `CloneableSecret`) is infallible.
- **Guarded access.** `expose_guarded()` temporarily unlocks memory via mprotect and re-locks it when the guard is dropped. secrecy has no equivalent.
- **Extra protections.** shroud adds mlock, guard pages, and core dump exclusion on top of zeroize-on-drop.

---

## From memsec

### Concept mapping

| memsec | shroud | notes |
|--------|--------|-------|
| `malloc<T>()` + `mlock()` | `Shroud<T>::new()` | lifecycle is automatic |
| `allocarray<T>(n)` | `ShroudedArray<N>` | fixed-size |
| raw pointer access | `.expose()` / `.expose_mut()` | safe API |
| `memzero()` + `munlock()` + `free()` | automatic on `Drop` | |

### Before / after

memsec:

```rust
use memsec::{mlock, munlock, malloc, free, memzero};

unsafe {
    let ptr: *mut u8 = malloc(32).unwrap();
    mlock(ptr, 32);
    // ... use ptr ...
    memzero(ptr, 32);
    munlock(ptr, 32);
    free(ptr);
}
```

shroud:

```rust
use shroud::{ShroudedBytes, Expose};

let secret = ShroudedBytes::new_with(32, |buf| {
    // initialize buf
}).unwrap();
let data: &[u8] = secret.expose();
// Zeroized, munlocked, and freed on drop
```

### Behavioral differences

- **Safe API.** memsec requires `unsafe` for most operations. shroud's public API is entirely safe.
- **Automatic lifecycle.** shroud manages alloc, mlock, guard pages, zeroize, munlock, and free as a single unit. memsec requires you to call each step manually.
- **No libsodium.** shroud calls OS APIs (mlock, mprotect, VirtualLock) directly. memsec depends on libsodium on some platforms.
- **Policy control.** `Policy::Strict` turns protection failures into errors. `Policy::BestEffort` (default) falls back gracefully. memsec operations return `Option` or `bool` with no configurable behavior.

---

## From secstr

### Concept mapping

| secstr | shroud | notes |
|--------|--------|-------|
| `SecStr` | `ShroudedString` or `ShroudedBytes` | `SecStr` wraps `Vec<u8>`, not necessarily UTF-8 |
| `SecVec<T>` | `ShroudedBytes` / `Shroud<T>` | |
| `.unsecure()` | `.expose()` | |
| `.unsecure_mut()` | `.expose_mut()` | |
| `SecStr::from("...")` | `ShroudedString::new(s)` | returns `Result` |
| `SecStr::new(vec)` | `ShroudedBytes::from_slice(&mut v)` | zeroizes source |

### Before / after

secstr:

```rust
use secstr::SecStr;

let secret = SecStr::from("hunter2");
let value: &[u8] = secret.unsecure();
```

shroud (as string):

```rust
use shroud::{ShroudedString, Expose};

let secret = ShroudedString::new("hunter2".to_string()).unwrap();
let value: &str = secret.expose();
```

shroud (as bytes):

```rust
use shroud::{ShroudedBytes, Expose};

let mut data = b"hunter2".to_vec();
let secret = ShroudedBytes::from_slice(&mut data).unwrap();
let value: &[u8] = secret.expose();
```

### Behavioral differences

- **Fallible constructors.** shroud returns `Result`; secstr constructors are infallible.
- **Choose your type.** `SecStr` wraps `Vec<u8>` regardless of content. Use `ShroudedString` for text (UTF-8 validated) or `ShroudedBytes` for raw bytes.
- **Source zeroization.** `ShroudedBytes::from_slice()` zeroizes the input slice. secstr does not zeroize the source.
- **Guard pages + mprotect.** shroud adds guard pages around allocations and supports automatic re-locking via `expose_guarded()`. secstr has neither.
- **Explicit failure handling.** `Policy::Strict` turns mlock failures into errors. secstr silently falls back when mlock fails.
- **Serde.** secstr supports optional Serialize + Deserialize. shroud supports Deserialize only — serialize by calling `.expose()` on the inner value.
