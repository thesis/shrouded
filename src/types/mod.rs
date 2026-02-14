//! Protected secret types.
//!
//! This module provides the main user-facing types for storing secrets:
//!
//! - [`ShroudedBytes`]: Dynamic-size protected byte buffer
//! - [`ShroudedString`]: UTF-8 string with protected storage
//! - [`ShroudedArray`]: Fixed-size protected array
//! - [`Shroud`]: Generic protected box for any `Zeroize` type
//! - [`ShroudedHasher`]: Hasher with protected internal state (requires `digest` feature)

mod array;
mod boxed;
mod bytes;
mod string;

#[cfg(feature = "digest")]
mod hasher;

pub use array::ShroudedArray;
pub use boxed::Shroud;
pub use bytes::ShroudedBytes;
pub use string::ShroudedString;

#[cfg(feature = "digest")]
pub use hasher::ShroudedHasher;

#[cfg(feature = "sha1")]
pub use hasher::ShroudedSha1;

#[cfg(feature = "sha2")]
pub use hasher::{ShroudedSha256, ShroudedSha384, ShroudedSha512};
