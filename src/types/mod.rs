//! Protected secret types.
//!
//! This module provides the main user-facing types for storing secrets:
//!
//! - [`ShroudedBytes`]: Dynamic-size protected byte buffer
//! - [`ShroudedString`]: UTF-8 string with protected storage
//! - [`ShroudedArray`]: Fixed-size protected array
//! - [`Shroud`]: Generic protected box for any `Zeroize` type

mod bytes;
mod string;
mod array;
mod boxed;

pub use bytes::ShroudedBytes;
pub use string::ShroudedString;
pub use array::ShroudedArray;
pub use boxed::Shroud;
