//! Optional serde support for shrouded types.
//!
//! This module provides `Deserialize` implementations for shrouded types.
//! Note that `Serialize` is intentionally NOT implemented to prevent
//! accidental serialization of secrets.
//!
//! # Features
//!
//! Enable the `serde` feature to use these implementations:
//!
//! ```toml
//! [dependencies]
//! shroud = { version = "0.1", features = ["serde"] }
//! ```
//!
//! # Example
//!
//! ```ignore
//! use shroud::ShroudedString;
//! use serde::Deserialize;
//!
//! #[derive(Deserialize)]
//! struct Config {
//!     #[serde(deserialize_with = "shroud::serde::deserialize_string")]
//!     api_key: ShroudedString,
//! }
//! ```

use serde::de::{self, Deserialize, Deserializer, Visitor};
use crate::types::{ShroudedBytes, ShroudedString};

/// Deserializes a `ShroudedString` from a string value.
///
/// Use with `#[serde(deserialize_with = "shroud::serde::deserialize_string")]`
pub fn deserialize_string<'de, D>(deserializer: D) -> Result<ShroudedString, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringVisitor;

    impl<'de> Visitor<'de> for StringVisitor {
        type Value = ShroudedString;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter.write_str("a string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            ShroudedString::new(v.to_string())
                .map_err(|e| E::custom(format!("failed to create ShroudedString: {}", e)))
        }
    }

    deserializer.deserialize_str(StringVisitor)
}

/// Deserializes a `ShroudedBytes` from a string (for JSON compatibility).
///
/// Use with `#[serde(deserialize_with = "shroud::serde::deserialize_bytes")]`
pub fn deserialize_bytes<'de, D>(deserializer: D) -> Result<ShroudedBytes, D::Error>
where
    D: Deserializer<'de>,
{
    struct BytesVisitor;

    impl<'de> Visitor<'de> for BytesVisitor {
        type Value = ShroudedBytes;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter.write_str("a string or byte sequence")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let mut data = v.as_bytes().to_vec();
            ShroudedBytes::from_slice(&mut data)
                .map_err(|e| E::custom(format!("failed to create ShroudedBytes: {}", e)))
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let mut data = v.to_vec();
            ShroudedBytes::from_slice(&mut data)
                .map_err(|e| E::custom(format!("failed to create ShroudedBytes: {}", e)))
        }
    }

    // Use deserialize_str for JSON compatibility (JSON doesn't have native bytes)
    deserializer.deserialize_str(BytesVisitor)
}

impl<'de> Deserialize<'de> for ShroudedString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_string(deserializer)
    }
}

impl<'de> Deserialize<'de> for ShroudedBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_bytes(deserializer)
    }
}

// Note: Serialize is intentionally NOT implemented to prevent accidental
// serialization of secrets. If you need to serialize, explicitly call
// .expose() and serialize the result.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Expose;

    #[test]
    fn test_deserialize_string() {
        let json = r#""secret_password""#;
        let secret: ShroudedString = serde_json::from_str(json).unwrap();
        assert_eq!(secret.expose(), "secret_password");
    }

    #[test]
    fn test_deserialize_bytes_from_string() {
        // In JSON, bytes are typically represented as strings
        let json = r#""binary_data""#;
        let secret: ShroudedBytes = serde_json::from_str(json).unwrap();
        assert_eq!(secret.expose(), b"binary_data");
    }

    #[derive(serde::Deserialize)]
    struct TestConfig {
        #[serde(deserialize_with = "deserialize_string")]
        api_key: ShroudedString,
    }

    #[test]
    fn test_deserialize_in_struct() {
        let json = r#"{"api_key": "sk_test_123"}"#;
        let config: TestConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.api_key.expose(), "sk_test_123");
    }
}
