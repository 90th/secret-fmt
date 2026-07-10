#![no_std]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic, clippy::cargo)]

//! A zero-dependency wrapper type that prevents accidental logging of sensitive data.
//!
//! `Secret<T>` wraps any value and explicitly overrides its `Debug` and `Display`
//! (and optionally `Serialize`) implementations to emit `"[REDACTED]"`.
//!
//! Unlike other secrecy crates, `Secret` has **zero trait bounds**. You can wrap
//! any type instantly without implementing boilerplate traits like `Zeroize`.
//!
//! Note: `Secret` intentionally does not implement `Deref` to prevent implicit
//! coercions that could bypass the redaction formatting.

use core::fmt;

/// A wrapper type that redacts its contents when logged or formatted.
///
/// Implements standard traits like `Clone`, `PartialEq`, and `Hash` transparently,
/// so it can be freely used in standard collections without exposing the secret via formatting.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use = "wrapping a value in a secret_fmt is useless if the secret_fmt is immediately dropped"]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Creates a new `Secret` wrapping the provided value.
    ///
    /// # Examples
    /// ```
    /// use secret_fmt::Secret;
    /// let secret = Secret::new("super_secret_password");
    /// assert_eq!(format!("{:?}", secret), "[REDACTED]");
    /// ```
    #[inline]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Consumes the `Secret`, returning the wrapped value.
    ///
    /// # Examples
    /// ```
    /// use secret_fmt::Secret;
    /// let secret = Secret::new(12345);
    /// assert_eq!(secret.into_inner(), 12345);
    /// ```
    #[inline]
    #[must_use = "consuming the secret_fmt to discard the inner value is likely a mistake"]
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Returns a shared reference to the wrapped value.
    ///
    /// # Examples
    /// ```
    /// use secret_fmt::Secret;
    /// let secret = Secret::new(String::from("test"));
    /// assert_eq!(secret.as_inner(), "test");
    /// ```
    #[inline]
    #[must_use = "getting the inner reference without using it is likely a mistake"]
    pub const fn as_inner(&self) -> &T {
        &self.0
    }

    /// Returns a mutable reference to the wrapped value.
    ///
    /// # Examples
    /// ```
    /// use secret_fmt::Secret;
    /// let mut secret = Secret::new(String::from("test"));
    /// secret.as_inner_mut().push_str("ing");
    /// assert_eq!(secret.into_inner(), "testing");
    /// ```
    #[inline]
    #[must_use = "getting the inner mutable reference without using it is likely a mistake"]
    pub fn as_inner_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> From<T> for Secret<T> {
    #[inline]
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> AsRef<T> for Secret<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        &self.0
    }
}

/// Wraps a reference or value in a `Secret` on the fly.
///
/// Useful for inline logging without taking ownership or altering structs.
///
/// # Examples
/// ```
/// use secret_fmt::redact;
/// let token = "sensitive_data";
/// assert_eq!(format!("{}", redact!(&token)), "[REDACTED]");
/// ```
#[macro_export]
macro_rules! redact {
    ($val:expr) => {
        $crate::Secret::new($val)
    };
}

#[cfg(feature = "serde")]
pub mod serialize_redacted {
    //! Helper module to serialize a `Secret` as `"[REDACTED]"`.
    //!
    //! # Examples
    //! ```
    //! use serde::Serialize;
    //! use secret_fmt::{Secret, serialize_redacted};
    //!
    //! #[derive(Serialize)]
    //! struct LogPayload {
    //!     #[serde(serialize_with = "serialize_redacted::serialize")]
    //!     api_key: Secret<String>,
    //! }
    //! ```
    use super::Secret;
    use serde::Serializer;

    /// Serializes the wrapped value as the literal string `"[REDACTED]"`.
    ///
    /// # Errors
    /// Returns an error if the underlying serializer fails.
    pub fn serialize<T, S>(_: &Secret<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("[REDACTED]")
    }
}

#[cfg(feature = "serde")]
pub mod serialize_actual {
    //! Helper module to serialize the actual underlying value of a `Secret`.
    //!
    //! # Examples
    //! ```
    //! use serde::Serialize;
    //! use secret_fmt::{Secret, serialize_actual};
    //!
    //! #[derive(Serialize)]
    //! struct UpstreamRequest {
    //!     #[serde(serialize_with = "serialize_actual::serialize")]
    //!     api_key: Secret<String>,
    //! }
    //! ```
    use super::Secret;
    use serde::{Serialize, Serializer};

    /// Serializes the actual underlying value, ignoring the redaction.
    ///
    /// # Errors
    /// Returns an error if the underlying serializer fails.
    pub fn serialize<T: Serialize, S>(val: &Secret<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        val.as_inner().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, T> serde::Deserialize<'de> for Secret<T>
where
    T: serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Allow incoming JSON to parse the secret properly.
        T::deserialize(deserializer).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Using std only for testing string formatting and collections
    extern crate std;
    use std::collections::hash_map::DefaultHasher;
    use std::format;
    use std::hash::{Hash, Hasher};
    use std::string::String;

    #[test]
    fn test_debug_redacted() {
        let secret = Secret::new("super_secret_password");
        assert_eq!(format!("{:?}", secret), "[REDACTED]");
    }

    #[test]
    fn test_display_redacted() {
        let secret = Secret::new(12345);
        assert_eq!(format!("{}", secret), "[REDACTED]");
    }

    #[test]
    fn test_as_inner() {
        let mut secret = Secret::new(String::from("test"));
        assert_eq!(secret.as_inner(), "test");

        secret.as_inner_mut().push_str("ing");
        assert_eq!(secret.into_inner(), "testing");
    }

    #[test]
    fn test_derived_traits() {
        // Test that traits like Eq, Ord, Hash transparently pass through to the inner value
        let a = Secret::new(10);
        let a_clone = a.clone();
        let b = Secret::new(20);

        assert_eq!(a, a_clone);
        assert_ne!(a, b);
        assert!(a < b);

        let mut hasher_a = DefaultHasher::new();
        a.hash(&mut hasher_a);
        let mut hasher_inner = DefaultHasher::new();
        10.hash(&mut hasher_inner);
        assert_eq!(hasher_a.finish(), hasher_inner.finish());
    }

    #[test]
    fn test_macro_and_conversions() {
        let original = "sensitive_data";
        let wrapped: Secret<&str> = original.into();

        assert_eq!(wrapped.as_ref(), &"sensitive_data");
        assert_eq!(format!("{}", redact!(&original)), "[REDACTED]");
        assert_eq!(format!("{:?}", redact!(original)), "[REDACTED]");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, core::fmt::Debug)]
        struct User {
            id: u32,
            #[serde(serialize_with = "serialize_redacted::serialize")]
            api_key: Secret<String>,
            #[serde(serialize_with = "serialize_actual::serialize")]
            pass_through: Secret<String>,
        }

        let json = r#"{"id":123,"api_key":"secret_token_abc","pass_through":"sent_to_stripe"}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.id, 123);
        assert_eq!(user.api_key.as_inner(), "secret_token_abc");
        assert_eq!(user.pass_through.as_inner(), "sent_to_stripe");

        let serialized = serde_json::to_string(&user).unwrap();
        assert_eq!(
            serialized,
            r#"{"id":123,"api_key":"[REDACTED]","pass_through":"sent_to_stripe"}"#
        );
    }
}
