//! JWT Claims are pieces of information asserted about a subject.
//! In a JWT, a claim appears as a name/value pair where the name
//! is always a string and the value can be any JSON value.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::ClaimErrorKind;
use crate::JwtError;

/// Time-related options for token creation and validation.
///
/// If the `clock` crate feature is on (and it's on by default), `TimeOptions` can be created
/// using the `Default` impl or [`Self::from_leeway()`]. If the feature is off,
/// you can still create options using [a generic constructor](Self::new).
///
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct TimeOptions<F = fn() -> DateTime<Utc>> {
    /// Leeway to use during validation.
    pub leeway: Duration,
    /// Source of the current timestamps.
    pub clock_fn: F,
}

impl<F: Fn() -> DateTime<Utc>> TimeOptions<F> {
    /// Creates options based on the specified time leeway and clock function.
    pub fn new(leeway: Duration, clock_fn: F) -> Self {
        Self { leeway, clock_fn }
    }
}

impl TimeOptions {
    /// Creates options based on the specified time leeway. The clock source is [`Utc::now()`].
    #[cfg(feature = "clock")]
    #[cfg_attr(docsrs, doc(cfg(feature = "clock")))]
    pub fn from_leeway(leeway: Duration) -> Self {
        Self {
            leeway,
            clock_fn: Utc::now,
        }
    }
}

/// Creates options with a default leeway (60 seconds) and the [`Utc::now()`] clock.
///
/// This impl is supported on **crate feature `clock`** only.
#[cfg(feature = "clock")]
impl Default for TimeOptions {
    fn default() -> Self {
        Self::from_leeway(Duration::seconds(60))
    }
}

/// A structure with no fields that can be used as a type parameter to `Claims`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Empty {}

/// Claims encoded in a token.
///
/// Claims are comprised of a "standard" part (`exp`, `nbf` and `iat` claims as per [JWT spec]),
/// and custom fields. `iss`, `sub` and `aud` claims are not in the standard part
/// due to a variety of data types they can be reasonably represented by.
///
/// [JWT spec]: https://tools.ietf.org/html/rfc7519#section-4.1
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct JwtClaims<T> {
    /// Expiration time of the token.
    #[serde(rename = "exp", default, skip_serializing_if = "Option::is_none", with = "self::serde_timestamp")]
    pub expiration: Option<DateTime<Utc>>,

    /// Minimum time at which token is valid.
    #[serde(rename = "nbf", default, skip_serializing_if = "Option::is_none", with = "self::serde_timestamp")]
    pub not_before: Option<DateTime<Utc>>,

    /// Time of token issuance.
    #[serde(rename = "iat", default, skip_serializing_if = "Option::is_none", with = "self::serde_timestamp")]
    pub issued_at: Option<DateTime<Utc>>,

    /// Custom claims.
    #[serde(flatten)]
    pub custom: T,
}

impl JwtClaims<Empty> {
    /// Creates an empty claims instance.
    pub fn empty() -> Self {
        Self {
            expiration: None,
            not_before: None,
            issued_at: None,
            custom: Empty {},
        }
    }
}

impl<T> JwtClaims<T> {
    /// Creates a new instance with the provided custom claims.
    pub fn new(custom_claims: T) -> Self {
        Self {
            expiration: None,
            not_before: None,
            issued_at: None,
            custom: custom_claims,
        }
    }

    /// Sets the `expiration` claim so that the token has the specified `duration`.
    /// The current timestamp is taken from `options`.
    pub fn with_expiration<F>(self, options: &TimeOptions<F>, expiration: Duration) -> Self
        where
            F: Fn() -> DateTime<Utc>,
    {
        Self {
            expiration: Some((options.clock_fn)() + expiration),
            ..self
        }
    }

    /// Atomically sets `issued_at` and `expiration` claims: first to the current time
    /// (taken from `options`), and the second to match the specified `duration` of the token.
    pub fn with_expiration_and_issuance<F>(self, options: &TimeOptions<F>, expiration: Duration) -> Self
        where
            F: Fn() -> DateTime<Utc>,
    {
        let issued_at = (options.clock_fn)();
        Self {
            expiration: Some(issued_at + expiration),
            issued_at: Some(issued_at),
            ..self
        }
    }

    /// Sets the `nbf` claim.
    pub fn with_not_before(self, moment: DateTime<Utc>) -> Self {
        Self {
            not_before: Some(moment),
            ..self
        }
    }

    /// Validates the expiration claim.
    ///
    /// This method will return an error if the claims do not feature an expiration time,
    /// or if it is in the past (subject to the provided `options`).
    pub fn validate_expiration<F>(&self, options: &TimeOptions<F>) -> Result<&Self, JwtError>
        where
            F: Fn() -> DateTime<Utc>,
    {
        self.expiration.map_or(
            Ok(self),
            |expiration| {
                let expiration_with_leeway = expiration
                    .checked_add_signed(options.leeway)
                    .unwrap_or(chrono::MAX_DATETIME);
                if (options.clock_fn)() > expiration_with_leeway {
                    Err(JwtError::InvalidClaims(ClaimErrorKind::TokenExpired))
                } else {
                    Ok(self)
                }
            },
        )
    }

    /// Validates the maturity time (`nbf` claim).
    ///
    /// This method will return an error if the claims do not feature a maturity time,
    /// or if it is in the future (subject to the provided `options`).
    pub fn validate_maturity<F>(&self, options: &TimeOptions<F>) -> Result<&Self, JwtError>
        where
            F: Fn() -> DateTime<Utc>,
    {
        self.not_before.map_or(
            Ok(self),
            |not_before| {
                if (options.clock_fn)() < not_before - options.leeway {
                    Err(JwtError::InvalidClaims(ClaimErrorKind::TokenNotMature))
                } else {
                    Ok(self)
                }
            },
        )
    }
}

mod serde_timestamp {
    use core::{convert::TryFrom, fmt};

    use chrono::{DateTime, offset::TimeZone, Utc};
    use serde::{
        de::{Error as DeError, Visitor},
        Deserializer, Serializer,
    };

    struct TimestampVisitor;

    impl<'de> Visitor<'de> for TimestampVisitor {
        type Value = DateTime<Utc>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("UTC timestamp")
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: DeError,
        {
            Ok(Utc.timestamp(value, 0))
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: DeError,
        {
            let value = i64::try_from(value).map_err(DeError::custom)?;
            Ok(Utc.timestamp(value, 0))
        }
    }

    pub fn serialize<S: Serializer>(
        time: &Option<DateTime<Utc>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        // `unwrap` is safe due to `skip_serializing_if` option
        serializer.serialize_i64(time.unwrap().timestamp())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<DateTime<Utc>>, D::Error> {
        deserializer.deserialize_i64(TimestampVisitor).map(Some)
    }
}
