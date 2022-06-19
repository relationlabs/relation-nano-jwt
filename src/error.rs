//! Error used by JWT

use thiserror::Error;

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("Invalid token")]
    InvalidToken,

    #[error("Invalid header: {0:?}")]
    InvalidHeader(HeaderErrorKind),

    #[error("Invalid claims: {0:?}")]
    InvalidClaims(ClaimErrorKind),

    #[error("Failed to sign the token: {0:?}")]
    Signature(SignatureErrorKind),
}

impl JwtError {
    pub fn is_token_expired(&self) -> bool {
        match *self {
            JwtError::InvalidClaims(ClaimErrorKind::TokenExpired) => true,
            _ => false,
        }
    }
}

/// Detailed errors of a header.
#[derive(Debug)]
#[non_exhaustive]
pub enum HeaderErrorKind {
    /// Header cannot be serialized/deserialized to/from JSON.
    Malformed(serde_json::Error),

    /// Header cannot decode base64.
    Base64Encoding,
}

/// Detailed errors of a claim.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClaimErrorKind {
    /// `exp` claim (token has expired as per `exp` claim).
    TokenExpired,

    /// `nbf` claim (token is not yet valid as per `nbf` claim).
    TokenNotMature,

    /// Claims cannot be serialized/deserialized to/from JSON.
    Malformed(serde_json::Error),

    /// Claims cannot decode base64.
    Base64Encoding,
}

/// Detailed errors when signing a token
#[derive(Debug)]
#[non_exhaustive]
pub enum SignatureErrorKind {
    /// The algorithm failed to sign the token to generate signature.
    Algorithm,

    /// Signature cannot be converted to UTF8.
    Utf8Encoding,

    /// Signature cannot decode base64.
    Base64Encoding,

    /// Invalid signature.
    Invalid,
}
