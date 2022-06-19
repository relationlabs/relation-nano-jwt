//! JWT token encode and decode

use std::convert::TryFrom;
use std::str;

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Serialize};
use smallvec::{smallvec, SmallVec};

use crate::{JwtClaims, JwtError, JwtHeader, JwtResult, TimeOptions};
use crate::algo::{Algorithm, Signature};
use crate::error::{ClaimErrorKind, HeaderErrorKind, SignatureErrorKind};

/// Maximum "reasonable" signature size in bytes.
const SIGNATURE_SIZE: usize = 128;

/// Token is not verified
#[derive(Debug)]
pub struct UnverifiedToken<'a> {
    /// The decoded header.
    header: JwtHeader,
    /// The decoded claims.
    claims: Vec<u8>,
    /// The encoded header + "." + encoded claims.
    signed_data: &'a str,
    /// The decoded signature.
    signature: SmallVec<[u8; SIGNATURE_SIZE]>,
}

impl<'a> UnverifiedToken<'a> {
    /// Verify this token with the given algorithm
    pub fn verify<T, A, F>(&self, algo: &A, options: &TimeOptions<F>) -> JwtResult<VerifiedToken<T>>
        where
            T: DeserializeOwned,
            A: Algorithm,
            F: Fn() -> DateTime<Utc>,
    {
        let signed_data = self.signed_data.as_bytes();
        let decoded_signature: &[u8] = &self.signature;
        let signature = A::Signature::try_from_bytes(decoded_signature)
            .map_err(|_| JwtError::Signature(SignatureErrorKind::Invalid))?;

        // assume that parsing claims is less computationally demanding than validating a signature.
        let claims = self.deserialize_claims::<T>()?;
        algo.verify(signed_data, signature)
            .map_err(|_| JwtError::Signature(SignatureErrorKind::Invalid))?;

        // validate maturity and expiration
        claims.validate_maturity(options)?.validate_expiration(options)?;

        Ok(VerifiedToken {
            header: self.header.clone(),
            claims,
        })
    }

    /// Deserializes claims from this token without checking token integrity. The resulting
    /// claims are thus **not** guaranteed to be valid.
    #[must_use]
    pub fn deserialize_claims<T>(&self) -> JwtResult<JwtClaims<T>>
        where
            T: DeserializeOwned,
    {
        serde_json::from_slice(&self.claims)
            .map_err(|e| JwtError::InvalidClaims(ClaimErrorKind::Malformed(e)))

        // TODO: add content type support
        // match self.content_type {
        //     ContentType::Json => serde_json::from_slice(&self.serialized_claims)
        //         .map_err(|e| JwtError::InvalidClaims(ClaimErrorKind::ClaimErrorKind(e))),
        //
        //     #[cfg(feature = "serde_cbor")]
        //     ContentType::Cbor => serde_cbor::from_slice(&self.serialized_claims)
        //         .map_err(|e| JwtError::InvalidClaims(ClaimErrorKind::Malformed(e))),
        // }
    }
}

impl<'a> TryFrom<&'a str> for UnverifiedToken<'a> {
    type Error = JwtError;

    fn try_from(token: &'a str) -> JwtResult<Self> {
        let mut parts = token.rsplitn(2, '.');
        let (signature, signed_data) = match (parts.next(), parts.next()) {
            (Some(signature), Some(signed_data)) => (signature, signed_data),
            _ => return Err(JwtError::InvalidToken),
        };

        let mut parts = signed_data.rsplitn(3, '.');
        let (claims, header) = match (parts.next(), parts.next(), parts.next()) {
            (Some(claims), Some(header), None) => (claims, header),
            _ => return Err(JwtError::InvalidToken),
        };

        // decodes header
        let header = Base64UrlUnpadded::decode_vec(header)
            .map_err(|_| JwtError::InvalidHeader(HeaderErrorKind::Base64Encoding))?;
        let header: JwtHeader = serde_json::from_slice(&header)
            .map_err(|err| JwtError::InvalidHeader(HeaderErrorKind::Malformed(err)))?;

        // decodes claims
        let claims = Base64UrlUnpadded::decode_vec(claims)
            .map_err(|_| JwtError::InvalidClaims(ClaimErrorKind::Base64Encoding))?;

        // decodes signature
        let mut decoded_signature = smallvec![0; 3 * (signature.len() + 3) / 4];
        let signature_len = Base64UrlUnpadded::decode(signature, &mut decoded_signature[..])
            .map_err(|_| JwtError::Signature(SignatureErrorKind::Base64Encoding))?
            .len();
        decoded_signature.truncate(signature_len);

        Ok(Self {
            header,
            claims,
            signed_data,
            signature: decoded_signature,
        })
    }
}

/// Token with validated integrity.
#[derive(Debug)]
#[non_exhaustive]
pub struct VerifiedToken<T: DeserializeOwned> {
    /// Token header
    pub header: JwtHeader,
    /// Token claims
    pub claims: JwtClaims<T>,
}

/// Token signed.
#[non_exhaustive]
pub struct SignedToken {
    /// Token signature.
    pub signature: String,
}

impl SignedToken {
    /// Sign the header and claim with the given algorithm to generate a signature
    pub fn sign<T, A>(header: &JwtHeader, claims: &JwtClaims<T>, algo: &A) -> JwtResult<SignedToken>
        where
            T: Serialize,
            A: Algorithm,
    {
        // encode header
        let header_str = serde_json::to_string(header)
            .map_err(|err| JwtError::InvalidHeader(HeaderErrorKind::Malformed(err)))?;
        let mut buffer = Vec::new();
        encode_base64_buf(&header_str, &mut buffer);

        // encode claims
        let claims_str = serde_json::to_string(claims)
            .map_err(|err| JwtError::InvalidClaims(ClaimErrorKind::Malformed(err)))?;
        buffer.push(b'.');
        encode_base64_buf(&claims_str, &mut buffer);

        // sign token to generate signature
        let signature = algo.sign(&buffer)
            .map_err(|_| JwtError::Signature(SignatureErrorKind::Algorithm))?;
        let signature = signature.as_ref();

        buffer.push(b'.');
        encode_base64_buf(signature.as_ref(), &mut buffer);

        // error is unlike to happen, because base64 alphabet and `.` char are valid UTF-8.
        let signature = str::from_utf8(&buffer[..])
            .map_err(|_| JwtError::Signature(SignatureErrorKind::Utf8Encoding))?
            .to_string();
        Ok(SignedToken { signature })
    }
}

fn encode_base64_buf(source: impl AsRef<[u8]>, buffer: &mut Vec<u8>) {
    let source = source.as_ref();
    let previous_len = buffer.len();
    let claims_len = Base64UrlUnpadded::encoded_len(source);
    buffer.resize(previous_len + claims_len, 0);
    Base64UrlUnpadded::encode(source, &mut buffer[previous_len..])
        .expect("miscalculated base64-encoded length; this should never happen");
}
