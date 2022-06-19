//! Entry point of this JWT crate to sign and verify token.

use std::convert::TryFrom;
use chrono::{DateTime, Utc};

use serde::{de::DeserializeOwned, Serialize};

use crate::{JwtError, JwtResult, JwtToken, TimeOptions};
use crate::algo::Algorithm;
use crate::claims::JwtClaims;
use crate::header::JwtHeader;
use crate::token::{SignedToken, UnverifiedToken};

/// Provide JWT token sign and verify functions
#[derive(Clone)]
pub struct Jwt<A: Algorithm> {
    algo: A,
}

impl<A: Algorithm> Jwt<A> {
    pub fn new(algo: A) -> Jwt<A> {
        Self {
            algo
        }
    }

    /// Sign token with default header
    pub fn sign<T>(&self, claims: &JwtClaims<T>) -> JwtResult<String>
        where
            T: Serialize,
    {
        let header = JwtHeader::new(self.algo.name().to_string());
        self.sign_with_header(&header, claims)
    }

    /// Sign token with header
    pub fn sign_with_header<T>(&self, header: &JwtHeader, claims: &JwtClaims<T>) -> JwtResult<String>
        where
            T: Serialize,
    {
        let signed = SignedToken::sign::<T, A>(&header, claims, &self.algo)?;
        Ok(signed.signature)
    }

    /// Verify token
    pub fn verify<T, F>(&self, token: &str, options: &TimeOptions<F>) -> JwtResult<JwtToken<T>>
        where
            T: DeserializeOwned,
            F: Fn() -> DateTime<Utc>,
    {
        let unverified = UnverifiedToken::try_from(token).map_err(|_| JwtError::InvalidToken)?;
        unverified.verify(&self.algo, options)
    }
}
