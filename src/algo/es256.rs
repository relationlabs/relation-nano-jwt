//! ES256 = ECDSA using P-256(secp256r1, aka prime256v1) and SHA-256

use anyhow::anyhow;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::ecdsa::signature::{Signature as P256Signature, Signer, Verifier};
use p256::pkcs8::DecodePrivateKey;
use p256::SecretKey;

use crate::algo::{Algorithm, Signature};
use crate::error::SignatureErrorKind;
use crate::JwtError;

impl Signature for p256::ecdsa::Signature {
    fn try_from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        p256::ecdsa::Signature::from_bytes(bytes).map_err(|err| anyhow!(err))
    }
}

/// ES256 = ECDSA using P-256(secp256r1, aka prime256v1) and SHA-256
#[derive(Clone)]
pub struct ES256 {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl ES256 {
    pub fn from_jwk(jwk: &str) -> Self {
        let secret_key = SecretKey::from_jwk_str(jwk).expect("Invalid JWK");
        Self::new(secret_key)
    }

    /// Parse from PEM-encoded SEC1 `ECPrivateKey` format.
    ///
    /// PEM-encoded SEC1 keys can be identified by the leading delimiter:
    ///
    /// ```text
    /// -----BEGIN EC PRIVATE KEY-----
    /// ```
    pub fn from_sec1_pem(sec1_pem: &str) -> Self {
        let secret_key = SecretKey::from_sec1_pem(sec1_pem).expect("Invalid SEC1 pem");
        Self::new(secret_key)
    }

    // Parse PKCS#8-encoded private key from PEM (Privacy-Enhanced Mail)
    ///
    /// Keys in this format begin with the following delimiter:
    ///
    /// ```text
    /// -----BEGIN PRIVATE KEY-----
    /// ```
    pub fn from_pkcs8_pem(pkcs8_pem: &str) -> Self {
        let secret_key = SecretKey::from_pkcs8_pem(pkcs8_pem).expect("Invalid PKCS#8 pem");
        Self::new(secret_key)
    }

    fn new(secret_key: SecretKey) -> Self {
        let signing_key = SigningKey::from(secret_key);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }
}

impl Algorithm for ES256 {
    type Signature = p256::ecdsa::Signature;
    type Error = JwtError;

    fn name(&self) -> &'static str {
        "ES256"
    }

    fn sign(&self, bytes: &[u8]) -> Result<Self::Signature, Self::Error> {
        Ok(Signer::sign(&self.signing_key, bytes))
    }

    fn verify<M>(&self, message: M, signature: Self::Signature) -> Result<(), Self::Error>
        where M: AsRef<[u8]> {
        let signature = P256Signature::from_bytes(signature.as_ref())
            .map_err(|_| JwtError::Signature(SignatureErrorKind::Algorithm))?;

        Verifier::verify(&self.verifying_key, message.as_ref(), &signature)
            .map_err(|_| JwtError::Signature(SignatureErrorKind::Algorithm))
    }
}