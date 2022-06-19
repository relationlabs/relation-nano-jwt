//! JWT signature algorithm traits.

/// A signature which can be represented by bytes.
pub trait Signature: AsRef<[u8]> + Sized {
    /// Attempts to restore a signature from a byte slice. This method may fail
    /// if the slice is malformed.
    fn try_from_bytes(slice: &[u8]) -> anyhow::Result<Self>;

    /// Borrow a byte slice representing the serialized form of this signature
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

/// JWT signing algorithm.
pub trait Algorithm {
    /// Returned signature type which implements the [Signature] trait.
    type Signature: Signature;

    /// Returns an error.
    type Error;

    /// The algorithm name.
    fn name(&self) -> &'static str;

    /// Returns a signature from a byte buffer.
    ///
    /// # Errors
    ///
    /// Returns an error dependent on the signer.
    fn sign(&self, bytes: &[u8]) -> Result<Self::Signature, Self::Error>;

    /// Verifies the message with the given signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is not valid for the message.
    fn verify<M>(&self, message: M, signature: Self::Signature) -> Result<(), Self::Error>
        where
            M: AsRef<[u8]>;
}
