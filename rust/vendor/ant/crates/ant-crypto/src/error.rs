use k256::ecdsa;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid secp256k1 secret key")]
    InvalidSecretKey(#[from] k256::elliptic_curve::Error),
    #[error("invalid secp256k1 public key")]
    InvalidPublicKey,
    #[error("signing failed: {0}")]
    Sign(#[from] ecdsa::Error),
    #[error("bad signature")]
    BadSignature,
    #[error("recovered overlay does not match declared overlay")]
    OverlayMismatch,
    #[error("gsoc mining exhausted its attempt budget without a match")]
    GsocMiningExhausted,
    #[error("chunk payload must be 1..=4096 bytes")]
    InvalidChunkPayload,
    #[error("PSS message exceeds the maximum payload size")]
    PssMessageTooLong,
    #[error("PSS targets must be 1..=3 bytes and all the same length")]
    PssInvalidTargets,
    #[error("PSS nonce mining was cancelled")]
    PssMiningCancelled,
}
