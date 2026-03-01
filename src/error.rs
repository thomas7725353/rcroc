use thiserror::Error;

pub type Result<T> = std::result::Result<T, RcrocError>;

#[derive(Debug, Error)]
pub enum RcrocError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("authentication failed")]
    Authentication,

    #[error("invalid secret: {0}")]
    InvalidSecret(String),

    #[error("invalid path: {0}")]
    InvalidPath(String),

    #[error("unexpected message: {0}")]
    UnexpectedMessage(String),
}
