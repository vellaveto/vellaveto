#[derive(Debug, thiserror::Error)]
pub enum ProjectorError {
    #[error("unsupported model family: {0:?}")]
    UnsupportedFamily(vellaveto_types::ModelFamily),
    #[error("lock poisoned")]
    LockPoisoned,
    #[error("invalid schema: {0}")]
    InvalidSchema(String),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}
