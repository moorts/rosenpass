use rosenpass_lenses::LenseError;

pub mod app_server;
pub mod cli;
pub mod config;
pub mod hash_domains;
pub mod msgs;
pub mod protocol;

#[cfg(feature = "test_vectors")]
pub mod test_vector;

#[derive(thiserror::Error, Debug)]
pub enum RosenpassError {
    #[error("buffer size mismatch")]
    BufferSizeMismatch,
    #[error("invalid message type")]
    InvalidMessageType(u8),
}

impl From<LenseError> for RosenpassError {
    fn from(value: LenseError) -> Self {
        match value {
            LenseError::BufferSizeMismatch => RosenpassError::BufferSizeMismatch,
        }
    }
}
