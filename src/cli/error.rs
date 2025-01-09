use tracing_subscriber::util::TryInitError;

use crate::error::CertGenError;

pub type RCSSLResult<T = (), E = RCSSLError> = Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum RCSSLError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Failed to parse config file: {0}")]
    ConfigParseError(String),
    #[error("Unsupported file extension: {0}")]
    UnsupportedFileExtension(String),
    #[error("Failed to initialize tracing")]
    TryInitError(#[from] TryInitError),
    #[error("Certificate generation error: {0}")]
    CertGenError(#[from] CertGenError),
    #[error("Unknown profile: {0}")]
    UnknownProfile(String),
    #[error("Runtime error: {0}")]
    RuntimeError(#[from] color_eyre::Report),
    #[error("Invalid CA")]
    InvalidCA,
}

impl From<serde_json::Error> for RCSSLError {
    fn from(e: serde_json::Error) -> Self {
        RCSSLError::ConfigParseError(e.to_string())
    }
}

impl From<serde_yaml::Error> for RCSSLError {
    fn from(e: serde_yaml::Error) -> Self {
        RCSSLError::ConfigParseError(e.to_string())
    }
}
