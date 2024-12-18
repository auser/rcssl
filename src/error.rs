use openssl::error::ErrorStack;

pub type CertGenResult<T, E = CertGenError> = Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum CertGenError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Invalid profile")]
    InvalidProfile,
    #[error("Invalid CA")]
    InvalidCA,
    #[error("Invalid certificate generation: {0}")]
    InvalidCertificateGeneration(String),
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid directory")]
    InvalidDirectory,
    #[error("Invalid UTF-8")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    #[error("Invalid PEM")]
    InvalidPem(#[from] ErrorStack),
    #[error("Generation error: {0}")]
    GenerationError(String),
}

impl From<rcgen::Error> for CertGenError {
    fn from(e: rcgen::Error) -> Self {
        CertGenError::InvalidCertificateGeneration(e.to_string())
    }
}
