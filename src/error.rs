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
    #[error("RSA error: {0}")]
    RsaError(#[from] rsa::errors::Error),
    #[error("Invalid CA")]
    InvalidCAError(String),
}

impl PartialEq for CertGenError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::IoError(a), Self::IoError(b)) => a.kind() == b.kind(),
            (Self::InvalidProfile, Self::InvalidProfile) => true,
            (Self::InvalidCA, Self::InvalidCA) => true,
            (Self::InvalidCertificateGeneration(a), Self::InvalidCertificateGeneration(b)) => {
                a == b
            }
            (Self::InvalidKey, Self::InvalidKey) => true,
            (Self::InvalidDirectory, Self::InvalidDirectory) => true,
            (Self::InvalidUtf8(a), Self::InvalidUtf8(b)) => a == b,
            (Self::InvalidPem(a), Self::InvalidPem(b)) => a.to_string() == b.to_string(),
            (Self::GenerationError(a), Self::GenerationError(b)) => a == b,
            (Self::RsaError(a), Self::RsaError(b)) => a.to_string() == b.to_string(),
            (Self::InvalidCAError(a), Self::InvalidCAError(b)) => a == b,
            _ => false,
        }
    }
}

impl From<rcgen::Error> for CertGenError {
    fn from(e: rcgen::Error) -> Self {
        CertGenError::InvalidCertificateGeneration(e.to_string())
    }
}
