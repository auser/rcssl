use std::fmt::Debug;
use std::fs;
use std::path::PathBuf;

use rcgen::{Certificate, CertificateParams, KeyPair};
use tracing::debug;

use crate::error::CertGenError;

pub struct CertificateKeyPair {
    certificate: Certificate,
    key_pair: KeyPair,
    name: String,
}

impl Debug for CertificateKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CertificateKeyPair")
    }
}

impl Clone for CertificateKeyPair {
    fn clone(&self) -> Self {
        // Get the PEM contents
        let cert_pem = self.certificate.pem();
        let key_pem = self.key_pair.serialize_pem();

        // Create new key pair from PEM
        let key_pair =
            KeyPair::from_pem(&key_pem).expect("Failed to clone key pair from valid PEM");

        // Create new certificate params and certificate
        let params = CertificateParams::from_ca_cert_pem(&cert_pem)
            .expect("Failed to create params from valid certificate PEM");
        let certificate = params
            .self_signed(&key_pair)
            .expect("Failed to create certificate from valid params");

        Self {
            certificate,
            key_pair,
            name: self.name.clone(),
        }
    }
}

impl CertificateKeyPair {
    pub fn new(name: String, certificate: Certificate, key_pair: KeyPair) -> CertificateKeyPair {
        Self {
            certificate,
            key_pair,
            name,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn write(&self, parent_dir: &str) -> Result<(), CertGenError> {
        // Create parent directory if it doesn't exist
        let parent_dir = PathBuf::from(parent_dir);
        if !parent_dir.exists() {
            debug!("Creating parent directory: {:?}", parent_dir);
            fs::create_dir_all(&parent_dir)?;
        }
        let cert_path = parent_dir.join(format!("{}.pem", self.name));
        let key_path = parent_dir.join(format!("{}.key", self.name));
        debug!("Writing certificate to {:?}", cert_path);
        fs::write(cert_path, self.certificate.pem())?;
        debug!("Writing key to {:?}", key_path);
        fs::write(key_path, self.key_pair.serialize_pem())?;
        Ok(())
    }

    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }
}

impl TryFrom<PathBuf> for CertificateKeyPair {
    type Error = CertGenError;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let ca_key_path = path.with_extension("key");
        let ca_key_pem = fs::read_to_string(&ca_key_path).map_err(|e| CertGenError::IoError(e))?;
        let ca_key =
            KeyPair::from_pem(ca_key_pem.as_str()).map_err(|_e| CertGenError::InvalidKey)?;

        let ca_cert_path = path.with_extension("pem");
        let ca_cert_pem =
            fs::read_to_string(&ca_cert_path).map_err(|e| CertGenError::IoError(e))?;
        let ca_cert_params = CertificateParams::from_ca_cert_pem(ca_cert_pem.as_str())
            .map_err(|e| CertGenError::InvalidCAError(e.to_string()))?;

        // rcgen doesn't offer a way of loading the CA, so we create a fake temporary certificate.
        let ca_cert = ca_cert_params
            .self_signed(&ca_key)
            .map_err(|e| CertGenError::InvalidCAError(e.to_string()))?;

        Ok(CertificateKeyPair::new(name, ca_cert, ca_key))
    }
}
