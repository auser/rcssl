use std::fmt::Display;

use serde::{Deserialize, Serialize};

use crate::{cert::CertificateProfile, cert_kp::CertificateKeyPair};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct CertificateConfig {
    pub domain: String,
    #[serde(default = "default_profile")]
    pub profile: CertificateProfile,
    pub common_name: String,
    pub country: String,
    pub state: String,
    pub city: String,
    pub organization: String,
    pub organizational_unit: Option<String>,
    pub validity_days: i64,
    pub hosts: Vec<String>,
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
}

fn default_profile() -> CertificateProfile {
    CertificateProfile::Ca
}

fn default_algorithm() -> String {
    "ECDSA_P256_SHA256".to_string()
}

impl Display for CertificateProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl From<String> for CertificateProfile {
    fn from(s: String) -> Self {
        s.as_str().into()
    }
}

impl From<&str> for CertificateProfile {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "server" => CertificateProfile::Server,
            "client" => CertificateProfile::Client,
            "peer" => CertificateProfile::Peer,
            "ca" => CertificateProfile::Ca,
            _ => panic!("Unknown profile: {}", s),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub ca_config: CertificateConfig,
    pub services: Vec<ServiceConfig>,
    #[serde(skip)]
    pub ca: Option<CertificateKeyPair>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceConfig {
    pub name: String,
    pub profile: String,
    pub common_name: Option<String>,
    pub hosts: Option<Vec<String>>,
}
