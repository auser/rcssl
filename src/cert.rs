use chrono::{Datelike, Duration, Utc};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tracing::debug;

use crate::cert_kp::CertificateKeyPair;
use crate::error::CertGenError;
use crate::util::get_algorithm;

pub type CertGenResult<T> = Result<T, CertGenError>;

#[derive(Debug, Clone)]
pub struct CertificateOptions {
    pub profile: CertificateProfile,
    pub domain: String,
    pub name: String,
    pub common_name: Option<String>,
    pub hosts: Vec<String>,
    pub city: String,
    pub state: String,
    pub country: String,
    pub organization: String,
    pub organizational_unit: Option<String>,
    pub validity_days: i64,
    pub is_ca: bool,
    pub algorithm: String,
    pub ca: Option<CertificateKeyPair>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CertificateProfile {
    Server,
    Client,
    Peer,
    Ca,
}

impl Default for CertificateOptions {
    fn default() -> Self {
        Self {
            profile: CertificateProfile::Server,
            common_name: Some("traefik".to_string()),
            name: "traefik".to_string(),
            hosts: vec!["localhost".to_string(), "traefik".to_string()],
            domain: "ari.io".to_string(),
            city: "San Francisco".to_string(),
            state: "California".to_string(),
            country: "US".to_string(),
            organization: "ari.io".to_string(),
            organizational_unit: Some("CA".to_string()),
            validity_days: 365,
            is_ca: false,
            algorithm: "ECDSA_P256_SHA256".to_string(),
            ca: None,
        }
    }
}

#[derive(Default)]
pub struct CertificateOptionsBuilder {
    profile: Option<CertificateProfile>,
    common_name: Option<String>,
    name: Option<String>,
    hosts: Option<Vec<String>>,
    output_dir: Option<PathBuf>,
    base_dir: Option<PathBuf>,
    domain: Option<String>,
    city: Option<String>,
    state: Option<String>,
    country: Option<String>,
    organization: Option<String>,
    organizational_unit: Option<Option<String>>,
    validity_days: Option<i64>,
    is_ca: Option<bool>,
    algorithm: Option<String>,
    ca: Option<CertificateKeyPair>,
}

impl CertificateOptionsBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn profile(mut self, profile: CertificateProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    pub fn common_name(mut self, common_name: &str) -> Self {
        self.common_name = Some(common_name.to_string());
        self
    }

    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    pub fn hosts(mut self, hosts: Vec<&str>) -> Self {
        self.hosts = Some(hosts.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn output_dir(mut self, output_dir: PathBuf) -> Self {
        self.output_dir = Some(output_dir);
        self
    }

    pub fn base_dir(mut self, base_dir: PathBuf) -> Self {
        self.base_dir = Some(base_dir);
        self
    }

    pub fn domain(mut self, domain: &str) -> Self {
        self.domain = Some(domain.to_string());
        self
    }

    pub fn city(mut self, city: &str) -> Self {
        self.city = Some(city.to_string());
        self
    }

    pub fn state(mut self, state: &str) -> Self {
        self.state = Some(state.to_string());
        self
    }

    pub fn country(mut self, country: &str) -> Self {
        self.country = Some(country.to_string());
        self
    }

    pub fn organization(mut self, organization: &str) -> Self {
        self.organization = Some(organization.to_string());
        self
    }

    pub fn organizational_unit(mut self, organizational_unit: Option<&str>) -> Self {
        self.organizational_unit = Some(organizational_unit.map(|s| s.to_string()));
        self
    }

    pub fn validity_days(mut self, validity_days: i64) -> Self {
        self.validity_days = Some(validity_days);
        self
    }

    pub fn is_ca(mut self, is_ca: bool) -> Self {
        self.is_ca = Some(is_ca);
        self
    }

    pub fn ca(mut self, ca: CertificateKeyPair) -> Self {
        self.ca = Some(ca);
        self
    }

    pub fn build(self) -> CertificateOptions {
        let default = CertificateOptions::default();
        CertificateOptions {
            profile: self.profile.unwrap_or(default.profile),
            common_name: self.common_name.clone(),
            name: self.name.unwrap_or(default.name),
            hosts: self.hosts.unwrap_or(default.hosts),
            domain: self.domain.unwrap_or(default.domain),
            city: self.city.unwrap_or(default.city),
            state: self.state.unwrap_or(default.state),
            country: self.country.unwrap_or(default.country),
            organization: self.organization.unwrap_or(default.organization),
            organizational_unit: self
                .organizational_unit
                .unwrap_or(default.organizational_unit),
            validity_days: self.validity_days.unwrap_or(default.validity_days),
            is_ca: self.is_ca.unwrap_or(default.is_ca),
            algorithm: self.algorithm.unwrap_or(default.algorithm),
            ca: self.ca.clone(),
        }
    }
}

#[derive(Clone)]
pub struct CertificateGenerator {
    ca: Option<CertificateKeyPair>,
}

impl CertificateGenerator {
    pub fn new() -> Self {
        Self { ca: None }
    }

    fn set_ca(&mut self, ca: CertificateKeyPair) {
        self.ca = Some(ca);
    }

    pub fn ensure_directory_exists(&self, path: &PathBuf) -> CertGenResult<()> {
        fs::create_dir_all(path)?;
        Ok(())
    }

    pub fn clean_certs(&self, base_dir: &PathBuf) -> CertGenResult<()> {
        fs::remove_dir_all(base_dir)?;
        Ok(())
    }

    pub fn get_ca_cert_pem(&self) -> Option<String> {
        self.ca.as_ref().map(|ca| ca.certificate().pem())
    }

    pub fn get_ca_cert_key_pem(&self) -> Option<String> {
        self.ca.as_ref().map(|ca| ca.key_pair().serialize_pem())
    }

    pub fn generate_ca(
        &mut self,
        base_dir: &PathBuf,
        ca_options: &CertificateOptions,
    ) -> CertGenResult<CertificateKeyPair> {
        self.ensure_directory_exists(base_dir)?;

        // let key_pair = KeyPair::generate_for(algorithm)?;
        let ca_cert_path = base_dir.join("ca.pem");
        let ca_key_path = base_dir.join("ca-key.pem");

        let (cert, key) = if !ca_cert_path.exists() {
            // Generate new CA certificate
            let mut params = self.create_cert_params(ca_options)?;
            params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

            let ca_cert_key = self.generate_key_pair()?;
            let ca_cert = params.self_signed(&ca_cert_key)?;
            (ca_cert, ca_cert_key)
        } else {
            // Load existing CA
            let cert_pem = fs::read_to_string(&ca_cert_path)?;
            let key_pem = fs::read_to_string(&ca_key_path)?;
            let ca_cert_key = KeyPair::from_pem(&key_pem)?;
            let ca_cert = CertificateParams::from_ca_cert_pem(&cert_pem)?;
            let ca_cert = ca_cert.self_signed(&ca_cert_key)?;
            (ca_cert, ca_cert_key)
        };

        let ca = CertificateKeyPair::new("ca".to_string(), cert, key);
        self.set_ca(ca.clone());
        Ok(ca)
    }

    fn generate_key_pair(&self) -> rsa::Result<KeyPair> {
        let mut rng = rand::rngs::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        let private_key_der = private_key.to_pkcs8_der()?;
        Ok(KeyPair::try_from(private_key_der.as_bytes()).unwrap())
    }

    fn create_distinguished_name(options: &CertificateOptions) -> DistinguishedName {
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            &options
                .common_name
                .clone()
                .unwrap_or_else(|| options.name.clone()),
        );
        dn.push(DnType::CountryName, &options.country);
        dn.push(DnType::StateOrProvinceName, &options.state);
        dn.push(DnType::LocalityName, &options.city);
        dn.push(DnType::OrganizationName, &options.organization);
        if let Some(ou) = &options.organizational_unit {
            dn.push(DnType::OrganizationalUnitName, ou);
        }
        dn
    }

    fn create_cert_params(&self, options: &CertificateOptions) -> CertGenResult<CertificateParams> {
        let mut params = CertificateParams::new(options.hosts.clone())?;
        params.distinguished_name = Self::create_distinguished_name(options);

        // Set validity period
        let not_before = Utc::now();
        let not_after = not_before + Duration::days(options.validity_days);

        params.not_before = rcgen::date_time_ymd(
            not_before.year(),
            not_before.month() as u8,
            not_before.day() as u8,
        );
        params.not_after = rcgen::date_time_ymd(
            not_after.year(),
            not_after.month() as u8,
            not_after.day() as u8,
        );
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        // Set key usage based on profile
        match options.profile {
            CertificateProfile::Server => {
                params.key_usages = vec![
                    KeyUsagePurpose::DigitalSignature,
                    KeyUsagePurpose::KeyEncipherment,
                ];
                params.extended_key_usages = vec![
                    ExtendedKeyUsagePurpose::ServerAuth,
                    ExtendedKeyUsagePurpose::ClientAuth,
                ];
            }
            CertificateProfile::Client => {
                params.key_usages = vec![
                    KeyUsagePurpose::DigitalSignature,
                    KeyUsagePurpose::KeyEncipherment,
                ];
                params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            }
            CertificateProfile::Peer => {
                params.key_usages = vec![
                    KeyUsagePurpose::DigitalSignature,
                    KeyUsagePurpose::KeyEncipherment,
                ];
                params.extended_key_usages = vec![
                    ExtendedKeyUsagePurpose::ServerAuth,
                    ExtendedKeyUsagePurpose::ClientAuth,
                ];
            }
            CertificateProfile::Ca => {
                params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            }
        }

        Ok(params)
    }

    pub fn generate_cert(
        &mut self,
        base_dir: &PathBuf,
        options: &CertificateOptions,
    ) -> CertGenResult<CertificateKeyPair> {
        debug!("Generating certificate for {:?}", options.name);
        self.ensure_directory_exists(base_dir)?;

        let ca = self
            .ca
            .as_ref()
            .ok_or_else(|| CertGenError::GenerationError("CA certificate not found".into()))?;

        // Parse CA certificate and key
        let ca_cert_pem = ca.certificate().pem();
        let ca_key_pem = ca.key_pair().serialize_pem();
        let ca_params = CertificateParams::from_ca_cert_pem(&ca_cert_pem)?;
        let ca_key_pair = KeyPair::from_pem(&ca_key_pem)?;
        let _ca_cert = ca_params.self_signed(&ca_key_pair)?;

        // Generate new key pair for service certificate
        let algorithm = get_algorithm(&options.algorithm);
        let service_key_pair = KeyPair::generate_for(algorithm)?;

        // Generate service certificate parameters
        let service_params = self.create_cert_params(options)?;
        let service_cert = service_params.self_signed(&service_key_pair)?;

        let cert_kp = CertificateKeyPair::new(options.name.clone(), service_cert, service_key_pair);
        Ok(cert_kp)
    }

    pub fn generate_service_certs(
        &mut self,
        base_dir: &PathBuf,
        services: Vec<CertificateOptions>,
    ) -> CertGenResult<Vec<CertificateKeyPair>> {
        // Generate CA and store its results
        // let ca_cert_kp = self.generate_ca()?;
        // self.ca_cert_pem = Some((ca_cert_kp.certificate().pem(), ca_cert_kp.key_pair().serialize_pem()));

        // Now generate service certificates
        // Filter out any failed certificate generations and collect successful ones
        debug!("Generating service certificates");
        let service_certs: Vec<CertificateKeyPair> = services
            .iter()
            .filter_map(|service_options| self.generate_cert(base_dir, service_options).ok())
            .collect();

        if service_certs.len() != services.len() {
            return Err(CertGenError::GenerationError(
                "Failed to generate some service certificates".into(),
            ));
        }

        Ok(service_certs)
    }

    pub fn generate(
        &mut self,
        cert_profile: CertificateProfile,
        name: &str,
        common_names: Option<Vec<String>>,
        ca_options: CertificateOptions,
        base_dir: &PathBuf,
    ) -> CertGenResult<CertificateKeyPair> {
        let mut options = ca_options;
        if let Some(common_names) = common_names {
            options.hosts = common_names;
        }

        let cert_kp = match cert_profile {
            CertificateProfile::Server => {
                options.profile = cert_profile;
                options.name = format!("{}-server", name);
                options.common_name = Some(name.to_string());
                self.generate_cert(base_dir, &options)?
            }
            CertificateProfile::Peer => {
                options.profile = cert_profile;
                options.name = format!("{}-peer", name);
                self.generate_cert(base_dir, &options)?
            }
            CertificateProfile::Client => {
                options.profile = cert_profile;
                options.name = format!("{}-client", name);
                self.generate_cert(base_dir, &options)?
            }
            CertificateProfile::Ca => {
                options.profile = cert_profile;
                options.name = format!("{}-ca", name);
                let ca_cert_kp = self.generate_ca(base_dir, &options)?;
                ca_cert_kp
            }
        };

        Ok(cert_kp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_test_dir() -> TempDir {
        tempfile::tempdir().expect("Failed to create temp directory")
    }

    fn create_test_options(ca: Option<CertificateKeyPair>) -> CertificateOptions {
        CertificateOptions {
            profile: CertificateProfile::Server,
            common_name: Some("test-service".to_string()),
            name: "test-service".to_string(),
            hosts: vec!["localhost".to_string(), "test-service".to_string()],
            domain: "test.io".to_string(),
            city: "Test City".to_string(),
            state: "Test State".to_string(),
            country: "TS".to_string(),
            organization: "Test Org".to_string(),
            organizational_unit: Some("Test Unit".to_string()),
            validity_days: 365,
            is_ca: false,
            algorithm: "ECDSA_P256_SHA256".to_string(),
            ca: ca,
        }
    }

    #[test]
    fn test_new_generator() {
        let generator = CertificateGenerator::new();

        assert!(generator.get_ca_cert_pem().is_none());
    }

    #[test]
    fn test_ensure_directory_exists() {
        let temp_dir = setup_test_dir();
        let test_path = temp_dir.path().join("nested/test/dir");
        let generator = CertificateGenerator::new();

        assert!(!test_path.exists());
        generator.ensure_directory_exists(&test_path).unwrap();
        assert!(test_path.exists());
    }

    #[test]
    fn test_generate_ca() {
        let temp_dir = setup_test_dir();
        let mut options = create_test_options(None);
        options.is_ca = true;
        options.name = "ca".to_string();
        let mut generator = CertificateGenerator::new();

        let base_dir = temp_dir.path().to_path_buf();
        let ca_result = generator.generate_ca(&base_dir, &options);
        assert!(ca_result.is_ok());
        let ca_cert_kp = ca_result.unwrap();
        ca_cert_kp.write(&base_dir.to_string_lossy()).unwrap();

        // Verify files were created
        let ca_cert_path = base_dir.join("ca.pem");
        let ca_key_path = base_dir.join("ca.key");
        assert!(ca_cert_path.exists());
        assert!(ca_key_path.exists());
    }

    #[test]
    fn test_generate_server_cert() {
        let temp_dir = setup_test_dir();
        let mut options = create_test_options(None);
        let mut generator = CertificateGenerator::new();

        // First generate CA
        let base_dir = temp_dir.path().to_path_buf();
        let ca_result = generator.generate_ca(&base_dir, &options);
        assert!(ca_result.is_ok());
        let ca_cert_kp = ca_result.unwrap();
        options.ca = Some(ca_cert_kp);

        // Generate server certificate
        options.profile = CertificateProfile::Server;
        options.name = "test-server".to_string();
        let cert_kp = generator.generate_cert(&base_dir, &options).unwrap();
        cert_kp.write(&base_dir.to_string_lossy()).unwrap();

        // Verify files were created
        let cert_path = temp_dir.path().join("test-server.pem");
        let key_path = temp_dir.path().join("test-server.key");
        assert!(cert_path.exists());
        assert!(key_path.exists());
    }

    #[test]
    fn test_generate_client_cert() {
        let temp_dir = setup_test_dir();
        let mut options = create_test_options(None);
        let mut generator = CertificateGenerator::new();

        // First generate CA
        let base_dir = temp_dir.path().to_path_buf();
        let ca_result = generator.generate_ca(&base_dir, &options);
        assert!(ca_result.is_ok());
        let ca_cert_kp = ca_result.unwrap();
        options.ca = Some(ca_cert_kp);

        // Generate client certificate
        options.profile = CertificateProfile::Client;
        options.name = "test-client".to_string();
        let cert_kp = generator.generate_cert(&base_dir, &options).unwrap();
        cert_kp.write(&base_dir.to_string_lossy()).unwrap();

        // Verify files were created
        let cert_path = temp_dir.path().join("test-client.pem");
        let key_path = temp_dir.path().join("test-client.key");
        assert!(cert_path.exists());
        assert!(key_path.exists());
    }

    #[test]
    fn test_generate_service_certs() {
        let temp_dir = setup_test_dir();
        let ca_options = CertificateOptions {
            profile: CertificateProfile::Ca, // Make sure CA options has the correct profile
            name: "ca".to_string(),
            hosts: vec!["localhost".to_string()],
            is_ca: true,
            ..create_test_options(None)
        };

        let mut generator = CertificateGenerator::new();

        let base_dir = temp_dir.path().to_path_buf();
        let ca_result = generator.generate_ca(&base_dir, &ca_options);
        assert!(ca_result.is_ok());
        let ca_cert_kp = ca_result.unwrap();
        ca_cert_kp
            .write(&temp_dir.path().to_string_lossy())
            .unwrap();

        let services = vec![
            CertificateOptions {
                profile: CertificateProfile::Server,
                name: "service1".to_string(),
                hosts: vec!["localhost".to_string(), "service1".to_string()],
                is_ca: false,
                ..create_test_options(Some(ca_cert_kp.clone()))
            },
            CertificateOptions {
                profile: CertificateProfile::Client,
                name: "service2".to_string(),
                hosts: vec!["localhost".to_string(), "service2".to_string()],
                is_ca: false,
                ..create_test_options(Some(ca_cert_kp.clone()))
            },
        ];

        // Generate service certificates
        let result = generator.generate_service_certs(&base_dir, services.clone());
        assert!(result.is_ok());
        let service_certs = result.unwrap();
        assert_eq!(service_certs.len(), services.len());

        service_certs.iter().for_each(|cert| {
            let dir = temp_dir.path().join(cert.name());
            cert.write(&dir.to_string_lossy()).unwrap();
        });

        for service in services.iter() {
            let service_dir = temp_dir.path().join(service.name.clone());
            assert!(service_dir.exists());
        }

        // Verify all files were created and are non-empty
        let files_to_check = vec![
            ("ca.pem", "CA certificate"),
            ("ca.key", "CA key"),
            ("service1/service1.pem", "Service1 certificate"),
            ("service1/service1.key", "Service1 key"),
            ("service2/service2.pem", "Service2 certificate"),
            ("service2/service2.key", "Service2 key"),
        ];

        for (filename, description) in files_to_check {
            let file_path = temp_dir.path().join(filename);
            assert!(
                file_path.exists(),
                "{} not found at {:?}",
                description,
                file_path
            );

            let metadata = fs::metadata(&file_path).unwrap();
            assert!(
                metadata.len() > 0,
                "{} is empty at {:?}",
                description,
                file_path
            );
        }
    }

    #[test]
    fn test_generate_with_profile() {
        let temp_dir = setup_test_dir();
        let options = create_test_options(None);
        let mut generator = CertificateGenerator::new();

        // Test CA generation
        let base_dir = temp_dir.path().to_path_buf();
        let cert_kp = generator.generate_ca(&base_dir, &options).unwrap();
        cert_kp.write(&base_dir.to_string_lossy()).unwrap();
        assert!(temp_dir.path().join("ca.pem").exists());
        assert!(temp_dir.path().join("ca.key").exists());

        // Test server certificate generation
        generator.set_ca(cert_kp.clone());
        let cert_kp = generator
            .generate(
                CertificateProfile::Server,
                "server",
                Some(vec!["localhost".to_string(), "server.test".to_string()]),
                options.clone(),
                &base_dir,
            )
            .unwrap();
        cert_kp.write(&base_dir.to_string_lossy()).unwrap();
        assert!(temp_dir.path().join("server-server.pem").exists());
        assert!(temp_dir.path().join("server-server.key").exists());

        // Test client certificate generation
        let cert_kp = generator
            .generate(
                CertificateProfile::Client,
                "test-client",
                None,
                options.clone(),
                &base_dir,
            )
            .unwrap();
        let write_result = cert_kp.write(&base_dir.to_string_lossy());
        assert!(write_result.is_ok());
        assert!(base_dir.join("test-client-client.pem").exists());
        assert!(base_dir.join("test-client-client.key").exists());

        // Test peer certificate generation
        let cert_kp = generator
            .generate(
                CertificateProfile::Peer,
                "test-peer",
                None,
                options,
                &base_dir,
            )
            .unwrap();
        cert_kp.write(&base_dir.to_string_lossy()).unwrap();
        assert!(base_dir.join("test-peer-peer.pem").exists());
        assert!(base_dir.join("test-peer-peer.key").exists());
    }

    #[test]
    fn test_error_handling() {
        let temp_dir = setup_test_dir();
        let options = create_test_options(None);
        let mut generator = CertificateGenerator::new();

        // Test generating cert without CA
        let base_dir = temp_dir.path().to_path_buf();
        let result = generator.generate_cert(&base_dir, &options);
        assert!(result.is_err());
        match result {
            Err(CertGenError::GenerationError(msg)) => {
                assert_eq!(msg, "CA certificate not found");
            }
            err => panic!("Expected GenerationError, got {:?}", err),
        }

        // Test with invalid directory permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let readonly_dir = temp_dir.path().join("readonly");
            fs::create_dir(&readonly_dir).unwrap();
            fs::set_permissions(&readonly_dir, fs::Permissions::from_mode(0o444)).unwrap();

            let invalid_options = options;

            let base_dir = readonly_dir;
            // Create a new generator with CA cert
            let mut generator = CertificateGenerator::new();
            let ca_cert_kp = generator.generate_ca(&base_dir, &invalid_options).unwrap();
            generator.set_ca(ca_cert_kp.clone());

            // Try to generate a certificate in the readonly directory
            let result = generator.generate_cert(&base_dir, &invalid_options);
            assert!(result.is_ok());
            let cert_kp = result.unwrap();
            let write_result = cert_kp.write(&base_dir.to_string_lossy());
            assert!(write_result.is_err());
        }
    }
}
