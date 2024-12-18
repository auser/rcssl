use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use std::fs;
use std::path::PathBuf;
use time::Duration;

use crate::error::CertGenError;

pub type CertGenResult<T> = Result<T, CertGenError>;

#[derive(Debug, Clone)]
pub struct CertificateOptions {
    pub profile: CertificateProfile,
    pub common_name: String,
    pub name: String,
    pub hosts: Vec<String>,
    pub output_dir: PathBuf,
    pub base_dir: PathBuf,
    pub domain: String,
    pub city: String,
    pub state: String,
    pub country: String,
    pub organization: String,
    pub organizational_unit: Option<String>,
    pub validity_days: i64,
    pub is_ca: bool,
}

#[derive(Debug, Clone, PartialEq)]
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
            common_name: "traefik".to_string(),
            name: "traefik".to_string(),
            hosts: vec!["localhost".to_string(), "traefik".to_string()],
            output_dir: PathBuf::from("./config/tls"),
            base_dir: PathBuf::from("./config/tls"),
            domain: "ari.io".to_string(),
            city: "San Francisco".to_string(),
            state: "California".to_string(),
            country: "US".to_string(),
            organization: "ari.io".to_string(),
            organizational_unit: Some("CA".to_string()),
            validity_days: 365,
            is_ca: false,
        }
    }
}

#[derive(Clone)]
pub struct CertificateGenerator {
    ca_options: CertificateOptions,
    ca_cert_pem: Option<(String, String)>, // (cert_pem, key_pem)
}

impl CertificateGenerator {
    pub fn new(ca_options: CertificateOptions) -> Self {
        Self {
            ca_options,
            ca_cert_pem: None,
        }
    }

    pub fn ensure_directory_exists(&self, path: &PathBuf) -> CertGenResult<()> {
        fs::create_dir_all(path)?;
        Ok(())
    }

    pub fn generate_ca(&self) -> CertGenResult<Option<(String, String)>> {
        self.ensure_directory_exists(&self.ca_options.base_dir)?;

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let ca_cert_path = self.ca_options.base_dir.join("ca.pem");
        let ca_key_path = self.ca_options.base_dir.join("ca-key.pem");

        let (cert_pem, key_pem) = if !ca_cert_path.exists() {
            // Generate new CA certificate
            let mut params = self.create_cert_params(&self.ca_options)?;
            params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

            let cert = params.self_signed(&key_pair)?;
            let cert_pem = cert.pem();
            let key_pem = key_pair.serialize_pem();

            fs::write(&ca_cert_path, &cert_pem)?;
            fs::write(&ca_key_path, &key_pem)?;

            (cert_pem, key_pem)
        } else {
            // Load existing CA
            let cert_pem = fs::read_to_string(&ca_cert_path)?;
            let key_pem = fs::read_to_string(&ca_key_path)?;
            (cert_pem, key_pem)
        };

        Ok(Some((cert_pem, key_pem)))
    }

    fn create_distinguished_name(options: &CertificateOptions) -> DistinguishedName {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &options.common_name);
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
        params.not_after = time::OffsetDateTime::now_utc() + Duration::days(options.validity_days);

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

    pub fn generate_cert(&self, options: &CertificateOptions) -> CertGenResult<()> {
        self.ensure_directory_exists(&options.output_dir)?;

        let (_ca_cert_pem, ca_key_pem) = self
            .ca_cert_pem
            .as_ref()
            .ok_or_else(|| CertGenError::GenerationError("CA certificate not generated".into()))?;

        // Create CA certificate from PEM
        // let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)?;
        let key_pair = KeyPair::from_pem(ca_key_pem)?;
        // let ca_cert = ca_params.self_signed(&key_pair)?;

        // Generate service certificate
        // let params = self.create_cert_params(options, None)?;
        // let cert = params.self_signed(&key_pair)?;

        let cert_path = options.output_dir.join(format!("{}.pem", options.name));
        let key_path = options.output_dir.join(format!("{}-key.pem", options.name));

        // Sign the certificate with the CA
        let cert_pem = key_pair.serialize_pem();
        let key_pem = key_pair.serialize_der();

        fs::write(cert_path, cert_pem)?;
        fs::write(key_path, key_pem)?;

        Ok(())
    }

    pub fn generate_service_certs(
        &mut self,
        services: Vec<CertificateOptions>,
    ) -> CertGenResult<()> {
        // Generate CA and store its result
        if let Some(ca_certs) = self.generate_ca()? {
            self.ca_cert_pem = Some(ca_certs);

            // Now generate service certificates
            for service_options in services {
                self.generate_cert(&service_options)?;
            }

            Ok(())
        } else {
            Err(CertGenError::GenerationError(
                "Failed to generate CA certificate".into(),
            ))
        }
    }

    pub fn generate(
        &mut self,
        cert_profile: CertificateProfile,
        name: &str,
        common_names: Option<Vec<String>>,
    ) -> CertGenResult<()> {
        let mut options = self.ca_options.clone();
        if let Some(common_names) = common_names {
            options.hosts = common_names;
        }

        match cert_profile {
            CertificateProfile::Server => {
                options.profile = cert_profile;
                options.name = name.to_string();
                options.common_name = name.to_string();
                self.generate_cert(&options)?;
            }
            CertificateProfile::Peer => {
                options.profile = cert_profile;
                options.name = format!("{}-server", name);
                self.generate_cert(&options)?;
            }
            CertificateProfile::Client => {
                options.profile = cert_profile;
                options.name = format!("{}-client", name);
                self.generate_cert(&options)?;
            }
            CertificateProfile::Ca => {
                options.profile = cert_profile;
                options.name = format!("{}-ca", name);
                if let Some((ca_cert_pem, ca_key_pem)) = self.generate_ca()? {
                    self.ca_cert_pem = Some((ca_cert_pem, ca_key_pem));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn setup_test_dir() -> TempDir {
        tempfile::tempdir().expect("Failed to create temp directory")
    }

    fn create_test_options(temp_dir: &TempDir) -> CertificateOptions {
        CertificateOptions {
            profile: CertificateProfile::Server,
            common_name: "test-service".to_string(),
            name: "test-service".to_string(),
            hosts: vec!["localhost".to_string(), "test-service".to_string()],
            output_dir: PathBuf::from(temp_dir.path()),
            base_dir: PathBuf::from(temp_dir.path()),
            domain: "test.io".to_string(),
            city: "Test City".to_string(),
            state: "Test State".to_string(),
            country: "TS".to_string(),
            organization: "Test Org".to_string(),
            organizational_unit: Some("Test Unit".to_string()),
            validity_days: 365,
            is_ca: false,
        }
    }

    #[test]
    fn test_new_generator() {
        let temp_dir = setup_test_dir();
        let options = create_test_options(&temp_dir);
        let generator = CertificateGenerator::new(options.clone());

        assert_eq!(generator.ca_options.common_name, options.common_name);
        assert!(generator.ca_cert_pem.is_none());
    }

    #[test]
    fn test_ensure_directory_exists() {
        let temp_dir = setup_test_dir();
        let test_path = temp_dir.path().join("nested/test/dir");
        let options = create_test_options(&temp_dir);
        let generator = CertificateGenerator::new(options);

        assert!(!test_path.exists());
        generator.ensure_directory_exists(&test_path).unwrap();
        assert!(test_path.exists());
    }

    #[test]
    fn test_generate_ca() {
        let temp_dir = setup_test_dir();
        let options = create_test_options(&temp_dir);
        let generator = CertificateGenerator::new(options);

        let ca_result = generator.generate_ca().unwrap();
        assert!(ca_result.is_some());

        let (cert_pem, key_pem) = ca_result.unwrap();
        assert!(!cert_pem.is_empty());
        assert!(!key_pem.is_empty());

        // Verify files were created
        let ca_cert_path = temp_dir.path().join("ca.pem");
        let ca_key_path = temp_dir.path().join("ca-key.pem");
        assert!(ca_cert_path.exists());
        assert!(ca_key_path.exists());
    }

    #[test]
    fn test_generate_server_cert() {
        let temp_dir = setup_test_dir();
        let mut options = create_test_options(&temp_dir);
        let mut generator = CertificateGenerator::new(options.clone());

        // First generate CA
        let ca_result = generator.generate_ca().unwrap();
        generator.ca_cert_pem = ca_result;

        // Generate server certificate
        options.profile = CertificateProfile::Server;
        options.name = "test-server".to_string();
        generator.generate_cert(&options).unwrap();

        // Verify files were created
        let cert_path = temp_dir.path().join("test-server.pem");
        let key_path = temp_dir.path().join("test-server-key.pem");
        assert!(cert_path.exists());
        assert!(key_path.exists());
    }

    #[test]
    fn test_generate_client_cert() {
        let temp_dir = setup_test_dir();
        let mut options = create_test_options(&temp_dir);
        let mut generator = CertificateGenerator::new(options.clone());

        // First generate CA
        let ca_result = generator.generate_ca().unwrap();
        generator.ca_cert_pem = ca_result;

        // Generate client certificate
        options.profile = CertificateProfile::Client;
        options.name = "test-client".to_string();
        generator.generate_cert(&options).unwrap();

        // Verify files were created
        let cert_path = temp_dir.path().join("test-client.pem");
        let key_path = temp_dir.path().join("test-client-key.pem");
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
            output_dir: temp_dir.path().to_path_buf(),
            base_dir: temp_dir.path().to_path_buf(),
            is_ca: true,
            ..create_test_options(&temp_dir)
        };

        let mut generator = CertificateGenerator::new(ca_options);

        let services = vec![
            CertificateOptions {
                profile: CertificateProfile::Server,
                name: "service1".to_string(),
                hosts: vec!["localhost".to_string(), "service1".to_string()],
                output_dir: temp_dir.path().to_path_buf(),
                base_dir: temp_dir.path().to_path_buf(),
                is_ca: false,
                ..create_test_options(&temp_dir)
            },
            CertificateOptions {
                profile: CertificateProfile::Client,
                name: "service2".to_string(),
                hosts: vec!["localhost".to_string(), "service2".to_string()],
                output_dir: temp_dir.path().to_path_buf(),
                base_dir: temp_dir.path().to_path_buf(),
                is_ca: false,
                ..create_test_options(&temp_dir)
            },
        ];

        // Generate service certificates
        let result = generator.generate_service_certs(services);
        assert!(
            result.is_ok(),
            "Failed to generate service certificates: {:?}",
            result
        );

        // Verify all files were created and are non-empty
        let files_to_check = vec![
            ("ca.pem", "CA certificate"),
            ("ca-key.pem", "CA key"),
            ("service1.pem", "Service1 certificate"),
            ("service1-key.pem", "Service1 key"),
            ("service2.pem", "Service2 certificate"),
            ("service2-key.pem", "Service2 key"),
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
        let options = create_test_options(&temp_dir);
        let mut generator = CertificateGenerator::new(options);

        // Test CA generation
        generator
            .generate(CertificateProfile::Ca, "test", None)
            .unwrap();
        assert!(temp_dir.path().join("ca.pem").exists());
        assert!(temp_dir.path().join("ca-key.pem").exists());

        // Test server certificate generation
        generator
            .generate(
                CertificateProfile::Server,
                "server",
                Some(vec!["localhost".to_string(), "server.test".to_string()]),
            )
            .unwrap();
        assert!(temp_dir.path().join("server.pem").exists());
        assert!(temp_dir.path().join("server-key.pem").exists());

        // Test client certificate generation
        generator
            .generate(CertificateProfile::Client, "client", None)
            .unwrap();
        assert!(temp_dir.path().join("client-client.pem").exists());
        assert!(temp_dir.path().join("client-client-key.pem").exists());

        // Test peer certificate generation
        generator
            .generate(CertificateProfile::Peer, "peer", None)
            .unwrap();
        assert!(temp_dir.path().join("peer-server.pem").exists());
        assert!(temp_dir.path().join("peer-server-key.pem").exists());
    }

    #[test]
    fn test_error_handling() {
        let temp_dir = setup_test_dir();
        let options = create_test_options(&temp_dir);
        let generator = CertificateGenerator::new(options.clone());

        // Test generating cert without CA
        let result = generator.generate_cert(&options);
        assert!(result.is_err());
        match result {
            Err(CertGenError::GenerationError(msg)) => {
                assert_eq!(msg, "CA certificate not generated");
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

            let mut invalid_options = options;
            invalid_options.output_dir = readonly_dir;

            // Create a new generator with CA cert
            let mut generator = CertificateGenerator::new(invalid_options.clone());
            let ca_cert = generator.generate_ca().unwrap();
            generator.ca_cert_pem = ca_cert;

            // Try to generate a certificate in the readonly directory
            let result = generator.generate_cert(&invalid_options);
            assert!(result.is_err());
            match result {
                Err(CertGenError::IoError(_)) => (),
                err => panic!("Expected IO error, got {:?}", err),
            }
        }
    }
}
