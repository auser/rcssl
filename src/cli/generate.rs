use std::{collections::HashSet, path::PathBuf};

use clap::Args;
use tracing::debug;

use crate::{
    cert::{
        CertificateGenerator, CertificateOptions, CertificateOptionsBuilder, CertificateProfile,
    },
    cert_kp::CertificateKeyPair,
    cli::error::RCSSLError,
};

use super::{
    config::{Config, ServiceConfig},
    error::RCSSLResult,
    Cli,
};

#[derive(Debug, Clone, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Yaml,
    Json,
}

#[derive(Args, Debug, Clone, Default)]
pub struct GenerateCommand {
    /// Generate CA certificate along with the services
    #[arg(short, long)]
    pub ca: bool,
    /// Generate services certificates
    #[arg(short, long, value_delimiter = ',')]
    pub services: Option<Vec<String>>,

    /// Clean up the certificates
    #[arg(short, long)]
    pub reset: bool,

    /// Set the algorithm
    #[arg(short, long, default_value = "RSA256")]
    pub algorithm: String,
}

impl GenerateCommand {
    pub fn get_services(&self) -> Option<&Vec<String>> {
        // None means "all"
        self.services.as_ref()
    }
}

pub async fn run(cli: &Cli, gen_command: &GenerateCommand, config: &Config) -> RCSSLResult<()> {
    let ca_options = build_ca_configuration_options(config);
    let mut generator = CertificateGenerator::new();
    let ca = if gen_command.ca {
        let base_dir = cli
            .output_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("./certs"));
        if !base_dir.exists() {
            generator.ensure_directory_exists(&base_dir)?;
        }
        let ca = generator.generate_ca(&base_dir, &ca_options)?;
        debug!("Generated CA");
        let write_result = ca.write(&base_dir.to_string_lossy())?;
        debug!("Write result: {:?}", write_result);
        ca
    } else if let Some(ca_file) = cli.ca_file.clone() {
        debug!("Using CA file: {:?}", ca_file);
        CertificateKeyPair::try_from(PathBuf::from(ca_file))?
    } else {
        return Err(RCSSLError::InvalidCA);
    };

    debug!("Using CA: {:?}", ca);

    let config = config.clone();
    // config.ca = Some(ca);
    generator.set_ca(ca);

    if gen_command.reset {
        debug!("Cleaning up certificates");
        let base_dir = cli
            .output_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("./certs"));
        generator.clean_certs(&base_dir)?;
    }

    let services_to_generate = match gen_command.get_services() {
        Some(services) => {
            let service_names: Vec<String> = services.iter().map(|s| s.to_string()).collect();
            config
                .services
                .into_iter()
                .filter(|s| service_names.contains(&s.name))
                .collect()
        }
        None => config.services,
    };

    debug!(
        "Generating certificates for services: {:?}",
        services_to_generate
    );

    let service_options: Vec<CertificateOptions> = services_to_generate
        .iter()
        .map(|service| build_service_configuration_options(cli, &ca_options, service))
        .filter_map(|result| result.ok())
        .collect();

    let base_dir = cli
        .output_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("./certs"));
    let service_certs = generator.generate_service_certs(&base_dir, service_options)?;
    debug!("Generated service certificates: {:?}", service_certs.len());
    service_certs.iter().for_each(|cert| {
        debug!("Service certificate: {:?}", cert.name());
        let output_dir = base_dir.join(&cert.name());
        cert.write(&output_dir.to_string_lossy()).ok();
    });
    Ok(())
}

fn build_service_configuration_options(
    cli: &Cli,
    ca_options: &CertificateOptions,
    service: &ServiceConfig,
) -> RCSSLResult<CertificateOptions> {
    let mut builder = CertificateOptionsBuilder::default();
    let parsed_profile: CertificateProfile = service.profile.clone().into();

    if let Some(ca) = ca_options.ca.clone() {
        builder = builder.ca(ca);
    } else {
        return Err(RCSSLError::InvalidCA);
    }

    let service_name = service.name.clone();

    let hosts: HashSet<String> = service
        .hosts
        .as_ref()
        .map(|h| h.iter().map(|s| s.to_string()).collect())
        .unwrap_or_else(|| vec!["localhost".to_string()])
        .into_iter()
        .collect();

    let mut hosts: Vec<String> = hosts.into_iter().collect();
    hosts.sort();
    let mut hosts: HashSet<String> = hosts.into_iter().collect();

    let ca_hosts = ca_options.hosts.clone();
    hosts.extend(ca_hosts);
    let hosts = hosts.iter().map(|s| s.as_str()).collect();

    let output_dir = cli
        .output_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("./certs"));

    let output_dir = output_dir.join(&service_name);

    let base_dir = cli
        .output_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("./certs"));

    println!("parsed_profile: {:?}", parsed_profile);

    builder = builder
        .profile(parsed_profile)
        .name(&service_name)
        .common_name(
            &service
                .common_name
                .clone()
                .unwrap_or_else(|| service_name.clone()),
        )
        .domain(&ca_options.domain)
        .hosts(hosts);
    builder = builder
        .output_dir(output_dir)
        .base_dir(base_dir)
        .city(&ca_options.city)
        .state(&ca_options.state)
        .country(&ca_options.country);
    builder = builder
        .organization(&ca_options.organization)
        .organizational_unit(ca_options.organizational_unit.clone().as_deref());
    builder = builder.validity_days(ca_options.validity_days).is_ca(false);
    Ok(builder.build())
}

fn build_ca_configuration_options(config: &Config) -> CertificateOptions {
    CertificateOptions {
        profile: CertificateProfile::Ca,
        common_name: Some(config.ca_config.common_name.clone()),
        name: "ca".to_string(),
        hosts: config.ca_config.hosts.clone(),
        domain: "local".to_string(),
        city: config.ca_config.city.clone(),
        state: config.ca_config.state.clone(),
        country: config.ca_config.country.clone(),
        organization: config.ca_config.organization.clone(),
        organizational_unit: config.ca_config.organizational_unit.clone(),
        validity_days: config.ca_config.validity_days,
        is_ca: true,
        algorithm: config.ca_config.algorithm.clone(),
        ca: config.ca.clone(),
    }
}

#[cfg(test)]
mod tests {

    use crate::cli::config::CertificateConfig;

    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_build_ca_configuration_options() {
        let config = Config {
            ca_config: CertificateConfig {
                domain: "test.local".to_string(),
                profile: CertificateProfile::Ca,
                common_name: "Test CA".to_string(),
                hosts: vec!["localhost".to_string(), "ca.local".to_string()],
                city: "Test City".to_string(),
                state: "Test State".to_string(),
                country: "Test Country".to_string(),
                organization: "Test Org".to_string(),
                organizational_unit: Some("Test Unit".to_string()),
                validity_days: 365,
                algorithm: "ed25519".to_string(),
            },
            ca: None,
            services: vec![],
        };

        let options = build_ca_configuration_options(&config);

        assert_eq!(options.profile, CertificateProfile::Ca);
        assert_eq!(options.common_name, Some("Test CA".to_string()));
        assert_eq!(options.name, "ca");
        assert_eq!(options.hosts, vec!["localhost", "ca.local"]);
        assert_eq!(options.domain, "local");
        assert_eq!(options.city, "Test City");
        assert_eq!(options.state, "Test State");
        assert_eq!(options.country, "Test Country");
        assert_eq!(options.organization, "Test Org");
        assert_eq!(options.organizational_unit, Some("Test Unit".to_string()));
        assert_eq!(options.validity_days, 365);
        assert!(options.is_ca);
        assert_eq!(options.algorithm, "ed25519");
        assert!(options.ca.is_none());
    }

    #[test]
    fn test_build_service_configuration_options() {
        let cli = Cli {
            output_dir: Some(PathBuf::from("./test-certs")),
            ..Default::default()
        };

        let mut ca_options = CertificateOptions {
            domain: "test.local".to_string(),
            city: "Test City".to_string(),
            state: "Test State".to_string(),
            country: "Test Country".to_string(),
            organization: "Test Org".to_string(),
            organizational_unit: Some("Test Unit".to_string()),
            validity_days: 365,
            ..Default::default()
        };

        let mut generator = CertificateGenerator::new();
        let ca = generator.generate_ca(&PathBuf::from("./test-certs"), &ca_options);
        let ca = ca.unwrap();
        ca_options.ca = Some(ca);
        let service = ServiceConfig {
            name: "test-service".to_string(),
            profile: "server".to_string(),
            common_name: Some("test.service.local".to_string()),
            hosts: Some(vec![
                "localhost".to_string(),
                "test.service.local".to_string(),
            ]),
        };

        let result = build_service_configuration_options(&cli, &ca_options, &service);
        assert!(result.is_ok());

        let options = result.unwrap();
        assert_eq!(options.profile, CertificateProfile::Server);
        assert_eq!(options.name, "test-service");
        assert_eq!(options.common_name, Some("test.service.local".to_string()));
        assert!(options.hosts.contains(&"localhost".to_string()));
        assert!(options.hosts.contains(&"test.service.local".to_string()));
        assert_eq!(options.domain, "test.local");
        assert_eq!(options.city, "Test City");
        assert_eq!(options.state, "Test State");
        assert_eq!(options.country, "Test Country");
        assert_eq!(options.organization, "Test Org");
        assert_eq!(options.organizational_unit, Some("Test Unit".to_string()));
        assert_eq!(options.validity_days, 365);
        assert!(!options.is_ca);
    }

    #[test]
    fn test_build_service_configuration_options_invalid_profile() {
        let cli = Cli {
            output_dir: Some(PathBuf::from("./test-certs")),
            ..Default::default()
        };
        let ca_options = CertificateOptions::default();
        let service = ServiceConfig {
            name: "test".to_string(),
            profile: "invalid".to_string(),
            common_name: None,
            hosts: None,
        };

        let result = build_service_configuration_options(&cli, &ca_options, &service);
        assert!(result.is_err());
    }
}
