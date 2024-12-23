use std::path::PathBuf;

use clap::Args;

use crate::cert::{
    CertificateGenerator, CertificateOptions, CertificateOptionsBuilder, CertificateProfile,
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

#[derive(Args, Debug, Clone)]
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
    let ca_options = build_ca_configuration_options(cli, config);
    let mut generator = CertificateGenerator::new(ca_options.clone());
    if gen_command.ca {
        generator.generate_ca()?;
    }

    let config = config.clone();

    if gen_command.reset {
        generator.clean_certs()?;
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

    let service_options: Vec<CertificateOptions> = services_to_generate
        .iter()
        .map(|service| build_service_configuration_options(cli, &ca_options, service))
        .filter_map(|result| result.ok())
        .collect();

    generator.generate_service_certs(service_options)?;
    Ok(())
}

fn build_service_configuration_options(
    cli: &Cli,
    ca_options: &CertificateOptions,
    service: &ServiceConfig,
) -> RCSSLResult<CertificateOptions> {
    let mut builder = CertificateOptionsBuilder::default();
    let parsed_profile: CertificateProfile = service.profile.clone().into();

    let service_name = service.name.clone();

    let mut hosts = service
        .hosts
        .as_ref()
        .map(|h| h.iter().map(|s| s.to_string()).collect())
        .unwrap_or_else(|| vec!["localhost".to_string()]);

    let ca_hosts = ca_options.hosts.clone();
    hosts.extend(ca_hosts);
    let hosts = hosts.iter().map(|s| s.as_str()).collect();

    let output_dir = cli
        .output_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("./certs"));

    let output_dir = output_dir.join(&service_name);

    let base_dir = cli
        .base_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("./certs"));

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

fn build_ca_configuration_options(cli: &Cli, config: &Config) -> CertificateOptions {
    CertificateOptions {
        profile: CertificateProfile::Ca,
        common_name: Some(config.ca.common_name.clone()),
        name: "ca".to_string(),
        hosts: config.ca.hosts.clone(),
        output_dir: cli
            .output_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("./certs")),
        base_dir: cli
            .base_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("./certs")),
        domain: "local".to_string(),
        city: config.ca.city.clone(),
        state: config.ca.state.clone(),
        country: config.ca.country.clone(),
        organization: config.ca.organization.clone(),
        organizational_unit: config.ca.organizational_unit.clone(),
        validity_days: config.ca.validity_days,
        is_ca: true,
        algorithm: config.ca.algorithm.clone(),
    }
}
