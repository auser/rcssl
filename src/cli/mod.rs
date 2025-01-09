use ::tracing::{debug, instrument};
use clap::{command, Parser, Subcommand};
use config::Config;
use error::{RCSSLError, RCSSLResult};
use std::path::PathBuf;
use tracing::LogConfig;

static NAME: &str = "rcssl";
static ABOUT: &str = "Generate certificates for services";
static AUTHOR: &str = "Ari Lerner <me@ari.io>";

lazy_static::lazy_static! {
    static ref VERSION: String = std::env::var("CARGO_PKG_VERSION")
        .unwrap_or("0.1.0".to_string());
}

mod config;
mod error;
mod generate;
mod tracing;

use tracing::init_tracing;

use crate::cert_kp::CertificateKeyPair;

#[derive(Debug, Parser, Clone, Default)]
#[command(author = AUTHOR, about = ABOUT, long_about = None, name = NAME)]
#[command(version = &**VERSION)]
pub struct Cli {
    /// The command to run
    #[command(subcommand)]
    pub command: Commands,

    /// The log level
    #[arg(long, short = 'l', default_value = "info", global = true)]
    pub log_level: String,

    /// The output directory for the certificates
    #[arg(
        long,
        short,
        default_value = "./certs",
        env = "CERT_OUTPUT_DIR",
        global = true
    )]
    pub output_dir: Option<PathBuf>,

    /// A comma separated list of service names
    #[arg(long, short, global = true)]
    pub services: Option<String>,

    /// Use existing CA file (path)
    #[arg(long, short = 'C', global = true)]
    pub ca_file: Option<PathBuf>,

    /// The config file
    #[arg(
        long,
        short = 'f',
        global = true,
        default_value = "./config/config.yaml",
        env = "CERT_CONFIG_FILE"
    )]
    pub config_file: Option<PathBuf>,

    /// The variable files
    #[arg(long, short = 'v', global = true)]
    pub variable_files: Vec<String>,
}

#[derive(Debug, Subcommand, Clone)]
pub enum Commands {
    Generate(generate::GenerateCommand),
}

impl Default for Commands {
    fn default() -> Self {
        Commands::Generate(generate::GenerateCommand::default())
    }
}

#[instrument]
pub async fn run() -> RCSSLResult<()> {
    color_eyre::install()?;
    let cli: Cli = Cli::parse();
    let log_level = cli.log_level.clone();
    let log_config = LogConfig {
        max_level: log_level.to_string(),
        filter: format!("{}={}", NAME, &log_level),
        rolling_file_path: None,
    };
    init_tracing(NAME, &log_config)?;

    let cli_clone = cli.clone();
    let config_file = cli_clone.config_file.clone().unwrap_or_default();
    debug!("Using config file: {:?}", config_file);

    if cli.output_dir.is_some() {
        let output_dir = cli.output_dir.unwrap();
        std::fs::create_dir_all(output_dir)?;
    }

    let mut config = parse_config(config_file.clone())?;
    if let Some(ca_file) = cli.ca_file.clone() {
        let ca_kp = CertificateKeyPair::try_from(ca_file)?;
        config.ca = Some(ca_kp);
    }

    match cli.command {
        Commands::Generate(gen_command) => {
            generate::run(&cli_clone, &gen_command, &config).await?;
        }
    }

    Ok(())
}

fn parse_config(config_file: PathBuf) -> RCSSLResult<Config> {
    let config_str = std::fs::read_to_string(&config_file)?;
    let extension = config_file
        .extension()
        .map(|ext| ext.to_str().unwrap())
        .unwrap_or_else(|| "json");

    match extension {
        "json" => Ok(serde_json::from_str(&config_str)?),
        "yaml" | "yml" => Ok(serde_yaml::from_str(&config_str)?),
        _ => Err(RCSSLError::UnsupportedFileExtension(extension.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accepts_yaml_config() {
        let config_file = PathBuf::from("config/config.yaml");
        parse_config(config_file).unwrap();
    }
    #[test]
    fn test_accepts_yml_config() {
        let config_file = PathBuf::from("config/config.yml");
        parse_config(config_file).unwrap();
    }

    #[test]
    fn test_accepts_json_config() {
        let config_file = PathBuf::from("config/config.json");
        parse_config(config_file).unwrap();
    }
}
