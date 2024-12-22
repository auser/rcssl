use ::tracing::{debug, instrument};
use clap::{Parser, Subcommand, command};
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

#[derive(Debug, Parser, Clone)]
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
    #[arg(long, short, default_value = "./certs", env = "CERT_OUTPUT_DIR")]
    pub output_dir: Option<PathBuf>,

    /// The base directory for the certificates
    #[arg(long, short, default_value = "./certs", env = "CERT_BASE_DIR")]
    pub base_dir: Option<PathBuf>,

    /// A comma separated list of service names
    #[arg(long, short)]
    pub services: Option<String>,

    #[arg(long, short, default_value_t = false)]
    pub generate_ca: bool,

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

#[instrument]
pub async fn run() -> RCSSLResult<()> {
    color_eyre::install()?;
    let cli: Cli = Cli::parse();
    let log_level = cli.log_level.clone();
    let log_config = LogConfig {
        max_level: log_level.clone(),
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

    if cli.base_dir.is_some() {
        let base_dir = cli.base_dir.unwrap();
        std::fs::create_dir_all(base_dir)?;
    }

    let config = parse_config(config_file.clone())?;

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
        "yaml" => Ok(serde_yaml::from_str(&config_str)?),
        _ => Err(RCSSLError::UnsupportedFileExtension(extension.to_string())),
    }
}
