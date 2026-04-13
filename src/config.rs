use crate::errors::ConfigError;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
pub struct Config {
    keys: Keys,
    apis: Apis,
}

#[derive(Deserialize)]
struct Keys {
    virustotal: Option<String>,
    ipdb: Option<String>,
}

#[derive(Deserialize)]
struct Apis {
    virustotal: bool,
    ipdb: bool,
}

pub fn run() -> Result<(), ConfigError> {
    let path = check_config_loc()?;
    let content = std::fs::read_to_string(path).map_err(|_| ConfigError::FileNotFound)?;
    let config = toml::from_str(&content).map_err(|_| ConfigError::ParseError)?;
    validate_config(&config)?;
    Ok(())
}

fn check_config_loc() -> Result<PathBuf, ConfigError> {
    let config_file = std::env::current_exe()
        .map_err(|_| ConfigError::FileNotFound)?
        .parent()
        .ok_or(ConfigError::FileNotFound)?
        .join("crab.toml");

    if config_file.exists() {
        Ok(config_file)
    } else {
        Err(ConfigError::FileNotFound)
    }
}

fn validate_config(config: &Config) -> Result<(), ConfigError> {
    let checks = [
        (
            config.apis.virustotal,
            &config.keys.virustotal,
            "virustotal",
        ),
        (config.apis.ipdb, &config.keys.ipdb, "ipdb"),
    ];

    for (enabled, key, name) in checks {
        if enabled && key.is_none() {
            return Err(ConfigError::MissingKey(name.to_string()));
        }
    }
    Ok(())
}
