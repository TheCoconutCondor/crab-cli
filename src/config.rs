use crate::enrich::utils::ApiName;
use crate::errors::ConfigError;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
pub struct Config {
    keys: Keys,
    apis: Apis,
}

impl Config {
    fn api_entries(&self) -> [(bool, &Option<String>, ApiName); 2] {
        [
            (
                self.apis.virustotal,
                &self.keys.virustotal,
                ApiName::Virustotal,
            ),
            (
                self.apis.metadefender,
                &self.keys.metadefender,
                ApiName::Metadefender,
            ),
        ]
    }
}

#[derive(Deserialize)]
struct Keys {
    virustotal: Option<String>,
    metadefender: Option<String>,
}

#[derive(Deserialize)]
struct Apis {
    virustotal: bool,
    metadefender: bool,
}

pub struct EnabledApi {
    pub name: ApiName,
    pub key: String,
}

pub fn run() -> Result<(), ConfigError> {
    let config = get_config()?;
    validate_config(&config)?;
    Ok(())
}

pub fn get_enabled_apis() -> Result<Vec<EnabledApi>, ConfigError> {
    let config = get_config()?;
    let enabled = config
        .api_entries()
        .into_iter()
        .filter(|(enabled, _, _)| *enabled)
        .filter_map(|(_, key, name)| {
            key.as_ref().map(|k| EnabledApi {
                name,
                key: k.clone(),
            })
        })
        .collect();
    Ok(enabled)
}

fn get_config() -> Result<Config, ConfigError> {
    let path = check_config_location()?;
    let content = std::fs::read_to_string(path).map_err(|_| ConfigError::FileNotFound)?;
    let config = toml::from_str(&content).map_err(|_| ConfigError::ParseError)?;
    Ok(config)
}

fn check_config_location() -> Result<PathBuf, ConfigError> {
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
    let checks = config.api_entries();
    for (enabled, key, name) in checks {
        if enabled && key.as_deref().map_or(true, |k| k.is_empty()) {
            return Err(ConfigError::MissingKey(name.as_str().to_string()));
        }
    }
    Ok(())
}
