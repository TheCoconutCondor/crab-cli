use crate::enrich::utils::check_path;
use crate::errors::EnrichError;
use std::path::PathBuf;
use url::Host;

pub fn pass_domain_args(name: Option<String>, path: Option<PathBuf>) {
    match (name, path) {
        (Some(name), None) => match check_domain_format(&name) {
            Ok(()) => println!("Domain accepted: {name}"),
            Err(error) => println!("{error}"),
        },
        (None, Some(path)) => match check_path(&path) {
            Ok(()) => println!("File path is a file!"),
            Err(error) => println!("{error}"),
        },
        (Some(_name), Some(_path)) => {
            println!("Must be either a single domain OR file path.");
        }
        (None, None) => {
            println!("Please enter a domain or file path");
        }
    }
}

fn check_domain_format(name: &str) -> Result<(), EnrichError> {
    if name.contains("..") || name.starts_with(".") || name.ends_with(".") {
        return Err(EnrichError::InvalidDomain);
    }
    match Host::parse(name) {
        Ok(Host::Domain(_)) => Ok(()),
        _ => Err(EnrichError::InvalidDomain),
    }
}
