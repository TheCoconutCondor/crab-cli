use crate::enrich::apis::handler::ApiHandler;
use crate::errors::EnrichError;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use url::{Host, Url};

pub enum Hash {
    MD5(String),
    SHA1(String),
    SHA256(String),
}

pub enum ApiName {
    Virustotal,
    Metadefender,
}

pub enum IocType {
    Ip,
    Hash,
    Domain,
    Url,
}

impl ApiName {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApiName::Virustotal => "virustotal",
        }
    }
}

pub fn check_path(path: &PathBuf) -> Result<(), EnrichError> {
    match path.exists() {
        true => {
            if path.is_file() {
                Ok(())
            } else if path.is_dir() && (path.is_relative() || path.is_absolute()) {
                Err(EnrichError::IsDirectory)
            } else {
                Err(EnrichError::NotFound)
            }
        }
        false => Err(EnrichError::NotFound),
    }
}

pub fn check_url_format(link: &str) -> Result<(), EnrichError> {
    match Url::parse(link) {
        Ok(_) => Ok(()),
        _ => Err(EnrichError::InvalidUrl),
    }
}

pub fn check_ip_format(ip: &str) -> Result<(), EnrichError> {
    let is_ip4 = ip.parse::<Ipv4Addr>().is_ok();
    let is_ip6 = ip.parse::<Ipv6Addr>().is_ok();

    if is_ip4 || is_ip6 {
        Ok(())
    } else {
        Err(EnrichError::InvalidAddress)
    }
}

pub fn check_hash_format(sig: &str) -> Result<Hash, EnrichError> {
    match sig.len() {
        32 => Ok(Hash::MD5(sig.to_string())),
        40 => Ok(Hash::SHA1(sig.to_string())),
        64 => Ok(Hash::SHA256(sig.to_string())),
        _ => Err(EnrichError::InvalidSignature),
    }
}

pub fn check_domain_format(name: &str) -> Result<(), EnrichError> {
    if name.contains("..") || name.starts_with(".") || name.ends_with(".") {
        return Err(EnrichError::InvalidDomain);
    }
    match Host::parse(name) {
        Ok(Host::Domain(_)) => Ok(()),
        _ => Err(EnrichError::InvalidDomain),
    }
}
