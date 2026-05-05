use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::{fmt::Formatter, ops::IndexMut};

pub struct VtClient {
    pub endpoint: Client,
    pub key: String,
}

// Abstracted response struct that *should* handle the different VT calls
// The structure is based off of this sample data: https://docs.virustotal.com/reference/ip-object
#[derive(Deserialize, Debug)]
pub struct VtResponse<T> {
    pub data: VtData<T>,
}

#[derive(Deserialize, Debug)]
pub struct VtData<T> {
    id: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    pub attributes: T,
}

// VIRUSTOTAL IP ATTRIBUTES
#[derive(Deserialize, Debug)]
pub struct IpAttributes {
    as_owner: Option<String>,
    asn: Option<u32>,
    continent: Option<String>,
    country: Option<String>,
    last_analysis_date: Option<u32>,
    last_analysis_stats: AnalysisStats,
    network: Option<String>,
    reputation: Option<u32>,
    total_votes: VtVotes,
    whois: String,
    whois_date: u32,
}

#[derive(Deserialize, Debug)]
struct AnalysisStats {
    #[serde(rename = "confirmed-timeout")]
    confirmed_timeout: Option<u32>,
    failure: Option<u32>,
    harmless: Option<u32>,
    suspicious: Option<u32>,
    timeout: Option<u32>,
    #[serde(rename = "type-unsupported")]
    type_unsupported: Option<u32>,
    undetected: Option<u32>,
}

#[derive(Deserialize, Debug)]
struct VtVotes {
    harmless: Option<u32>,
    malicious: Option<u32>,
}
// END VIRUSTOTAL IP ATTRIBUTES

// VIRUSTOTAL HASH ATTRIBUTES
#[derive(Deserialize, Debug)]
pub struct HashAttributes {
    last_analysis_stats: AnalysisStats,
    meaningful_name: Option<String>,
    #[serde(default)]
    sandbox_verdicts: HashMap<String, SandboxResults>,
    total_votes: VtVotes,
    type_description: Option<String>,
}

#[derive(Deserialize, Debug)]
struct SandboxResults {
    category: Option<String>,
    confidence: Option<u32>,
}
// END VIRUSTOTAL HASH ATTRIBUTES
//
// VIRUSTOTAL DOMAIN ATTRIBUTES
#[derive(Deserialize, Debug)]
pub struct DomainAttributes {
    last_analysis_stats: AnalysisStats,
    creation_date: Option<u32>,
    last_analysis_date: Option<u32>,
    registrar: Option<String>,
}
// END VIRUSTOTAL DOMAIN ATTRIBUTES
//
// VIRUSTOTAL URL ATTRIBUTES
#[derive(Deserialize, Debug)]
pub struct UrlAttributes {
    categories: UrlCategories,
    last_analysis_date: Option<u32>,
    last_analysis_stats: AnalysisStats,
    last_final_url: Option<String>,
}

#[derive(Deserialize, Debug)]
struct UrlCategories {
    #[serde(rename = "BitDefender")]
    bitdefender: Option<String>,
    #[serde(rename = "Forcepoint ThreatSeeker")]
    forcepoint_threatseeker: Option<String>,
}

impl VtClient {
    pub fn new(apikey: &str) -> Self {
        Self {
            endpoint: Client::new(),
            key: apikey.to_string(),
        }
    }

    pub async fn get_ip_report(
        &self,
        ip: &str,
    ) -> Result<VtResponse<IpAttributes>, reqwest::Error> {
        self.endpoint
            .get(format!(
                "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            ))
            .header("x-apikey", &self.key)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
    }

    pub async fn get_hash_report(
        &self,
        hash: &str,
    ) -> Result<VtResponse<HashAttributes>, reqwest::Error> {
        self.endpoint
            .get(format!("https://www.virustotal.com/api/v3/files/{hash}"))
            .header("x-apikey", &self.key)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
    }

    pub async fn get_domain_report(
        &self,
        domain: &str,
    ) -> Result<VtResponse<DomainAttributes>, reqwest::Error> {
        self.endpoint
            .get(format!(
                "https://www.virustotal.com/api/v3/domains/{domain}"
            ))
            .header("x-apikey", &self.key)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
    }

    pub async fn get_url_report(
        &self,
        url: &str,
    ) -> Result<VtResponse<UrlAttributes>, reqwest::Error> {
        self.endpoint
            .get(format!("https://www.virustotal.com/api/v3/urls/{url}"))
            .header("x-apikey", &self.key)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
    }
}

impl std::fmt::Display for IpAttributes {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{:<25} {}",
            "Owner:",
            self.as_owner.as_deref().unwrap_or("?")
        )?;
        writeln!(
            f,
            "{:<25} {}",
            "Country:",
            self.country.as_deref().unwrap_or("?")
        )?;
        writeln!(
            f,
            "{:<25} {}",
            "Analyze Date:",
            self.last_analysis_date
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(f, "{:<25} {}", "Stats:", "")?;
        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "Harmless:",
            self.last_analysis_stats
                .harmless
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "Suspicious:",
            self.last_analysis_stats
                .suspicious
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "Timeout:",
            self.last_analysis_stats
                .timeout
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "Undetected:",
            self.last_analysis_stats
                .undetected
                .map_or("?".into(), |d| d.to_string())
        )?;
        Ok(())
    }
}

impl std::fmt::Display for HashAttributes {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{:<25} {}",
            "Meaningful Name:",
            self.meaningful_name.as_deref().unwrap_or("?")
        )?;

        writeln!(f, "{:<25} {}", "Stats:", "")?;
        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "Harmless:",
            self.last_analysis_stats
                .harmless
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "Suspicious:",
            self.last_analysis_stats
                .suspicious
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "Timeout:",
            self.last_analysis_stats
                .timeout
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "Undetected:",
            self.last_analysis_stats
                .undetected
                .map_or("?".into(), |d| d.to_string())
        )?;
        Ok(())
    }
}

impl std::fmt::Display for DomainAttributes {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{:<25} {}",
            "Registrar:",
            self.registrar.as_deref().unwrap_or("?")
        )?;

        writeln!(f, "{:<25} {}", "Stats:", "")?;

        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "Harmless:",
            self.last_analysis_stats
                .harmless
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "Suspicious:",
            self.last_analysis_stats
                .suspicious
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "Timeout:",
            self.last_analysis_stats
                .timeout
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "Undetected:",
            self.last_analysis_stats
                .undetected
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(
            f,
            "{:<25} {}",
            "Creation Date:",
            self.creation_date.map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(
            f,
            "{:<25} {}",
            "Analyze Date:",
            self.last_analysis_date
                .map_or("?".into(), |d| d.to_string())
        )?;
        Ok(())
    }
}

impl std::fmt::Display for UrlAttributes {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{:<25} {}",
            "Last Final URL:",
            self.last_final_url.as_deref().unwrap_or("?")
        )?;
        writeln!(f, "{:<25} {}", "Categories:", "")?;
        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "BitDefender:",
            self.categories.bitdefender.as_deref().unwrap_or("?")
        )?;
        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "ForcePoint ThreatSeeker:",
            self.categories
                .forcepoint_threatseeker
                .as_deref()
                .unwrap_or("?")
        )?;
        writeln!(
            f,
            "{:<25} {}",
            "Analyze Date:",
            self.last_analysis_date
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(f, "{:<25} {}", "Stats:", "")?;
        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "Harmless:",
            self.last_analysis_stats
                .harmless
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "Suspicious:",
            self.last_analysis_stats
                .suspicious
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "Timeout:",
            self.last_analysis_stats
                .timeout
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(
            f,
            "{:<10}{:<15} {}",
            "",
            "Undetected:",
            self.last_analysis_stats
                .undetected
                .map_or("?".into(), |d| d.to_string())
        )?;
        Ok(())
    }
}
