use reqwest::Client;
use serde::Deserialize;
use std::fmt::Formatter;

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
    harmless: Option<u32>,
    suspicious: Option<u32>,
    timeout: Option<u32>,
    undetected: Option<u32>,
}

#[derive(Deserialize, Debug)]
struct VtVotes {
    harmless: Option<u32>,
    malicious: Option<u32>,
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
