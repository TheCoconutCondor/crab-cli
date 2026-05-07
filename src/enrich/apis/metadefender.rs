use reqwest::Client;
use serde::Deserialize;
use std::fmt::Formatter;

pub struct MdClient {
    pub endpoint: Client,
    pub key: String,
}

// The response object which will take different ReportData structs
#[derive(Deserialize, Debug)]
pub struct MdResponse<T> {
    pub object: T,
}

// HASH REPORT RESPONSE DATA
#[derive(Deserialize, Debug)]
pub struct HashReportData {
    file_info: FileInfo,
    votes: Votes,
}

#[derive(Deserialize, Debug)]
struct FileInfo {
    display_name: Option<String>,
    file_type_extension: Option<String>,
    file_type_category: Option<String>,
    file_type_description: Option<String>,
}

#[derive(Deserialize, Debug)]
struct Votes {
    up: Option<u32>,
    down: Option<u32>,
}
// END HASH REPORT RESPONSE DATA
//
// IP REPORT RESPONSE DATA
#[derive(Deserialize, Debug)]
pub struct IpReportData {
    address: Option<String>,
    lookup_results: LookupResults,
    geo_info: GeoInfo,
}

#[derive(Deserialize, Debug)]
struct LookupResults {
    detected_by: Option<i32>,
    sources: Option<Vec<Source>>,
}

#[derive(Deserialize, Debug)]
struct Source {
    provider: Option<String>,
    assessment: Option<String>,
    detect_time: Option<String>,
    update_time: Option<String>,
    status: Option<i32>,
}

#[derive(Deserialize, Debug)]
struct GeoInfo {
    country: Country,
    city: City,
    location: Location,
}

#[derive(Deserialize, Debug)]
struct Country {
    name: Option<String>,
}

#[derive(Deserialize, Debug)]
struct City {
    name: Option<String>,
}

#[derive(Deserialize, Debug)]
struct Location {
    latitude: Option<i32>,
    longitude: Option<i32>,
    name: Option<String>,
}

impl MdClient {
    pub fn new(apikey: &str) -> Self {
        Self {
            endpoint: Client::new(),
            key: apikey.to_string(),
        }
    }

    pub async fn get_hash_report(
        &self,
        sig: &str,
    ) -> Result<MdResponse<HashReportData>, reqwest::Error> {
        self.endpoint
            .get(format!("https://api.metadefender.com/v4/hash/{sig}"))
            .header("apikey", &self.key)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
    }

    pub async fn get_ip_report(
        &self,
        address: &str,
    ) -> Result<MdResponse<IpReportData>, reqwest::Error> {
        self.endpoint
            .get(format!("https://api.metadefender.com/v4/ip/{address}"))
            .header("apikey", &self.key)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
    }
}

impl std::fmt::Display for HashReportData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{:<25} {}",
            "Display Name:",
            self.file_info.display_name.as_deref().unwrap_or("?")
        )?;
        writeln!(
            f,
            "{:<25} {}",
            "File Type Extension:",
            self.file_info.file_type_extension.as_deref().unwrap_or("?")
        )?;
        writeln!(
            f,
            "{:<25} {}",
            "File Type Category:",
            self.file_info.file_type_category.as_deref().unwrap_or("?")
        )?;
        writeln!(
            f,
            "{:<25} {}",
            "File Type Description:",
            self.file_info
                .file_type_description
                .as_deref()
                .unwrap_or("?")
        )?;
        writeln!(f, "{:<25} {}", "Votes:", "")?;
        writeln!(
            f,
            "{:<15}{:<10} {}",
            "",
            "Up:",
            self.votes.up.map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(
            f,
            "{:<15}{:<10} {}",
            "",
            "Down:",
            self.votes.down.map_or("?".into(), |d| d.to_string())
        )?;
        Ok(())
    }
}

impl std::fmt::Display for IpReportData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{:<25} {}",
            "IP Address:",
            self.address.as_deref().unwrap_or("?")
        )?;
        writeln!(
            f,
            "{:<25} {}",
            "Detected By:",
            self.lookup_results
                .detected_by
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(f, "{:<25} {}", "Sources:", "")?;
        match &self.lookup_results.sources {
            Some(sources) => {
                for source in sources {
                    writeln!(f, "{source}")?;
                }
            }
            None => (),
        }
        writeln!(
            f,
            "{:<25} {}",
            "Geo Info - Country:",
            self.geo_info.country.name.as_deref().unwrap_or("?")
        )?;
        writeln!(
            f,
            "{:<25} {}",
            "Geo Info - City:",
            self.geo_info.city.name.as_deref().unwrap_or("?")
        )?;
        writeln!(f, "{:<25} {}", "Geo Info - Location:", "")?;
        writeln!(
            f,
            "{:<15}{:<10} {}",
            "",
            "Latitude:",
            self.geo_info
                .location
                .latitude
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(
            f,
            "{:<15}{:<10} {}",
            "",
            "Longitude:",
            self.geo_info
                .location
                .longitude
                .map_or("?".into(), |d| d.to_string())
        )?;
        writeln!(
            f,
            "{:<15}{:<10} {}",
            "",
            "Name:",
            self.geo_info.location.name.as_deref().unwrap_or("?")
        )?;
        Ok(())
    }
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{:<15}{:<10} {}",
            "",
            "Provider:",
            self.provider.as_deref().unwrap_or("?")
        )?;
        writeln!(
            f,
            "{:<15}{:<10} {}",
            "",
            "Assessment:",
            self.assessment.as_deref().unwrap_or("?")
        )?;
        writeln!(
            f,
            "{:<15}{:<10} {}",
            "",
            "Detect Time:",
            self.detect_time.as_deref().unwrap_or("?")
        )?;
        writeln!(
            f,
            "{:<15}{:<10} {}",
            "",
            "Update Time:",
            self.update_time.as_deref().unwrap_or("?")
        )?;
        writeln!(
            f,
            "{:<15}{:<10} {}",
            "",
            "Status:",
            self.status.map_or("?".into(), |d| d.to_string())
        )?;
        Ok(())
    }
}
