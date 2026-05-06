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
