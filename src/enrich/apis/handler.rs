use crate::config::get_enabled_apis;
use crate::enrich::apis::metadefender::*;
use crate::enrich::apis::virustotal::*;
use crate::enrich::utils::ApiName;
use crate::errors::ConfigError;

// This struct serves as a single place to build all the enabled api clients in a central accepted struct.
// With only one implemented, it seems asinine, but as it extends, hopefully it will make more sense.
//
// TODO: Add more API client wrappers to the ApiHandler struct.
pub struct ApiHandler {
    pub vt: Option<VtClient>,
    pub md: Option<MdClient>,
}

pub struct IntelResult {
    pub provider: ApiName,
    pub data: String,
}

impl ApiHandler {
    pub fn new() -> Result<Self, ConfigError> {
        let enabled = get_enabled_apis()?;
        let mut handler = Self { vt: None, md: None };
        for api in enabled {
            match api.name {
                ApiName::Virustotal => handler.vt = Some(VtClient::new(&api.key)),
                ApiName::Metadefender => handler.md = Some(MdClient::new(&api.key)),
            }
        }
        Ok(handler)
    }

    pub async fn get_ip_intel(&self, address: &String) -> Vec<IntelResult> {
        let mut results = Vec::new();

        if let Some(vt) = &self.vt {
            match vt.get_ip_report(address).await {
                Ok(result) => results.push(IntelResult {
                    provider: ApiName::Virustotal,
                    data: result.data.attributes.to_string(),
                }),
                Err(e) => results.push(IntelResult {
                    provider: ApiName::Virustotal,
                    data: format!("ERROR: {e}"),
                }),
            }
        }

        if let Some(md) = &self.md {
            match md.get_ip_report(address).await {
                Ok(result) => results.push(IntelResult {
                    provider: ApiName::Metadefender,
                    data: result.to_string(),
                }),
                Err(e) => results.push(IntelResult {
                    provider: ApiName::Metadefender,
                    data: format!("ERROR: {e}"),
                }),
            }
        }
        results
    }
    pub async fn get_hash_intel(&self, sig: &String) -> Vec<IntelResult> {
        let mut results = Vec::new();

        if let Some(vt) = &self.vt {
            match vt.get_hash_report(sig).await {
                Ok(result) => results.push(IntelResult {
                    provider: ApiName::Virustotal,
                    data: result.data.attributes.to_string(),
                }),
                Err(e) => results.push(IntelResult {
                    provider: ApiName::Virustotal,
                    data: format!("ERROR: {e}"),
                }),
            }
        }

        if let Some(md) = &self.md {
            match md.get_hash_report(sig).await {
                Ok(result) => results.push(IntelResult {
                    provider: ApiName::Metadefender,
                    data: result.to_string(),
                }),
                Err(e) => results.push(IntelResult {
                    provider: ApiName::Metadefender,
                    data: format!("ERROR: {e}"),
                }),
            }
        }
        results
    }
}
