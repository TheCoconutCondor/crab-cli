use crate::config::get_enabled_apis;
use crate::enrich::apis::virustotal::*;
use crate::enrich::utils::ApiName;
use crate::errors::ConfigError;

// This struct serves as a single place to build all the enabled api clients in a central accepted struct.
// With only one implemented, it seems asinine, but as it extends, hopefully it will make more sense.
//
// TODO: Add more API client wrappers to the ApiHandler struct.
pub struct ApiHandler {
    pub vt: Option<VtClient>,
}

impl ApiHandler {
    pub fn new() -> Result<Self, ConfigError> {
        let enabled = get_enabled_apis()?;
        let mut handler = Self { vt: None };
        for api in enabled {
            match api.name {
                ApiName::Virustotal => handler.vt = Some(VtClient::new(&api.key)),
            }
        }
        Ok(handler)
    }
}
