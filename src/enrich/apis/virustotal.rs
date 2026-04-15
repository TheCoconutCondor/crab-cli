use virustotal3::VtClient;

pub fn create_vt_client(apikey: &str) -> VtClient {
    VtClient(apikey)
}

pub fn get_ip_intel(address: &str) {
    todo!()
}
