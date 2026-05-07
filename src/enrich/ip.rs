use crate::enrich::apis::handler::ApiHandler;
use crate::enrich::utils::*;
use std::path::PathBuf;

/// This function will take in the args for an IP address
/// input to enrich from the user
/// and based on the input given, handle accordingly.
pub async fn pass_ip_args(address: Option<String>, path: Option<PathBuf>, handle: &ApiHandler) {
    match (address, path) {
        // If single address is passed.
        (Some(address), None) => match check_ip_format(&address) {
            Ok(()) => {
                for result in handle.get_ip_intel(&address).await {
                    println!("====== {} ======", result.provider.as_str());
                    println!("{}", result.data);
                }
            }
            Err(e) => println!("{e}"),
        },
        // If a file path is passed.
        (None, Some(path)) => match check_path(&path) {
            Ok(()) => println!("File path is a file!"), // TODO: Need to implement IOC specific path logic instead of Ok(())
            Err(e) => println!("{e}"),
        },
        // If both are passed in the same command.
        (Some(_address), Some(_path)) => {
            println!("Must be either single IP OR file path.");
        }
        // If neither are passed.
        (None, None) => {
            println!("Please enter an IP address or file path.");
        }
    }
}
