use crate::enrich::utils::check_path;
use crate::errors::EnrichError;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

/// This function will take in the args input from the user
/// and based on the input given, handle accordingly.
pub fn pass_ip_args(address: Option<String>, path: Option<PathBuf>) {
    match (address, path) {
        // If single address is passed.
        (Some(address), None) => match check_ip_format(&address) {
            Ok(()) => {
                println!("Format OK!");
                println!("IP address entered: {address}");
            }
            Err(error) => println!("{error}"),
        },
        // If a file path is passed.
        (None, Some(path)) => match check_path(&path) {
            Ok(()) => println!("File path is a file!"), // TODO: Need to implement IOC specific path logic instead of Ok(())
            Err(error) => println!("{error}"),
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

fn check_ip_format(ip: &str) -> Result<(), EnrichError> {
    let is_ip4 = ip.parse::<Ipv4Addr>().is_ok();
    let is_ip6 = ip.parse::<Ipv6Addr>().is_ok();

    if is_ip4 || is_ip6 {
        Ok(())
    } else {
        Err(EnrichError::InvalidAddress)
    }
}
