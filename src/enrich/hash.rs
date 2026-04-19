use crate::enrich::utils::*;
use std::path::PathBuf;

pub fn pass_hash_args(sig: Option<String>, path: Option<PathBuf>) {
    match (sig, path) {
        (Some(sig), None) => match check_hash_format(&sig) {
            Ok(_) => println!("Hash entered: {sig}"),
            Err(error) => println!("{error}"),
        },
        // If a file path is targeted.
        (None, Some(path)) => match check_path(&path) {
            Ok(()) => println!("File path is a file!"), // TODO: Need to implement IOC specific path logic instead of Ok(())
            Err(error) => println!("{error}"),
        },
        (Some(_sig), Some(_path)) => {
            println!("Must be either single hash OR file path.");
        }
        (None, None) => {
            println!("Please enter a hash or a file path.");
        }
    }
}
