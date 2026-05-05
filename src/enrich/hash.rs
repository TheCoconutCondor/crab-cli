use crate::enrich::{apis::handler::ApiHandler, utils::*};
use std::path::PathBuf;

pub async fn pass_hash_args(sig: Option<String>, path: Option<PathBuf>, handle: &ApiHandler) {
    match (sig, path) {
        (Some(sig), None) => match check_hash_format(&sig) {
            Ok(_) => {
                if let Some(vt) = &handle.vt {
                    match vt.get_hash_report(&sig).await {
                        Ok(report) => println!("{}", report.data.attributes),
                        Err(e) => eprintln!("{e}"),
                    }
                }
            }
            Err(e) => println!("{e}"),
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
