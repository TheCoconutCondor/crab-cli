use crate::enrich::{apis::handler::ApiHandler, utils::*};
use std::path::PathBuf;

pub async fn pass_domain_args(name: Option<String>, path: Option<PathBuf>, handle: &ApiHandler) {
    match (name, path) {
        (Some(name), None) => match check_domain_format(&name) {
            Ok(()) => {
                if let Some(vt) = &handle.vt {
                    match vt.get_domain_report(&name).await {
                        Ok(result) => println!("{}", result.data.attributes),
                        Err(e) => eprintln!("{e}"),
                    }
                }
            }
            Err(e) => eprintln!("{e}"),
        },
        (None, Some(path)) => match check_path(&path) {
            Ok(()) => println!("File path is a file!"),
            Err(e) => eprintln!("{e}"),
        },
        (Some(_name), Some(_path)) => {
            println!("Must be either a single domain OR file path.");
        }
        (None, None) => {
            println!("Please enter a domain or file path");
        }
    }
}
