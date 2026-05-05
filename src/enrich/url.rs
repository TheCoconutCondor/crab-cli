use crate::enrich::{apis::handler::ApiHandler, utils::*};
use base64::{Engine, prelude::BASE64_STANDARD};
use std::path::PathBuf;

pub async fn pass_url_args(link: Option<String>, path: Option<PathBuf>, handle: &ApiHandler) {
    match (link, path) {
        (Some(link), None) => match check_url_format(&link) {
            Ok(()) => {
                if let Some(vt) = &handle.vt {
                    match vt.get_url_report(&BASE64_STANDARD.encode(link)).await {
                        Ok(result) => println!("{}", result.data.attributes),
                        Err(e) => eprintln!("{e}"),
                    }
                }
            }
            Err(e) => eprintln!("{e}"),
        },
        (None, Some(path)) => match check_path(&path) {
            Ok(()) => println!("Path is a file!"), // TODO: Implement IOC specific handling logic.
            Err(e) => eprintln!("{e}"),
        },
        (Some(_link), Some(_path)) => {
            println!("Must be either single URL OR file path.")
        }
        (None, None) => {
            println!("Please enter a URL or file path.")
        }
    }
}
