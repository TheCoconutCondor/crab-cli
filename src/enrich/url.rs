use crate::enrich::utils::*;
use std::path::PathBuf;

pub fn pass_url_args(link: Option<String>, path: Option<PathBuf>) {
    match (link, path) {
        (Some(link), None) => match check_url_format(&link) {
            Ok(()) => println!("Url format accepted!"),
            Err(error) => println!("{error}"),
        },
        (None, Some(path)) => match check_path(&path) {
            Ok(()) => println!("Path is a file!"), // TODO: Implement IOC specific handling logic.
            Err(error) => println!("{error}"),
        },
        (Some(_link), Some(_path)) => {
            println!("Must be either single URL OR file path.")
        }
        (None, None) => {
            println!("Please enter a URL or file path.")
        }
    }
}
