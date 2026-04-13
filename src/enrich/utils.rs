use crate::errors::EnrichError;
use std::path::PathBuf;

pub fn check_path(path: &PathBuf) -> Result<(), EnrichError> {
    match path.exists() {
        true => {
            if path.is_file() {
                Ok(())
            } else if path.is_dir() && (path.is_relative() || path.is_absolute()) {
                Err(EnrichError::IsDirectory)
            } else {
                Err(EnrichError::NotFound)
            }
        }
        false => Err(EnrichError::NotFound),
    }
}
