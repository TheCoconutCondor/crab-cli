use std::fmt;

pub enum EnrichError {
    InvalidAddress,
    InvalidSignature,
    InvalidDomain,
    InvalidUrl,
    NotFound,
    IsDirectory,
}

impl fmt::Display for EnrichError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnrichError::InvalidAddress => write!(
                f,
                "Invalid address format: use Ipv4 or Ipv6 standard patterns."
            ),
            EnrichError::InvalidSignature => {
                write!(f, "Invalid hash signature: use MD5, SHA1, or SHA256.")
            }
            EnrichError::InvalidDomain => write!(f, "Invalid domain."),
            EnrichError::InvalidUrl => write!(f, "Invalid URL."),
            EnrichError::NotFound => write!(f, "Not found."),
            EnrichError::IsDirectory => write!(f, "Path provided is a directory."),
        }
    }
}

pub enum ConfigError {
    FileNotFound,
    IncorrectFormat,
    ParseError,
    MissingKey(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::FileNotFound => {
                write!(
                    f,
                    "Config file not found. Is crab.toml in the same directory as crab?"
                )
            }
            ConfigError::IncorrectFormat => write!(f, "Incorrect format"),
            ConfigError::ParseError => write!(f, "Parsing error on crab.toml"),
            ConfigError::MissingKey(s) => write!(f, "Missing key from enabled api: {s}"),
        }
    }
}
