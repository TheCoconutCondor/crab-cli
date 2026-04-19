mod cli;
mod config;
mod enrich;
mod errors;

use crate::enrich::apis::handler::ApiHandler;

#[tokio::main]
async fn main() {
    match config::run() {
        Ok(()) => {
            if let Ok(handler) = ApiHandler::new() {
                cli::run(&handler).await;
            }
        }
        Err(e) => {
            eprintln!("{e}")
        }
    }
}
