mod cli;
mod config;
mod enrich;
mod errors;

fn main() {
    match config::run() {
        Ok(_) => cli::run(),
        Err(e) => eprintln!("{e}"),
    }
}
