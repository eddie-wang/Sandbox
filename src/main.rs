mod config;
mod controller;
mod http;
mod lifecycle;
mod model;
mod scheduler;
mod worker;

use std::path::Path;

const USAGE: &str = "Usage: sandboxd <controller|worker> --config <file>\nCredentials are read only from the configured environment variable or file.";

fn main() {
    if let Err(message) = start() {
        eprintln!("sandboxd: {message}");
        std::process::exit(1);
    }
}

fn start() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--help" {
        println!("{USAGE}");
        return Ok(());
    }
    if args.len() != 3 || args[1] != "--config" {
        return Err(USAGE);
    }
    // Startup filesystem reads occur before entering the async runtime.
    match args[0].to_str() {
        Some("controller") => {
            let config: config::ControllerConfig = config::load(Path::new(&args[2]))?;
            config.validate()?;
            let token = config.auth.load()?;
            let worker_token = config.worker_auth.load()?;
            runtime()?.block_on(controller::run(config, token, worker_token))
        }
        Some("worker") => {
            let config: config::WorkerConfig = config::load(Path::new(&args[2]))?;
            config.validate()?;
            let token = config.auth.load()?;
            runtime()?.block_on(worker::run(config, token))
        }
        _ => Err(USAGE),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, &'static str> {
    tokio::runtime::Builder::new_multi_thread().enable_all().build()
        .map_err(|_| "cannot initialize async runtime")
}
