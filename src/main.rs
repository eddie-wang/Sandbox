mod config;
mod controller;
mod http;
mod lifecycle;
mod model;
mod scheduler;
mod worker;
mod engine;
mod native;
mod network;
mod phases;
mod process;
mod proxy;
mod storage;
mod mounts;
mod overlay;

use std::path::Path;

const USAGE: &str = "Usage: sandboxd <controller|worker|preflight> --config <file>\nCredentials are read only from the configured environment variable or file.";

// Run the selected mode, printing a safe startup error and exiting unsuccessfully on failure.
fn main() {
    if let Err(message) = start() {
        eprintln!("sandboxd: {message}");
        std::process::exit(1);
    }
}

// Dispatch internal helpers or load and validate the selected service configuration. Load credentials
// only for serving; preflight prints prerequisite checks. Worker mount boundaries and active probes
// are established before starting any threads, including the request runtime.
fn start() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 2 && args[0] == "internal-unmount" { return mounts::unmount(Path::new(&args[1])); }
    if args.len() == 2 && args[0] == "internal-overlay-probe" {
        if !overlay::probe(Path::new(&args[1]))? { std::process::exit(2); }
        return Ok(());
    }
    if args.len() == 3 && args[0] == "internal-erofs-mount" { return native::erofs_mount_helper(&args[1], &args[2]); }
    if args.first().is_some_and(|a| a == "internal-exec") { return process::exec_helper(&args[1..]); }
    if args.len() == 1 && args[0] == "internal-forward" { return network::forward_helper(true); }
    if args.len() == 1 && args[0] == "internal-guest-network" { return network::forward_helper(false); }
    if args.len() == 1 && args[0] == "internal-slot-reset" { return network::slot_reset_helper(); }
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
        Some("preflight") => {
            let config: config::WorkerConfig = config::load(Path::new(&args[2]))?;
            config.validate()?;
            let report = native::preflight(config.native.as_ref());
            println!("{}", serde_json::to_string_pretty(&report).map_err(|_| "preflight_encode_failed")?);
            if report.ready { Ok(()) } else { Err("preflight requirements not met; no host state changed") }
        }
        Some("worker") => {
            let config: config::WorkerConfig = config::load(Path::new(&args[2]))?;
            config.validate()?;
            let token = config.auth.load()?;
            let report = native::preflight(config.native.as_ref());
            let handle = engine::Handle::start(&config, report)?;
            runtime()?.block_on(worker::run(config, token, handle))
        }
        _ => Err(USAGE),
    }
}

// Create the event-processing runtime used to serve controller or worker requests.
fn runtime() -> Result<tokio::runtime::Runtime, &'static str> {
    tokio::runtime::Builder::new_multi_thread().enable_all().build()
        .map_err(|_| "cannot initialize async runtime")
}
