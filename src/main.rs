use std::path::PathBuf;

use clap::Parser;
use windows::Win32::Foundation::STATUS_NONCONTINUABLE_EXCEPTION;
use winfsp::{service::FileSystemServiceBuilder, winfsp_init_or_die};

mod block;
mod fs;
mod range;
mod service;
mod vfs;

/// MainArgs
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None,)]
pub struct Args {
    /// -1: enable all debug logs
    #[clap(short = 'd', default_value = "0")]
    flags: i32,

    /// file path
    #[clap(short = 'D', long)]
    logfile: Option<PathBuf>,

    #[clap(short = 'u', long)]
    volume_prefix: Option<String>,

    #[clap(short = 'p', long)]
    backing_file: Option<PathBuf>,

    #[clap(short = 'm', long)]
    mountpoint: Option<PathBuf>,
}

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug"))
        )
        .init();

    let init = winfsp_init_or_die();
    let fsp = FileSystemServiceBuilder::new()
        .with_start(|| {
            let args = Args::parse();
            Ok(service::svc_start(args).map_err(|e| {
                eprintln!("Failed to start service: {:?}", e);
                STATUS_NONCONTINUABLE_EXCEPTION
            })?)
        })
        .with_stop(|f| {
            service::svc_stop(f);
            Ok(())
        })
        .build("encryptedfs-winfsp-rs", init)
        .expect("failed to build fsp");

    let _ = fsp.start().join();
}
