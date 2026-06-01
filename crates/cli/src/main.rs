//! The `overlay-broadcast` binary entry point. Parses arguments with clap and runs the
//! requested command, exiting non-zero on any error (REQ-CLI-001/003).
#![forbid(unsafe_code)]

use clap::Parser;
use cli::{run, Cli};
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
