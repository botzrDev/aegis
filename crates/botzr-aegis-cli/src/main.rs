use std::env;
use std::process::ExitCode;

use botzr_aegis_cli::{dispatch, parse_args, usage_text};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match parse_args(&args) {
        Ok(cmd) => dispatch(cmd),
        Err(e) => {
            eprintln!("error: {e}");
            if !e.contains("Usage:") {
                eprint!("{}", usage_text());
            }
            ExitCode::from(1)
        }
    }
}
