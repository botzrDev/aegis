//! Happy-path demo: run the path-detector guest through the sandbox using only
//! `botzr-aegis-sandbox` + `botzr-aegis-core`, and print its findings.
//!
//! ```text
//! cargo run -p sandbox-consumer
//! ```

use std::process::ExitCode;

use sandbox_consumer::scan_fixtures;

fn main() -> ExitCode {
    let run = match scan_fixtures(br#"{"scan_root":"fixtures"}"#) {
        Ok(run) => run,
        Err(err) => {
            eprintln!("sandbox setup failed: {err}");
            return ExitCode::FAILURE;
        }
    };

    match run.output {
        Ok(bytes) if !bytes.is_empty() => {
            println!("path-detector findings: {}", String::from_utf8_lossy(&bytes));
            println!(
                "metrics: wall_ms={} peak_memory_bytes={}",
                run.metrics.wall_ms, run.metrics.peak_memory_bytes
            );
            ExitCode::SUCCESS
        }
        Ok(_) => {
            eprintln!("scan produced no output");
            ExitCode::FAILURE
        }
        Err(err) => {
            eprintln!("scan failed: {err}");
            ExitCode::FAILURE
        }
    }
}
