//! Test fixture for `botzr-aegis-confine`. Not operator surface.
//!
//! Verbs:
//! - `read <PATH>` / `write <PATH>` / `connect <HOST> <PORT>` / `nnp`
//! - `landlock-only` / `seccomp-only` / `restrict-exec -- <CMD> [ARGS…]`
//!
//! `restrict-exec` is the same mechanism as `aegis __confine-exec`: apply
//! the profile from `AEGIS_CONFINE_PROFILE`, report, strip the env, `exec`.
//! Kept in this crate so escape tests do not depend on the CLI binary.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let verb = args.get(1).map(String::as_str).unwrap_or("");
    match verb {
        "read" => {
            let path = args.get(2).expect("read <PATH>");
            match std::fs::read(path) {
                Ok(bytes) => {
                    let _ = std::io::Write::write_all(&mut std::io::stdout(), &bytes);
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        "write" => {
            let path = args.get(2).expect("write <PATH>");
            match std::fs::write(path, b"x") {
                Ok(()) => std::process::exit(0),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        "connect" => {
            let host = args.get(2).expect("connect <HOST> <PORT>");
            let port = args.get(3).expect("connect <HOST> <PORT>");
            match std::net::TcpStream::connect(format!("{host}:{port}")) {
                Ok(_) => std::process::exit(0),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        "nnp" => print_nnp(),
        "landlock-only" => {
            #[cfg(target_os = "linux")]
            {
                let profile = botzr_aegis_confine::load_profile_from_env().unwrap_or_else(|e| {
                    eprintln!("{e}");
                    std::process::exit(1);
                });
                if let Err(e) = botzr_aegis_confine::apply_landlock(&profile) {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                print_nnp();
            }
            #[cfg(not(target_os = "linux"))]
            {
                eprintln!("linux only");
                std::process::exit(1);
            }
        }
        "seccomp-only" => {
            #[cfg(target_os = "linux")]
            {
                let profile = botzr_aegis_confine::load_profile_from_env().unwrap_or_else(|e| {
                    eprintln!("{e}");
                    std::process::exit(1);
                });
                if let Err(e) = botzr_aegis_confine::apply_seccomp(&profile) {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                print_nnp();
            }
            #[cfg(not(target_os = "linux"))]
            {
                eprintln!("linux only");
                std::process::exit(1);
            }
        }
        "restrict-exec" => {
            #[cfg(unix)]
            restrict_exec(&args);
            #[cfg(not(unix))]
            {
                eprintln!("unix only");
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!(
                "aegis-confine-probe: read|write|connect|nnp|landlock-only|seccomp-only|restrict-exec"
            );
            std::process::exit(2);
        }
    }
}

fn print_nnp() {
    match std::fs::read_to_string("/proc/self/status") {
        Ok(status) => {
            for line in status.lines() {
                if line.starts_with("NoNewPrivs:") {
                    println!("{line}");
                    std::process::exit(0);
                }
            }
            eprintln!("NoNewPrivs line missing");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

#[cfg(unix)]
fn restrict_exec(args: &[String]) {
    use std::os::unix::process::CommandExt;

    let dash = args.iter().position(|a| a == "--").unwrap_or(args.len());
    let child_argv = &args[dash + 1..];
    if child_argv.is_empty() {
        eprintln!("aegis-confine-probe restrict-exec: missing command after `--`");
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    {
        let profile = match botzr_aegis_confine::load_profile_from_env() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("aegis-confine-probe: {e}");
                std::process::exit(1);
            }
        };
        let mut report = match botzr_aegis_confine::open_report() {
            Ok(f) => f,
            Err(e) => {
                eprintln!("aegis-confine-probe: {e}");
                std::process::exit(1);
            }
        };
        let enforced = match botzr_aegis_confine::restrict_self(&profile) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("aegis-confine-probe: {e}");
                std::process::exit(1);
            }
        };
        if let Some(file) = report.as_mut() {
            if let Err(e) = botzr_aegis_confine::write_report(file, &enforced) {
                eprintln!("aegis-confine-probe: {e}");
                std::process::exit(1);
            }
        }
    }

    let err = std::process::Command::new(&child_argv[0])
        .args(&child_argv[1..])
        .env_remove(botzr_aegis_confine::PROFILE_ENV)
        .env_remove(botzr_aegis_confine::REPORT_ENV)
        .exec();
    eprintln!("aegis-confine-probe: exec {}: {err}", child_argv[0]);
    std::process::exit(1);
}
