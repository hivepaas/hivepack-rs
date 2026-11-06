//! `hivepack::memory::available` on the system the tests run on: a figure
//! above 0 and no more than the machine's memory; and on Linux, under
//! `ulimit -v` and `ulimit -d`, no more than the limit, bound by it. For
//! those, the test runs this file's test binary again in a shell that sets
//! the limit, which then prints what it measures.

use hivepack::memory::{self, Bound};

/// Set in the test binary run again under a limit.
const CHILD: &str = "HIVEPACK_MEMORY_CHILD";

/// The machine's memory, as the system tells it, if it can be told.
fn total_memory() -> Option<u64> {
    if cfg!(target_os = "linux") {
        let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
        let line = meminfo.lines().find(|l| l.starts_with("MemTotal:"))?;
        let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
        return Some(kib * 1024);
    }
    let output = if cfg!(target_os = "macos") {
        std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
    } else if cfg!(windows) {
        std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
            ])
            .output()
    } else {
        return None;
    };
    let output = output.ok()?;
    String::from_utf8(output.stdout).ok()?.trim().parse().ok()
}

#[test]
fn a_figure_within_the_machines_memory() {
    if std::env::var_os(CHILD).is_some() {
        return;
    }
    let available = memory::available();
    if !cfg!(any(target_os = "linux", target_os = "macos", windows)) {
        assert_eq!(available, None);
        return;
    }
    let available = available.expect("measured");
    assert!(available.bytes > 0, "{available:?}");
    match total_memory() {
        Some(total) => assert!(available.bytes <= total, "{available:?} of {total}"),
        None => eprintln!("the machine's memory could not be told"),
    }
    let bounds: &[Bound] = if cfg!(target_os = "linux") {
        &[Bound::System, Bound::ControlGroup, Bound::Ulimit]
    } else if cfg!(windows) {
        // CI runners may run the tests in a job of their own.
        &[Bound::System, Bound::JobObject]
    } else {
        &[Bound::System]
    };
    assert!(bounds.contains(&available.bound), "{available:?}");
    eprintln!("{available:?}");
}

/// What the test binary run again prints, under the limit its shell set.
#[test]
fn report() {
    if std::env::var_os(CHILD).is_none() {
        return;
    }
    let available = memory::available().expect("measured");
    println!(
        "available {} {:?} {}",
        available.bytes, available.bound, available.thread_overhead
    );
}

#[cfg(target_os = "linux")]
#[test]
fn under_ulimit_no_more_than_the_limit() {
    if std::env::var_os(CHILD).is_some() {
        return;
    }
    const LIMIT: u64 = 1 << 30;
    let before = memory::available().expect("measured");
    let exe = std::env::current_exe().expect("this test binary");
    for flag in ["-v", "-d"] {
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "ulimit {flag} {} && exec \"$0\" \"$@\"",
                LIMIT >> 10
            ))
            .arg(&exe)
            .args(["--exact", "report", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .expect("sh runs");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "ulimit {flag}: {stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let line = stdout
            .lines()
            // After the test's name, on the same line.
            .find_map(|l| l.split_once("available ").map(|(_, rest)| rest))
            .unwrap_or_else(|| panic!("ulimit {flag}: {stdout}"));
        let fields: Vec<&str> = line.split(' ').collect();
        let bytes: u64 = fields[0].parse().expect("bytes");
        let overhead: u64 = fields[2].parse().expect("overhead");
        assert!(bytes > 0 && bytes <= LIMIT, "ulimit {flag}: {line}");
        // What the program holds of it is counted: its code, its stacks.
        assert!(bytes < LIMIT, "ulimit {flag}: {line}");
        // Unless the machine had less than the limit to start with.
        if before.bytes > LIMIT + (256 << 20) {
            assert_eq!(fields[1], "Ulimit", "ulimit {flag}: {line}");
        }
        // Each thread's stack, at least.
        assert!(overhead >= 2 << 20, "ulimit {flag}: {line}");
    }
}
