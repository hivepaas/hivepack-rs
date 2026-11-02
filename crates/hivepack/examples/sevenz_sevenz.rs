//! Lists 7z archives and extracts their files, both ways, telling what
//! each gives: `cargo run -p hivepack --all-features --example sevenz_sevenz -- ARCHIVE...`,
//! with the password of encrypted ones in `SEVENZ_PASSWORD`.

use std::io::Read;

fn main() {
    for path in std::env::args().skip(1) {
        let name = std::path::Path::new(&path)
            .file_name()
            .map_or(path.clone(), |n| n.to_string_lossy().into_owned());
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                println!("{name}: {e}");
                continue;
            }
        };
        let options = hivepack::sevenz::Options {
            password: std::env::var("SEVENZ_PASSWORD").ok(),
            ..Default::default()
        };
        let reader = std::io::BufReader::new(file);
        let mut archive = match hivepack::sevenz::Archive::open_with(reader, &options) {
            Ok(a) => a,
            Err(e) => {
                println!("{name}: open {}", e.name());
                continue;
            }
        };
        let n = archive.len();
        let mut extract_ok = 0;
        let mut errors = Vec::new();
        let mut datas = Vec::new();
        for i in 0..n {
            match archive.extract(i) {
                Ok(data) => {
                    extract_ok += 1;
                    datas.push(Some(data));
                }
                Err(e) => {
                    errors.push(format!("x{i}:{}", e.name()));
                    datas.push(None);
                }
            }
        }
        let mut stream_ok = 0;
        let mut files = archive.files();
        let mut i = 0;
        loop {
            match files.next() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(e) => {
                    errors.push(format!("n{i}:{}", e.name()));
                    break;
                }
            }
            let mut data = Vec::new();
            match files.read_to_end(&mut data) {
                Ok(_) => {
                    if datas[i].as_ref().is_some_and(|d| *d != data) {
                        errors.push(format!("s{i}:differs"));
                    } else {
                        stream_ok += 1;
                    }
                }
                Err(e) => errors.push(format!("s{i}:{e}")),
            }
            i += 1;
        }
        println!(
            "{name}: {n} files, {} folders, extract {extract_ok}, stream {stream_ok} {}",
            archive.folders(),
            errors.iter().take(4).cloned().collect::<Vec<_>>().join(" ")
        );
    }
}
