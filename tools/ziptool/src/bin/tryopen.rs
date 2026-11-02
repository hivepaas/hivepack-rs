//! tryopen, which opens archives and says how it went: port of libzip's
//! `regress/programs/tryopen.c`.

use std::process::ExitCode;

use hivepack::zip::{Error, Flags, OpenFlags, SystemType};
use ziptool::{Getopt, zip_close, zip_open};

const TRYOPEN_USAGE: &str = "usage: {} [-cent] file\n\n\t-c\tcheck consistency\n\t-e\texclusively open archive\n\t-n\tcreate new file\n\t-s\tprint error string\n\t-t\ttruncate file to size 0";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let mut flags = OpenFlags(0);
    let mut error_strings = false;

    let mut getopt = Getopt::new(&argv);
    while let Some(option) = getopt.next("censt") {
        match option {
            Ok(('c', _)) => flags = flags | OpenFlags::CHECKCONS,
            Ok(('e', _)) => flags = flags | OpenFlags::EXCL,
            Ok(('n', _)) => flags = flags | OpenFlags::CREATE,
            Ok(('s', _)) => error_strings = true,
            Ok(('t', _)) => flags = flags | OpenFlags::TRUNCATE,
            _ => {
                eprintln!("{}", TRYOPEN_USAGE.replacen("{}", &argv[0], 1));
                return ExitCode::from(1);
            }
        }
    }

    let mut error_count = 0;
    for fname in &argv[getopt.optind..] {
        match zip_open(fname, flags, 0, 0) {
            Ok(mut z) => {
                println!(
                    "opening '{fname}' succeeded, {} entries",
                    z.get_num_entries(Flags::NONE)
                );
                let _ = zip_close(&mut z, fname);
                continue;
            }
            Err(error) => {
                print!("opening '{fname}' returned error ");
                if error_strings {
                    print!("{error}");
                } else {
                    // zip_error_init_with_code: errno, for the system types.
                    print!("{}", error.code().number());
                    if matches!(error.system_type(), SystemType::Sys | SystemType::Libzip) {
                        print!("/{}", system(&error));
                    }
                }
                println!();
                error_count += 1;
            }
        }
    }

    if error_count > 0 {
        eprintln!("{error_count} errors");
    }
    ExitCode::from(u8::from(error_count > 0))
}

/// The system error tryopen prints: `zip_open` puts it in `errno`, and
/// `zip_error_init_with_code` takes it from there.
fn system(error: &Error) -> i32 {
    error.system()
}
