//! Command-line subcommands. `harborgate` with no arguments serves; `restore <file>`
//! and `rotate-key` are offline commands run with the app stopped. See
//! `specs/security.md` (Backup and restore, Key rotation).

use std::path::PathBuf;

/// What the binary was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Run the web server and worker.
    Serve,
    /// Replace the database from a verified backup file.
    Restore(PathBuf),
    /// Re-encrypt stored credentials under a new key (#41).
    RotateKey,
}

/// The text printed when the arguments are not understood.
pub const USAGE: &str = "usage:
  harborgate                  run the server
  harborgate restore <file>   replace the database from a backup (stop the app first)
  harborgate rotate-key       re-encrypt stored credentials under a new key (stop the app first)";

/// Reads the arguments after the program name. No arguments means `Serve`. Anything
/// that is not a known command, or a known command with the wrong arguments, returns
/// the usage text.
pub fn parse(args: &[String]) -> Result<Command, String> {
    let Some((command, rest)) = args.split_first() else {
        return Ok(Command::Serve);
    };
    match (command.as_str(), rest) {
        ("restore", [file]) => Ok(Command::Restore(PathBuf::from(file))),
        ("restore", _) => Err(format!("restore needs exactly one backup file.\n{USAGE}")),
        ("rotate-key", []) => Ok(Command::RotateKey),
        _ => Err(USAGE.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn no_args_is_serve() {
        assert_eq!(parse(&[]), Ok(Command::Serve));
    }

    #[test]
    fn restore_takes_one_file() {
        assert_eq!(
            parse(&args(&["restore", "/data/backups/x.hgbk"])),
            Ok(Command::Restore(PathBuf::from("/data/backups/x.hgbk")))
        );
    }

    #[test]
    fn restore_needs_a_file() {
        let missing = parse(&args(&["restore"]));
        assert!(matches!(&missing, Err(text) if text.contains("restore needs")));
        let extra = parse(&args(&["restore", "a", "b"]));
        assert!(extra.is_err(), "two files were accepted");
    }

    #[test]
    fn rotate_key_is_recognised() {
        assert_eq!(parse(&args(&["rotate-key"])), Ok(Command::RotateKey));
    }

    #[test]
    fn unknown_command_prints_usage() {
        assert_eq!(parse(&args(&["frobnicate"])), Err(USAGE.to_owned()));
    }
}
