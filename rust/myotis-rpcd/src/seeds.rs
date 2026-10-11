//! Operator-supplied EL seed pins (`--boot-enodes`).
//!
//! The engine dials a network's pinned `enode://` URLs as its EL pool starts
//! (Gnosis and mainnet ship none). A host can add its own through
//! `myotis_set_boot_enodes` (#465): servers it knows to be up and serving
//! snap, so a cold start does not wait for discovery to surface one.
//! This module turns the flag into that push.
//!
//! The flag takes a comma-separated list, or `@FILE` with one URL per line
//! (blank lines and `#` comments skipped, commas also accepted, a leading
//! UTF-8 BOM ignored). The engine is the judge of each URL: it applies the
//! list or refuses it AS A WHOLE, naming every bad entry in one WARN. The only
//! check here is the one that needs no engine: an empty list.

use std::ffi::CString;

/// `--boot-enodes` → the list of URLs, reading `@FILE` when given one.
pub fn load(arg: &str) -> Result<Vec<String>, String> {
    match arg.strip_prefix('@') {
        Some(path) => {
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("--boot-enodes {path}: {e}"))?;
            parse(&text).map_err(|e| format!("--boot-enodes {path}: {e}"))
        }
        None => parse(arg).map_err(|e| format!("--boot-enodes: {e}")),
    }
}

/// Pure: a list's text → its URLs. Entries are separated by commas or
/// newlines; `#` starts a comment that runs to the end of the line. A leading
/// UTF-8 BOM (some editors write one) is dropped: it is not White_Space, so
/// `trim` would leave it glued, invisibly, to the first URL.
pub fn parse(text: &str) -> Result<Vec<String>, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let urls: Vec<String> = text
        .lines()
        .map(|line| line.split('#').next().unwrap_or(""))
        .flat_map(|line| line.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if urls.is_empty() {
        return Err("no enode:// URLs given".into());
    }
    Ok(urls)
}

/// Hand the list to a created (not yet started) handle: the engine stashes it
/// and dials it once the handle starts. `Err` names why it was not applied:
/// a local failure before the engine was asked, or the engine's refusal,
/// quoting its WARN. Call with the engine's log ring drained, so the lines
/// drained here are the push's own.
pub fn push(handle: i64, urls: &[String]) -> Result<(), String> {
    let json = serde_json::to_string(urls).map_err(|e| format!("--boot-enodes: {e}"))?;
    // serde_json escapes control characters (NUL → \u0000), so this cannot
    // fail on a parsed list; an entry with a NUL reaches the engine, which
    // refuses it by name.
    let c = CString::new(json).map_err(|e| format!("--boot-enodes: {e}"))?;
    // SAFETY: a valid NUL-terminated C string that outlives the call; the
    // engine copies it before returning.
    if unsafe { myotis_engine::capi::myotis_set_boot_enodes(handle, c.as_ptr()) } {
        Ok(())
    } else {
        let drained = myotis_engine::ffi::drain_logs(1024);
        // Anything else drained with the WARN is still the engine's to say.
        for line in drained.lines().filter(|l| !l.contains(REFUSED)) {
            eprintln!("{line}");
        }
        Err(refusal(&drained))
    }
}

/// The engine's WARN message for a refused push (`host::set_boot_enodes_json`).
const REFUSED: &str = "boot enodes refused";

/// Pure: the engine's refusal → the daemon's error, quoting the engine's
/// WARN line(s) from the drained ring. A filter that hides WARN (`RUST_LOG`)
/// leaves none to quote; say so rather than point at nothing.
fn refusal(drained: &str) -> String {
    let warns: Vec<&str> = drained
        .lines()
        .filter(|l| l.contains(REFUSED))
        .map(str::trim)
        .collect();
    if warns.is_empty() {
        "--boot-enodes refused by the engine; its reason was not logged \
         (does RUST_LOG filter out WARN?)"
            .into()
    } else {
        format!("--boot-enodes refused by the engine: {}", warns.join(" | "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(port: u16) -> String {
        format!("enode://{}@192.0.2.1:{port}", "ab".repeat(64))
    }

    #[test]
    fn a_comma_list_is_split_and_trimmed() {
        let got = parse(&format!("{}, {} ,", url(1), url(2))).unwrap();
        assert_eq!(got, vec![url(1), url(2)]);
    }

    #[test]
    fn a_file_takes_lines_comments_and_commas() {
        let text = format!(
            "# good snap peers\n{}  # geth\n\n{},{}\n   \n",
            url(1),
            url(2),
            url(3)
        );
        assert_eq!(parse(&text).unwrap(), vec![url(1), url(2), url(3)]);
    }

    #[test]
    fn refuses_what_cannot_be_a_seed_list() {
        assert!(parse("").is_err());
        assert!(parse("# only a comment\n , \n").is_err());
        assert!(parse("\u{feff}\n").is_err());
    }

    #[test]
    fn a_leading_bom_is_dropped() {
        let text = format!("\u{feff}{}\n{}\n", url(1), url(2));
        assert_eq!(parse(&text).unwrap(), vec![url(1), url(2)]);
    }

    #[test]
    fn every_entry_goes_to_the_engine_unjudged() {
        // The engine names every bad entry at once; a local pre-check would
        // stop at the first. Its cap is its own, too.
        let got = parse(&format!("{},192.0.2.1:30303,nope", url(1))).unwrap();
        assert_eq!(got.len(), 3);
        let many: Vec<String> = (1..=65).map(url).collect();
        assert_eq!(parse(&many.join(",")).unwrap().len(), 65);
    }

    #[test]
    fn a_refusal_quotes_the_engine_warn_or_says_there_is_none() {
        let ring = "INFO myotis_engine::host: created\n\
                    WARN myotis_engine::host: boot enodes refused; nothing applied reason=entry 1: x";
        let msg = refusal(ring);
        assert!(msg.contains("entry 1: x"), "{msg}");
        assert!(!msg.contains("created"), "{msg}");
        assert!(refusal("").contains("RUST_LOG"));
    }

    #[test]
    fn load_reads_a_file_and_names_it_on_error() {
        let dir = std::env::temp_dir().join(format!("myotis-rpcd-seeds-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("enodes.txt");
        std::fs::write(&path, format!("{}\n{}\n", url(1), url(2))).unwrap();
        let arg = format!("@{}", path.display());
        assert_eq!(load(&arg).unwrap(), vec![url(1), url(2)]);
        let missing = format!("@{}", dir.join("nope.txt").display());
        assert!(load(&missing).unwrap_err().contains("nope.txt"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_engine_takes_a_good_list_and_refuses_a_bad_one() {
        let dir =
            std::env::temp_dir().join(format!("myotis-rpcd-seeds-engine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        myotis_engine::ffi::engine_init();
        let handle =
            myotis_engine::ffi::create_handle("gnosis".into(), dir.to_string_lossy().into_owned());
        assert!(handle > 0, "create failed: {handle}");
        let _ = myotis_engine::ffi::drain_logs(1024);
        assert_eq!(push(handle, &[url(30303), url(30304)]), Ok(()));
        // Bad entries pass the local parse; the engine refuses the list and
        // names every one, which the error quotes.
        let err = push(handle, &[url(30303), url(30303), "nope".into()]).unwrap_err();
        assert!(err.contains("entry 1") && err.contains("entry 2"), "{err}");
        // A NUL byte is JSON-escaped on the way, so the engine judges it too.
        let err = push(handle, &[format!("{}\0", url(30303))]).unwrap_err();
        assert!(err.contains("entry 0"), "{err}");
        myotis_engine::ffi::stop_handle(handle);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
