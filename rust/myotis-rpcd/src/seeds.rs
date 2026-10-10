//! Operator-supplied EL seed pins (`--boot-enodes`).
//!
//! The engine dials a network's pinned `enode://` URLs first, before the peer
//! cache and discovery (Gnosis and mainnet ship none). A host can supply its
//! own through `myotis_set_boot_enodes` (#465): servers it knows to be up and
//! serving snap, so a cold start does not wait for discovery to surface one.
//! This module turns the flag into that push.
//!
//! The flag takes a comma-separated list, or `@FILE` with one URL per line
//! (blank lines and `#` comments skipped, commas also accepted). The engine is
//! the judge of each URL: it applies the list or refuses it AS A WHOLE, naming
//! every bad entry. The checks here only catch what can be caught before an
//! engine handle exists (an empty list, something that is not an `enode://`
//! URL at all, more entries than the engine accepts).

use std::ffi::CString;

/// The engine's cap on a host's seed list (`MAX_HOST_ENODES` in
/// myotis-engine's host.rs); a longer push is refused there anyway.
const MAX_SEEDS: usize = 64;

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
/// newlines; `#` starts a comment that runs to the end of the line.
pub fn parse(text: &str) -> Result<Vec<String>, String> {
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
    if urls.len() > MAX_SEEDS {
        return Err(format!(
            "{} entries; the engine accepts at most {MAX_SEEDS}",
            urls.len()
        ));
    }
    if let Some(bad) = urls.iter().find(|u| !u.starts_with("enode://")) {
        return Err(format!("'{bad}' is not an enode:// URL"));
    }
    Ok(urls)
}

/// Hand the list to a created (not yet started) handle: the engine stashes it
/// and dials it first on start. `false` when the engine refused it; the engine
/// logs one WARN naming every bad entry.
pub fn push(handle: i64, urls: &[String]) -> bool {
    let Ok(json) = serde_json::to_string(urls) else {
        return false;
    };
    let Ok(c) = CString::new(json) else {
        return false;
    };
    // SAFETY: a valid NUL-terminated C string that outlives the call; the
    // engine copies it before returning.
    unsafe { myotis_engine::capi::myotis_set_boot_enodes(handle, c.as_ptr()) }
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
        assert!(parse(&format!("{},192.0.2.1:30303", url(1)))
            .unwrap_err()
            .contains("192.0.2.1:30303"));
        let too_many: Vec<String> = (1..=65).map(url).collect();
        assert!(parse(&too_many.join(",")).is_err());
        assert_eq!(parse(&too_many[..64].join(",")).unwrap().len(), 64);
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
        assert!(push(handle, &[url(30303), url(30304)]));
        // A duplicate address passes the local checks; the engine refuses it.
        assert!(!push(handle, &[url(30303), url(30303)]));
        myotis_engine::ffi::stop_handle(handle);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
