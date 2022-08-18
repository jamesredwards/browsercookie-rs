use byteorder::{LittleEndian, ReadBytesExt};
use cookie::{Cookie, CookieJar};
#[allow(unused_imports)]
use dirs::home_dir;
use ini::Ini;
use lz4::block::decompress;
use memmap::MmapOptions;
use regex::Regex;
use serde_json::Value;
use sqlite;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use tempdir;

use crate::errors::BrowsercookieError;

#[allow(non_snake_case)]
#[derive(Deserialize, Debug)]
struct MozCookie {
    host: String,
    name: String,
    originAttributes: Value,
    path: String,
    value: String,

    #[serde(default)]
    secure: bool,

    #[serde(default)]
    httponly: bool,
}

#[cfg(test)]
fn get_master_profile_path() -> PathBuf {
    // Only used for tests, should do this a better way by mocking
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/resources/profiles.ini");
    path
}

#[cfg(not(test))]
fn get_master_profile_path() -> PathBuf {
    let mut path = home_dir().expect("Unable to find home directory");
    if cfg!(target_os = "macos") {
        path.push("Library/Application Support/Firefox/profiles.ini");
    } else if cfg!(target_os = "linux") {
        path.push(".mozilla/firefox/profiles.ini")
    }
    path
}

fn get_default_profile_path(master_profile: &Path) -> Result<PathBuf, Box<Error>> {
    let profiles_conf: Ini;
    let mut default_profile_path = PathBuf::from(master_profile);
    default_profile_path.pop();

    match Ini::load_from_file(&master_profile) {
        Err(_) => {
            return Err(Box::new(BrowsercookieError::InvalidProfile(String::from(
                "Unable to parse firefox ini profile",
            ))))
        }
        Ok(p) => profiles_conf = p,
    }

    for (sec, _) in &profiles_conf {
        if let Some(s) = sec {
            // for firefox versions >= 72.0.1
            if s.to_owned().starts_with("Install") {
                let section = profiles_conf
                    .section(sec.clone())
                    .ok_or("Invalid profile section")?;
                match section.get("Default") {
                    Some(path) => {
                        default_profile_path.push(path);
                        break;
                    }
                    None => continue,
                }
            } else {
                let section = profiles_conf
                    .section(sec.clone())
                    .ok_or("Invalid profile section")?;
                match section.get("Default").and(section.get("Path")) {
                    Some(path) => {
                        default_profile_path.push(path);
                        // eprintln!("Default profile path: {}", path.as_str());
                        break;
                    }
                    None => continue,
                }
            }
        }
    }
    Ok(default_profile_path)
}

fn load_from_recovery(
    recovery_path: &Path,
    bcj: &mut Box<CookieJar>,
    domain_regex: &Regex,
) -> Result<bool, Box<Error>> {
    let recovery_file = File::open(recovery_path)?;
    let recovery_mmap = unsafe { MmapOptions::new().map(&recovery_file)? };

    if recovery_mmap.len() <= 8
        || recovery_mmap.get(0..8).ok_or("Invalid recovery")? != "mozLz40\0".as_bytes()
    {
        return Err(Box::new(BrowsercookieError::InvalidRecovery(String::from(
            "Firefox invalid recovery archive",
        ))));
    }

    let mut rdr = Cursor::new(recovery_mmap.get(8..12).ok_or("Invalid recovery")?);
    let uncompressed_size = rdr.read_i32::<LittleEndian>().ok();

    let recovery_json_bytes = decompress(
        recovery_mmap.get(12..).ok_or("Invalid recovery")?,
        uncompressed_size,
    )?;

    let recovery_json: Value = serde_json::from_slice(&recovery_json_bytes)?;
    for c in recovery_json["cookies"]
        .as_array()
        .ok_or("Invalid recovery")?
    {
        if let Ok(cookie) =
            serde_json::from_value(c.clone()) as Result<MozCookie, serde_json::error::Error>
        {
            // println!("Loading for {}: {}={}", cookie.host, cookie.name, cookie.value);
            if domain_regex.is_match(&cookie.host) {
                bcj.add(
                    Cookie::build(cookie.name, cookie.value)
                        .domain(cookie.host)
                        .path(cookie.path)
                        .secure(cookie.secure)
                        .http_only(cookie.httponly)
                        .finish(),
                );
            }
        }
    }
    Ok(true)
}

fn load_from_sqldb(
    profile_path: &Path,
    bcj: &mut Box<CookieJar>,
    domain_regex: &Regex,
) -> Result<(), Box<Error>> {
    let sql_path = profile_path.join(Path::new("cookies.sqlite"));
    let tmp_dir = tempdir::TempDir::new("ff_cookies")?;
    let tmp_cookies = tmp_dir.path().join("cookies.sqlite");
    fs::copy(sql_path, &tmp_cookies)?;

    let conn = sqlite::open(&tmp_cookies)?;
    let mut cursor = conn.prepare("select host, path, isSecure, expiry, name, value, isHttpOnly from moz_cookies where host like ?")
        .unwrap()
        .into_cursor()
        .bind(&[sqlite::Value::String(domain_regex.to_string())])?;

    while let Some(Ok(row)) = cursor.next() {
        let host: String = row.get::<String, _>(0);
        let path: String = row.get::<String, _>(1);
        let isSecure: bool = match row.get::<i64, _>(2) {
            1 => true,
            _ => false,
        };
        let expiry: i64 = row.get::<i64, _>(3);
        let name: String = row.get::<String, _>(4);
        let value: String = row.get::<String, _>(5);
        let isHttpOnly: bool = match row.get::<i64, _>(6) {
            1 => true,
            _ => false,
        };
        let cookie = Cookie::build(name, value)
            .domain(host)
            .path(path)
            .secure(isSecure)
            .http_only(isHttpOnly)
            .finish();

        bcj.add(cookie);
    }

    fs::remove_file(tmp_cookies)?;
    tmp_dir.close()?;
    Ok(())
}

pub(crate) fn load(bcj: &mut Box<CookieJar>, domain_regex: &Regex) -> Result<(), Box<Error>> {
    // Returns a CookieJar on heap if following steps go right
    //
    // 1. Get default profile path for firefox from master ini profiles config.
    // 2. Load cookies from recovery json (sessionstore-backups/recovery.jsonlz4)
    //    of the default profile.
    let master_profile_path = get_master_profile_path();
    if !master_profile_path.exists() {
        return Err(Box::new(BrowsercookieError::ProfileMissing(String::from(
            "Firefox profile path doesn't exist",
        ))));
    }

    let profile_path = get_default_profile_path(&master_profile_path)?;

    let mut recovery_path = profile_path.clone();
    recovery_path.push("sessionstore-backups/recovery.jsonlz4");

    if !recovery_path.exists() {
        return Err(Box::new(BrowsercookieError::InvalidCookieStore(
            String::from("Firefox invalid cookie store"),
        )));
    }

    load_from_recovery(&recovery_path, bcj, domain_regex)?;
    load_from_sqldb(&profile_path, bcj, domain_regex)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_load() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests/resources/recovery.jsonlz4");
        let mut bcj = Box::new(CookieJar::new());

        let domain_re = Regex::new(".*").unwrap();
        load_from_recovery(&path, &mut bcj, &domain_re)
            .expect("Failed to load from firefox recovery json");

        let c = bcj
            .get("taarId")
            .expect("Failed to get cookie from firefox recovery");

        assert_eq!(c.value(), "value");
        assert_eq!(c.path(), Some("/"));
        assert_eq!(c.secure(), Some(true));
        assert_eq!(c.http_only(), Some(true));
        assert_eq!(c.domain(), Some("addons.mozilla.org"));
    }

    #[test]
    fn test_master_profile() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests/resources/profiles.ini");

        let default_profile_path =
            get_default_profile_path(&path).expect("Failed to parse master firefox profile");

        assert!(default_profile_path.ends_with(PathBuf::from("Profiles/1qbuu7ux.default")));
    }
}
