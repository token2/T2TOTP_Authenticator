//! Tiny dependency-free settings persistence for the GUI.
//!
//! Saves a handful of UI preferences (the Auto-OTP hotkey binding, whether it
//! was active, append-Enter, and the chosen transport) to a flat `key=value`
//! file in the OS config directory. Hand-rolled rather than pulling serde+dirs,
//! both to keep the dependency tree small and to avoid the edition2024 crates
//! those drag in under the pinned toolchain.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// The persisted settings. All fields optional-by-default so a partial or absent
/// file still loads.
#[derive(Clone, Default)]
pub struct Persisted {
    pub transport: Option<String>, // "auto" | "hid" | "nfc"
    /// Keep the OTP-PIN read/write window open for the whole session by
    /// re-verifying with the cached PIN before the device's ~5-minute timeout.
    pub keep_unlocked: bool,
    #[cfg(feature = "hotkey")]
    pub hotkey_enabled: bool,
    #[cfg(feature = "hotkey")]
    pub hotkey_ctrl: bool,
    #[cfg(feature = "hotkey")]
    pub hotkey_shift: bool,
    #[cfg(feature = "hotkey")]
    pub hotkey_alt: bool,
    #[cfg(feature = "hotkey")]
    pub hotkey_meta: bool,
    #[cfg(feature = "hotkey")]
    pub hotkey_key: Option<String>, // a stable key name, see hotkey::key_name
    #[cfg(feature = "hotkey")]
    pub hotkey_append_enter: bool,
}

/// Resolve `<config-dir>/t2totp/settings.conf` for the current OS.
fn config_path() -> Option<PathBuf> {
    let dir = config_dir()?;
    Some(dir.join("t2totp").join("settings.conf"))
}

/// The `t2totp` config directory (`<config-dir>/t2totp`), if resolvable.
pub fn app_config_dir() -> Option<PathBuf> {
    config_dir().map(|d| d.join("t2totp"))
}

#[cfg(target_os = "windows")]
fn config_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(PathBuf::from)
}

#[cfg(target_os = "macos")]
fn config_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library").join("Application Support"))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn config_dir() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME") {
        if !x.is_empty() {
            return Some(PathBuf::from(x));
        }
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config"))
}

impl Persisted {
    /// Load settings, returning defaults if the file is missing or unreadable.
    pub fn load() -> Self {
        let mut out = Persisted::default();
        let Some(path) = config_path() else {
            return out;
        };
        let Ok(text) = fs::read_to_string(&path) else {
            return out;
        };
        let map: HashMap<&str, &str> = text
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                if l.is_empty() || l.starts_with('#') {
                    return None;
                }
                l.split_once('=').map(|(k, v)| (k.trim(), v.trim()))
            })
            .collect();

        let _ = &map;
        #[cfg(feature = "hotkey")]
        let b = |k: &str| map.get(k).map(|v| *v == "true").unwrap_or(false);

        if let Some(t) = map.get("transport") {
            out.transport = Some((*t).to_string());
        }
        out.keep_unlocked = map
            .get("keep_unlocked")
            .map(|v| *v == "true")
            .unwrap_or(false);
        #[cfg(feature = "hotkey")]
        {
            out.hotkey_enabled = b("hotkey_enabled");
            out.hotkey_ctrl = b("hotkey_ctrl");
            out.hotkey_shift = b("hotkey_shift");
            out.hotkey_alt = b("hotkey_alt");
            out.hotkey_meta = b("hotkey_meta");
            out.hotkey_key = map.get("hotkey_key").map(|v| (*v).to_string());
            // default append_enter to true when the key is absent
            out.hotkey_append_enter = map
                .get("hotkey_append_enter")
                .map(|v| *v == "true")
                .unwrap_or(true);
        }
        out
    }

    /// Write settings to disk (best-effort; errors are returned for logging).
    pub fn save(&self) -> Result<(), String> {
        let path = config_path().ok_or("no config directory available")?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut s = String::new();
        s.push_str("# T2 TOTP Authenticator settings\n");
        if let Some(t) = &self.transport {
            s.push_str(&format!("transport = {t}\n"));
        }
        s.push_str(&format!("keep_unlocked = {}\n", self.keep_unlocked));
        #[cfg(feature = "hotkey")]
        {
            s.push_str(&format!("hotkey_enabled = {}\n", self.hotkey_enabled));
            s.push_str(&format!("hotkey_ctrl = {}\n", self.hotkey_ctrl));
            s.push_str(&format!("hotkey_shift = {}\n", self.hotkey_shift));
            s.push_str(&format!("hotkey_alt = {}\n", self.hotkey_alt));
            s.push_str(&format!("hotkey_meta = {}\n", self.hotkey_meta));
            if let Some(k) = &self.hotkey_key {
                s.push_str(&format!("hotkey_key = {k}\n"));
            }
            s.push_str(&format!(
                "hotkey_append_enter = {}\n",
                self.hotkey_append_enter
            ));
        }
        fs::write(&path, s).map_err(|e| e.to_string())
    }
}
