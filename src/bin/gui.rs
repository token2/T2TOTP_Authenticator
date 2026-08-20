//! T2 TOTP Authenticator — native desktop GUI (egui/eframe).
//!
//! Mirrors the `t2totp` CLI: pick a transport, list profiles with live TOTP
//! codes and countdown rings, add, copy (with auto-clear), delete, and erase —
//! all against [`t2totp::transport::OtpSession`]. The NFC/PC-SC path identifies
//! a Token2 key by reading its serial, same as the CLI.
//!
//! Device I/O is blocking and runs on a worker thread; the UI thread only ever
//! touches the results. Brand palette: Token2 red #F20043 / gold #F0A830.

#![forbid(unsafe_code)]
// On Windows, hide the console window for release builds (debug keeps it so
// `--debug` traces and panics are visible). Without this a black console window
// lingers behind the GUI.
#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]
// egui builds UI by side-effecting closures; the result-must-use lint is noise.
#![allow(clippy::let_and_return)]

use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eframe::egui::{self, Color32, FontId, RichText, Stroke};
use t2totp::entry::{Algorithm, OtpType, WriteEntry};
use t2totp::transport::{Interface, OtpSession};
use t2totp::AUTO_TAG;
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "hotkey")]
#[path = "../gui/hotkey.rs"]
mod hotkey;

#[cfg(feature = "qr")]
#[path = "../gui/qr.rs"]
mod qr;

#[path = "../gui/config.rs"]
mod config;

// ---------------------------------------------------------------------------
// Brand palette
// ---------------------------------------------------------------------------

struct Palette {
    bg: Color32,
    card: Color32,
    line: Color32,
    line_soft: Color32,
    txt: Color32,
    txt3: Color32,
    accent: Color32, // brand red
    accent_deep: Color32,
    gold: Color32,
    warn: Color32,
    ok: Color32,
    err: Color32,
}

impl Palette {
    fn t2() -> Self {
        Palette {
            bg: Color32::from_rgb(0xF6, 0xF7, 0xF9),
            card: Color32::from_rgb(0xFF, 0xFF, 0xFF),
            line: Color32::from_rgb(0xE2, 0xE5, 0xEC),
            line_soft: Color32::from_rgb(0xEE, 0xF0, 0xF4),
            txt: Color32::from_rgb(0x1B, 0x2A, 0x4A),    // navy
            txt3: Color32::from_rgb(0x8A, 0x93, 0xA6),
            accent: Color32::from_rgb(0xF2, 0x00, 0x43), // #F20043
            accent_deep: Color32::from_rgb(0xC1, 0x00, 0x38),
            gold: Color32::from_rgb(0xF0, 0xA8, 0x30),   // #F0A830
            warn: Color32::from_rgb(0xE6, 0x7A, 0x00),
            ok: Color32::from_rgb(0x1E, 0x8E, 0x3E),
            err: Color32::from_rgb(0xC1, 0x00, 0x38),
        }
    }
}

fn mono(size: f32) -> FontId {
    FontId::monospace(size)
}
fn prop(size: f32) -> FontId {
    FontId::proportional(size)
}

// ---------------------------------------------------------------------------
// Background jobs: blocking device I/O off the UI thread
// ---------------------------------------------------------------------------

/// A row shown in the list — the stored entry plus its live code (when the
/// device returned one: TOTP without a touch requirement).
#[derive(Clone)]
struct Row {
    app_name: String,
    account_name: String,
    otp_type: &'static str,
    algo: &'static str,
    button_required: bool,
    period: u16,
    code: Option<String>,
}

impl Row {
    fn label(&self) -> String {
        if self.app_name.is_empty() {
            self.account_name.clone()
        } else {
            format!("{}:{}", self.app_name, self.account_name)
        }
    }
    fn is_auto(&self) -> bool {
        self.app_name.contains(AUTO_TAG)
    }
}

/// Outcome of a finished job, sent from worker back to UI.
enum JobResult {
    Loaded {
        rows: Vec<Row>,
        serial: Option<String>,
        transport: &'static str,
    },
    /// A quiet background refresh succeeded (codes/rows updated in place).
    Refreshed {
        rows: Vec<Row>,
        serial: Option<String>,
        transport: &'static str,
    },
    /// A quiet background refresh found the key gone; clear the list.
    Disconnected,
    /// Load/refresh hit a PIN-protected key with no (or wrong) PIN supplied.
    /// The UI opens the PIN prompt in response. `wrong` distinguishes a bad
    /// PIN retry from the first prompt.
    PinRequired { wrong: bool },
    /// PIN status read (whether set + retries remaining).
    PinStatus { set: bool, retries: u8, max: u8 },
    /// A keep-unlocked keep-alive re-verify succeeded (no UI change needed).
    PinKeptAlive,
    TouchCode {
        key: (String, String),
        code: String,
    },
    Ok(String),
    Err(String),
}

/// A request to read a single value for `transport`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Transport {
    Auto,
    Hid,
    Nfc,
}

impl Transport {
    fn iface(self) -> Interface {
        match self {
            Transport::Auto => Interface::Auto,
            Transport::Hid => Interface::Hid,
            Transport::Nfc => Interface::Nfc,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Transport::Auto => "Auto",
            Transport::Hid => "USB-HID",
            Transport::Nfc => "NFC / PC-SC",
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn open(t: Transport) -> Result<OtpSession, String> {
    OtpSession::open(t.iface(), false).map_err(|e| e.to_string())
}

fn type_str(t: OtpType) -> &'static str {
    t.as_str()
}
fn algo_str(a: Algorithm) -> &'static str {
    a.as_str()
}

/// Load every entry + serial. Runs on the worker thread.
fn job_load(t: Transport, pin: Option<Zeroizing<String>>) -> JobResult {
    let mut session = match open(t) {
        Ok(s) => s,
        Err(e) => return JobResult::Err(e),
    };
    let is_pcsc = session.is_pcsc();
    let serial = session
        .cached_serial()
        .map(|s| t2totp::proto::hex(s))
        .or_else(|| session.read_serial().ok().map(|s| t2totp::proto::hex(&s)));
    match session.enumerate_pinned(now_secs(), pin.as_deref().map(|z| z.as_str())) {
        Ok(entries) => {
            let rows = entries
                .into_iter()
                .map(|e| Row {
                    app_name: e.app_name,
                    account_name: e.account_name,
                    otp_type: type_str(e.otp_type),
                    algo: algo_str(e.algorithm),
                    button_required: e.button_required,
                    period: e.timestep,
                    code: e.code,
                })
                .collect();
            JobResult::Loaded {
                rows,
                serial,
                transport: if is_pcsc { "NFC / PC-SC" } else { "USB-HID" },
            }
        }
        Err(t2totp::transport::Error::PinRequired) => JobResult::PinRequired { wrong: false },
        Err(t2totp::transport::Error::Applet(t2totp::proto::OtpError::PinNotVerified)) => {
            JobResult::PinRequired { wrong: true }
        }
        Err(e) => JobResult::Err(e.to_string()),
    }
}

/// Quiet background refresh: re-read entries to update codes and detect unplug.
/// Returns `Disconnected` when the key is no longer reachable, so the UI can
/// clear stale codes instead of showing codes for an absent device.
fn job_refresh(t: Transport, pin: Option<Zeroizing<String>>) -> JobResult {
    let mut session = match open(t) {
        Ok(s) => s,
        // Any failure to open the session is treated as "device gone" for the
        // purpose of a background refresh.
        Err(_) => return JobResult::Disconnected,
    };
    let is_pcsc = session.is_pcsc();
    let serial = session
        .cached_serial()
        .map(|s| t2totp::proto::hex(s))
        .or_else(|| session.read_serial().ok().map(|s| t2totp::proto::hex(&s)));
    match session.enumerate_pinned(now_secs(), pin.as_deref().map(|z| z.as_str())) {
        Ok(entries) => {
            let rows = entries
                .into_iter()
                .map(|e| Row {
                    app_name: e.app_name,
                    account_name: e.account_name,
                    otp_type: type_str(e.otp_type),
                    algo: algo_str(e.algorithm),
                    button_required: e.button_required,
                    period: e.timestep,
                    code: e.code,
                })
                .collect();
            JobResult::Refreshed {
                rows,
                serial,
                transport: if is_pcsc { "NFC / PC-SC" } else { "USB-HID" },
            }
        }
        // Enumerate failed mid-session — the key was likely removed.
        Err(_) => JobResult::Disconnected,
    }
}

fn job_pin_status(t: Transport) -> JobResult {
    let mut s = match open(t) {
        Ok(s) => s,
        Err(e) => return JobResult::Err(e),
    };
    match s.pin_status() {
        Ok(f) => JobResult::PinStatus {
            set: f.is_set(),
            retries: f.retries_left,
            max: f.max_retries,
        },
        Err(e) => JobResult::Err(e.to_string()),
    }
}

fn job_pin_set(t: Transport, pin: Zeroizing<String>) -> JobResult {
    let mut s = match open(t) {
        Ok(s) => s,
        Err(e) => return JobResult::Err(e),
    };
    match s.set_pin(&pin) {
        Ok(()) => JobResult::Ok("OTP PIN set.".into()),
        Err(e) => JobResult::Err(e.to_string()),
    }
}

fn job_pin_change(t: Transport, cur: Zeroizing<String>, new: Zeroizing<String>) -> JobResult {
    let mut s = match open(t) {
        Ok(s) => s,
        Err(e) => return JobResult::Err(e),
    };
    match s.change_pin(&cur, &new) {
        Ok(()) => JobResult::Ok("OTP PIN changed.".into()),
        Err(e) => JobResult::Err(e.to_string()),
    }
}

fn job_pin_remove(t: Transport, cur: Zeroizing<String>) -> JobResult {
    let mut s = match open(t) {
        Ok(s) => s,
        Err(e) => return JobResult::Err(e),
    };
    match s.remove_pin(&cur) {
        Ok(()) => JobResult::Ok("OTP PIN removed.".into()),
        Err(e) => JobResult::Err(e.to_string()),
    }
}

fn job_pin_lock(t: Transport) -> JobResult {
    let mut s = match open(t) {
        Ok(s) => s,
        Err(e) => return JobResult::Err(e),
    };
    match s.lock_pin() {
        Ok(()) => JobResult::Ok("OTP PIN window locked.".into()),
        Err(e) => JobResult::Err(e.to_string()),
    }
}

/// Keep-unlocked keep-alive: re-verify with the cached PIN to refresh the window
/// before the device's ~5-minute timeout. Quiet — reports Refreshed-style status
/// only via PinRequired on failure (so the UI can re-prompt).
fn job_pin_keepalive(t: Transport, pin: Zeroizing<String>) -> JobResult {
    let mut s = match open(t) {
        Ok(s) => s,
        Err(_) => return JobResult::Disconnected,
    };
    match s.reverify_pin(&pin) {
        Ok(()) => JobResult::PinKeptAlive,
        Err(t2totp::transport::Error::Applet(t2totp::proto::OtpError::PinNotVerified)) => {
            JobResult::PinRequired { wrong: true }
        }
        Err(t2totp::transport::Error::PinNotSet) => JobResult::PinKeptAlive,
        Err(e) => JobResult::Err(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

struct AddForm {
    open: bool,
    issuer: String,
    account: String,
    secret: String,
    sha256: bool,
    digits: u8,
    period: u16,
    auto: bool,
    touch: bool,
    /// Feedback from the last QR scan (feature `qr`).
    #[cfg(feature = "qr")]
    scan_status: Option<String>,
    #[cfg(feature = "qr")]
    scan_ok: bool,
}

impl Default for AddForm {
    fn default() -> Self {
        AddForm {
            open: false,
            issuer: String::new(),
            account: String::new(),
            secret: String::new(),
            sha256: false,
            digits: 6,
            period: 30,
            auto: false,
            touch: false,
            #[cfg(feature = "qr")]
            scan_status: None,
            #[cfg(feature = "qr")]
            scan_ok: false,
        }
    }
}

impl Drop for AddForm {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// State for the PIN prompt (verify to unlock reads) and the PIN-management
/// section in Settings.
#[derive(Default)]
struct PinUi {
    /// The unlock prompt is open (key is PIN-protected and not yet verified).
    prompt_open: bool,
    /// Text in the unlock prompt.
    entry: String,
    /// The last unlock attempt was rejected.
    wrong: bool,
    /// Whether the key currently has a PIN (from a status read); None = unknown.
    is_set: Option<bool>,
    retries: u8,
    max: u8,
    // --- management (Settings) fields ---
    mgmt_open: bool,
    set_new: String,
    set_confirm: String,
    change_cur: String,
    change_new: String,
    remove_cur: String,
}

impl Drop for PinUi {
    fn drop(&mut self) {
        self.entry.zeroize();
        self.set_new.zeroize();
        self.set_confirm.zeroize();
        self.change_cur.zeroize();
        self.change_new.zeroize();
        self.remove_cur.zeroize();
    }
}

struct App {
    p: Palette,
    /// The app icon as an egui texture for the header badge (loaded once).
    badge: Option<egui::TextureHandle>,
    transport: Transport,
    rows: Vec<Row>,
    serial: Option<String>,
    active_transport: Option<&'static str>,
    loaded: bool,
    /// True while a background (non-blocking) refresh is in flight, so the UI
    /// keeps showing current rows instead of the "Reading…" placeholder.
    refreshing: bool,
    /// Epoch seconds for the next automatic code refresh (period rollover).
    next_refresh_at: f64,
    busy: Option<String>,
    info: Option<String>,
    /// When the current info message should auto-clear (epoch seconds).
    info_expires_at: Option<f64>,
    error: Option<String>,
    add: AddForm,
    confirm_delete: Option<(String, String)>,
    confirm_erase: bool,
    confirm_exit: bool,
    /// Set when the user has confirmed exit, so the accidental-close guard lets
    /// the window actually close instead of hiding.
    really_quit: bool,
    settings_open: bool,
    touch_codes: std::collections::HashMap<(String, String), String>,
    clipboard_clear_at: Option<(String, f64)>,
    /// A verified OTP PIN, kept for the session so background refreshes can
    /// re-open the read window. Cleared when the key is unplugged or on exit.
    pin: Option<Zeroizing<String>>,
    pin_ui: PinUi,
    /// When true, keep the PIN window open all session by re-verifying with the
    /// cached PIN before the device's ~5-minute timeout. Persisted.
    keep_unlocked: bool,
    /// Epoch seconds for the next keep-unlocked re-verify (0 = none scheduled).
    next_pin_refresh_at: f64,
    // job plumbing
    tx: Sender<JobResult>,
    rx: Receiver<JobResult>,
    clipboard: Option<Arc<Mutex<arboard::Clipboard>>>,
    #[cfg(feature = "hotkey")]
    hotkey: Option<hotkey::HotkeyService>,
    /// The user's *intent* to have the hotkey on. Persisted and used to retry
    /// registration; kept separate from `hotkey` (the live registration) so a
    /// transient registration failure doesn't erase the saved preference.
    #[cfg(feature = "hotkey")]
    hotkey_wanted: bool,
    #[cfg(feature = "hotkey")]
    hotkey_binding: hotkey::HotkeyBinding,
    #[cfg(feature = "hotkey")]
    hotkey_append_enter: bool,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = mpsc::channel();
        let clipboard = arboard::Clipboard::new().ok().map(|c| Arc::new(Mutex::new(c)));
        let _ = &cc;

        // Load persisted preferences (transport + hotkey config).
        let saved = config::Persisted::load();
        let mut app = App {
            p: Palette::t2(),
            badge: None,
            transport: match saved.transport.as_deref() {
                Some("hid") => Transport::Hid,
                Some("auto") => Transport::Auto,
                // Default to NFC/PC-SC: the HID path is less stable on some
                // setups, and CCID works the same over a contact or NFC reader.
                _ => Transport::Nfc,
            },
            rows: Vec::new(),
            serial: None,
            active_transport: None,
            loaded: false,
            refreshing: false,
            next_refresh_at: 0.0,
            busy: None,
            info: None,
            info_expires_at: None,
            error: None,
            add: AddForm::default(),
            confirm_delete: None,
            confirm_erase: false,
            confirm_exit: false,
            really_quit: false,
            settings_open: false,
            touch_codes: std::collections::HashMap::new(),
            clipboard_clear_at: None,
            pin: None,
            pin_ui: PinUi::default(),
            keep_unlocked: saved.keep_unlocked,
            next_pin_refresh_at: 0.0,
            tx,
            rx,
            clipboard,
            #[cfg(feature = "hotkey")]
            hotkey: None,
            #[cfg(feature = "hotkey")]
            hotkey_wanted: saved.hotkey_enabled,
            #[cfg(feature = "hotkey")]
            hotkey_binding: {
                // Modifiers are fixed to Ctrl+Alt; only the letter is
                // configurable (and validated against the allowed set).
                let mut b = hotkey::HotkeyBinding::default();
                if let Some(k) = &saved.hotkey_key {
                    b.key = hotkey::key_from_name(k);
                }
                b
            },
            #[cfg(feature = "hotkey")]
            hotkey_append_enter: saved.hotkey_append_enter,
        };
        #[cfg(feature = "hotkey")]
        if saved.hotkey_enabled {
            app.enable_hotkey();
        }
        app.reload();
        app
    }

    /// Spawn a worker that produces one `JobResult`, then wakes the UI.
    fn spawn<F>(&mut self, busy: &str, ctx_repaint: Option<egui::Context>, f: F)
    where
        F: FnOnce() -> JobResult + Send + 'static,
    {
        self.busy = Some(busy.to_string());
        self.info = None;
        self.error = None;
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = f();
            let _ = tx.send(result);
            if let Some(ctx) = ctx_repaint {
                ctx.request_repaint();
            }
        });
    }

    fn reload(&mut self) {
        self.loaded = false;
        self.touch_codes.clear();
        let t = self.transport;
        let pin = self.pin.clone();
        self.spawn("Reading entries…", None, move || job_load(t, pin));
    }

    /// Schedule the next automatic refresh. We refresh shortly after the
    /// shortest TOTP period rolls over (so codes stay current), and at least
    /// every few seconds so an unplug is noticed promptly.
    fn schedule_next_refresh(&mut self) {
        let now = now_secs_f64();
        // Shortest period among visible rows (default 30s); 0 guards bad data.
        let shortest = self
            .rows
            .iter()
            .map(|r| r.period as u64)
            .filter(|p| *p > 0)
            .min()
            .unwrap_or(30);
        // Time until the next period boundary, plus a small margin so the key
        // has rolled the code over before we read.
        let secs_now = now as u64;
        let into_period = secs_now % shortest;
        let until_boundary = (shortest - into_period) as f64 + 0.4;
        // Also cap the interval so disconnects are caught within ~5s even for
        // long periods.
        let interval = until_boundary.min(5.0);
        self.next_refresh_at = now + interval;
    }

    /// Lock the PIN window now: drop the cached PIN, cancel the keep-alive, and
    /// close the window on the device. After this the entry list is hidden until
    /// the user unlocks again. Shared by the toolbar Lock button and the "Lock
    /// now" control in Manage OTP PIN.
    fn lock_now(&mut self, ctx: &egui::Context) {
        if let Some(mut pp) = self.pin.take() {
            pp.zeroize();
        }
        self.next_pin_refresh_at = 0.0;
        // Hide entries immediately; the reload after locking will re-fetch and
        // land back on the PIN prompt.
        self.rows.clear();
        let t = self.transport;
        self.spawn_pin("Locking…", ctx, move || job_pin_lock(t));
    }

    /// Schedule the next keep-unlocked re-verify (~4 min; the device window is
    /// ~5 min, so this refreshes comfortably before it closes).
    fn schedule_next_pin_refresh(&mut self) {
        if self.keep_unlocked && self.pin.is_some() {
            self.next_pin_refresh_at = now_secs_f64() + 240.0;
        } else {
            self.next_pin_refresh_at = 0.0;
        }
    }

    /// Fire a quiet keep-alive re-verify using the cached PIN.
    fn pin_keepalive(&mut self, ctx: &egui::Context) {
        let Some(pin) = self.pin.clone() else {
            self.next_pin_refresh_at = 0.0;
            return;
        };
        let t = self.transport;
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        // Reschedule immediately so we don't spam if the job is slow.
        self.next_pin_refresh_at = now_secs_f64() + 240.0;
        std::thread::spawn(move || {
            let result = job_pin_keepalive(t, pin);
            let _ = tx.send(result);
            ctx.request_repaint();
        });
    }

    /// Kick off a quiet background refresh (keeps showing current rows).
    fn refresh_codes(&mut self, ctx: &egui::Context) {
        if self.refreshing || !self.loaded {
            return;
        }
        self.refreshing = true;
        let t = self.transport;
        let pin = self.pin.clone();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = job_refresh(t, pin);
            let _ = tx.send(result);
            ctx.request_repaint();
        });
    }

    /// Persist current preferences to disk (best-effort).
    fn save_settings(&self) {
        #[allow(unused_mut)]
        let mut p = config::Persisted {
            transport: Some(
                match self.transport {
                    Transport::Auto => "auto",
                    Transport::Hid => "hid",
                    Transport::Nfc => "nfc",
                }
                .to_string(),
            ),
            keep_unlocked: self.keep_unlocked,
            ..Default::default()
        };
        #[cfg(feature = "hotkey")]
        {
            p.hotkey_enabled = self.hotkey_wanted;
            p.hotkey_ctrl = self.hotkey_binding.ctrl;
            p.hotkey_shift = self.hotkey_binding.shift;
            p.hotkey_alt = self.hotkey_binding.alt;
            p.hotkey_meta = self.hotkey_binding.meta;
            p.hotkey_key = Some(hotkey::key_name(self.hotkey_binding.key));
            p.hotkey_append_enter = self.hotkey_append_enter;
        }
        if let Err(e) = p.save() {
            eprintln!("[t2totp] could not save settings: {e}");
        }
    }

    /// Show a transient info message in the status bar; it auto-clears after a
    /// few seconds.
    fn set_info(&mut self, msg: String) {
        self.info = Some(msg);
        self.info_expires_at = Some(now_secs_f64() + 4.0);
        self.error = None;
    }

    #[cfg(feature = "hotkey")]
    fn poll_hotkey(&mut self) {
        let mut outcome = None;
        if let Some(hk) = &self.hotkey {
            hk.poll();
            while let Ok(o) = hk.outcomes.try_recv() {
                outcome = Some(o); // keep only the latest for the status line
            }
        }
        match outcome {
            Some(hotkey::HotkeyOutcome::Typed { label }) => {
                self.set_info(format!("Auto-OTP typed for {label}"))
            }
            Some(hotkey::HotkeyOutcome::NoAutoProfile) => {
                self.error = Some("No [A]-tagged profile on the key (add one with Auto-OTP).".into())
            }
            Some(hotkey::HotkeyOutcome::Error(e)) => self.error = Some(format!("Auto-OTP: {e}")),
            None => {}
        }
    }

    /// Enable or disable the global Auto-OTP hotkey.
    #[cfg(feature = "hotkey")]
    fn toggle_hotkey(&mut self) {
        if self.hotkey_wanted {
            self.disable_hotkey();
        } else {
            self.enable_hotkey();
        }
        self.save_settings();
    }

    #[cfg(feature = "hotkey")]
    fn enable_hotkey(&mut self) {
        self.hotkey_wanted = true;
        match hotkey::HotkeyService::new(
            self.hotkey_binding,
            self.transport.iface(),
            self.hotkey_append_enter,
        ) {
            Ok(svc) => {
                let label = svc.label();
                self.hotkey = Some(svc);
                self.set_info(format!("Auto-OTP hotkey on: {label} types the [A] code."));
            }
            Err(e) => {
                // Keep the intent so it persists and can be retried, but report.
                self.error = Some(format!("Auto-OTP: {e}"));
            }
        }
    }

    #[cfg(feature = "hotkey")]
    fn disable_hotkey(&mut self) {
        self.hotkey_wanted = false;
        if self.hotkey.take().is_some() {
            self.set_info("Global Auto-OTP hotkey disabled.".into());
        }
    }

    /// Drop the info message once its expiry passes.
    fn expire_info(&mut self) {
        if let Some(at) = self.info_expires_at {
            if now_secs_f64() >= at {
                self.info = None;
                self.info_expires_at = None;
            }
        }
    }

    fn copy_code(&mut self, code: String) {
        if let Some(cb) = &self.clipboard {
            if let Ok(mut c) = cb.lock() {
                let _ = c.set_text(code.clone());
            }
        }
        self.clipboard_clear_at = Some((code, now_secs_f64() + 45.0));
    }

    fn drain_jobs(&mut self) {
        while let Ok(res) = self.rx.try_recv() {
            self.busy = None;
            match res {
                JobResult::Loaded {
                    rows,
                    serial,
                    transport,
                } => {
                    self.rows = rows;
                    self.serial = serial;
                    self.active_transport = Some(transport);
                    self.loaded = true;
                    self.refreshing = false;
                    self.error = None; // a successful read clears any prior "no device" error
                    self.schedule_next_refresh();
                }
                JobResult::Refreshed {
                    rows,
                    serial,
                    transport,
                } => {
                    // Update in place without disturbing the view.
                    self.rows = rows;
                    self.serial = serial;
                    self.active_transport = Some(transport);
                    self.loaded = true;
                    self.refreshing = false;
                    self.error = None; // recovered: a device is readable again
                    self.schedule_next_refresh();
                }
                JobResult::Disconnected => {
                    // Key removed (or unreadable): clear stale codes and any
                    // cached PIN / keep-alive (the window is gone with the key).
                    self.refreshing = false;
                    self.next_pin_refresh_at = 0.0;
                    if let Some(mut pp) = self.pin.take() {
                        pp.zeroize();
                    }
                    if !self.rows.is_empty() || self.serial.is_some() {
                        self.rows.clear();
                        self.serial = None;
                        self.active_transport = None;
                        self.touch_codes.clear();
                        self.set_info("Key disconnected.".into());
                    }
                    self.schedule_next_refresh();
                }
                JobResult::TouchCode { key, code } => {
                    self.touch_codes.insert(key, code);
                }
                JobResult::Ok(msg) => {
                    if !msg.is_empty() {
                        self.set_info(msg);
                    }
                    self.reload();
                }
                JobResult::PinRequired { wrong } => {
                    // Key is PIN-protected and locked: stop the "reading" state,
                    // hide any codes, and prompt to unlock.
                    self.refreshing = false;
                    self.loaded = true;
                    self.next_pin_refresh_at = 0.0;
                    self.rows.clear();
                    self.touch_codes.clear();
                    if wrong {
                        // A stored PIN was rejected — drop it and re-prompt.
                        if let Some(mut p) = self.pin.take() {
                            p.zeroize();
                        }
                    }
                    self.pin_ui.wrong = wrong;
                    self.pin_ui.prompt_open = true;
                    self.schedule_next_refresh();
                }
                JobResult::PinStatus { set, retries, max } => {
                    self.pin_ui.is_set = Some(set);
                    self.pin_ui.retries = retries;
                    self.pin_ui.max = max;
                    self.refreshing = false;
                }
                JobResult::PinKeptAlive => {
                    // Window refreshed silently; schedule the next keep-alive.
                    self.schedule_next_pin_refresh();
                }
                JobResult::Err(msg) => {
                    self.error = Some(msg);
                    self.loaded = true;
                    self.refreshing = false;
                    // Keep polling so that plugging a key in (or fixing the
                    // reader) recovers automatically and clears this error.
                    self.schedule_next_refresh();
                }
            }
        }
    }

    fn maybe_clear_clipboard(&mut self) {
        if let Some((code, at)) = self.clipboard_clear_at.clone() {
            if now_secs_f64() >= at {
                if let Some(cb) = &self.clipboard {
                    if let Ok(mut c) = cb.lock() {
                        // Only wipe if the clipboard still holds *our* code.
                        if c.get_text().map(|t| t == code).unwrap_or(false) {
                            let _ = c.set_text(String::new());
                        }
                    }
                }
                self.clipboard_clear_at = None;
            }
        }
    }
}

fn now_secs_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Remaining seconds + fraction for a TOTP window.
fn totp_window(period: u64) -> (u64, f32) {
    let period = period.max(1);
    let now = now_secs();
    let rem = period - (now % period);
    (rem, rem as f32 / period as f32)
}

/// Draw a countdown ring (clockwise arc from 12 o'clock).
fn ring(ui: &mut egui::Ui, pct: f32, size: f32, color: Color32, track: Color32) {
    use std::f32::consts::{FRAC_PI_2, TAU};
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let c = rect.center();
    let r = size / 2.0 - 1.5;
    let painter = ui.painter();
    painter.circle_stroke(c, r, Stroke::new(2.5, track));
    let pct = pct.clamp(0.0, 1.0);
    let n = (48.0 * pct).ceil().max(1.0) as usize;
    let pts: Vec<egui::Pos2> = (0..=n)
        .map(|i| {
            let t = pct * (i as f32 / n as f32);
            let a = -FRAC_PI_2 + TAU * t;
            c + r * egui::vec2(a.cos(), a.sin())
        })
        .collect();
    painter.add(egui::Shape::line(pts, Stroke::new(2.5, color)));
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_jobs();
        self.maybe_clear_clipboard();
        self.expire_info();
        // Periodic, presence-aware refresh: keeps codes current and clears the
        // list if the key has been unplugged.
        if self.loaded
            && !self.refreshing
            && self.busy.is_none()
            && now_secs_f64() >= self.next_refresh_at
        {
            self.refresh_codes(ctx);
        }
        // Keep-unlocked keep-alive: re-verify with the cached PIN before the
        // device's ~5-minute window closes.
        if self.keep_unlocked
            && self.pin.is_some()
            && self.busy.is_none()
            && self.next_pin_refresh_at > 0.0
            && now_secs_f64() >= self.next_pin_refresh_at
        {
            self.pin_keepalive(ctx);
        }
        #[cfg(feature = "hotkey")]
        self.poll_hotkey();
        apply_style(ctx, &self.p);

        egui::TopBottomPanel::top("header")
            .frame(egui::Frame::none().fill(self.p.bg).inner_margin(egui::Margin::symmetric(18.0, 14.0)))
            .show(ctx, |ui| self.header(ui));

        // Status bar pinned to the bottom: serial / transport / busy spinner on
        // the left, transient info/error messages on the right.
        egui::TopBottomPanel::bottom("status")
            .frame(
                egui::Frame::none()
                    .fill(self.p.card)
                    .inner_margin(egui::Margin::symmetric(14.0, 7.0))
                    .stroke(Stroke::new(1.0, self.p.line)),
            )
            .show(ctx, |ui| self.status_bar(ui));

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(self.p.bg).inner_margin(egui::Margin::symmetric(18.0, 8.0)))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| self.body(ui, ctx));
            });

        // Modal dialogs.
        self.add_dialog(ctx);
        self.delete_dialog(ctx);
        self.settings_dialog(ctx);
        self.erase_dialog(ctx);
        self.exit_dialog(ctx);
        self.pin_dialog(ctx);
        self.pin_mgmt_dialog(ctx);

        // Keep TOTP countdowns ticking and clipboard-clear timely.
        ctx.request_repaint_after(Duration::from_millis(250));

        // Guard against accidental closing. The title-bar close button is
        // disabled (see `main`), but if a close is somehow requested and the
        // user hasn't confirmed Exit, cancel it and prompt for confirmation
        // instead of quitting.
        if !self.really_quit && ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.confirm_exit = true;
        }
    }
}

impl App {
    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            // T2 badge — the real app icon, loaded once into a texture.
            if self.badge.is_none() {
                if let Some(icon) = load_app_icon() {
                    let img = egui::ColorImage::from_rgba_unmultiplied(
                        [icon.width as usize, icon.height as usize],
                        &icon.rgba,
                    );
                    self.badge = Some(ui.ctx().load_texture("app_badge", img, egui::TextureOptions::LINEAR));
                }
            }
            if let Some(tex) = &self.badge {
                ui.add(egui::Image::new(tex).fit_to_exact_size(egui::vec2(26.0, 26.0)));
            } else {
                // Fallback: a plain accent square (should not normally happen).
                let (rect, _) = ui.allocate_exact_size(egui::vec2(26.0, 26.0), egui::Sense::hover());
                ui.painter().rect_filled(rect, 7.0, self.p.accent);
            }

            ui.add_space(8.0);
            ui.label(RichText::new("T2 TOTP").font(prop(15.0)).strong().color(self.p.txt));

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // Exit (far right): always-available way to quit, with a
                // confirmation, so the app is never closed by accident.
                if plain_button(ui, &self.p, "Exit").on_hover_text("Exit the app").clicked() {
                    self.confirm_exit = true;
                }
                ui.add_space(6.0);
                // Transport selector (compact).
                egui::ComboBox::from_id_source("transport")
                    .width(96.0)
                    .selected_text(self.transport.label())
                    .show_ui(ui, |ui| {
                        for t in [Transport::Auto, Transport::Hid, Transport::Nfc] {
                            if ui.selectable_label(self.transport == t, t.label()).clicked()
                                && self.transport != t
                            {
                                self.transport = t;
                                #[cfg(feature = "hotkey")]
                                if let Some(hk) = &mut self.hotkey {
                                    hk.set_transport(t.iface());
                                }
                                self.save_settings();
                                self.reload();
                            }
                        }
                    });

                ui.add_space(6.0);
                if accent_button(ui, &self.p, "+ Add").clicked() {
                    let mut f = AddForm::default();
                    f.open = true;
                    self.add = f;
                }
                ui.add_space(6.0);
                if icon_button(ui, &self.p, "↻").on_hover_text("Refresh").clicked() {
                    self.reload();
                }
                ui.add_space(6.0);
                if icon_button(ui, &self.p, "⚙").on_hover_text("Settings").clicked() {
                    self.settings_open = true;
                }

                // Lock button: only while a PIN-protected key is currently
                // unlocked (a PIN is cached). Closes the window and hides codes.
                if self.pin.is_some() {
                    ui.add_space(6.0);
                    if icon_button(ui, &self.p, "\u{1F512}")
                        .on_hover_text("Lock OTP PIN (hide codes)")
                        .clicked()
                    {
                        self.lock_now(ui.ctx());
                    }
                }

                // Small Auto-OTP toggle: icon only, accent when active. The full
                // combo lives in Settings and the bottom status bar.
                #[cfg(feature = "hotkey")]
                {
                    ui.add_space(6.0);
                    let wanted = self.hotkey_wanted;
                    let registered = self.hotkey.is_some();
                    let hover = if registered {
                        format!("Auto-OTP hotkey on ({}). Click to disable.", self.hotkey_binding.label())
                    } else if wanted {
                        format!(
                            "Auto-OTP wanted ({}) but not registered — the combo may be taken. Click to turn off, or change it in Settings.",
                            self.hotkey_binding.label()
                        )
                    } else {
                        "Auto-OTP hotkey off. Click to enable; configure in Settings.".to_string()
                    };
                    let btn = if registered {
                        icon_button_accent(ui, &self.p, "⌨")
                    } else {
                        icon_button(ui, &self.p, "⌨")
                    };
                    if btn.on_hover_text(hover).clicked() {
                        self.toggle_hotkey();
                    }
                }
            });
        });
    }

    /// Bottom status bar: connection facts on the left, the latest transient
    /// message (copied / added / error) on the right.
    fn status_bar(&mut self, ui: &mut egui::Ui) {
        // Right side first so it reserves its width; the left side then fills the
        // remainder and truncates instead of overlapping.
        ui.horizontal(|ui| {
            // Left: spinner/connection + hotkey state, truncated to fit.
            let left = if let Some(busy) = self.busy.clone() {
                ui.add(egui::Spinner::new().size(12.0));
                ui.add_space(6.0);
                busy
            } else {
                let mut bits: Vec<String> = Vec::new();
                match self.active_transport {
                    Some(t) if !self.rows.is_empty() || self.serial.is_some() => {
                        bits.push(format!("via {t}"));
                    }
                    _ => {}
                }
                if let Some(serial) = &self.serial {
                    bits.push(format!("S/N {serial}"));
                }
                #[cfg(feature = "hotkey")]
                if self.hotkey.is_some() {
                    bits.push(format!("Auto-OTP {}", self.hotkey_binding.label()));
                }
                if bits.is_empty() {
                    "No key connected".to_string()
                } else {
                    bits.join("   ·   ")
                }
            };

            // Reserve the right-aligned message, then let the left text take the
            // rest and truncate.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(err) = self.error.clone() {
                    ui.add(egui::Label::new(
                        RichText::new(format!("⚠  {err}")).font(prop(11.5)).color(self.p.err),
                    ).truncate(true));
                } else if let Some(info) = self.info.clone() {
                    ui.add(egui::Label::new(
                        RichText::new(format!("✔  {info}")).font(prop(11.5)).color(self.p.ok),
                    ).truncate(true));
                }
                // Left text fills whatever remains, single-line truncated.
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.add(
                        egui::Label::new(RichText::new(left).font(prop(11.5)).color(self.p.txt3))
                            .truncate(true),
                    );
                });
            });
        });
    }

    fn body(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.add_space(6.0);
        if !self.loaded {
            ui.add_space(8.0);
            ui.label(RichText::new("Reading entries…").font(prop(13.0)).color(self.p.txt3));
            return;
        }
        if self.rows.is_empty() && self.error.is_none() {
            ui.add_space(8.0);
            ui.label(RichText::new("No TOTP profiles on this key.").font(prop(13.0)).color(self.p.txt3));
            ui.add_space(8.0);
            return;
        }

        let mut copy: Option<String> = None;
        let mut delete: Option<(String, String)> = None;
        let mut read_touch: Option<(String, String)> = None;
        let touch_codes = self.touch_codes.clone();

        let rows = self.rows.clone();
        let n = rows.len();
        card(ui, &self.p, |ui| {
            for (i, row) in rows.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(row.label()).font(prop(14.0)).strong().color(self.p.txt));
                            if row.is_auto() {
                                tag(ui, &self.p, "Auto-OTP", self.p.gold);
                            }
                            if row.button_required {
                                tag(ui, &self.p, "touch", self.p.txt3);
                            }
                        });
                        ui.label(
                            RichText::new(format!("{}/{}", row.otp_type, row.algo))
                                .font(prop(11.0))
                                .color(self.p.txt3),
                        );
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if plain_button(ui, &self.p, "Delete").clicked() {
                            delete = Some((row.app_name.clone(), row.account_name.clone()));
                        }
                        ui.add_space(8.0);

                        match &row.code {
                            Some(code) => {
                                let (secs, pct) = totp_window(row.period as u64);
                                let warn = secs <= 5;
                                if plain_button(ui, &self.p, "Copy").clicked() {
                                    copy = Some(code.clone());
                                }
                                ui.add_space(8.0);
                                ui.label(
                                    RichText::new(format!("{secs}s"))
                                        .font(prop(11.0))
                                        .color(self.p.txt3),
                                );
                                ui.add_space(4.0);
                                ring(
                                    ui,
                                    pct,
                                    18.0,
                                    if warn { self.p.warn } else { self.p.accent },
                                    self.p.line,
                                );
                                ui.add_space(8.0);
                                ui.label(
                                    RichText::new(spaced(code))
                                        .font(mono(17.0))
                                        .color(if warn { self.p.warn } else { self.p.txt }),
                                );
                            }
                            None => {
                                let rkey = (row.app_name.clone(), row.account_name.clone());
                                if let Some(code) = touch_codes.get(&rkey) {
                                    if plain_button(ui, &self.p, "Copy").clicked() {
                                        copy = Some(code.clone());
                                    }
                                    ui.add_space(8.0);
                                    ui.label(RichText::new(spaced(code)).font(mono(17.0)).color(self.p.txt));
                                } else if row.button_required {
                                    if plain_button(ui, &self.p, "Read")
                                        .on_hover_text("Touch the key to read this code")
                                        .clicked()
                                    {
                                        read_touch = Some(rkey);
                                    }
                                } else {
                                    ui.label(RichText::new("—").color(self.p.txt3));
                                }
                            }
                        }
                    });
                });
                if i + 1 < n {
                    ui.add_space(6.0);
                    let y = ui.cursor().top();
                    ui.painter()
                        .hline(ui.max_rect().x_range(), y, Stroke::new(1.0, self.p.line_soft));
                    ui.add_space(6.0);
                }
            }
        });

        if let Some(code) = copy {
            self.copy_code(code);
            self.set_info("Copied — clipboard clears in 45s.".into());
        }
        if let Some(key) = delete {
            self.confirm_delete = Some(key);
        }
        if let Some(key) = read_touch {
            let t = self.transport;
            let (a, acct) = key.clone();
            let ctx2 = ctx.clone();
            let pin = self.pin.clone();
            self.spawn("Touch your key to read the code…", Some(ctx.clone()), move || {
                let mut session = match open(t) {
                    Ok(s) => s,
                    Err(e) => return JobResult::Err(e),
                };
                let _ = &ctx2;
                match session.unlock_if_pinned(pin.as_deref().map(|z| z.as_str())) {
                    Ok(()) => {}
                    Err(t2totp::transport::Error::PinRequired) => {
                        return JobResult::PinRequired { wrong: false }
                    }
                    Err(t2totp::transport::Error::Applet(
                        t2totp::proto::OtpError::PinNotVerified,
                    )) => return JobResult::PinRequired { wrong: true },
                    Err(e) => return JobResult::Err(e.to_string()),
                }
                match session.read_entry(now_secs(), &a, &acct) {
                    Ok(entry) => match entry.code {
                        Some(code) => JobResult::TouchCode { key, code },
                        None => JobResult::Err("the key returned no code".into()),
                    },
                    Err(e) => JobResult::Err(e.to_string()),
                }
            });
        }
    }

    fn add_dialog(&mut self, ctx: &egui::Context) {
        if !self.add.open {
            return;
        }
        let mut submit = false;
        let mut cancel = false;
        #[cfg(feature = "qr")]
        let mut scan_qr = false;
        let (keep_open, _) = modal(ctx, &self.p, "add_dialog", "Add TOTP profile", 360.0, |ui| {
            let field_w = ui.available_width();
            grid_label(ui, &self.p, "Issuer");
            ui.add(egui::TextEdit::singleline(&mut self.add.issuer).desired_width(field_w));
            grid_label(ui, &self.p, "Account");
            ui.add(egui::TextEdit::singleline(&mut self.add.account).desired_width(field_w));
            grid_label(ui, &self.p, "Base32 secret");
            ui.add(
                egui::TextEdit::singleline(&mut self.add.secret)
                    .password(true)
                    .desired_width(field_w),
            );

            #[cfg(feature = "qr")]
            {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if plain_button(ui, &self.p, "Scan QR from screen").clicked() {
                        scan_qr = true;
                    }
                    if let Some(msg) = &self.add.scan_status {
                        ui.add_space(8.0);
                        let color = if self.add.scan_ok { self.p.ok } else { self.p.warn };
                        ui.add(
                            egui::Label::new(RichText::new(msg).font(prop(10.5)).color(color))
                                .truncate(true),
                        );
                    }
                });
            }

            ui.add_space(12.0);
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut self.add.sha256, "SHA-256");
                ui.checkbox(&mut self.add.auto, "Auto-OTP [A]");
                ui.checkbox(&mut self.add.touch, "Require touch");
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Digits").font(prop(11.5)).color(self.p.txt3));
                ui.add(egui::DragValue::new(&mut self.add.digits).clamp_range(4..=10));
                ui.add_space(16.0);
                ui.label(RichText::new("Period (s)").font(prop(11.5)).color(self.p.txt3));
                ui.add(egui::DragValue::new(&mut self.add.period).clamp_range(1..=600));
            });
            ui.add_space(14.0);
            ui.separator();
            ui.add_space(10.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if accent_button(ui, &self.p, "Add").clicked() {
                    submit = true;
                }
                ui.add_space(8.0);
                if plain_button(ui, &self.p, "Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if !keep_open || cancel {
            self.add.open = false;
        }
        #[cfg(feature = "qr")]
        if scan_qr {
            self.scan_qr_into_form();
        }
        if submit {
            self.submit_add(ctx.clone());
        }
    }

    /// Capture the screen(s), find a TOTP QR, and fill the Add form from it.
    #[cfg(feature = "qr")]
    fn scan_qr_into_form(&mut self) {
        match qr::scan_screens() {
            Ok(t) => {
                if let Some(issuer) = t.issuer {
                    self.add.issuer = issuer;
                }
                if let Some(account) = t.account {
                    self.add.account = account;
                }
                self.add.secret = t.secret;
                if let Some(algo) = t.algorithm {
                    // We support SHA-1 and SHA-256; SHA-512 isn't written by the
                    // device, so fall back to SHA-256 for it and note as much.
                    self.add.sha256 = matches!(algo, qr::Algo::Sha256 | qr::Algo::Sha512);
                }
                if let Some(d) = t.digits {
                    self.add.digits = d.clamp(4, 10);
                }
                if let Some(p) = t.period {
                    self.add.period = p.max(1);
                }
                self.add.scan_ok = true;
                self.add.scan_status = Some("Scanned — review and Add.".to_string());
            }
            Err(e) => {
                self.add.scan_ok = false;
                self.add.scan_status = Some(e);
            }
        }
    }

    fn submit_add(&mut self, ctx: egui::Context) {
        let issuer_base = self.add.issuer.trim().to_string();
        let account = self.add.account.trim().to_string();
        if account.is_empty() {
            self.error = Some("Account is required.".into());
            return;
        }
        let issuer = if self.add.auto && !issuer_base.contains(AUTO_TAG) {
            format!("{issuer_base}{AUTO_TAG}")
        } else {
            issuer_base
        };
        let secret = self.add.secret.clone();
        let sha256 = self.add.sha256;
        let digits = self.add.digits;
        let period = self.add.period;
        let touch = self.add.touch;
        let t = self.transport;

        self.add.open = false;
        let pin = self.pin.clone();
        self.spawn("Adding profile…", Some(ctx), move || {
            let seed = match t2totp::proto::decode_base32_seed(&secret) {
                Ok(s) => s,
                Err(e) => return JobResult::Err(format!("invalid Base32 secret: {e}")),
            };
            let mut session = match open(t) {
                Ok(s) => s,
                Err(e) => return JobResult::Err(e),
            };
            let entry = WriteEntry {
                otp_type: OtpType::Totp,
                algorithm: if sha256 { Algorithm::Sha256 } else { Algorithm::Sha1 },
                timestep: period,
                code_length: digits,
                button_required: touch,
                app_name: &issuer,
                account_name: &account,
                seed: &seed,
            };
            // On a PIN-protected key, verify first: this opens the write window
            // and captures the agreement pubkey the seal reuses (GET_ECDH_PUBKEY
            // is blocked while a PIN is set).
            match session.write_entry_pinned(&entry, pin.as_deref().map(|z| z.as_str())) {
                Ok(()) => JobResult::Ok(format!("Added {issuer}:{account}")),
                Err(t2totp::transport::Error::PinRequired) => {
                    JobResult::PinRequired { wrong: false }
                }
                Err(t2totp::transport::Error::Applet(
                    t2totp::proto::OtpError::PinNotVerified,
                )) => JobResult::PinRequired { wrong: true },
                Err(e) => JobResult::Err(e.to_string()),
            }
        });
    }

    fn delete_dialog(&mut self, ctx: &egui::Context) {
        let Some((app_name, account)) = self.confirm_delete.clone() else {
            return;
        };
        let mut decided: Option<bool> = None;
        let (keep_open, _) = modal(ctx, &self.p, "delete_dialog", "Delete profile", 320.0, |ui| {
            let label = if app_name.is_empty() {
                account.clone()
            } else {
                format!("{app_name}:{account}")
            };
            ui.label(
                RichText::new(format!("Delete “{label}” from the key?"))
                    .font(prop(12.5))
                    .color(self.p.txt),
            );
            ui.add_space(14.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if danger_button(ui, &self.p, "Delete").clicked() {
                    decided = Some(true);
                }
                ui.add_space(8.0);
                if plain_button(ui, &self.p, "Cancel").clicked() {
                    decided = Some(false);
                }
            });
        });
        if !keep_open {
            decided = Some(false);
        }
        match decided {
            Some(true) => {
                self.confirm_delete = None;
                let t = self.transport;
                let pin = self.pin.clone();
                self.spawn("Deleting…", Some(ctx.clone()), move || {
                    let mut session = match open(t) {
                        Ok(s) => s,
                        Err(e) => return JobResult::Err(e),
                    };
                    // Delete is a seed-write; on a PIN-protected key verify first
                    // (opens the window + captures the agreement pubkey the seal
                    // reuses, since GET_ECDH_PUBKEY is blocked while a PIN is set).
                    match session.delete_entry_pinned(
                        &app_name,
                        &account,
                        pin.as_deref().map(|z| z.as_str()),
                    ) {
                        Ok(()) => JobResult::Ok("Deleted.".into()),
                        Err(t2totp::transport::Error::PinRequired) => {
                            JobResult::PinRequired { wrong: false }
                        }
                        Err(t2totp::transport::Error::Applet(
                            t2totp::proto::OtpError::PinNotVerified,
                        )) => JobResult::PinRequired { wrong: true },
                        Err(e) => JobResult::Err(e.to_string()),
                    }
                });
            }
            Some(false) => self.confirm_delete = None,
            None => {}
        }
    }

    /// Settings window: Auto-OTP hotkey configuration (when built with the
    /// `hotkey` feature) plus the dangerous Erase-all action.
    fn settings_dialog(&mut self, ctx: &egui::Context) {
        if !self.settings_open {
            return;
        }
        let mut open = true;
        #[cfg(feature = "hotkey")]
        let mut apply_hotkey = false;
        #[cfg(feature = "hotkey")]
        let mut close_clicked = false;
        let mut start_erase = false;
        let mut open_pin_mgmt = false;

        egui::Window::new("Settings")
            .title_bar(false)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(380.0)
            .max_width(380.0)
            .frame(
                egui::Frame::none()
                    .fill(self.p.card)
                    .stroke(Stroke::new(1.0, self.p.line))
                    .rounding(12.0)
                    .inner_margin(egui::Margin::symmetric(18.0, 16.0))
                    .shadow(egui::epaint::Shadow {
                        offset: egui::vec2(0.0, 6.0),
                        blur: 24.0,
                        spread: 0.0,
                        color: Color32::from_black_alpha(40),
                    }),
            )
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_width(380.0);

                // Our own compact header (native title bar is disabled).
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Settings").font(prop(15.0)).strong().color(self.p.txt));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if icon_button(ui, &self.p, "×").clicked() {
                            self.settings_open = false;
                            #[cfg(feature = "hotkey")]
                            {
                                close_clicked = true;
                            }
                        }
                    });
                });
                ui.add_space(6.0);
                ui.separator();
                ui.add_space(8.0);

                // Scroll the body so a small app window never clips the dialog.
                let max_body = (ctx.screen_rect().height() - 170.0).max(220.0);
                egui::ScrollArea::vertical()
                    .max_height(max_body)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {

                #[cfg(feature = "hotkey")]
                {
                    ui.label(RichText::new("Global Auto-OTP hotkey").font(prop(13.5)).strong().color(self.p.txt));
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(
                            "A system-wide combo that types the [A]-tagged profile's code into the focused window.",
                        )
                        .font(prop(11.0))
                        .color(self.p.txt3),
                    );
                    ui.add_space(8.0);

                    grid_label(ui, &self.p, "Shortcut");
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Ctrl + Alt +")
                                .font(mono(12.5))
                                .strong()
                                .color(self.p.txt),
                        );
                        let cur = self.hotkey_binding.key;
                        egui::ComboBox::from_id_source("hk_key")
                            .width(64.0)
                            .selected_text(key_label_for(cur))
                            .show_ui(ui, |ui| {
                                for (code, label) in hotkey::selectable_keys() {
                                    ui.selectable_value(&mut self.hotkey_binding.key, *code, *label);
                                }
                            });
                    });
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new("The combo is fixed to Ctrl + Alt plus one of the supported letters.")
                            .font(prop(10.5))
                            .color(self.p.txt3),
                    );

                    ui.add_space(8.0);
                    ui.checkbox(
                        &mut self.hotkey_append_enter,
                        "Press Enter after typing the code",
                    );

                    ui.add_space(6.0);
                    let preview = self.hotkey_binding.label();
                    let enabled = self.hotkey.is_some();
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("Combo:  {preview}")).font(mono(12.5)).color(self.p.txt));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let apply_label = if enabled { "Apply & re-enable" } else { "Apply & enable" };
                            if accent_button(ui, &self.p, apply_label).clicked() {
                                apply_hotkey = true;
                            }
                            if enabled {
                                ui.add_space(6.0);
                                if plain_button(ui, &self.p, "Disable").clicked() {
                                    self.hotkey = None;
                                    self.hotkey_wanted = false;
                                }
                            }
                        });
                    });

                    ui.add_space(14.0);
                    ui.separator();
                    ui.add_space(10.0);
                }

                #[cfg(not(feature = "hotkey"))]
                {
                    ui.label(
                        RichText::new("Built without the Auto-OTP hotkey (rebuild with --features hotkey).")
                            .font(prop(11.5))
                            .color(self.p.txt3),
                    );
                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(10.0);
                }

                // OTP PIN (privacy protection).
                ui.label(
                    RichText::new("OTP PIN (privacy protection)")
                        .font(prop(13.5))
                        .strong(),
                );
                ui.add_space(2.0);
                ui.label(
                    RichText::new(
                        "Require a PIN before OTP codes can be read from this key \
                         (needs R3.4 firmware).",
                    )
                    .font(prop(11.0))
                    .color(self.p.txt3),
                );
                ui.add_space(8.0);
                if accent_button(ui, &self.p, "Manage OTP PIN…").clicked() {
                    open_pin_mgmt = true;
                }
                ui.add_space(14.0);
                ui.separator();
                ui.add_space(10.0);

                // Danger zone.
                ui.label(RichText::new("Danger zone").font(prop(13.5)).strong().color(self.p.err));
                ui.add_space(2.0);
                ui.label(
                    RichText::new("Erase every TOTP profile stored on the key.")
                        .font(prop(11.0))
                        .color(self.p.txt3),
                );
                ui.add_space(8.0);
                if danger_button(ui, &self.p, "Erase all profiles…").clicked() {
                    start_erase = true;
                }

                ui.add_space(14.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if plain_button(ui, &self.p, "Close").clicked() {
                        self.settings_open = false;
                        #[cfg(feature = "hotkey")]
                        {
                            close_clicked = true;
                        }
                    }
                });
                }); // end ScrollArea
            });

        if !open {
            self.settings_open = false;
        }
        #[cfg(feature = "hotkey")]
        if close_clicked {
            // Persist append-Enter / binding edits made without re-applying.
            self.save_settings();
        }
        #[cfg(feature = "hotkey")]
        if apply_hotkey {
            // Drop any existing registration first to free the old combo, then
            // register the new one.
            self.hotkey = None;
            self.enable_hotkey();
            self.save_settings();
        }
        if start_erase {
            self.settings_open = false;
            self.confirm_erase = true;
        }
        if open_pin_mgmt {
            self.settings_open = false;
            self.pin_ui.mgmt_open = true;
            self.pin_ui.is_set = None;
            self.refresh_pin_status(ctx);
        }
    }

    fn exit_dialog(&mut self, ctx: &egui::Context) {
        if !self.confirm_exit {
            return;
        }
        let mut decided: Option<bool> = None;
        let (keep_open, _) = modal(ctx, &self.p, "exit_dialog", "Exit T2 TOTP?", 320.0, |ui| {
            ui.label(
                RichText::new("Are you sure you want to exit?")
                    .font(prop(12.5))
                    .color(self.p.txt),
            );
            #[cfg(feature = "hotkey")]
            if self.hotkey.is_some() {
                ui.add_space(2.0);
                ui.label(
                    RichText::new("The global Auto-OTP hotkey will stop working until you reopen the app.")
                        .font(prop(11.0))
                        .color(self.p.txt3),
                );
            }
            ui.add_space(14.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if danger_button(ui, &self.p, "Exit").clicked() {
                    decided = Some(true);
                }
                ui.add_space(8.0);
                if plain_button(ui, &self.p, "Cancel").clicked() {
                    decided = Some(false);
                }
            });
        });
        if !keep_open {
            decided = Some(false);
        }
        match decided {
            Some(true) => {
                self.confirm_exit = false;
                self.really_quit = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Some(false) => self.confirm_exit = false,
            None => {}
        }
    }

    fn erase_dialog(&mut self, ctx: &egui::Context) {
        if !self.confirm_erase {
            return;
        }
        let mut decided: Option<bool> = None;
        let (keep_open, _) = modal(ctx, &self.p, "erase_dialog", "Erase all profiles", 340.0, |ui| {
            ui.label(
                RichText::new("This wipes ALL profiles on the key.")
                    .color(self.p.err)
                    .strong(),
            );
            ui.add_space(2.0);
            ui.label(
                RichText::new("Over USB-HID you'll need to touch the key to confirm.")
                    .font(prop(11.5))
                    .color(self.p.txt3),
            );
            ui.add_space(14.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if danger_button(ui, &self.p, "Erase everything").clicked() {
                    decided = Some(true);
                }
                ui.add_space(8.0);
                if plain_button(ui, &self.p, "Cancel").clicked() {
                    decided = Some(false);
                }
            });
        });
        if !keep_open {
            decided = Some(false);
        }
        match decided {
            Some(true) => {
                self.confirm_erase = false;
                let t = self.transport;
                self.spawn("Erasing… (touch the key if over USB-HID)", Some(ctx.clone()), move || {
                    let mut session = match open(t) {
                        Ok(s) => s,
                        Err(e) => return JobResult::Err(e),
                    };
                    if !session.is_pcsc() {
                        session.set_button_prompt(Box::new(|| {}));
                    }
                    match session.erase_all() {
                        Ok(()) => JobResult::Ok("Erased all profiles.".into()),
                        Err(e) => JobResult::Err(e.to_string()),
                    }
                });
            }
            Some(false) => self.confirm_erase = false,
            None => {}
        }
    }

    /// Spawn a PIN-management job (status/set/change/remove) on the worker.
    fn spawn_pin<F>(&mut self, busy: &str, ctx: &egui::Context, f: F)
    where
        F: FnOnce() -> JobResult + Send + 'static,
    {
        self.spawn(busy, Some(ctx.clone()), f);
    }

    /// Kick off a PIN status read (used to populate the management section).
    fn refresh_pin_status(&mut self, ctx: &egui::Context) {
        let t = self.transport;
        self.spawn_pin("Reading PIN status…", ctx, move || job_pin_status(t));
    }

    /// The unlock prompt: shown when the key is PIN-protected and we don't yet
    /// have a verified PIN. Entering the correct PIN reloads with reads unlocked.
    fn pin_dialog(&mut self, ctx: &egui::Context) {
        if !self.pin_ui.prompt_open {
            return;
        }
        let mut submit = false;
        let mut cancel = false;
        let (keep_open, _) = modal(ctx, &self.p, "pin_dialog", "Enter OTP PIN", 340.0, |ui| {
            ui.label(
                RichText::new("This key is protected by an OTP PIN.")
                    .font(prop(12.5))
                    .color(self.p.txt),
            );
            ui.add_space(8.0);
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.pin_ui.entry)
                    .password(true)
                    .hint_text("OTP PIN")
                    .desired_width(f32::INFINITY),
            );
            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                submit = true;
            }
            if self.pin_ui.wrong {
                ui.add_space(4.0);
                ui.label(
                    RichText::new("Incorrect PIN — try again.")
                        .font(prop(11.5))
                        .color(self.p.err),
                );
            }
            ui.add_space(14.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if accent_button(ui, &self.p, "Unlock").clicked() {
                    submit = true;
                }
                ui.add_space(8.0);
                if plain_button(ui, &self.p, "Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if !keep_open {
            cancel = true;
        }
        if submit && !self.pin_ui.entry.trim().is_empty() {
            let pin = Zeroizing::new(self.pin_ui.entry.trim().to_string());
            self.pin_ui.entry.zeroize();
            self.pin_ui.entry.clear();
            self.pin_ui.prompt_open = false;
            self.pin_ui.wrong = false;
            self.pin = Some(pin);
            self.schedule_next_pin_refresh();
            self.reload();
        } else if cancel {
            self.pin_ui.entry.zeroize();
            self.pin_ui.entry.clear();
            self.pin_ui.prompt_open = false;
        }
    }

    /// PIN management modal: status + set / change / remove. Opened from Settings.
    fn pin_mgmt_dialog(&mut self, ctx: &egui::Context) {
        if !self.pin_ui.mgmt_open {
            return;
        }
        let mut action: Option<PinAction> = None;
        let mut close = false;
        let mut lock_now = false;
        let is_set = self.pin_ui.is_set;
        let has_cached_pin = self.pin.is_some();
        let mut keep_unlocked = self.keep_unlocked;
        let (keep_open, _) =
            modal(ctx, &self.p, "pin_mgmt_dialog", "OTP PIN (privacy protection)", 380.0, |ui| {
                match is_set {
                    Some(true) => {
                        ui.label(
                            RichText::new(format!(
                                "PIN is set — {} of {} attempts remaining.",
                                self.pin_ui.retries, self.pin_ui.max
                            ))
                            .font(prop(12.0))
                            .color(self.p.txt),
                        );
                    }
                    Some(false) => {
                        ui.label(
                            RichText::new("No PIN is set on this key.")
                                .font(prop(12.0))
                                .color(self.p.txt),
                        );
                    }
                    None => {
                        ui.label(
                            RichText::new("Reading PIN status…")
                                .font(prop(12.0))
                                .color(self.p.txt3),
                        );
                    }
                }
                ui.add_space(10.0);

                if is_set == Some(false) {
                    ui.label(RichText::new("Set a PIN").font(prop(12.5)).strong());
                    ui.add(
                        egui::TextEdit::singleline(&mut self.pin_ui.set_new)
                            .password(true)
                            .hint_text("New PIN (≥6 digits, or ≥10 chars)")
                            .desired_width(f32::INFINITY),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.pin_ui.set_confirm)
                            .password(true)
                            .hint_text("Confirm new PIN")
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if accent_button(ui, &self.p, "Set PIN").clicked() {
                            action = Some(PinAction::Set);
                        }
                    });
                }

                if is_set == Some(true) {
                    ui.label(RichText::new("Change PIN").font(prop(12.5)).strong());
                    ui.add(
                        egui::TextEdit::singleline(&mut self.pin_ui.change_cur)
                            .password(true)
                            .hint_text("Current PIN")
                            .desired_width(f32::INFINITY),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.pin_ui.change_new)
                            .password(true)
                            .hint_text("New PIN")
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if accent_button(ui, &self.p, "Change PIN").clicked() {
                            action = Some(PinAction::Change);
                        }
                    });
                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(6.0);
                    ui.label(RichText::new("Remove PIN").font(prop(12.5)).strong());
                    ui.add(
                        egui::TextEdit::singleline(&mut self.pin_ui.remove_cur)
                            .password(true)
                            .hint_text("Current PIN")
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if danger_button(ui, &self.p, "Remove PIN").clicked() {
                            action = Some(PinAction::Remove);
                        }
                    });
                }

                if is_set == Some(true) {
                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(6.0);
                    ui.label(RichText::new("Session").font(prop(12.5)).strong());
                    ui.add_space(2.0);
                    ui.checkbox(
                        &mut keep_unlocked,
                        "Keep unlocked until I lock or unplug",
                    );
                    ui.label(
                        RichText::new(
                            "Re-verifies with the PIN you entered before the key's \
                             ~5-minute window closes. The PIN is held in memory only \
                             for this session.",
                        )
                        .font(prop(10.5))
                        .color(self.p.txt3),
                    );
                    if has_cached_pin {
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if plain_button(ui, &self.p, "Lock now").clicked() {
                                lock_now = true;
                            }
                        });
                    }
                }

                ui.add_space(14.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if plain_button(ui, &self.p, "Close").clicked() {
                        close = true;
                    }
                });
            });
        // Persist a keep-unlocked toggle change and (re)schedule the keep-alive.
        if keep_unlocked != self.keep_unlocked {
            self.keep_unlocked = keep_unlocked;
            self.save_settings();
            self.schedule_next_pin_refresh();
        }
        if lock_now {
            self.lock_now(ctx);
        }
        if !keep_open {
            close = true;
        }
        match action {
            Some(PinAction::Set) => {
                let new = self.pin_ui.set_new.trim().to_string();
                let confirm = self.pin_ui.set_confirm.trim().to_string();
                if new.is_empty() {
                    self.error = Some("Enter a new PIN.".into());
                } else if new != confirm {
                    self.error = Some("PINs do not match.".into());
                } else {
                    let t = self.transport;
                    let pin = Zeroizing::new(new);
                    self.pin_ui.set_new.zeroize();
                    self.pin_ui.set_confirm.zeroize();
                    self.spawn_pin("Setting PIN…", ctx, move || job_pin_set(t, pin));
                    self.pin_ui.is_set = None; // will re-read after
                }
            }
            Some(PinAction::Change) => {
                let cur = Zeroizing::new(self.pin_ui.change_cur.trim().to_string());
                let new = Zeroizing::new(self.pin_ui.change_new.trim().to_string());
                if cur.is_empty() || new.is_empty() {
                    self.error = Some("Enter both the current and new PIN.".into());
                } else {
                    let t = self.transport;
                    self.pin_ui.change_cur.zeroize();
                    self.pin_ui.change_new.zeroize();
                    self.spawn_pin("Changing PIN…", ctx, move || job_pin_change(t, cur, new));
                    self.pin_ui.is_set = None;
                }
            }
            Some(PinAction::Remove) => {
                let cur = Zeroizing::new(self.pin_ui.remove_cur.trim().to_string());
                if cur.is_empty() {
                    self.error = Some("Enter the current PIN.".into());
                } else {
                    let t = self.transport;
                    self.pin_ui.remove_cur.zeroize();
                    // Removing the PIN also clears any cached verified PIN.
                    if let Some(mut pp) = self.pin.take() {
                        pp.zeroize();
                    }
                    self.spawn_pin("Removing PIN…", ctx, move || job_pin_remove(t, cur));
                    self.pin_ui.is_set = None;
                }
            }
            None => {}
        }
        if close {
            self.pin_ui.mgmt_open = false;
            self.pin_ui.set_new.zeroize();
            self.pin_ui.set_confirm.zeroize();
            self.pin_ui.change_cur.zeroize();
            self.pin_ui.change_new.zeroize();
            self.pin_ui.remove_cur.zeroize();
        }
    }
}

/// Which PIN-management action a click requested.
enum PinAction {
    Set,
    Change,
    Remove,
}

// ---------------------------------------------------------------------------
// Small widgets / style helpers
// ---------------------------------------------------------------------------

/// Display label for a key code in the settings combo.
#[cfg(feature = "hotkey")]
fn key_label_for(code: global_hotkey::hotkey::Code) -> String {
    hotkey::selectable_keys()
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, l)| (*l).to_string())
        .unwrap_or_else(|| format!("{code:?}"))
}

/// Group a 6-digit code as "123 456" for readability; leave others as-is.
fn spaced(code: &str) -> String {
    if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) {
        format!("{} {}", &code[..3], &code[3..])
    } else {
        code.to_string()
    }
}

fn apply_style(ctx: &egui::Context, p: &Palette) {
    let mut style = (*ctx.style()).clone();
    let v = &mut style.visuals;
    v.panel_fill = p.bg;
    v.window_fill = p.card;
    v.override_text_color = Some(p.txt);

    // Text inputs and other widgets: a visible 1px border in every state so
    // fields read as boxes, not floating text. Inactive = the soft line; hover
    // = a darker line; focused = the brand accent.
    let field_bg = Color32::from_rgb(0xFC, 0xFC, 0xFD);
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.line);
    v.widgets.inactive.bg_fill = field_bg;
    v.widgets.inactive.weak_bg_fill = field_bg;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, p.line);
    v.widgets.inactive.rounding = egui::Rounding::same(7.0);
    v.widgets.hovered.bg_fill = field_bg;
    v.widgets.hovered.weak_bg_fill = field_bg;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, p.txt3);
    v.widgets.hovered.rounding = egui::Rounding::same(7.0);
    v.widgets.active.bg_fill = field_bg;
    v.widgets.active.weak_bg_fill = field_bg;
    v.widgets.active.bg_stroke = Stroke::new(1.5, p.accent);
    v.widgets.active.rounding = egui::Rounding::same(7.0);
    // Keyboard/focus highlight uses the brand accent rather than egui's blue.
    v.selection.stroke = Stroke::new(1.5, p.accent);
    v.selection.bg_fill = Color32::from_rgba_unmultiplied(0xF2, 0x00, 0x43, 28);

    // Dialogs: compact, with a soft drop shadow and rounded corners.
    v.window_rounding = egui::Rounding::same(12.0);
    v.window_stroke = Stroke::new(1.0, p.line);
    v.window_shadow = egui::epaint::Shadow {
        offset: egui::vec2(0.0, 6.0),
        blur: 24.0,
        spread: 0.0,
        color: Color32::from_black_alpha(38),
    };
    v.popup_shadow = egui::epaint::Shadow {
        offset: egui::vec2(0.0, 3.0),
        blur: 12.0,
        spread: 0.0,
        color: Color32::from_black_alpha(30),
    };

    // Tighter default spacing inside dialogs.
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.window_margin = egui::Margin::symmetric(16.0, 14.0);
    style.spacing.interact_size.y = 30.0;

    ctx.set_style(style);
}

/// A consistently-styled modal dialog: centered, fixed width, no native title
/// bar (we draw our own compact header with the title and an ✕). Returns
/// `false` when the dialog should close (✕ clicked or clicked-away handling done
/// by the caller). The content closure receives the inner `Ui`.
fn modal<R>(
    ctx: &egui::Context,
    p: &Palette,
    id: &str,
    title: &str,
    width: f32,
    add: impl FnOnce(&mut egui::Ui) -> R,
) -> (bool, Option<R>) {
    let mut keep_open = true;
    let mut out = None;
    egui::Window::new(id)
        .title_bar(false)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .default_width(width)
        .max_width(width)
        .frame(
            egui::Frame::none()
                .fill(p.card)
                .stroke(Stroke::new(1.0, p.line))
                .rounding(12.0)
                .inner_margin(egui::Margin::symmetric(18.0, 16.0))
                .shadow(egui::epaint::Shadow {
                    offset: egui::vec2(0.0, 6.0),
                    blur: 24.0,
                    spread: 0.0,
                    color: Color32::from_black_alpha(40),
                }),
        )
        .show(ctx, |ui| {
            ui.set_width(width);
            // Header: title + close button.
            ui.horizontal(|ui| {
                ui.label(RichText::new(title).font(prop(15.0)).strong().color(p.txt));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if icon_button(ui, p, "×").clicked() {
                        keep_open = false;
                    }
                });
            });
            ui.add_space(6.0);
            ui.separator();
            ui.add_space(10.0);
            out = Some(add(ui));
        });
    (keep_open, out)
}

fn card<R>(ui: &mut egui::Ui, p: &Palette, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::none()
        .fill(p.card)
        .stroke(Stroke::new(1.0, p.line))
        .rounding(10.0)
        .inner_margin(egui::Margin::symmetric(14.0, 12.0))
        .show(ui, add)
        .inner
}

fn tag(ui: &mut egui::Ui, _p: &Palette, text: &str, color: Color32) {
    let bg = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 28);
    egui::Frame::none()
        .fill(bg)
        .rounding(7.0)
        .inner_margin(egui::Margin::symmetric(6.0, 1.0))
        .show(ui, |ui| {
            ui.label(RichText::new(text).font(prop(10.5)).color(color).strong());
        });
}

fn grid_label(ui: &mut egui::Ui, p: &Palette, text: &str) {
    ui.add_space(3.0);
    ui.label(RichText::new(text).font(prop(11.0)).color(p.txt3));
}

fn accent_button(ui: &mut egui::Ui, p: &Palette, text: &str) -> egui::Response {
    styled_button(ui, text, p.accent, Color32::WHITE, p.accent_deep)
}
fn danger_button(ui: &mut egui::Ui, p: &Palette, text: &str) -> egui::Response {
    styled_button(ui, text, Color32::from_rgb(0xFB, 0xE9, 0xEE), p.err, p.err)
}
fn plain_button(ui: &mut egui::Ui, p: &Palette, text: &str) -> egui::Response {
    styled_button(ui, text, p.card, p.txt, p.line)
}

/// A compact square icon button (plain).
fn icon_button(ui: &mut egui::Ui, p: &Palette, glyph: &str) -> egui::Response {
    let btn = egui::Button::new(RichText::new(glyph).font(prop(14.0)).color(p.txt))
        .fill(p.card)
        .stroke(Stroke::new(1.0, p.line))
        .rounding(7.0)
        .min_size(egui::vec2(30.0, 28.0));
    ui.add(btn)
}

/// A compact square icon button rendered in the brand accent (active state).
#[cfg(feature = "hotkey")]
fn icon_button_accent(ui: &mut egui::Ui, p: &Palette, glyph: &str) -> egui::Response {
    let btn = egui::Button::new(RichText::new(glyph).font(prop(14.0)).color(Color32::WHITE))
        .fill(p.accent)
        .stroke(Stroke::new(1.0, p.accent_deep))
        .rounding(7.0)
        .min_size(egui::vec2(30.0, 28.0));
    ui.add(btn)
}

fn styled_button(
    ui: &mut egui::Ui,
    text: &str,
    fill: Color32,
    fg: Color32,
    stroke: Color32,
) -> egui::Response {
    let btn = egui::Button::new(RichText::new(text).font(prop(12.5)).color(fg))
        .fill(fill)
        .stroke(Stroke::new(1.0, stroke))
        .rounding(7.0)
        .min_size(egui::vec2(0.0, 28.0));
    ui.add(btn)
}

fn main() -> eframe::Result<()> {
    // Single-instance guard: hold an exclusive lock for the process lifetime.
    // If another instance already holds it, exit quietly instead of opening a
    // second window.
    let _instance = match acquire_single_instance() {
        Some(guard) => guard,
        None => {
            eprintln!("T2 TOTP Authenticator is already running.");
            return Ok(());
        }
    };

    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([720.0, 560.0])
        .with_min_inner_size([560.0, 400.0])
        .with_title("T2 TOTP Authenticator")
        // Prevent accidental quitting: no title-bar close (X) button. Minimize
        // and maximize/restore remain. To quit, use the in-app Exit button,
        // which confirms first.
        .with_close_button(false)
        .with_minimize_button(true)
        .with_maximize_button(true);
    if let Some(icon) = load_app_icon() {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "T2 TOTP Authenticator",
        options,
        Box::new(|cc| Box::new(App::new(cc))),
    )
}

/// Process-lifetime guard proving this is the only running instance.
struct InstanceGuard {
    // A bound loopback listener; the OS frees the port when the process exits,
    // so a second instance's bind fails while we're alive. Held only to keep
    // the socket open.
    _listener: std::net::TcpListener,
}

/// Try to become the single instance by binding a fixed loopback port. Returns
/// `None` if another instance already holds it.
///
/// 49517 is an arbitrary port in the private/ephemeral range; binding to
/// 127.0.0.1 keeps it local-only (no firewall prompt, not reachable off-box).
fn acquire_single_instance() -> Option<InstanceGuard> {
    const PORT: u16 = 49517;
    match std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, PORT)) {
        Ok(listener) => Some(InstanceGuard { _listener: listener }),
        Err(_) => None,
    }
}

/// The application icon, compiled into the binary from `assets/icon.png`. This
/// is the canonical T2 icon — no procedural fallback.
const EMBEDDED_ICON_PNG: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/icon.png"));

fn load_app_icon() -> Option<egui::IconData> {
    // An optional override in the config dir (or next to the exe) lets a
    // deployment swap the window icon without recompiling; otherwise the icon
    // bundled into the binary is used.
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Some(dir) = config::app_config_dir() {
        candidates.push(dir.join("icon.png"));
        candidates.push(dir.join("icon.ico"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("icon.png"));
            candidates.push(dir.join("icon.ico"));
        }
    }
    for path in candidates {
        if let Ok(bytes) = std::fs::read(&path) {
            if let Some(icon) = decode_png_icon(&bytes) {
                return Some(icon);
            }
        }
    }
    // Bundled icon, always present.
    decode_png_icon(EMBEDDED_ICON_PNG)
}

/// Decode a PNG (or ICO) into RGBA icon data using the `image` crate (already in
/// the GUI dependency tree via eframe).
fn decode_png_icon(bytes: &[u8]) -> Option<egui::IconData> {
    let img = image::load_from_memory(bytes).ok()?.into_rgba8();
    let (w, h) = img.dimensions();
    Some(egui::IconData {
        rgba: img.into_raw(),
        width: w,
        height: h,
    })
}

