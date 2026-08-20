//! Token2 OTP management over USB-HID or PC/SC (NFC / contact reader).
//!
//! Two transports implement the same `transmit` contract; [`OtpSession`] wraps
//! either with the high-level operations (enumerate, read-one, write, delete,
//! erase, serial read, device info).
//!
//! The PC/SC path identifies a Token2 FIDO key by **reading its serial number**,
//! not by reader name / USB VID / PID — so a key tapped on a generic NFC reader
//! is still recognised.

#![allow(dead_code)] // bundled library-style modules expose a fuller API than the CLI uses

use std::path::Path;
use std::time::{Duration, Instant};

use crate::crypto::{self, EncryptError};
use crate::entry::{
    parse_enum_page, parse_read_one, serialize_delete_entry, serialize_read_entry,
    serialize_write_entry, Entry, WriteEntry,
};
use crate::hidframe::{self, ResponseAssembler, Step};
use crate::proto::{
    self as t2, build_apdu, build_select, cmd, read_agreement_pubkey, read_otp_pin_flag,
    serialize_enum_all, validate_otp_pin, DeviceInfo, OtpError, ParseError, PinFlag,
};

#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
use std::fs::{File, OpenOptions};
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
use std::io::Write;
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
use std::sync::mpsc;
#[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
use std::thread;

/// Errors from the Token2 OTP transport / session.
#[derive(Debug)]
pub enum Error {
    /// No Token2 OTP-capable device was found on any transport.
    NotDetected,
    /// A transport opened but I/O failed partway.
    Transport(String),
    /// HID frame-level error.
    Frame(hidframe::FrameError),
    /// The applet returned a non-success status word.
    Applet(OtpError),
    /// A response could not be parsed.
    Parse(ParseError),
    /// The ECDH+AES seal failed.
    Encrypt(EncryptError),
    /// PC/SC service / reader error.
    Pcsc(pcsc::Error),
    /// The device sent a response with no status word.
    EmptyResponse,
    /// This model/reader does not expose the serial number.
    SerialUnavailable,
    /// A Token2 key was found, but the OTP applet was not reachable over HID or
    /// CCID.
    NoUsableInterface,
    /// A PIN failed the client-side policy check before being sent.
    InvalidPin(&'static str),
    /// A verify/remove/change was attempted but no PIN is set on the key.
    PinNotSet,
    /// The key has an OTP PIN set and it must be verified before entries can be
    /// listed. The GUI uses this to prompt for the PIN.
    PinRequired,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotDetected => write!(f, "no Token2 OTP-capable security key was detected"),
            Error::Transport(s) => write!(f, "transport unavailable: {}", s),
            Error::Frame(e) => write!(f, "HID framing error: {}", e),
            Error::Applet(e) => write!(f, "{}", e),
            Error::Parse(e) => write!(f, "{}", e),
            Error::Encrypt(e) => write!(f, "{}", e),
            Error::Pcsc(e) => write!(f, "PC/SC error: {}", e),
            Error::EmptyResponse => write!(f, "device returned an empty response"),
            Error::SerialUnavailable => {
                write!(f, "this model/reader does not expose the serial number")
            }
            Error::NoUsableInterface => write!(
                f,
                "the OTP applet is not reachable over HID or CCID — HID may be disabled on \
                 the key; enable it, or use a contact/NFC reader"
            ),
            Error::InvalidPin(m) => write!(f, "invalid PIN: {}", m),
            Error::PinNotSet => write!(
                f,
                "no OTP PIN is set on this key — nothing to verify (set one with `pin set`)"
            ),
            Error::PinRequired => write!(
                f,
                "this key is protected by an OTP PIN — verify the PIN first (pass --pin, or unlock in the GUI)"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<hidframe::FrameError> for Error {
    fn from(e: hidframe::FrameError) -> Self {
        Error::Frame(e)
    }
}
impl From<OtpError> for Error {
    fn from(e: OtpError) -> Self {
        Error::Applet(e)
    }
}
impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        Error::Parse(e)
    }
}
impl From<EncryptError> for Error {
    fn from(e: EncryptError) -> Self {
        Error::Encrypt(e)
    }
}
impl From<pcsc::Error> for Error {
    fn from(e: pcsc::Error) -> Self {
        Error::Pcsc(e)
    }
}

/// Callback fired while a touch-required command waits, so a front-end can show
/// "touch your key". Must be `Send` (the HID probe may run on a worker thread).
pub type ButtonPrompt = Box<dyn FnMut() + Send>;

/// The contract both transports implement.
trait Transport {
    fn transmit(&mut self, apdu: &[u8], detect_button_wait: bool) -> Result<(Vec<u8>, u16), Error>;
    fn set_button_prompt(&mut self, _cb: ButtonPrompt) {}
    fn set_debug(&mut self, _on: bool) {}
}

// ---------------------------------------------------------------------------
// USB-HID transport
// ---------------------------------------------------------------------------

enum HidIo {
    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    Hidraw(File),
    #[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
    Hidapi(hidapi::HidDevice),
}

/// USB-HID transport for the OTP applet.
pub struct HidTransport {
    io: HidIo,
    timeout: Duration,
    button_prompt: Option<ButtonPrompt>,
    debug: bool,
}

impl HidTransport {
    /// Open the first connected Token2 OTP key. Matches the Token2 vendor ID
    /// plus the FIDO usage page or product string (PIDs vary by model).
    pub fn open_first() -> Result<Self, Error> {
        let devices = crate::hid::enumerate().map_err(|e| Error::Transport(e.to_string()))?;
        let found = devices.into_iter().find(|d| {
            d.vendor_id == t2::USB_VID
                && (d.usage_page == t2::FIDO_USAGE_PAGE
                    || d.product_name.contains(t2::USB_PRODUCT)
                    || d.product_id == t2::USB_PID)
        });
        let dev = found.ok_or(Error::NotDetected)?;
        Self::open_path(&dev.path)
    }

    pub fn open_path(path: &Path) -> Result<Self, Error> {
        let io = Self::open_io(path)?;
        Ok(Self {
            io,
            timeout: Duration::from_secs(20),
            button_prompt: None,
            debug: false,
        })
    }

    /// Override the per-operation response timeout (e.g. a short probe vs. a
    /// long touch-confirmed write).
    pub fn set_timeout(&mut self, t: Duration) {
        self.timeout = t;
    }

    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    fn open_io(path: &Path) -> Result<HidIo, Error> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(HidIo::Hidraw(file))
    }

    #[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
    fn open_io(path: &Path) -> Result<HidIo, Error> {
        let api = hidapi::HidApi::new().map_err(|e| Error::Transport(e.to_string()))?;
        let cpath = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| Error::Transport("device path had a NUL".into()))?;
        let dev = api
            .open_path(&cpath)
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(HidIo::Hidapi(dev))
    }

    fn write_report(&mut self, frame: &[u8]) -> Result<(), Error> {
        match &mut self.io {
            #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
            HidIo::Hidraw(f) => f
                .write_all(frame)
                .map_err(|e| Error::Transport(e.to_string()))?,
            #[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
            HidIo::Hidapi(d) => {
                d.write(frame).map_err(|e| Error::Transport(e.to_string()))?;
            }
        }
        Ok(())
    }

    fn read_report(&mut self, buf: &mut [u8; hidframe::REPORT_PAYLOAD + 1]) -> Result<usize, Error> {
        let n = match &mut self.io {
            #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
            HidIo::Hidraw(f) => {
                use std::io::Read;
                f.read(&mut buf[..hidframe::REPORT_PAYLOAD])
                    .map_err(|e| Error::Transport(e.to_string()))?
            }
            #[cfg(any(not(target_os = "linux"), feature = "hidapi-backend"))]
            HidIo::Hidapi(d) => {
                buf.fill(0);
                // A bounded read so the caller's deadline loop can fire even if
                // the device never answers (e.g. HID applet disabled). 250ms is
                // short enough to stay responsive, long enough to avoid busy-spin.
                d.read_timeout(&mut buf[..hidframe::REPORT_PAYLOAD], 250)
                    .map_err(|e| Error::Transport(e.to_string()))?
            }
        };
        Ok(n)
    }
}

impl Transport for HidTransport {
    fn transmit(&mut self, apdu: &[u8], detect_button_wait: bool) -> Result<(Vec<u8>, u16), Error> {
        for frame in hidframe::build_send_frames(apdu) {
            self.write_report(&frame)?;
        }

        let mut asm = ResponseAssembler::new();
        let deadline = Instant::now() + self.timeout;
        let mut prompted = false;
        let mut buf = [0u8; hidframe::REPORT_PAYLOAD + 1];
        loop {
            if Instant::now() >= deadline {
                return Err(Error::Applet(OtpError::ButtonPressRequired));
            }
            let n = self.read_report(&mut buf)?;
            if n == 0 {
                // Read timed out with no data; loop to re-check the deadline.
                continue;
            }
            match asm.push(&buf[..n])? {
                Step::Busy { retries } => {
                    if detect_button_wait && !prompted && retries >= 3 {
                        if let Some(cb) = self.button_prompt.as_mut() {
                            cb();
                        }
                        prompted = true;
                    }
                }
                Step::NeedMore => {}
                Step::Done => break,
            }
        }
        asm.into_response().ok_or(Error::EmptyResponse)
    }

    fn set_button_prompt(&mut self, cb: ButtonPrompt) {
        self.button_prompt = Some(cb);
    }
    fn set_debug(&mut self, on: bool) {
        self.debug = on;
    }
}

// ---------------------------------------------------------------------------
// PC/SC transport (NFC / contact reader)
// ---------------------------------------------------------------------------

/// A connected PC/SC reader as seen by serial-probe discovery
/// ([`PcScTransport::discover`]). `serial` is `Some` only when the card was
/// positively identified as a Token2 FIDO key by reading its serial number —
/// independent of the reader's name, USB VID, or PID.
#[derive(Debug, Clone)]
pub struct ReaderInfo {
    pub reader_name: String,
    pub serial: Option<Vec<u8>>,
}

impl ReaderInfo {
    pub fn is_token2(&self) -> bool {
        self.serial.is_some()
    }
    pub fn serial_hex(&self) -> Option<String> {
        self.serial.as_ref().map(|s| t2::hex(s))
    }
}

/// PC/SC transport for the OTP applet over NFC / contact readers.
pub struct PcScTransport {
    card: pcsc::Card,
    debug: bool,
}

impl PcScTransport {
    /// Open the first reader whose card accepts the OTP-applet SELECT (legacy
    /// behaviour; does not require a serial read).
    pub fn open_first(debug: bool) -> Result<Self, Error> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
        for name in Self::reader_names(&ctx)? {
            let Some(card) = Self::connect(&ctx, &name, debug) else {
                continue;
            };
            let mut t = PcScTransport { card, debug };
            if t.select(&t2::OTP_APPLET_AID).is_ok() {
                return Ok(t);
            }
            let _ = t.card.disconnect(pcsc::Disposition::LeaveCard);
        }
        Err(Error::NotDetected)
    }

    /// Open the first Token2 FIDO key reachable over PC/SC, **identifying it by
    /// reading its serial number** rather than by reader name / VID / PID.
    ///
    /// For each reader: SELECT the OTP applet, then SELECT the FIDO applet and
    /// read the serial. Only a reader whose card answers both with a parseable
    /// serial is accepted. Returns the live transport (left on the OTP applet)
    /// plus the decoded serial.
    pub fn open_first_token2(debug: bool) -> Result<(Self, Vec<u8>), Error> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
        let mut last = Error::NotDetected;
        for name in Self::reader_names(&ctx)? {
            match Self::probe(&ctx, &name, debug) {
                Ok(pair) => return Ok(pair),
                Err(e) => {
                    if debug {
                        eprintln!(
                            "[pcsc] {} is not a Token2 FIDO key: {e}",
                            name.to_string_lossy()
                        );
                    }
                    last = e;
                }
            }
        }
        Err(last)
    }

    /// Enumerate every reader and report which hold a Token2 FIDO key (by the
    /// serial probe), without keeping connections open. Useful for a picker.
    pub fn discover(debug: bool) -> Result<Vec<ReaderInfo>, Error> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
        let mut out = Vec::new();
        for name in Self::reader_names(&ctx)? {
            let reader_name = name.to_string_lossy().into_owned();
            match Self::probe(&ctx, &name, debug) {
                Ok((t, serial)) => {
                    let _ = t.card.disconnect(pcsc::Disposition::LeaveCard);
                    out.push(ReaderInfo {
                        reader_name,
                        serial: Some(serial),
                    });
                }
                Err(_) => out.push(ReaderInfo {
                    reader_name,
                    serial: None,
                }),
            }
        }
        Ok(out)
    }

    /// Open a specific reader by name and confirm via the serial probe.
    pub fn open_named(reader_name: &str, debug: bool) -> Result<(Self, Vec<u8>), Error> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
        let cname = std::ffi::CString::new(reader_name)
            .map_err(|_| Error::Transport("reader name had a NUL".into()))?;
        Self::probe(&ctx, &cname, debug)
    }

    fn reader_names(ctx: &pcsc::Context) -> Result<Vec<std::ffi::CString>, Error> {
        let mut buf = [0u8; 4096];
        Ok(ctx.list_readers(&mut buf)?.map(|r| r.to_owned()).collect())
    }

    fn connect(ctx: &pcsc::Context, name: &std::ffi::CStr, debug: bool) -> Option<pcsc::Card> {
        match ctx.connect(name, pcsc::ShareMode::Shared, pcsc::Protocols::ANY) {
            Ok(c) => Some(c),
            Err(e) => {
                if debug {
                    eprintln!("[pcsc] shared connect failed on {:?}: {e}", name);
                }
                ctx.connect(name, pcsc::ShareMode::Exclusive, pcsc::Protocols::ANY)
                    .ok()
            }
        }
    }

    /// Connect, SELECT OTP, then read the serial over the FIDO applet to
    /// positively identify a Token2 FIDO key. On success leaves the card on the
    /// OTP applet and returns the decoded serial.
    fn probe(
        ctx: &pcsc::Context,
        name: &std::ffi::CString,
        debug: bool,
    ) -> Result<(Self, Vec<u8>), Error> {
        if debug {
            eprintln!("[pcsc] serial-probing reader: {}", name.to_string_lossy());
        }
        let card = Self::connect(ctx, name.as_c_str(), debug).ok_or(Error::NotDetected)?;
        let mut t = PcScTransport { card, debug };

        // Step 1: must speak the Token2 OTP applet.
        if let Err(e) = t.select(&t2::OTP_APPLET_AID) {
            let _ = t.card.disconnect(pcsc::Disposition::LeaveCard);
            return Err(e);
        }

        // Step 2: read the serial over the FIDO applet — the positive ID. The
        // FIDO SELECT's own status word is ignored (some firmware answers 6A81
        // yet still switches applets); identification rests on a parseable
        // GET_INFO reply.
        let _ = t.raw_transmit(&build_select(&t2::FIDO_APPLET_AID));
        let serial = match t.raw_transmit(&t2::read_serial_request()) {
            Ok((data, sw)) if OtpError::check(sw).is_ok() => match t2::parse_serial(&data) {
                Ok(s) if !s.is_empty() => s,
                _ => {
                    let _ = t.card.disconnect(pcsc::Disposition::LeaveCard);
                    return Err(Error::SerialUnavailable);
                }
            },
            _ => {
                let _ = t.card.disconnect(pcsc::Disposition::LeaveCard);
                return Err(Error::SerialUnavailable);
            }
        };

        if debug {
            eprintln!("[pcsc] identified Token2 FIDO key, serial={}", t2::hex(&serial));
        }

        // Re-select the OTP applet so the session starts on the right applet.
        if let Err(e) = t.select(&t2::OTP_APPLET_AID) {
            let _ = t.card.disconnect(pcsc::Disposition::LeaveCard);
            return Err(e);
        }
        Ok((t, serial))
    }

    fn select(&mut self, aid: &[u8]) -> Result<(), Error> {
        let (_, sw) = self.raw_transmit(&build_select(aid))?;
        OtpError::check(sw)?;
        Ok(())
    }

    fn raw_transmit(&self, apdu: &[u8]) -> Result<(Vec<u8>, u16), Error> {
        if self.debug {
            eprintln!("[pcsc send] {}", t2::hex(apdu));
        }
        let mut acc = Vec::new();
        let mut to_send = apdu.to_vec();
        let mut chunks = 0usize;
        loop {
            let mut rbuf = [0u8; 4096];
            let resp = self.card.transmit(&to_send, &mut rbuf)?;
            if self.debug {
                eprintln!("[pcsc recv] {}", t2::hex(resp));
            }
            if resp.len() < 2 {
                return Err(Error::EmptyResponse);
            }
            let split = resp.len() - 2;
            let (data, sw_bytes) = resp.split_at(split);
            acc.extend_from_slice(data);
            chunks += 1;
            if acc.len() > 65536 || chunks > 64 {
                return Err(Error::Parse(ParseError::Malformed(
                    "61xx continuation exceeded reassembly limits",
                )));
            }
            match sw_bytes[0] {
                // 61 XX: XX more bytes available; GET RESPONSE with Le=XX.
                0x61 => {
                    to_send = vec![0x00, 0xC0, 0x00, 0x00, sw_bytes[1]];
                    continue;
                }
                // 6C XX: wrong Le; re-issue the same command with Le=XX.
                0x6C => {
                    to_send = apdu.to_vec();
                    to_send.push(sw_bytes[1]);
                    acc.clear();
                    chunks = 0;
                    continue;
                }
                _ => {}
            }
            let sw = ((sw_bytes[0] as u16) << 8) | sw_bytes[1] as u16;
            return Ok((acc, sw));
        }
    }
}

impl Transport for PcScTransport {
    fn transmit(&mut self, apdu: &[u8], _detect_button_wait: bool) -> Result<(Vec<u8>, u16), Error> {
        self.raw_transmit(apdu)
    }
    fn set_debug(&mut self, on: bool) {
        self.debug = on;
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Which interface to use.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Interface {
    /// HID first, then NFC/PC-SC (serial-probed).
    Auto,
    /// USB-HID only.
    Hid,
    /// NFC / PC-SC only, identifying the key by its serial number.
    Nfc,
}

/// An open Token2 OTP management session.
pub struct OtpSession {
    transport: Box<dyn Transport>,
    is_pcsc: bool,
    serial: Option<Vec<u8>>,
    /// Session keys from a live authenticated ECDH handshake, once
    /// [`OtpSession::open_session`] has run. Needed to decrypt PIN-protected
    /// enumeration output and to issue PIN commands.
    session: Option<crate::crypto::SessionKeys>,
    /// True once [`OtpSession::verify_pin`] has opened the read window this
    /// connection, so `enumerate`/`read_entry` know to expect encrypted output.
    pin_verified: bool,
}

/// How long the HID probe waits for the OTP applet to answer over HID before
/// falling back to PC/SC.
const HID_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Probe whether the OTP applet answers over HID, taking the transport by value
/// so a probe that hangs on a blocking read cannot stall the caller.
fn probe_hid_owned(mut t: HidTransport) -> Result<HidTransport, ()> {
    // Probe with a short timeout so an unresponsive/disabled HID applet falls
    // back to PC/SC quickly instead of blocking on the default (long) timeout.
    t.set_timeout(HID_PROBE_TIMEOUT);
    #[cfg(all(target_os = "linux", not(feature = "hidapi-backend")))]
    {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let res = probe_hid(&mut t);
            let _ = tx.send((res, t));
        });
        match rx.recv_timeout(HID_PROBE_TIMEOUT + Duration::from_millis(500)) {
            Ok((Ok(()), mut t)) => {
                t.set_timeout(Duration::from_secs(20));
                Ok(t)
            }
            Ok((Err(_), _)) => Err(()),
            Err(_) => Err(()),
        }
    }
    #[cfg(not(all(target_os = "linux", not(feature = "hidapi-backend"))))]
    {
        match probe_hid(&mut t) {
            Ok(()) => {
                t.set_timeout(Duration::from_secs(20));
                Ok(t)
            }
            Err(_) => Err(()),
        }
    }
}

/// Confirm the OTP applet answers over HID via the read-only `GET_ECDH_PUBKEY`.
fn probe_hid(t: &mut HidTransport) -> Result<(), Error> {
    let (_data, sw) = t.transmit(&t2::get_ecdh_pubkey(), false)?;
    OtpError::check(sw)?;
    Ok(())
}

fn hex(b: &[u8]) -> String {
    let mut o = String::with_capacity(b.len() * 2);
    for x in b {
        o.push_str(&format!("{x:02x}"));
    }
    o
}

impl OtpSession {
    /// Open using the chosen interface.
    pub fn open(iface: Interface, debug: bool) -> Result<Self, Error> {
        match iface {
            Interface::Auto => Self::detect(debug),
            Interface::Hid => Self::detect_hid_only(debug),
            Interface::Nfc => Self::detect_pcsc_token2(debug),
        }
    }

    /// HID first; on failure, fall back to NFC/PC-SC identified by serial, then
    /// to the legacy applet-SELECT scan.
    pub fn detect(debug: bool) -> Result<Self, Error> {
        // PC/SC (NFC or contact reader) is the primary transport — it's the more
        // reliable path and works even when the key's HID OTP applet is
        // disabled. Fall back to USB-HID only if no Token2 key is found over
        // PC/SC.
        match Self::detect_pcsc_any(debug) {
            Ok(s) => Ok(s),
            Err(_) => Self::detect_hid_fallback(debug),
        }
    }

    /// USB-HID fallback used only when PC/SC finds nothing.
    fn detect_hid_fallback(debug: bool) -> Result<Self, Error> {
        match HidTransport::open_first() {
            Ok(mut t) => {
                t.set_debug(debug);
                match probe_hid_owned(t) {
                    Ok(t) => Ok(Self {
                        transport: Box::new(t),
                        is_pcsc: false,
                        serial: None,
                        session: None,
                        pin_verified: false,
                    }),
                    Err(()) => Err(Error::NoUsableInterface),
                }
            }
            Err(Error::NotDetected) => Err(Error::NoUsableInterface),
            Err(e) => Err(e),
        }
    }

    /// PC/SC fallback: prefer serial-probe identification, then legacy SELECT.
    fn detect_pcsc_any(debug: bool) -> Result<Self, Error> {
        match PcScTransport::open_first_token2(debug) {
            Ok((t, serial)) => Ok(Self {
                transport: Box::new(t),
                is_pcsc: true,
                serial: Some(serial),
                session: None,
                pin_verified: false,
            }),
            Err(_) => match PcScTransport::open_first(debug) {
                Ok(t) => Ok(Self {
                    transport: Box::new(t),
                    is_pcsc: true,
                    serial: None,
                    session: None,
                    pin_verified: false,
                }),
                Err(_) => Err(Error::NoUsableInterface),
            },
        }
    }

    /// Force USB-HID (no PC/SC fallback).
    pub fn detect_hid_only(debug: bool) -> Result<Self, Error> {
        let mut t = HidTransport::open_first()?;
        t.set_debug(debug);
        let t = probe_hid_owned(t).map_err(|()| Error::NoUsableInterface)?;
        Ok(Self {
            transport: Box::new(t),
            is_pcsc: false,
            serial: None,
            session: None,
            pin_verified: false,
        })
    }

    /// Force NFC / PC-SC, identifying the key by reading its serial number.
    pub fn detect_pcsc_token2(debug: bool) -> Result<Self, Error> {
        let (t, serial) = PcScTransport::open_first_token2(debug)?;
        Ok(Self {
            transport: Box::new(t),
            is_pcsc: true,
            serial: Some(serial),
            session: None,
            pin_verified: false,
        })
    }

    /// Open a specific PC/SC reader by name (serial-confirmed).
    pub fn open_pcsc_reader(reader_name: &str, debug: bool) -> Result<Self, Error> {
        let (t, serial) = PcScTransport::open_named(reader_name, debug)?;
        Ok(Self {
            transport: Box::new(t),
            is_pcsc: true,
            serial: Some(serial),
            session: None,
            pin_verified: false,
        })
    }

    /// True when this session is over PC/SC (NFC / contact reader).
    pub fn is_pcsc(&self) -> bool {
        self.is_pcsc
    }

    /// The serial captured during a serial-probe open, if any.
    pub fn cached_serial(&self) -> Option<&[u8]> {
        self.serial.as_deref()
    }

    /// Register a "touch your key" prompt fired while a button-required command
    /// waits (HID only).
    pub fn set_button_prompt(&mut self, cb: ButtonPrompt) {
        self.transport.set_button_prompt(cb);
    }

    /// Enumerate every stored entry, paging through `ENUM_CODES_CONTINUE` as
    /// needed. `timestamp` is UNIX seconds. An empty token yields an empty list.
    pub fn enumerate(&mut self, timestamp: u64) -> Result<Vec<Entry>, Error> {
        let first = build_apdu(cmd::ENUM_CODES, &serialize_enum_all(timestamp));
        let (data, sw) = self.transport.transmit(&first, false)?;
        if let Err(e) = OtpError::check(sw) {
            if e.is_empty_token() {
                return Ok(Vec::new());
            }
            return Err(e.into());
        }
        let page_bytes = self.maybe_decrypt_page(&data)?;
        let mut page = parse_enum_page(&page_bytes)?;
        let mut entries = page.entries;
        while page.more_pages {
            let cont = build_apdu(cmd::ENUM_CODES_CONTINUE, &timestamp.to_be_bytes());
            let (data, sw) = self.transport.transmit(&cont, false)?;
            OtpError::check(sw)?;
            let page_bytes = self.maybe_decrypt_page(&data)?;
            page = parse_enum_page(&page_bytes)?;
            entries.extend(page.entries);
        }
        Ok(entries)
    }

    /// When a PIN is set and has been verified this connection, `ENUM_CODES`
    /// returns `IV(16) || EncData || EncDataAuth(16)` under the session key
    /// instead of a plaintext page. Detect that (we only know a PIN is in force
    /// once `pin_verified` is set) and return the decrypted page bytes;
    /// otherwise pass the data through unchanged.
    fn maybe_decrypt_page(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.pin_verified {
            return Ok(data.to_vec());
        }
        let keys = self
            .session
            .as_ref()
            .ok_or(Error::Parse(ParseError::Malformed("no session for PIN decrypt")))?;
        if data.len() < 16 + 16 + 16 {
            return Err(Error::Parse(ParseError::Truncated));
        }
        let iv: [u8; 16] = data[..16].try_into().expect("checked length");
        let enc = &data[16..data.len() - 16];
        let auth = &data[data.len() - 16..];
        crate::crypto::verify_auth_tag(&keys.mac, enc, auth).map_err(Error::Encrypt)?;
        let plain = crate::crypto::session_decrypt(&keys.enc, &iv, enc).map_err(Error::Encrypt)?;
        Ok(plain.to_vec())
    }

    /// If the key has an OTP PIN set, verify `pin` to open the read/write
    /// window for this session; if no PIN is set, this is a no-op. Write and
    /// touch-read commands need the window open just like enumeration does, so
    /// call this right after opening a session that will write to a
    /// possibly-protected key. Returns [`Error::PinRequired`] when a PIN is set
    /// but `pin` is `None`.
    pub fn unlock_if_pinned(&mut self, pin: Option<&str>) -> Result<(), Error> {
        if self.pin_is_set()? {
            match pin {
                Some(p) => self.verify_pin(p)?,
                None => return Err(Error::PinRequired),
            }
        }
        Ok(())
    }

    /// Close the PIN read/write window immediately (the window a `verify_pin`
    /// opens for ~5 minutes). Sends the lock form of `VERIFY_OTP_PIN` (body =
    /// a single `0x00`). After this, protected reads/writes need a fresh verify.
    pub fn lock_pin(&mut self) -> Result<(), Error> {
        let apdu = t2::lock_otp_pin();
        let (_, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check_pin(sw)?;
        self.pin_verified = false;
        Ok(())
    }

    /// Re-open the read/write window with an already-known PIN, without a full
    /// re-handshake if a session is live. Used by a keep-unlocked keep-alive to
    /// refresh the window before the device's ~5-minute timeout. Equivalent to
    /// `verify_pin` but named for intent; safe to call repeatedly.
    pub fn reverify_pin(&mut self, pin: &str) -> Result<(), Error> {
        self.verify_pin(pin)
    }

    /// Write an entry, transparently handling a PIN-protected key. If a PIN is
    /// set, `pin` must be supplied: it is verified first (which opens the write
    /// window AND captures the agreement pubkey the seal needs, since
    /// `GET_ECDH_PUBKEY` is rejected while a PIN exists). On an unprotected key
    /// this is just `write_entry`. Returns [`Error::PinRequired`] if a PIN is set
    /// but `pin` is `None`.
    pub fn write_entry_pinned(
        &mut self,
        entry: &WriteEntry<'_>,
        pin: Option<&str>,
    ) -> Result<(), Error> {
        // If the window is already open this session (e.g. the caller passed
        // --pin, which `open()` already verified), the agreement pubkey is
        // cached and we can write straight away. Only verify if it isn't.
        if !self.pin_verified && self.pin_is_set()? {
            match pin {
                Some(p) => self.verify_pin(p)?,
                None => return Err(Error::PinRequired),
            }
        }
        self.write_entry(entry)
    }

    /// Delete an entry, transparently handling a PIN-protected key (see
    /// [`OtpSession::write_entry_pinned`]). Delete is a seed-write with an empty
    /// seed, so it takes the same protected-write path.
    pub fn delete_entry_pinned(
        &mut self,
        app_name: &str,
        account_name: &str,
        pin: Option<&str>,
    ) -> Result<(), Error> {
        if !self.pin_verified && self.pin_is_set()? {
            match pin {
                Some(p) => self.verify_pin(p)?,
                None => return Err(Error::PinRequired),
            }
        }
        self.delete_entry(app_name, account_name)
    }

    /// Returns true if the key currently has an OTP PIN set (a quick flag read
    /// that needs no session).
    pub fn pin_is_set(&mut self) -> Result<bool, Error> {
        Ok(self.pin_status()?.is_set())
    }

    /// List entries, transparently handling a PIN-protected key. If a PIN is
    /// set, `pin` must be supplied (it is verified to open the read window);
    /// when a PIN is set but `pin` is `None`, returns [`Error::PinRequired`] so
    /// a caller (e.g. the GUI) can prompt for it.
    pub fn enumerate_pinned(
        &mut self,
        timestamp: u64,
        pin: Option<&str>,
    ) -> Result<Vec<Entry>, Error> {
        if self.pin_is_set()? {
            match pin {
                Some(p) => self.verify_pin(p)?,
                None => return Err(Error::PinRequired),
            }
        }
        self.enumerate(timestamp)
    }

    /// Read a single entry by `(app, account)`, returning its live code. A
    /// button-required entry blocks until the user touches the key.
    pub fn read_entry(
        &mut self,
        timestamp: u64,
        app_name: &str,
        account_name: &str,
    ) -> Result<Entry, Error> {
        let body = serialize_read_entry(timestamp, app_name, account_name)?;
        let apdu = build_apdu(cmd::ENUM_CODES, &body);
        let (data, sw) = self.transport.transmit(&apdu, true)?;
        OtpError::check(sw)?;
        // On a PIN-protected key (after verify), the single-entry read is
        // returned encrypted just like enumeration; decrypt if the window is open.
        let data = self.maybe_decrypt_page(&data)?;
        Ok(parse_read_one(&data)?)
    }

    /// Provision (or overwrite) an entry. Fetches the device ECDH pubkey, seals
    /// the cleartext, and sends `WRITE_SEED`.
    pub fn write_entry(&mut self, entry: &WriteEntry<'_>) -> Result<(), Error> {
        let cleartext = serialize_write_entry(entry)?;
        let blob = self.seal(cleartext.as_bytes())?;
        let apdu = build_apdu(cmd::WRITE_SEED, &blob);
        let (_, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check(sw)?;
        Ok(())
    }

    /// Delete an entry by `(app, account)`: an encrypted write with empty seed.
    pub fn delete_entry(&mut self, app_name: &str, account_name: &str) -> Result<(), Error> {
        let cleartext = serialize_delete_entry(app_name, account_name)?;
        let blob = self.seal(cleartext.as_bytes())?;
        let apdu = build_apdu(cmd::WRITE_SEED, &blob);
        let (_, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check(sw)?;
        Ok(())
    }

    /// Erase every entry: a bodyless `WRITE_SEED`. Requires a confirming button
    /// press over HID.
    pub fn erase_all(&mut self) -> Result<(), Error> {
        let (_, sw) = self.transport.transmit(&t2::erase_all(), true)?;
        OtpError::check(sw)?;
        Ok(())
    }

    /// Read and parse the device-info / configuration block.
    pub fn read_device_info(&mut self) -> Result<DeviceInfo, Error> {
        let apdu = t2::read_config(64);
        let (data, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check(sw)?;
        Ok(DeviceInfo::parse(&data)?)
    }

    /// Read the serial number. The FIDO applet answers it, so over PC/SC a
    /// FIDO-applet SELECT is sent first (its status word ignored).
    pub fn read_serial(&mut self) -> Result<Vec<u8>, Error> {
        if self.is_pcsc {
            let _ = self
                .transport
                .transmit(&build_select(&t2::FIDO_APPLET_AID), false);
        }
        let (data, sw) = self.transport.transmit(&t2::read_serial_request(), false)?;
        if OtpError::check(sw).is_err() {
            return Err(Error::SerialUnavailable);
        }
        // Restore the OTP applet selection over PC/SC for any subsequent ops.
        if self.is_pcsc {
            let _ = self
                .transport
                .transmit(&build_select(&t2::OTP_APPLET_AID), false);
        }
        Ok(t2::parse_serial(&data)?)
    }


    // --- OTP PIN (privacy protection, R3.4 / manual V1.2) -------------------

    /// Read the device's OTP-PIN status without opening a session.
    pub fn pin_status(&mut self) -> Result<PinFlag, Error> {
        let apdu = read_otp_pin_flag(t2::cmd::PIN_FLAG_LC_BASE);
        let (data, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check_pin(sw)?;
        Ok(PinFlag::parse(&data)?)
    }

    /// Establish an authenticated ECDH session (`READ_AGREEMENT_PUBKEY`) and
    /// cache the derived keys on this session. Required before any PIN command
    /// and before reading PIN-protected entries.
    ///
    /// NOTE: the protocol document specifies that the device also returns an
    /// ECC-P521 signature over `hostPub || devPub` that the host *should* verify
    /// against the device's known P-521 key. This client does **not** verify
    /// that signature: the P-256 crate in the dependency set cannot check a
    /// P-521 signature, and adding a P-521 verifier is out of scope here. The
    /// ECDH exchange still provides session confidentiality, but device
    /// *authenticity* is not cryptographically checked. See the README security
    /// note before relying on this against an untrusted reader.
    pub fn open_session(&mut self) -> Result<(), Error> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::SecretKey;
        use rand_core::OsRng;

        // The Token2 reference sequence reads the PIN flag FIRST (Lc=09) before
        // the handshake — this primes/initializes the device PIN state. Skipping
        // it makes a subsequent SET fail with 6985 (conditions not satisfied).
        let prime = read_otp_pin_flag(0x09);
        let (_pdata, psw) = self.transport.transmit(&prime, false)?;
        OtpError::check_pin(psw)?;

        // One host ephemeral keypair: send its public half, derive keys from the
        // device's agreement key in the response against this same secret.
        let host_secret = SecretKey::random(&mut OsRng);
        let host_point = host_secret.public_key().to_encoded_point(false);
        let mut host_xy = [0u8; 64];
        host_xy.copy_from_slice(&host_point.as_bytes()[1..]);

        let apdu = read_agreement_pubkey(&host_xy);
        let (data, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check_pin(sw)?;
        // Response: devPub(64) || sig(132). We consume devPub; sig is currently
        // unverified (see the doc-comment above).
        if data.len() < 64 {
            return Err(Error::Parse(ParseError::Truncated));
        }
        let dev_xy = &data[..64];

        let keys = crate::crypto::derive_session_keys(&host_secret, dev_xy)
            .map_err(Error::Encrypt)?;
        self.session = Some(keys);
        self.pin_verified = false;
        Ok(())
    }

    /// Set an OTP PIN on a currently-unprotected device.
    pub fn set_pin(&mut self, pin: &str) -> Result<(), Error> {
        validate_otp_pin(pin).map_err(Error::InvalidPin)?;
        self.ensure_session()?;
        let keys = self.session.as_ref().expect("session ensured above");
        let data = crate::crypto::build_set_pin_data(keys, pin.as_bytes(), 0x64);
        let apdu = build_apdu(t2::cmd::SET_OTP_PIN, &data);
        let (_, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check_pin(sw)?;
        Ok(())
    }

    /// Verify the OTP PIN, opening the device read window for this connection so
    /// subsequent `enumerate`/`read_entry` calls return usable codes.
    pub fn verify_pin(&mut self, pin: &str) -> Result<(), Error> {
        self.ensure_session()?;
        // Fetch the verify challenge: IV || EncRand (Lc = 0x29).
        let flag_apdu = read_otp_pin_flag(t2::cmd::PIN_FLAG_LC_CHALLENGE);
        let (data, sw) = self.transport.transmit(&flag_apdu, false)?;
        OtpError::check_pin(sw)?;
        let flag = PinFlag::parse(&data)?;
        if !flag.is_set() {
            return Err(Error::PinNotSet);
        }
        let (iv, enc_rand) = flag
            .challenge
            .ok_or(Error::Parse(ParseError::Malformed("verify challenge missing")))?;

        let keys = self.session.as_ref().expect("session ensured above");
        // Rand is a raw 16-byte block with NO PKCS#7 padding — decrypt without
        // unpadding (matching the reference client's plain AES-CBC decrypt).
        let rand = crate::crypto::session_decrypt_raw(&keys.enc, &iv, &enc_rand);
        if rand.len() != 16 {
            return Err(Error::Encrypt(crate::crypto::EncryptError::BadCiphertext));
        }

        // VERIFY proof (Token2 reference construction): nested AES-CBC —
        // inner = AES(SHA256(pin), SHA256(rand)[:16], rand);
        // outer = AES(SessionEncKey, randomIV, inner); data = IV || outer.
        let data_field = crate::crypto::build_verify_pin_data(keys, pin.as_bytes(), &rand);
        let apdu = build_apdu(t2::cmd::VERIFY_OTP_PIN, &data_field);
        let (_, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check_pin(sw)?;
        self.pin_verified = true;
        Ok(())
    }

    /// Change the OTP PIN (requires knowing the current PIN).
    pub fn change_pin(&mut self, current: &str, new: &str) -> Result<(), Error> {
        validate_otp_pin(new).map_err(Error::InvalidPin)?;
        self.change_pin_inner(current, Some(new))
    }

    /// Remove the OTP PIN (a change to length 0; requires the current PIN).
    pub fn remove_pin(&mut self, current: &str) -> Result<(), Error> {
        self.change_pin_inner(current, None)
    }

    fn change_pin_inner(&mut self, current: &str, new: Option<&str>) -> Result<(), Error> {
        self.ensure_session()?;
        // The change proof binds the current PIN to the fresh Rand, like verify.
        let flag_apdu = read_otp_pin_flag(t2::cmd::PIN_FLAG_LC_CHALLENGE);
        let (data, sw) = self.transport.transmit(&flag_apdu, false)?;
        OtpError::check_pin(sw)?;
        let flag = PinFlag::parse(&data)?;
        let (iv, enc_rand) = flag
            .challenge
            .ok_or(Error::Parse(ParseError::Malformed("change challenge missing")))?;
        let keys = self.session.as_ref().expect("session ensured above");
        let rand = crate::crypto::session_decrypt_raw(&keys.enc, &iv, &enc_rand);
        if rand.len() != 16 {
            return Err(Error::Encrypt(crate::crypto::EncryptError::BadCiphertext));
        }

        let new_bytes = new.map(|s| s.as_bytes()).unwrap_or(&[]);
        let data_field =
            crate::crypto::build_change_pin_data(keys, new_bytes, current.as_bytes(), &rand);
        let apdu = build_apdu(t2::cmd::CHANGE_OTP_PIN, &data_field);
        let (_, sw) = self.transport.transmit(&apdu, false)?;
        OtpError::check_pin(sw)?;
        self.pin_verified = false;
        Ok(())
    }

    /// Open an authenticated session if one is not already cached.
    fn ensure_session(&mut self) -> Result<(), Error> {
        if self.session.is_none() {
            self.open_session()?;
        }
        Ok(())
    }

    /// ECDH handshake: fetch the device pubkey, then seal `cleartext`.
    fn seal(&mut self, cleartext: &[u8]) -> Result<Vec<u8>, Error> {
        // Two write encryptions, chosen by PIN state:
        //
        //  * PIN window open (pin_verified): the device rejects GET_ECDH_PUBKEY
        //    with 6A81, so there is no ECDH blob. Instead the write reuses the
        //    verified PIN session keys, in the same authenticated format as
        //    PIN-mode reads reversed: IV || AES-CBC(SessionEncKey, IV, pt) ||
        //    HMAC(SessionMacKey, EncData)[:16]. (This is what the Token2
        //    companion app sends; confirmed against a device capture.)
        //
        //  * Otherwise (unprotected key): fetch a fresh ephemeral device pubkey
        //    via GET_ECDH_PUBKEY and build the standard ECDH seed blob.
        if self.pin_verified {
            let keys = self
                .session
                .as_ref()
                .ok_or(Error::Parse(ParseError::Malformed(
                    "PIN verified but no session keys",
                )))?;
            return Ok(crypto::build_protected_write_data(keys, cleartext));
        }
        let (device_pub, sw) = self.transport.transmit(&t2::get_ecdh_pubkey(), false)?;
        OtpError::check(sw)?;
        // The byte layer requires the IV; entries use IV_OTP.
        Ok(crypto::encrypt_seed_payload(
            &device_pub,
            cleartext,
            &crypto::IV_OTP,
        )?)
    }
}
