//! # T2 TOTP Authenticator (`t2totp`)
//!
//! A small, single-purpose tool for managing the **TOTP** profiles stored on a
//! Token2 **second-generation** FIDO2 key (the TOTP-capable models: T2F2-ALU,
//! T2F2-NFC, T2F2-NFC-Slim, T2F2-Bio, T2F2-Bio2), over **USB-HID** or
//! **NFC/PC-SC**.
//!
//! It does one thing — Token2 FIDO TOTP — and nothing else: no other-vendor
//! OATH, no OpenPGP/PIV, no FIDO2 credential management, no programmable tokens.
//! The NFC/PC-SC path identifies a Token2 key by **reading its serial number**,
//! not by the reader's name/VID/PID, so a key tapped on a generic NFC reader is
//! still recognised.
//!
//! ## Auto-OTP `[A]` tag
//!
//! Token2's Windows app marks the single profile its global hotkey emits with an
//! `[A]` tag appended to the issuer. That tag is plain text in the issuer field,
//! so it round-trips: `add --auto` appends it and `list` flags it. (Driving a
//! global hotkey to type the code is OS-specific and outside this CLI's scope.)
//!
//! Secrets are read from stdin or `$T2TOTP_SECRET`, never from argv, and are
//! zeroized after use.

#![forbid(unsafe_code)]

use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use t2totp::entry::{Algorithm, OtpType, WriteEntry};
use t2totp::transport::{Error as TError, Interface, OtpSession, PcScTransport};
use t2totp::{proto, AUTO_TAG};
use zeroize::{Zeroize, Zeroizing};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Error::Usage(msg)) => {
            eprintln!("{msg}\n");
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
        Err(Error::Device(e)) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
        Err(Error::Other(msg)) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

const BANNER: &str = "\
  ┌─────────────┐
  │   ┌┐ ┌─┐    │   T2 TOTP Authenticator
  │   │ │ ┌┘    │   for Token2 second-generation FIDO2 keys
  │   ┴ ┴ └─    │
  └─────────────┘";

const USAGE: &str = "\
t2totp — TOTP authenticator for Token2 second-generation FIDO2 keys

USAGE:
    t2totp [GLOBAL OPTS] <COMMAND> [ARGS]

GLOBAL OPTS:
    --transport <auto|hid|nfc>   Interface to use (default: auto)
    --reader <name>              Pin a specific PC/SC reader (serial-confirmed)
    --pin                        Verify the OTP PIN first (read from $T2TOTP_PIN/stdin)
    --debug                      Trace device I/O on stderr

COMMANDS:
    info                         Show the connected key (serial, transport, TOTP support)
    readers                      List PC/SC readers and flag Token2 FIDO keys (by serial)
    list                         List stored profiles with live TOTP codes
    code <issuer> <account>      Print the current code for one profile
    add <issuer> <account>       Add a TOTP profile (secret via stdin or $T2TOTP_SECRET)
                                   --auto            append the [A] Auto-OTP tag to the issuer
                                   --sha256          use SHA-256 (default SHA-1)
                                   --period <sec>    TOTP step (default 30)
                                   --digits <4..10>  code length (default 6)
                                   --touch           require a button press to emit the code
    delete <issuer> <account>    Delete a profile
    erase --yes                  Erase ALL profiles on the key
    pin status                   Show OTP-PIN state (set?, retries left)
    pin set                      Set an OTP PIN (privacy protection)
    pin change                   Change the OTP PIN
    pin remove                   Remove the OTP PIN
    pin lock                     Close the PIN read/write window now
                                   PINs are read from $T2TOTP_PIN or stdin, never argv

Notes:
  * Token2 FIDO keys only; HOTP/other-vendor/programmable-token features are absent.
  * The secret is read from stdin (or $T2TOTP_SECRET), never from the command line.
  * NFC/PC-SC keys are identified by reading their serial, not by reader name.
  * OTP-PIN 'privacy protection' requires R3.4 firmware; on a protected key,
    pass --pin to list/code so they can return codes. Device authenticity
    (the P-521 agreement signature) is NOT verified by this client yet.";

enum Error {
    Usage(String),
    Device(TError),
    Other(String),
}

impl From<TError> for Error {
    fn from(e: TError) -> Self {
        Error::Device(e)
    }
}

struct Globals {
    iface: Interface,
    debug: bool,
    /// Explicit PC/SC reader name (serial-confirmed) — overrides auto-detect.
    reader: Option<String>,
    /// When set, open + verify an OTP-PIN session before read commands so a
    /// privacy-protected key returns codes. The value is read from
    /// `$T2TOTP_PIN` / stdin, never argv — this flag is just a toggle.
    verify_pin: bool,
    /// True only if the user passed `--transport` explicitly. PIN operations
    /// run over CCID/PC-SC on the key, so when the transport was left at its
    /// default they force NFC rather than letting `auto` land on HID (whose
    /// OTP applet answers PIN commands with 6A86 on these models).
    iface_explicit: bool,
}

fn run(args: &[String]) -> Result<(), Error> {
    let (mut globals, rest) = parse_globals(args)?;
    let (cmd, rest_args) = match rest.split_first() {
        Some(x) => x,
        None => {
            println!("{BANNER}\n");
            println!("{USAGE}");
            return Ok(());
        }
    };
    // Global flags are also accepted *after* the command, so
    // `t2totp pin set --transport nfc` works as well as the leading form.
    let cmd_args_owned = merge_trailing_globals(&mut globals, rest_args)?;
    let cmd_args: &[String] = &cmd_args_owned;

    match cmd.as_str() {
        "help" | "--help" | "-h" => {
            println!("{BANNER}\n");
            println!("{USAGE}");
            Ok(())
        }
        "info" => cmd_info(&globals),
        "readers" => cmd_readers(&globals),
        "list" => cmd_list(&globals),
        "code" => cmd_code(&globals, cmd_args),
        "add" => cmd_add(&globals, cmd_args),
        "delete" | "del" | "rm" => cmd_delete(&globals, cmd_args),
        "erase" => cmd_erase(&globals, cmd_args),
        "pin" => cmd_pin(&globals, cmd_args),
        other => Err(Error::Usage(format!("unknown command: {other}"))),
    }
}

fn parse_globals(args: &[String]) -> Result<(Globals, &[String]), Error> {
    let mut iface = Interface::Auto;
    let mut iface_explicit = false;
    let mut debug = false;
    let mut reader: Option<String> = None;
    let mut verify_pin = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--transport" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| Error::Usage("--transport needs a value".into()))?;
                iface = match v.as_str() {
                    "auto" => Interface::Auto,
                    "hid" | "usb" => Interface::Hid,
                    "nfc" | "ccid" | "pcsc" => Interface::Nfc,
                    other => {
                        return Err(Error::Usage(format!(
                            "--transport must be auto|hid|nfc, got {other}"
                        )))
                    }
                };
                iface_explicit = true;
                i += 2;
            }
            "--reader" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| Error::Usage("--reader needs a PC/SC reader name".into()))?;
                reader = Some(v.clone());
                i += 2;
            }
            "--debug" => {
                debug = true;
                i += 1;
            }
            "--pin" => {
                verify_pin = true;
                i += 1;
            }
            _ => break,
        }
    }
    Ok((
        Globals {
            iface,
            debug,
            reader,
            verify_pin,
            iface_explicit,
        },
        &args[i..],
    ))
}

/// Pull any global flags that appear *after* the subcommand out of `args`,
/// applying them to `g`, and return the remaining (non-global) arguments. This
/// lets `--transport`, `--reader`, `--pin`, and `--debug` be written in either
/// position.
fn merge_trailing_globals(g: &mut Globals, args: &[String]) -> Result<Vec<String>, Error> {
    let mut out = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--transport" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| Error::Usage("--transport needs a value".into()))?;
                g.iface = match v.as_str() {
                    "auto" => Interface::Auto,
                    "hid" | "usb" => Interface::Hid,
                    "nfc" | "ccid" | "pcsc" => Interface::Nfc,
                    other => {
                        return Err(Error::Usage(format!(
                            "--transport must be auto|hid|nfc, got {other}"
                        )))
                    }
                };
                g.iface_explicit = true;
                i += 2;
            }
            "--reader" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| Error::Usage("--reader needs a PC/SC reader name".into()))?;
                g.reader = Some(v.clone());
                i += 2;
            }
            "--pin" => {
                g.verify_pin = true;
                i += 1;
            }
            "--debug" => {
                g.debug = true;
                i += 1;
            }
            _ => {
                out.push(args[i].clone());
                i += 1;
            }
        }
    }
    Ok(out)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn open(g: &Globals) -> Result<OtpSession, Error> {
    // When --pin is requested we need the CCID/PC-SC path (see open_for_pin);
    // otherwise honour the requested/auto transport for ordinary read commands.
    let mut s = if g.verify_pin {
        open_for_pin(g)?
    } else if let Some(name) = &g.reader {
        OtpSession::open_pcsc_reader(name, g.debug)?
    } else {
        OtpSession::open(g.iface, g.debug)?
    };
    if g.verify_pin {
        let pin = read_pin("OTP PIN")?;
        s.verify_pin(&pin)?;
    }
    Ok(s)
}

// --- commands ---------------------------------------------------------------

fn cmd_info(g: &Globals) -> Result<(), Error> {
    let mut s = open(g)?;
    let transport = if s.is_pcsc() { "NFC / PC-SC" } else { "USB-HID" };
    println!("Token2 FIDO2 key");
    println!("  transport : {transport}");

    let serial = s
        .cached_serial()
        .map(|x| x.to_vec())
        .or_else(|| s.read_serial().ok());
    match serial {
        Some(x) => println!("  serial    : {}", proto::hex(&x)),
        None => println!("  serial    : (unavailable on this model/reader)"),
    }

    match s.read_device_info() {
        Ok(info) => {
            if info.has_config_byte() {
                println!(
                    "  TOTP      : {}",
                    if info.totp_supported() {
                        "supported"
                    } else {
                        "NOT supported (first-gen key — HOTP only)"
                    }
                );
                println!("  NFC       : {}", yes_no(info.nfc_supported()));
                println!("  FIDO PIN  : {}", yes_no(info.fido_pin_set()));
            } else {
                println!("  TOTP      : (device returned a short config block; unknown)");
            }
        }
        Err(e) => println!("  device-info unavailable: {e}"),
    }
    Ok(())
}

/// List every PC/SC reader and say whether a Token2 FIDO key is present —
/// determined by **reading the serial**, not the reader's name.
fn cmd_readers(g: &Globals) -> Result<(), Error> {
    let readers = PcScTransport::discover(g.debug)?;
    if readers.is_empty() {
        println!("no PC/SC readers connected");
        return Ok(());
    }
    println!("PC/SC readers ({}):", readers.len());
    for r in &readers {
        match r.serial_hex() {
            Some(serial) => println!("  [Token2 FIDO] {}  serial={serial}", r.reader_name),
            None => println!("  [other/empty] {}", r.reader_name),
        }
    }
    Ok(())
}

fn cmd_list(g: &Globals) -> Result<(), Error> {
    let mut s = open(g)?;
    let entries = s.enumerate(now_secs())?;
    if entries.is_empty() {
        println!("no profiles stored on the key");
        return Ok(());
    }
    println!("{} profile(s):", entries.len());
    for e in &entries {
        let auto = if e.app_name.contains(AUTO_TAG) {
            " (Auto-OTP)"
        } else {
            ""
        };
        let label = if e.app_name.is_empty() {
            e.account_name.clone()
        } else {
            format!("{}:{}", e.app_name, e.account_name)
        };
        let touch = if e.button_required { " [touch]" } else { "" };
        match &e.code {
            Some(code) => println!(
                "  {:4} {label}{auto}{touch}  ->  {code}",
                e.otp_type.as_str()
            ),
            None => println!(
                "  {:4} {label}{auto}{touch}  ->  (touch key to view)",
                e.otp_type.as_str()
            ),
        }
    }
    Ok(())
}

fn cmd_code(g: &Globals, args: &[String]) -> Result<(), Error> {
    let (issuer, account) = two_args(args, "code")?;
    let mut s = open(g)?;
    if !s.is_pcsc() {
        s.set_button_prompt(Box::new(|| eprintln!("touch your key to release the code...")));
    }
    let entry = s.read_entry(now_secs(), issuer, account)?;
    match entry.code {
        Some(code) => {
            println!("{code}");
            Ok(())
        }
        None => Err(Error::Other("the key returned no code for that profile".into())),
    }
}

fn cmd_add(g: &Globals, args: &[String]) -> Result<(), Error> {
    let mut positionals: Vec<&String> = Vec::new();
    let mut auto = false;
    let mut sha256 = false;
    let mut touch = false;
    let mut period: u16 = 30;
    let mut digits: u8 = 6;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--auto" => auto = true,
            "--sha256" => sha256 = true,
            "--touch" => touch = true,
            "--period" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| Error::Usage("--period needs a value".into()))?;
                period = v
                    .parse()
                    .map_err(|_| Error::Usage("--period must be 1..=65535 seconds".into()))?;
                if period == 0 {
                    return Err(Error::Usage("--period must be at least 1 second".into()));
                }
            }
            "--digits" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| Error::Usage("--digits needs a value".into()))?;
                digits = v
                    .parse()
                    .map_err(|_| Error::Usage("--digits must be 4..=10".into()))?;
                if !(4..=10).contains(&digits) {
                    return Err(Error::Usage("--digits must be between 4 and 10".into()));
                }
            }
            flag if flag.starts_with("--") => {
                return Err(Error::Usage(format!("unknown flag for add: {flag}")))
            }
            _ => positionals.push(&args[i]),
        }
        i += 1;
    }

    if positionals.len() != 2 {
        return Err(Error::Usage(
            "add needs <issuer> <account> (and a secret on stdin or $T2TOTP_SECRET)".into(),
        ));
    }
    let base_issuer = positionals[0].as_str();
    let account = positionals[1].as_str();

    let issuer_owned;
    let issuer = if auto && !base_issuer.contains(AUTO_TAG) {
        issuer_owned = format!("{base_issuer}{AUTO_TAG}");
        issuer_owned.as_str()
    } else {
        base_issuer
    };

    let secret_b32 = read_secret()?;
    let seed = proto::decode_base32_seed(&secret_b32)
        .map_err(|m| Error::Other(format!("invalid Base32 secret: {m}")))?;

    let we = WriteEntry {
        otp_type: OtpType::Totp,
        algorithm: if sha256 {
            Algorithm::Sha256
        } else {
            Algorithm::Sha1
        },
        timestep: period,
        code_length: digits,
        button_required: touch,
        app_name: issuer,
        account_name: account,
        seed: &seed,
    };

    let mut s = open(g)?;
    // On a PIN-protected key the write needs the PIN (opens the window and
    // provides the agreement pubkey the seal reuses). If the user already passed
    // --pin, open() verified it; otherwise prompt now when the key is protected.
    let pin = if !g.verify_pin && s.pin_is_set().unwrap_or(false) {
        Some(read_pin("OTP PIN")?)
    } else {
        None
    };
    s.write_entry_pinned(&we, pin.as_deref().map(|z| z.as_str()))?;
    println!(
        "added TOTP profile {}:{}{}",
        issuer,
        account,
        if auto { "  (Auto-OTP [A])" } else { "" }
    );
    Ok(())
}

fn cmd_delete(g: &Globals, args: &[String]) -> Result<(), Error> {
    let (issuer, account) = two_args(args, "delete")?;
    let mut s = open(g)?;
    let pin = if !g.verify_pin && s.pin_is_set().unwrap_or(false) {
        Some(read_pin("OTP PIN")?)
    } else {
        None
    };
    s.delete_entry_pinned(issuer, account, pin.as_deref().map(|z| z.as_str()))?;
    println!("deleted profile {issuer}:{account}");
    Ok(())
}

/// Erase **all** profiles on the key. Requires `--yes` to proceed, and a
/// confirming button press on the key when over USB-HID.
fn cmd_erase(g: &Globals, args: &[String]) -> Result<(), Error> {
    if !args.iter().any(|a| a == "--yes") {
        return Err(Error::Usage(
            "erase wipes ALL profiles on the key; pass --yes to confirm".into(),
        ));
    }
    let mut s = open(g)?;
    if !s.is_pcsc() {
        s.set_button_prompt(Box::new(|| eprintln!("touch your key to confirm the erase...")));
    }
    s.erase_all()?;
    println!("erased all profiles");
    Ok(())
}

/// OTP-PIN management: `pin status|set|change|remove`.
fn cmd_pin(g: &Globals, args: &[String]) -> Result<(), Error> {
    let (sub, _rest) = args
        .split_first()
        .ok_or_else(|| Error::Usage("pin needs a subcommand: status|set|change|remove".into()))?;
    match sub.as_str() {
        "status" => {
            let mut s = open_no_verify(g)?;
            let flag = s.pin_status()?;
            if flag.is_set() {
                println!("OTP PIN: set");
                println!("  length      : {} byte(s)", flag.pin_len);
                println!("  retries left : {}", flag.retries_left);
                println!("  max retries  : {}", flag.max_retries);
            } else {
                println!("OTP PIN: not set");
            }
            Ok(())
        }
        "set" => {
            let mut s = open_no_verify(g)?;
            let pin = read_pin("new OTP PIN")?;
            let confirm = read_pin("confirm OTP PIN")?;
            if pin.as_str() != confirm.as_str() {
                return Err(Error::Other("PINs did not match".into()));
            }
            s.set_pin(&pin)?;
            println!("OTP PIN set");
            Ok(())
        }
        "change" => {
            let mut s = open_no_verify(g)?;
            let current = read_pin("current OTP PIN")?;
            let new = read_pin("new OTP PIN")?;
            let confirm = read_pin("confirm new OTP PIN")?;
            if new.as_str() != confirm.as_str() {
                return Err(Error::Other("new PINs did not match".into()));
            }
            s.change_pin(&current, &new)?;
            println!("OTP PIN changed");
            Ok(())
        }
        "remove" => {
            let mut s = open_no_verify(g)?;
            let current = read_pin("current OTP PIN")?;
            s.remove_pin(&current)?;
            println!("OTP PIN removed");
            Ok(())
        }
        "lock" => {
            let mut s = open_no_verify(g)?;
            s.lock_pin()?;
            println!("OTP PIN window locked");
            Ok(())
        }
        other => Err(Error::Usage(format!(
            "unknown pin subcommand: {other} (use status|set|change|remove|lock)"
        ))),
    }
}

/// Open a session WITHOUT auto-verifying a PIN — the pin subcommands drive the
/// session themselves (and set/verify must not double-prompt).
fn open_no_verify(g: &Globals) -> Result<OtpSession, Error> {
    let s = open_for_pin(g)?;
    Ok(s)
}

/// Open a session for OTP-PIN work. PIN commands run over the CCID/PC-SC
/// interface on the key (the same path the GUI uses); the HID OTP applet
/// answers them with `6A86` on these models. So unless the user explicitly
/// chose a transport, force NFC/PC-SC here, and refuse to proceed on a HID
/// session with an actionable message.
fn open_for_pin(g: &Globals) -> Result<OtpSession, Error> {
    if let Some(name) = &g.reader {
        return Ok(OtpSession::open_pcsc_reader(name, g.debug)?);
    }
    let iface = if g.iface_explicit {
        g.iface
    } else {
        // Default (unspecified) transport -> use NFC/PC-SC for PIN ops.
        Interface::Nfc
    };
    let s = OtpSession::open(iface, g.debug)?;
    if !s.is_pcsc() {
        return Err(Error::Other(
            "OTP-PIN commands must run over CCID/PC-SC (a contact or NFC reader), \
             but the key was opened over USB-HID. Re-run with `--transport nfc` \
             and the key on a PC/SC reader (this is the same interface the GUI uses)."
                .into(),
        ));
    }
    Ok(s)
}

// --- helpers ----------------------------------------------------------------


fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

fn two_args<'a>(args: &'a [String], cmd: &str) -> Result<(&'a str, &'a str), Error> {
    match args {
        [issuer, account] => Ok((issuer.as_str(), account.as_str())),
        _ => Err(Error::Usage(format!("{cmd} needs <issuer> <account>"))),
    }
}

/// Read the Base32 secret from `$T2TOTP_SECRET` if set, else from stdin. Never
/// echoes the secret; zeroizes the buffer on drop.
fn read_secret() -> Result<Zeroizing<String>, Error> {
    if let Some(val) = std::env::var_os("T2TOTP_SECRET") {
        let s = val
            .into_string()
            .map_err(|_| Error::Other("T2TOTP_SECRET was not valid UTF-8".into()))?;
        return Ok(Zeroizing::new(s.trim().to_string()));
    }

    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprint!("Base32 secret: ");
        let _ = std::io::stderr().flush();
    }
    let mut buf = Zeroizing::new(String::new());
    stdin
        .read_to_string(&mut buf)
        .map_err(|e| Error::Other(format!("failed to read secret from stdin: {e}")))?;
    let trimmed = buf.trim().to_string();
    if trimmed.is_empty() {
        return Err(Error::Other(
            "no secret provided (pipe it on stdin or set $T2TOTP_SECRET)".into(),
        ));
    }
    Ok(Zeroizing::new(trimmed))
}

/// Read an OTP PIN from `$T2TOTP_PIN` if set, else from the terminal with the
/// input **masked** (no echo). Zeroizes on drop. `label` is the prompt shown.
fn read_pin(label: &str) -> Result<Zeroizing<String>, Error> {
    if let Some(val) = std::env::var_os("T2TOTP_PIN") {
        let s = val
            .into_string()
            .map_err(|_| Error::Other("T2TOTP_PIN was not valid UTF-8".into()))?;
        return Ok(Zeroizing::new(s.trim().to_string()));
    }
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        // Masked prompt: nothing is echoed as the PIN is typed. Works on the
        // Windows console as well as Unix ttys.
        let entered = rpassword::prompt_password(format!("{label}: "))
            .map_err(|e| Error::Other(format!("failed to read PIN: {e}")))?;
        let mut entered = Zeroizing::new(entered);
        let trimmed = entered.trim().to_string();
        entered.zeroize();
        if trimmed.is_empty() {
            return Err(Error::Other("no PIN provided".into()));
        }
        return Ok(Zeroizing::new(trimmed));
    }
    // Non-interactive (piped): take the whole stdin as the PIN.
    let mut buf = Zeroizing::new(String::new());
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| Error::Other(format!("failed to read PIN from stdin: {e}")))?;
    let trimmed = buf.trim().to_string();
    if trimmed.is_empty() {
        return Err(Error::Other(
            "no PIN provided (pipe it on stdin or set $T2TOTP_PIN)".into(),
        ));
    }
    Ok(Zeroizing::new(trimmed))
}
