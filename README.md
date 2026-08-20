<p align="center">
  <img src="assets/logo.svg" alt="T2 TOTP Authenticator" width="560">
</p>


<h1 align="center">T2 TOTP Authenticator</h1>

<p align="center">
  <em>A small, dedicated TOTP app for Token2 <strong>PIN+ series</strong> FIDO2 keys —<br>
  with the one-keystroke <strong>Auto-OTP</strong> hotkey.</em>
</p>

<p align="center">
  <img alt="Open source" src="https://img.shields.io/badge/open%20source-yes-1E8E3E?style=flat-square">
  <img alt="Built with Rust" src="https://img.shields.io/badge/built%20with-Rust-F20043?style=flat-square">
  <img alt="License" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-1B2A4A?style=flat-square">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows-F0A830?style=flat-square">
</p>

---

> **ⓘ Supported keys: the Token2 PIN+ series only.** This app works with Token2
> **PIN+ series** FIDO2 keys. Older 
> first-generation keys (plain `T2F2`, `T2F2-TypeC`) which only have HOTP, are
> **not** supported for TOTP.

## What this is

Token2's PIN+ series FIDO2 keys can emulate the **TOTP** protocol. Doing a
TOTP login the long way — find the profile in an app, copy the code, switch to
the login page, paste, submit — is **seven steps** for something you might do
many times a day.

**T2 TOTP Authenticator** collapses that into **one keystroke**. Its headline
feature is **Auto-OTP**: press a global hotkey and the current one-time code for
your tagged profile is typed straight into whatever field has focus (optionally
followed by Enter). If the key is plugged in and the app is running, logging in
is a single hotkey press.

This is a **dedicated TOTP app** — it manages TOTP profiles and does Auto-OTP,
and nothing else. For the full feature set (other credential types, more
provisioning options, and so on) use Token2's full **Companion app**. This tool
is for people who want a small, fast, focused TOTP experience.

> This is an open-source, independent reimplementation of the original Token2
> *T2F2 TOTP Authenticator*, rewritten from scratch in **Rust**. It is released
> under the MIT or Apache-2.0 licenses — see [Licensing](#licensing).

## Auto-OTP — the idea

Instead of the seven-step copy-and-paste dance, you press a hotkey
(for example **Ctrl + Alt + Z**) and the code is sent to the focused input.

> **ⓘ For technical reasons, the shortcut is limited to left Ctrl + Alt + a
> letter** from a fixed set chosen not to clash with common shortcuts:
> **A, B, C, F, N, Q, S, V, X, Z**.

A key can hold up to **50 TOTP profiles**, but **only one** profile can be used
with Auto-OTP. That profile is marked with a special **`[A]`** tag appended to
its issuer.

So instead of seven steps, a TOTP login becomes three (plug in the key, focus
the field, press the hotkey) — and just **one** when the key is already plugged
in and the app is already running.

## The interface

The window lists your TOTP profiles with their live codes and a countdown ring.
The profile enabled for Auto-OTP is flagged with an **Auto-OTP** badge (the
`[A]` tag on its issuer). From the header you can pick the transport, add a
profile, refresh, open Settings, and Exit.

<img width="555" height="575" alt="image" src="https://github.com/user-attachments/assets/206c6892-b623-4b2b-8969-d67d7132d2ca" />

<img width="555" height="589" alt="image" src="https://github.com/user-attachments/assets/a4ebd180-e899-45b6-b735-9d5da6b5c9af" />


## Download & run

> **Releasing for Windows.** The original project was Windows-only, and this is
> a Windows-first release. Because it's written in Rust, **macOS and Linux
> builds are possible too** — but they are **untested**, mainly because of
> OS-specific behaviour around the global hotkey and synthetic keystrokes. See
> [Other platforms](#other-platforms).

T2 TOTP Authenticator is a self-contained executable — no installer, no runtime
to deploy. Download it, put it somewhere convenient, and run it.

- **Admin rights:** not required in normal use. If the key has been configured
  to **disable HID USB mode**, TOTP data is reachable only over the FIDO
  channel, which on Windows needs administrator rights — in that case run the
  app as administrator.

## Settings & configuration

Open **Settings** (the ⚙ button) to configure Auto-OTP:

- **Shortcut** — fixed to **Ctrl + Alt +** one of the allowed letters
  (A, B, C, F, N, Q, S, V, X, Z).
- **Press Enter after typing the code** — when on, an Enter keystroke is sent
  after the code so the login submits automatically.

Settings are saved to a small text file so they persist between runs and can be
pre-deployed alongside the executable. On Windows it lives at:

```
%APPDATA%\t2totp\settings.conf
```

(e.g. `C:\Users\<you>\AppData\Roaming\t2totp\settings.conf`). It's a simple
`key = value` file; the values that matter are:

```ini
# which transport to use: auto | hid | nfc
transport = auto

# Auto-OTP hotkey
hotkey_enabled = true
hotkey_key = KeyZ            # the letter: KeyA, KeyB, KeyC, KeyF, KeyN, KeyQ, KeyS, KeyV, KeyX, KeyZ
hotkey_append_enter = true   # send Enter after the code (true/false)
```

The same values are what the Settings dialog writes, so you normally never edit
this by hand — but you can ship a prepared file to standardise the hotkey across
machines.

## Adding a TOTP profile

You provision a profile from the **TOTP secret** of the account you're securing.
Below is the **Office 365 / Microsoft Entra (Azure) MFA** flow as an example.

> **⚠ These are full-featured FIDO2 keys.** For Microsoft accounts you can use
> the more secure **passwordless** method instead of TOTP MFA, and we recommend
> passwordless whenever it's an option. TOTP MFA remains useful where
> passwordless isn't available.

Have the key plugged in and the app running before you start.

### Step 1 — Get the TOTP secret

1. Sign in and open your security info:
   <https://mysignins.microsoft.com/security-info>
2. Choose **Add method → Authenticator app**.
3. When prompted for Microsoft Authenticator, click **I want to use a different
   authenticator app** (Microsoft Authenticator uses a different protocol that
   hardware tokens can't accept).
4. Click **Next** until the QR code is shown, then click **Can't scan image?**
   to reveal the **secret key**. Keep this page open.

### Step 2 — Add the secret to your key

1. In T2 TOTP Authenticator, click **+ Add** to open the form.
2. Fill it in:
   - **Issuer** — what the code is for, e.g. `O365`.
     > **To use this profile with Auto-OTP, tick _Auto-OTP [A]_** (or append the
     > `[A]` tag yourself). This is what marks the single Auto-OTP profile.
   - **Account** — your username.
   - **Base32 secret** — paste the secret from Step 1.
   - Adjust **SHA-256**, **digits**, **period**, or **require touch** only if the
     provider needs non-default values (Microsoft uses the defaults).
3. Click **Add**. The profile appears in the list with its live code.

> **Scan QR from the screen.** If you built with the optional `qr` feature, the
> Add form has a **Scan QR from screen** button: display the provider's QR code,
> click it, and the issuer, account, secret, algorithm, digits, and period are
> filled in automatically. Everything is captured and decoded locally — nothing
> is uploaded. If no TOTP QR is on screen, or it carries no secret, you get a
> clear message and nothing changes.

### Step 3 — Verify

Back on the Microsoft page, click **Next** and enter the current code shown for
your new profile. This is a good first try of **Auto-OTP**: if you tagged the
profile `[A]`, just focus the code field and press your hotkey
(e.g. **Ctrl + Alt + Z**) instead of typing the six digits.

## FAQ

**Can I turn Auto-OTP on for an existing profile?**
No. It can only be set when the profile is created — for security reasons the
device doesn't allow changing a TOTP slot's settings afterwards. Re-add the
profile with the `[A]` tag if you need it.

**Can I have more than one Auto-OTP profile?**
The `[A]` tag is just text appended to the issuer, so technically yes — but only
**one** is used by Auto-OTP. If several are tagged, the list is sorted and the
last one wins. Keep it to a single `[A]` profile to avoid surprises.

**Why might the app need administrator rights?**
Only if the key has **HID USB mode disabled**. Then TOTP data is reachable only
over the FIDO channel, which requires admin rights on Windows. With HID enabled
(the default), no elevation is needed.

**Where are my profiles stored?**
On the key itself — never on the PC. The app only reads codes and writes new
profiles to the device.

**Is the Auto-OTP Enter reliable on rapid presses?**
Yes. When the hotkey fires, the app first releases any held modifiers, types the
digits, then sends a clean Enter — so each press submits correctly even if you
press the hotkey repeatedly.

## Other platforms

The app is written in Rust and is **released for Windows**, matching the
original project. macOS and Linux are *buildable* from the same source, but are
**untested** and not part of this release. The parts most likely to need
platform-specific work are the **global hotkey** registration and **synthetic
keystrokes**:

- **Windows** — fully supported.
- **macOS** — should work but is untested; the OS will prompt for Accessibility
  permission the first time the app types on your behalf.
- **Linux (X11)** — should work but is untested.
- **Linux (Wayland)** — the compositor restricts global hotkeys and synthetic
  input; these may require a portal or simply not be permitted.

If you build for one of these and hit an OS-specific issue, contributions are
welcome.

## Command-line tool (`t2totp`)

Alongside the GUI, the project ships a small command-line tool, `t2totp`, for
scripting and headless use — listing codes, adding/removing profiles, and
inspecting the key. It talks to the same key over **USB-HID** or **NFC / PC-SC**
(auto-detected, PC/SC tried first).

```
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
```

**The secret is never passed on the command line.** `add` reads the Base32
secret from **stdin** or the **`T2TOTP_SECRET`** environment variable, so it
never lands in your shell history or process list.

### Examples

```sh
# Identify the connected key
t2totp info

# List every profile with its current code
t2totp list

# Print one code (useful in scripts)
t2totp code O365 alice@example.com

# Add a profile, piping the secret on stdin
printf '%s' "JBSWY3DPEHPK3PXP" | t2totp add O365 alice@example.com

# Add an Auto-OTP-tagged profile (issuer gets the [A] tag), SHA-256, 8 digits
printf '%s' "JBSWY3DPEHPK3PXP" | t2totp add O365 alice@example.com --auto --sha256 --digits 8

# Or pass the secret via the environment instead of stdin
T2TOTP_SECRET="JBSWY3DPEHPK3PXP" t2totp add Acme bob

# Force NFC, or pin a specific reader by name
t2totp --transport nfc list
t2totp --reader "ACS ACR1252 1S CL Reader" list

# Delete one profile, or wipe the key (requires --yes)
t2totp delete O365 alice@example.com
t2totp erase --yes
```

### OTP PIN (privacy protection)

Keys on **R3.4** firmware (manual V1.2) support an *OTP PIN* that gates read
access to stored codes. Once a PIN is set, the key returns encrypted
enumeration data, and a tool must run an authenticated ECDH session and verify
the PIN to open a short read window before it can show codes.

```sh
# Check whether a PIN is set (and how many retries remain)
t2totp pin status

# Set / change / remove the PIN (prompted; or via $T2TOTP_PIN)
t2totp pin set
t2totp pin change
t2totp pin remove

# On a PIN-protected key, add --pin so list/code can return codes
t2totp --pin list
t2totp --pin code O365 alice@example.com
```

Like the TOTP secret, **the PIN is never passed on the command line** — it is
read from **stdin** or the **`T2TOTP_PIN`** environment variable. The
client-side policy check mirrors the firmware's rules (numeric ≥ 6 digits with
no trivial sequences/repeats; alphanumeric ≥ 10 chars mixing at least two
character classes).

The OTP-PIN commands (`status` / `set` / `verify` / `change` / `remove`) are
confirmed working against R3.4 firmware, over CCID/PC-SC, with the session
crypto matching the Token2 reference client (`token2-otp-cli`).

> ⚠️ **Security note.** The device also returns a P-521 signature over the
> session handshake that a host *should* verify to authenticate the key. This
> client establishes the encrypted ECDH session but does **not** verify that
> signature (the bundled P-256 stack can't check a P-521 signature), so device
> *authenticity* is not cryptographically checked — keep that in mind on an
> untrusted reader.
>
> There is no PIN-only reset: if you forget the PIN, `t2totp erase --yes` wipes
> all OTP entries and clears the PIN.

In the **desktop GUI** (`t2totp-gui`), a PIN-protected key prompts for its PIN
before listing codes; PIN set / change / remove live under **Settings → Manage
OTP PIN**.

Adding or deleting entries on a PIN-protected key works too. The client verifies
the PIN first (opening the write window), then writes the seed using the verified
PIN session keys rather than an ECDH blob: on a protected key `GET_ECDH_PUBKEY` is
rejected, so the write is sealed in the same authenticated session format as
PIN-mode reads reversed — `IV || AES-CBC(SessionEncKey, IV, entry) ||
HMAC(SessionMacKey, EncData)`. Pass `--pin` to `add`/`delete` on the CLI; the GUI
uses the PIN you unlocked with.

The device closes the read/write window automatically after ~5 minutes. `t2totp
pin lock` closes it immediately. In the GUI, a lock button (🔒) appears in the
toolbar whenever a protected key is unlocked; clicking it closes the window and
hides the codes. **Settings → Manage OTP PIN** also offers "Keep unlocked until I
lock or unplug" — while on, the app re-verifies with the PIN you entered before
each timeout, so the window stays open until you lock it (toolbar 🔒 or "Lock
now") or remove the key. The PIN is held in memory only, for that session, and the
code list is hidden whenever the key is locked.

### Provisioning test profiles

Helper scripts add a handful of sample profiles for testing — including one
`[A]`-tagged for Auto-OTP — using well-known RFC test secrets (reproducible
codes; **not** for real accounts):

```sh
# Windows
.\scripts\add-sample-profiles.ps1

# macOS / Linux
./scripts/add-sample-profiles.sh
```

## Building from source

Requires a Rust toolchain. The GUI is the `t2totp-gui` binary:

```sh
# GUI + global Auto-OTP hotkey
cargo build --release --features hotkey

# also include scanning a TOTP QR from the screen
cargo build --release --features "hotkey qr"
```

## Licensing

Open source, dual-licensed under either of:

- **MIT** — see [`LICENSE-MIT`](LICENSE-MIT)
- **Apache License 2.0** — see [`LICENSE-APACHE`](LICENSE-APACHE)

at your option.

---

T2 TOTP Authenticator is an independent, open-source app. For the complete
feature set, see Token2's full Companion app.
