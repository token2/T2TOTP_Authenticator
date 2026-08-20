//! ECDH + AES-CBC payload encryption for the seed-bearing `WRITE_SEED` command.
//!
//! Flow:
//! 1. The device's `GET_ECDH_PUBKEY` reply is 64 bytes `X || Y` (no `0x04`).
//! 2. Generate a fresh ephemeral P-256 keypair per command.
//! 3. `shared = ECDH(host_priv, device_pub)`, take the 32-byte X coordinate.
//! 4. `key = SHA256(shared)` (32 bytes).
//! 5. AES-256-CBC encrypt PKCS#7-padded cleartext with a constant IV.
//!    Freshness comes from the ephemeral keypair, not the IV.
//! 6. On-wire blob = `host_pub_xy (64) || ciphertext`.
//!
//! The IV is a **constant** by design; randomizing it breaks device-side
//! decryption.

#![allow(dead_code)] // bundled library-style modules expose a fuller API than the CLI uses

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// IV used when writing or deleting OTP entries (`WRITE_SEED`).
pub const IV_OTP: [u8; 16] = [
    0x9D, 0xD8, 0x91, 0x8E, 0x34, 0xF3, 0xCC, 0xAB, 0x08, 0xCB, 0x75, 0x18, 0xF7, 0x19, 0x38, 0xF1,
];

/// Errors from the ECDH+AES seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptError {
    /// The device pubkey was not a valid 64-byte (`X || Y`) P-256 point.
    BadDevicePubkey,
    /// A session ciphertext did not decrypt / unpad cleanly.
    BadCiphertext,
    /// A session HMAC auth tag did not match.
    BadAuthTag,
}

impl std::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptError::BadDevicePubkey => {
                write!(f, "device ECDH public key was not a valid P-256 point")
            }
            EncryptError::BadCiphertext => write!(f, "session ciphertext failed to decrypt"),
            EncryptError::BadAuthTag => write!(f, "session HMAC authentication tag mismatch"),
        }
    }
}

impl std::error::Error for EncryptError {}

/// Seal `cleartext` into the on-wire `host_pub_xy || ciphertext` blob.
///
/// `device_pub_xy` is the raw 64-byte key from `GET_ECDH_PUBKEY` (no leading
/// `0x04`). A fresh ephemeral keypair is generated per call.
pub fn encrypt_seed_payload(
    device_pub_xy: &[u8],
    cleartext: &[u8],
    iv: &[u8; 16],
) -> Result<Vec<u8>, EncryptError> {
    if device_pub_xy.len() != 64 {
        return Err(EncryptError::BadDevicePubkey);
    }

    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(device_pub_xy);
    let device_point = EncodedPoint::from_bytes(sec1).map_err(|_| EncryptError::BadDevicePubkey)?;
    let device_pub = Option::<PublicKey>::from(PublicKey::from_encoded_point(&device_point))
        .ok_or(EncryptError::BadDevicePubkey)?;

    let host_secret = SecretKey::random(&mut OsRng);
    let host_pub = host_secret.public_key();

    let shared = diffie_hellman(host_secret.to_nonzero_scalar(), device_pub.as_affine());
    let session_key = Zeroizing::new({
        let mut h = Sha256::new();
        h.update(shared.raw_secret_bytes());
        h.finalize()
    });

    let mut work = Zeroizing::new(cleartext.to_vec());
    let pad_room = 16 - (cleartext.len() % 16);
    work.resize(cleartext.len() + pad_room, 0);
    let ct_len = cleartext.len();
    let ciphertext = Aes256CbcEnc::new(session_key.as_slice().into(), iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut work, ct_len)
        .expect("buffer sized for PKCS7 padding above")
        .to_vec();

    let host_point = host_pub.to_encoded_point(false);
    let host_xy = &host_point.as_bytes()[1..];

    let mut blob = Vec::with_capacity(64 + ciphertext.len());
    blob.extend_from_slice(host_xy);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}


// ---------------------------------------------------------------------------
// Authenticated ECDH session for the OTP-PIN commands (protocol doc §6.11)
// ---------------------------------------------------------------------------

/// The two 32-byte session keys derived from a `READ_AGREEMENT_PUBKEY` exchange.
///
/// Derivation (all HMAC-SHA256), per the protocol document:
/// ```text
/// shared        = ECDH-P256(hostPriv, devPub).X          (32 bytes)
/// pu1PRKey      = HMAC(key = 0x00*32, data = shared)
/// SessionMacKey = HMAC(key = pu1PRKey, data = "TOTP HMAC key" || 0x01)
/// SessionEncKey = HMAC(key = pu1PRKey, data = "TOTP AES key"  || 0x01)
/// ```
pub struct SessionKeys {
    pub enc: Zeroizing<[u8; 32]>,
    pub mac: Zeroizing<[u8; 32]>,
}

fn hmac256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// Derive the session keys from an existing host secret and the device's
/// 64-byte agreement pubkey (`X || Y`, no leading `0x04`).
pub fn derive_session_keys(
    host_secret: &SecretKey,
    device_agreement_xy: &[u8],
) -> Result<SessionKeys, EncryptError> {
    if device_agreement_xy.len() != 64 {
        return Err(EncryptError::BadDevicePubkey);
    }
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(device_agreement_xy);
    let dev_point = EncodedPoint::from_bytes(sec1).map_err(|_| EncryptError::BadDevicePubkey)?;
    let dev_pub = Option::<PublicKey>::from(PublicKey::from_encoded_point(&dev_point))
        .ok_or(EncryptError::BadDevicePubkey)?;

    let shared = diffie_hellman(host_secret.to_nonzero_scalar(), dev_pub.as_affine());
    let pu1_pr = Zeroizing::new(hmac256(&[0u8; 32], shared.raw_secret_bytes()));
    // Session-key ladder per the Token2 reference client (token2-otp-cli):
    //   pu1PRKey      = HMAC(0x00*32, sharedX)
    //   SessionMacKey = HMAC(pu1PRKey, "TOTP HMAC key" || 0x01)
    //   SessionEncKey = HMAC(pu1PRKey, "TOTP AES key"  || 0x01)
    let mut mac_info = b"TOTP HMAC key".to_vec();
    mac_info.push(0x01);
    let mut enc_info = b"TOTP AES key".to_vec();
    enc_info.push(0x01);
    Ok(SessionKeys {
        enc: Zeroizing::new(hmac256(pu1_pr.as_slice(), &enc_info)),
        mac: Zeroizing::new(hmac256(pu1_pr.as_slice(), &mac_info)),
    })
}

/// Generate a host ephemeral P-256 keypair and derive session keys against the
/// device's 64-byte agreement pubkey. Returns the host public key as raw
/// `X || Y` (to send in `READ_AGREEMENT_PUBKEY`) and the derived keys.
///
/// Convenience wrapper around [`derive_session_keys`] for callers that do not
/// need to keep the secret around; `transport` uses the split form so the
/// pubkey it sends matches the keys it derives.
pub fn establish_session(
    device_agreement_xy: &[u8],
) -> Result<([u8; 64], SessionKeys), EncryptError> {
    let host_secret = SecretKey::random(&mut OsRng);
    let keys = derive_session_keys(&host_secret, device_agreement_xy)?;
    let host_point = host_secret.public_key().to_encoded_point(false);
    let mut host_xy = [0u8; 64];
    host_xy.copy_from_slice(&host_point.as_bytes()[1..]);
    Ok((host_xy, keys))
}

/// AES-256-CBC encrypt `cleartext` (PKCS#7) under the session key with an
/// explicit `iv`.
pub fn session_encrypt(key: &[u8; 32], iv: &[u8; 16], cleartext: &[u8]) -> Vec<u8> {
    let mut work = Zeroizing::new(cleartext.to_vec());
    let pad_room = 16 - (cleartext.len() % 16);
    work.resize(cleartext.len() + pad_room, 0);
    let ct_len = cleartext.len();
    Aes256CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut work, ct_len)
        .expect("buffer sized for PKCS7 padding above")
        .to_vec()
}

/// AES-256-CBC decrypt WITHOUT unpadding — for diagnostics only, so debug
/// output can show the raw plaintext even when PKCS#7 would reject it.
pub fn session_decrypt_raw(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Vec::new();
    }
    let mut buf = ciphertext.to_vec();
    Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map(|s| s.to_vec())
        .unwrap_or_default()
}

/// AES-256-CBC decrypt+unpad a session ciphertext under the session key.
pub fn session_decrypt(
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EncryptError> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(EncryptError::BadCiphertext);
    }
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let plain = Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| EncryptError::BadCiphertext)?;
    Ok(Zeroizing::new(plain.to_vec()))
}

/// The first 16 bytes of `HMAC(mac_key, data)` — the auth-tag form the PIN
/// commands use (`NewPinAuth`, `EncDataAuth`).
pub fn session_auth_tag(mac_key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let full = hmac256(mac_key, data);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&full[..16]);
    tag
}

/// Constant-time-ish check of a 16-byte session auth tag.
pub fn verify_auth_tag(mac_key: &[u8; 32], data: &[u8], tag: &[u8]) -> Result<(), EncryptError> {
    if tag.len() != 16 {
        return Err(EncryptError::BadAuthTag);
    }
    let expect = session_auth_tag(mac_key, data);
    let mut diff = 0u8;
    for (a, b) in expect.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }
    if diff == 0 {
        Ok(())
    } else {
        Err(EncryptError::BadAuthTag)
    }
}

/// Build the `SET_OTP_PIN` data field: `IV || NewPinEnc || NewPinAuth`, where
/// `NewPin = alg(0x07) || retry(0x64) || pinLen || pin`, PKCS#7-padded to 16.
/// Build the data field for a **PIN-protected seed write** (`WRITE_SEED` while a
/// PIN window is open). Unlike an unprotected write — which is an ECDH blob keyed
/// by a fresh `GET_ECDH_PUBKEY` — a protected write reuses the verified PIN
/// session keys, exactly like PIN-mode reads in reverse:
///
///   `IV(16) || AES-CBC(SessionEncKey, IV, cleartext) || HMAC(SessionMacKey, EncData)[:16]`
///
/// (`GET_ECDH_PUBKEY` is rejected with 6A81 on a protected key, so no ECDH blob
/// is possible; this session-key format is what the Token2 companion app sends.)
pub fn build_protected_write_data(keys: &SessionKeys, cleartext: &[u8]) -> Vec<u8> {
    let iv = random_iv();
    let enc = session_encrypt(&keys.enc, &iv, cleartext);
    let auth = session_auth_tag(&keys.mac, &enc);
    let mut out = Vec::with_capacity(16 + enc.len() + 16);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&enc);
    out.extend_from_slice(&auth);
    out
}

pub fn build_set_pin_data(keys: &SessionKeys, pin: &[u8], retry: u8) -> Vec<u8> {
    let iv = random_iv();
    let mut newpin = Vec::with_capacity(3 + pin.len());
    newpin.push(0x07); // AlgId = AES256
    newpin.push(retry);
    newpin.push(pin.len() as u8);
    newpin.extend_from_slice(pin);
    let enc = session_encrypt(&keys.enc, &iv, &newpin);
    let auth = session_auth_tag(&keys.mac, &enc);
    let mut out = Vec::with_capacity(16 + enc.len() + 16);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&enc);
    out.extend_from_slice(&auth);
    out
}

/// Build the `VERIFY_OTP_PIN` data field, matching the Token2 reference client:
///
/// ```text
/// PinHash      = SHA256(pin)                         # 32 bytes
/// IV2          = SHA256(Rand)[0:16]
/// PinHashEnc   = AES-256-CBC(key = PinHash, IV2, data = Rand)   # inner, keyed by PIN
/// IV           = random(16)
/// PinHashEnc2  = AES-256-CBC(SessionEncKey, IV, PinHashEnc)     # outer, session key
/// data field   = IV || PinHashEnc2
/// ```
///
/// `rand` is the 16-byte challenge recovered from the `Lc=0x29` flag read
/// (`Rand = AES-256-CBC-dec(SessionEncKey, flag.IV, flag.EncRand)`).
pub fn build_verify_pin_data(keys: &SessionKeys, pin: &[u8], rand: &[u8]) -> Vec<u8> {
    // Inner layer: key = SHA256(pin) (32 bytes => AES-256), IV = SHA256(rand)[:16].
    let pin_hash = sha256(pin);
    let iv2_full = sha256(rand);
    let mut iv2 = [0u8; 16];
    iv2.copy_from_slice(&iv2_full[..16]);
    // Encrypt exactly the 16-byte Rand (no padding: it is already one block).
    let inner = aes256_cbc_encrypt_nopad(&pin_hash, &iv2, rand);

    // Outer layer under the session key with a fresh IV.
    let iv = random_iv();
    let outer = aes256_cbc_encrypt_nopad(keys.enc.as_slice().try_into().unwrap(), &iv, &inner);

    let mut out = Vec::with_capacity(16 + outer.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&outer);
    out
}

/// Build the `CHANGE_OTP_PIN` data field, matching the Token2 reference client:
///
/// ```text
/// body           = 0x07 || max_retry || len(newPin) || newPin      # newPin empty => remove
/// body           = PKCS#7 pad to 16
/// IV             = random(16)
/// NewPinEnc      = AES-256-CBC(SessionEncKey, IV, body)
/// OldPinHash     = SHA256(oldPin)[0:16]
/// OldPinHashEnc  = AES-256-CBC(SessionEncKey, IV, OldPinHash)       # SAME IV
/// NewPinAuth     = HMAC(SessionMacKey, NewPinEnc || OldPinHashEnc)[0:16]
/// data field     = IV || NewPinEnc || NewPinAuth || OldPinHashEnc
/// ```
pub fn build_change_pin_data(
    keys: &SessionKeys,
    new_pin: &[u8],
    current_pin: &[u8],
    _rand: &[u8],
) -> Vec<u8> {
    let enc_key: &[u8; 32] = keys.enc.as_slice().try_into().unwrap();
    let mut body = Vec::with_capacity(3 + new_pin.len());
    body.push(0x07);
    body.push(0x64);
    body.push(new_pin.len() as u8);
    body.extend_from_slice(new_pin);
    let body = pkcs7_pad16(&body);

    let iv = random_iv();
    let new_pin_enc = aes256_cbc_encrypt_nopad(enc_key, &iv, &body);

    let old_hash_full = sha256(current_pin);
    let old_pin_hash = &old_hash_full[..16]; // 16 bytes, one block
    let old_pin_hash_enc = aes256_cbc_encrypt_nopad(enc_key, &iv, old_pin_hash);

    let mut mac_input = Vec::with_capacity(new_pin_enc.len() + old_pin_hash_enc.len());
    mac_input.extend_from_slice(&new_pin_enc);
    mac_input.extend_from_slice(&old_pin_hash_enc);
    let new_pin_auth = session_auth_tag(&keys.mac, &mac_input);

    let mut out = Vec::new();
    out.extend_from_slice(&iv);
    out.extend_from_slice(&new_pin_enc);
    out.extend_from_slice(&new_pin_auth);
    out.extend_from_slice(&old_pin_hash_enc);
    out
}

/// The `alg(0x07) || retry(0x64) || len || pin` block used inside PIN proofs.
fn pin_block(pin: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(3 + pin.len());
    b.push(0x07);
    b.push(0x64);
    b.push(pin.len() as u8);
    b.extend_from_slice(pin);
    b
}

/// SHA-256 convenience.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// AES-256-CBC encrypt data that is already a whole number of 16-byte blocks,
/// with NO padding added. Panics if `data` is not block-aligned.
fn aes256_cbc_encrypt_nopad(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    assert!(
        !data.is_empty() && data.len() % 16 == 0,
        "aes256_cbc_encrypt_nopad needs block-aligned input"
    );
    let mut buf = data.to_vec();
    let n = buf.len();
    // encrypt_padded_mut with NoPadding requires buf already block-aligned.
    Aes256CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, n)
        .expect("block-aligned, NoPadding")
        .to_vec()
}

/// PKCS#7 pad to a 16-byte boundary (always adds 1..=16 bytes).
fn pkcs7_pad16(data: &[u8]) -> Vec<u8> {
    let n = 16 - (data.len() % 16);
    let mut out = data.to_vec();
    out.extend(std::iter::repeat(n as u8).take(n));
    out
}

fn random_iv() -> [u8; 16] {
    use rand_core::RngCore;
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    iv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_write_is_session_format_and_roundtrips() {
        // A protected write is IV || AES-CBC(enc, IV, pt) || HMAC(mac, EncData)[:16].
        // Verify the layout and that the read-side decrypt recovers the cleartext.
        let keys = SessionKeys {
            enc: Zeroizing::new([7u8; 32]),
            mac: Zeroizing::new([9u8; 32]),
        };
        let cleartext = b"01\xC1\x00\x1E\x06\x00\x04Test\x0Eme@example.com\x05Hello";
        let blob = build_protected_write_data(&keys, cleartext);
        // 16 (IV) + ciphertext (PKCS7, multiple of 16) + 16 (auth).
        assert!(blob.len() >= 16 + 16 + 16);
        assert_eq!((blob.len() - 32) % 16, 0);
        let iv = &blob[..16];
        let enc = &blob[16..blob.len() - 16];
        let auth = &blob[blob.len() - 16..];
        // Auth tag matches HMAC(mac, EncData)[:16].
        assert_eq!(auth, &session_auth_tag(&keys.mac, enc)[..]);
        // Read-side decrypt (session_decrypt) recovers the cleartext.
        let iv16: [u8; 16] = iv.try_into().unwrap();
        let pt = session_decrypt(&keys.enc, &iv16, enc).expect("decrypt");
        assert_eq!(&pt[..], &cleartext[..]);
    }

    #[test]
    fn rejects_wrong_length_pubkey() {
        assert_eq!(
            encrypt_seed_payload(&[0u8; 63], b"x", &IV_OTP),
            Err(EncryptError::BadDevicePubkey)
        );
    }

    #[test]
    fn roundtrip_decrypts_on_device_side() {
        use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
        type Dec = cbc::Decryptor<aes::Aes256>;

        let device_secret = SecretKey::random(&mut OsRng);
        let device_pub = device_secret.public_key();
        let device_xy = {
            let pt = device_pub.to_encoded_point(false);
            pt.as_bytes()[1..].to_vec()
        };

        let cleartext = b"01\xC1\x00\x1E\x06\x00\x04Test\x05alice\x05Hello";
        let blob = encrypt_seed_payload(&device_xy, cleartext, &IV_OTP).unwrap();

        let host_xy = &blob[..64];
        let ciphertext = &blob[64..];
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(host_xy);
        let host_pub = p256::PublicKey::from_sec1_bytes(&sec1).unwrap();
        let shared = diffie_hellman(device_secret.to_nonzero_scalar(), host_pub.as_affine());
        let key = {
            let mut h = Sha256::new();
            h.update(shared.raw_secret_bytes());
            h.finalize()
        };
        let mut buf = ciphertext.to_vec();
        let plain = Dec::new(key.as_slice().into(), (&IV_OTP).into())
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .unwrap();
        assert_eq!(plain, cleartext);
    }

    #[test]
    fn verify_build_is_nested_and_block_aligned() {
        // Deterministic check of the *inner* layer (the outer uses a random IV).
        // inner = AES-256-CBC(SHA256(pin), SHA256(rand)[:16], rand), no padding.
        let keys = SessionKeys {
            enc: Zeroizing::new([9u8; 32]),
            mac: Zeroizing::new([7u8; 32]),
        };
        let pin = b"1357924";
        let rand = [0x42u8; 16];
        let out = build_verify_pin_data(&keys, pin, &rand);
        // data = IV(16) || outer(16); outer is one block since inner is one block.
        assert_eq!(out.len(), 32);
        // Recompute the inner independently and confirm the outer decrypts to it.
        let pin_hash = sha256(pin);
        let mut iv2 = [0u8; 16];
        iv2.copy_from_slice(&sha256(&rand)[..16]);
        let inner = aes256_cbc_encrypt_nopad(&pin_hash, &iv2, &rand);
        let iv: [u8; 16] = out[..16].try_into().unwrap();
        let outer = &out[16..];
        // decrypt outer under session enc key with NoPadding
        use cbc::cipher::{BlockDecryptMut, KeyIvInit};
        let mut buf = outer.to_vec();
        let dec = Aes256CbcDec::new((&[9u8;32]).into(), (&iv).into())
            .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
            .unwrap();
        assert_eq!(dec, &inner[..]);
    }

    #[test]
    fn session_keys_agree_between_host_and_device() {
        // Device side: make a keypair, hand its xy to the host, host derives.
        let device_secret = SecretKey::random(&mut OsRng);
        let dev_xy = {
            let pt = device_secret.public_key().to_encoded_point(false);
            pt.as_bytes()[1..].to_vec()
        };
        let (host_xy, host_keys) = establish_session(&dev_xy).unwrap();

        // Device re-derives from the host's public xy and its own secret.
        let dev_keys = derive_session_keys(&device_secret, &host_xy).unwrap();
        assert_eq!(host_keys.enc.as_slice(), dev_keys.enc.as_slice());
        assert_eq!(host_keys.mac.as_slice(), dev_keys.mac.as_slice());
    }

    #[test]
    fn session_encrypt_decrypt_roundtrip_and_auth() {
        let device_secret = SecretKey::random(&mut OsRng);
        let dev_xy = {
            let pt = device_secret.public_key().to_encoded_point(false);
            pt.as_bytes()[1..].to_vec()
        };
        let (_hx, keys) = establish_session(&dev_xy).unwrap();
        let iv = [7u8; 16];
        let msg = b"the quick brown fox";
        let ct = session_encrypt(&keys.enc, &iv, msg);
        let pt = session_decrypt(&keys.enc, &iv, &ct).unwrap();
        assert_eq!(&pt[..], msg);

        let tag = session_auth_tag(&keys.mac, &ct);
        assert!(verify_auth_tag(&keys.mac, &ct, &tag).is_ok());
        let mut bad = tag;
        bad[0] ^= 0xFF;
        assert_eq!(
            verify_auth_tag(&keys.mac, &ct, &bad),
            Err(EncryptError::BadAuthTag)
        );
    }
}
