//! TOTP (RFC 6238) for console two-factor auth — self-contained.
//!
//! Authenticator apps default to HMAC-SHA1/30s/6-digits and several ignore
//! the algorithm parameter entirely, so SHA-1 it is. The workspace carries no
//! compatible SHA-1 crate, and RustCrypto's pre-release pairings are a
//! moving target — so the primitive lives here, ~80 lines, pinned to the
//! RFC 3174 / RFC 2202 / RFC 6238 test vectors below. SHA-1's collision
//! weakness is irrelevant to HMAC-based OTPs.

use crate::error::{ChalkError, Result};

// ---------------------------------------------------------------------------
// SHA-1 (RFC 3174)
// ---------------------------------------------------------------------------

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let ml = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&ml.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// HMAC-SHA1 (RFC 2104).
fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..20].copy_from_slice(&sha1(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + message.len());
    let mut outer = Vec::with_capacity(64 + 20);
    for byte in &k {
        inner.push(byte ^ 0x36);
    }
    inner.extend_from_slice(message);
    let inner_hash = sha1(&inner);
    for byte in &k {
        outer.push(byte ^ 0x5C);
    }
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

// ---------------------------------------------------------------------------
// Base32 (RFC 4648, no padding) — what otpauth URLs carry
// ---------------------------------------------------------------------------

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer = 0u64;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32_ALPHABET[((buffer >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32_ALPHABET[((buffer << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer = 0u64;
    let mut bits = 0u32;
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return Err(ChalkError::Config("invalid base32 in TOTP secret".into())),
        };
        buffer = (buffer << 5) | v as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238): 30-second step, 6 digits
// ---------------------------------------------------------------------------

pub const TOTP_STEP_SECONDS: u64 = 30;
pub const TOTP_DIGITS: u32 = 6;

/// A fresh 160-bit secret, base32-encoded for the otpauth URL.
pub fn generate_secret() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 20];
    rand::rng().fill_bytes(&mut bytes);
    base32_encode(&bytes)
}

/// The URL an authenticator app enrolls from (rendered as a QR).
pub fn otpauth_url(issuer: &str, account: &str, secret_base32: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECONDS}",
        urlencoding::encode(issuer),
        urlencoding::encode(account),
        secret_base32,
        urlencoding::encode(issuer),
    )
}

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mac = hmac_sha1(secret, &counter.to_be_bytes());
    let offset = (mac[19] & 0x0F) as usize;
    let code = u32::from_be_bytes([
        mac[offset],
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]) & 0x7FFF_FFFF;
    code % 10u32.pow(TOTP_DIGITS)
}

/// The code for a moment in time, zero-padded.
pub fn code_at(secret_base32: &str, unix_seconds: u64) -> Result<String> {
    let secret = base32_decode(secret_base32)?;
    Ok(format!(
        "{:06}",
        hotp(&secret, unix_seconds / TOTP_STEP_SECONDS)
    ))
}

/// Verify a submitted code against ±1 time step — the standard allowance for
/// clock skew and the human seconds between reading and typing.
pub fn verify_code(secret_base32: &str, submitted: &str, unix_seconds: u64) -> bool {
    let submitted = submitted.trim();
    if submitted.len() != TOTP_DIGITS as usize || !submitted.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Ok(secret) = base32_decode(secret_base32) else {
        return false;
    };
    let step = unix_seconds / TOTP_STEP_SECONDS;
    for candidate in [step.wrapping_sub(1), step, step + 1] {
        if format!("{:06}", hotp(&secret, candidate)) == submitted {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3174 / standard SHA-1 vectors.
    #[test]
    fn sha1_matches_the_rfc_vectors() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    /// RFC 2202 HMAC-SHA1 test cases 1-3.
    #[test]
    fn hmac_sha1_matches_the_rfc_vectors() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            hex(&hmac_sha1(&[0x0b; 20], b"Hi There")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        assert_eq!(
            hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
        assert_eq!(
            hex(&hmac_sha1(&[0xaa; 20], &[0xdd; 50])),
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
        );
    }

    /// RFC 6238 Appendix B vectors (SHA-1 rows), truncated to 6 digits from
    /// the published 8-digit values.
    #[test]
    fn totp_matches_the_rfc_vectors() {
        let secret = base32_encode(b"12345678901234567890");
        for (t, code8) in [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ] {
            assert_eq!(code_at(&secret, t).unwrap(), &code8[2..], "t={t}");
        }
    }

    #[test]
    fn verification_allows_one_step_of_skew_and_no_more() {
        let secret = generate_secret();
        let now = 1_700_000_000u64;
        let code = code_at(&secret, now).unwrap();
        assert!(verify_code(&secret, &code, now));
        assert!(
            verify_code(&secret, &code, now + TOTP_STEP_SECONDS),
            "+1 ok"
        );
        assert!(
            verify_code(&secret, &code, now - TOTP_STEP_SECONDS),
            "-1 ok"
        );
        assert!(
            !verify_code(&secret, &code, now + 3 * TOTP_STEP_SECONDS),
            "stale codes die"
        );
        assert!(!verify_code(&secret, "12345", now), "wrong length");
        assert!(!verify_code(&secret, "abcdef", now), "not digits");
    }

    #[test]
    fn base32_round_trips() {
        for data in [&b"12345678901234567890"[..], b"", b"a", b"ab", b"abcd"] {
            assert_eq!(base32_decode(&base32_encode(data)).unwrap(), data);
        }
        assert!(base32_decode("not base32!!").is_err());
    }

    #[test]
    fn otpauth_url_is_app_shaped() {
        let url = otpauth_url("Chalk", "tech@district.org", "ABC234");
        assert!(url.starts_with("otpauth://totp/Chalk:tech%40district.org?secret=ABC234"));
        assert!(url.contains("issuer=Chalk"));
        assert!(url.contains("period=30"));
    }
}
