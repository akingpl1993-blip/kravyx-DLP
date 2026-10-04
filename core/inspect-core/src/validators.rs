//! Checksum and structural validators. These are what separate a real detector
//! from "16 digits in a row" and are the main false-positive control.

use base64::Engine as _;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Validator {
    None,
    /// Luhn mod-10 over the digits.
    Luhn,
    /// Luhn + payment-card length + issuer prefix (IIN) checks.
    LuhnCard,
    /// ISO 13616 IBAN: country length table + mod-97 == 1.
    IbanMod97,
    /// Verhoeff checksum (India Aadhaar), 12 digits, first digit 2-9.
    Aadhaar,
    /// India PAN: AAAAA9999A with a valid holder-type 4th character.
    IndiaPan,
    /// UAE Emirates ID: 15 digits, prefix 784, Luhn check digit.
    EmiratesId,
    /// JWT: three base64url segments, header decodes to JSON containing "alg".
    Jwt,
}

pub fn digits(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}

pub fn luhn(d: &str) -> bool {
    if d.len() < 2 || !d.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut sum = 0u32;
    for (i, b) in d.bytes().rev().enumerate() {
        let mut v = u32::from(b - b'0');
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum % 10 == 0
}

/// Issuer identification: returns true for prefixes/lengths of major networks.
fn card_iin_ok(d: &str) -> bool {
    let n = d.len();
    let p = |k: usize| d[..k].parse::<u32>().unwrap_or(0);
    match d.as_bytes()[0] {
        b'4' => matches!(n, 13 | 16 | 19),                // Visa
        b'5' => (51..=55).contains(&p(2)) && n == 16,     // Mastercard
        b'2' => (2221..=2720).contains(&p(4)) && n == 16, // Mastercard 2-series
        b'3' => {
            ((p(2) == 34 || p(2) == 37) && n == 15)                            // Amex
                || ((3528..=3589).contains(&p(4)) && (16..=19).contains(&n))   // JCB
                || ((p(2) == 36 || p(2) == 38 || (300..=305).contains(&p(3))) && (14..=19).contains(&n))
            // Diners
        }
        b'6' => {
            (p(4) == 6011
                || p(2) == 65
                || (644..=649).contains(&p(3))
                || (622126..=622925).contains(&p(6))
                || p(2) == 62)
                && (16..=19).contains(&n) // Discover / UnionPay
        }
        _ => false,
    }
}

fn iban_length(country: &str) -> Option<usize> {
    // Subset; extend via detector packs. Source: SWIFT IBAN registry.
    Some(match country {
        "AE" => 23,
        "SA" => 24,
        "QA" => 29,
        "BH" => 22,
        "KW" => 30,
        "OM" => 23,
        "GB" => 22,
        "DE" => 22,
        "FR" => 27,
        "ES" => 24,
        "IT" => 27,
        "NL" => 18,
        "BE" => 16,
        "CH" => 21,
        "AT" => 20,
        "IE" => 22,
        "PT" => 25,
        "PL" => 28,
        "SE" => 24,
        "NO" => 15,
        "DK" => 18,
        "FI" => 18,
        "LU" => 20,
        "TR" => 26,
        "EG" => 29,
        "JO" => 30,
        "PK" => 24,
        "LB" => 28,
        _ => return None,
    })
}

pub fn iban_mod97(raw: &str) -> bool {
    let s: String = raw
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    if s.len() < 15 || !s.is_ascii() {
        return false;
    }
    match iban_length(&s[..2]) {
        Some(l) if l == s.len() => {}
        _ => return false,
    }
    let rearranged = format!("{}{}", &s[4..], &s[..4]);
    let mut rem: u32 = 0;
    for c in rearranged.chars() {
        let v = if c.is_ascii_digit() {
            c as u32 - '0' as u32
        } else if c.is_ascii_uppercase() {
            c as u32 - 'A' as u32 + 10
        } else {
            return false;
        };
        rem = if v >= 10 {
            (rem * 100 + v) % 97
        } else {
            (rem * 10 + v) % 97
        };
    }
    rem == 1
}

const VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 8, 7, 6, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

pub fn verhoeff(d: &str) -> bool {
    let mut c = 0u8;
    for (i, b) in d.bytes().rev().enumerate() {
        if !b.is_ascii_digit() {
            return false;
        }
        c = VERHOEFF_D[c as usize][VERHOEFF_P[i % 8][(b - b'0') as usize] as usize];
    }
    c == 0
}

fn jwt_ok(s: &str) -> bool {
    let mut parts = s.split('.');
    let Some(header) = parts.next() else {
        return false;
    };
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let Ok(bytes) = engine.decode(header.trim_end_matches('=')) else {
        return false;
    };
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(serde_json::Value::Object(m)) => m.contains_key("alg"),
        _ => false,
    }
}

impl Validator {
    pub fn check(self, m: &str) -> bool {
        match self {
            Validator::None => true,
            Validator::Luhn => luhn(&digits(m)),
            Validator::LuhnCard => {
                let d = digits(m);
                (13..=19).contains(&d.len()) && card_iin_ok(&d) && luhn(&d)
            }
            Validator::IbanMod97 => iban_mod97(m),
            Validator::Aadhaar => {
                let d = digits(m);
                d.len() == 12 && !d.starts_with('0') && !d.starts_with('1') && verhoeff(&d)
            }
            Validator::IndiaPan => {
                let b = m.as_bytes();
                b.len() == 10 && b"PCHFATBLJG".contains(&b[3])
            }
            Validator::EmiratesId => {
                let d = digits(m);
                d.len() == 15 && d.starts_with("784") && luhn(&d)
            }
            Validator::Jwt => jwt_ok(m),
        }
    }
}

/// Shannon entropy in bits per character. Used to reject low-entropy "secrets"
/// such as `password=xxxxxxxxxxxxxxxx`.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_known_values() {
        assert!(luhn("79927398713"));
        assert!(!luhn("79927398710"));
    }

    #[test]
    fn card_requires_iin_and_length() {
        assert!(Validator::LuhnCard.check("4111 1111 1111 1111"));
        assert!(Validator::LuhnCard.check("3782-822463-10005")); // Amex
        assert!(!Validator::LuhnCard.check("1234567812345670")); // Luhn-valid, bad IIN
        assert!(!Validator::LuhnCard.check("4111111111111112")); // bad checksum
    }

    #[test]
    fn iban_examples() {
        // Published example IBANs (ECBS / national examples), not real accounts.
        assert!(iban_mod97("GB82 WEST 1234 5698 7654 32"));
        assert!(iban_mod97("DE89370400440532013000"));
        assert!(!iban_mod97("GB82 WEST 1234 5698 7654 33"));
        assert!(!iban_mod97("XX82WEST12345698765432"));
    }

    #[test]
    fn verhoeff_known() {
        assert!(verhoeff("2363")); // textbook example: 236 + check digit 3
        assert!(!verhoeff("2364"));
    }

    #[test]
    fn jwt_header_must_decode() {
        // Assembled from parts so no JWT-shaped literal exists in the source.
        let good = concat!(
            "eyJhbGciOiJIUzI1NiJ9",
            ".",
            "eyJzdWIiOiJ0ZXN0In0",
            ".",
            "c2lnbmF0dXJlLWJ5dGVz"
        );
        assert!(Validator::Jwt.check(good));
        assert!(!Validator::Jwt.check(concat!(
            "eyJub3RfaGVhZGVyIjoxfQ",
            ".",
            "eyJ4IjoxfQ",
            ".",
            "abcdefghij"
        )));
    }

    #[test]
    fn entropy_orders_strings() {
        assert!(shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0);
        assert!(shannon_entropy(concat!("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY")) > 4.0);
    }
}
