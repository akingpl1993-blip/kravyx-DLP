//! Text normalisation applied before detection.
//!
//! Evasion via look-alike characters, zero-width joiners and bidi overrides is a
//! standard DLP bypass. We apply NFKC (folds full-width digits, ligatures, etc.),
//! drop invisible format characters, and collapse runs of whitespace.
//!
//! Offsets reported by detectors refer to the *normalised* text. Mapping back to
//! original byte offsets is a Phase 2 item (needed for in-document redaction).

use unicode_normalization::UnicodeNormalization;

/// Characters removed outright: zero-width and bidirectional control characters.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'               // soft hyphen
        | '\u{200B}'..='\u{200F}' // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | '\u{202A}'..='\u{202E}' // bidi embeddings/overrides
        | '\u{2060}'..='\u{2064}' // word joiner, invisible operators
        | '\u{2066}'..='\u{2069}' // bidi isolates
        | '\u{FEFF}'              // BOM / ZWNBSP
    )
}

/// Normalise `input`, writing at most `max_bytes` bytes of output.
/// Returns the normalised text and whether it was truncated.
pub fn normalize(input: &str, max_bytes: usize) -> (String, bool) {
    let mut out = String::with_capacity(input.len().min(max_bytes));
    let mut last_space = false;
    for c in input.nfkc() {
        if is_invisible(c) {
            continue;
        }
        let c = if c.is_whitespace() { ' ' } else { c };
        if c == ' ' {
            if last_space {
                continue;
            }
            last_space = true;
        } else {
            last_space = false;
        }
        if out.len() + c.len_utf8() > max_bytes {
            return (out, true);
        }
        out.push(c);
    }
    (out, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zero_width_and_bidi() {
        let (t, _) = normalize("41\u{200B}11-\u{202E}1111", 1024);
        assert_eq!(t, "4111-1111");
    }

    #[test]
    fn folds_fullwidth_digits() {
        let (t, _) = normalize("４１１１", 1024);
        assert_eq!(t, "4111");
    }

    #[test]
    fn collapses_whitespace_and_newlines() {
        let (t, _) = normalize("a \t\n\n b", 1024);
        assert_eq!(t, "a b");
    }

    #[test]
    fn truncates_on_char_boundary() {
        let (t, truncated) = normalize("ééééé", 5);
        assert!(truncated);
        assert_eq!(t, "éé");
    }
}
