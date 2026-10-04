//! Masking for evidence snippets. Analysts see masked values unless they hold
//! the `incident.evidence.unmask` permission (enforced server-side).

use serde::Deserialize;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MaskStyle {
    /// Payment cards: first 6 + last 4 digits (PCI DSS display rule).
    Card,
    /// Secrets: first 4 characters and the length only.
    Secret,
    /// Default: keep first 2 and last 2 characters.
    #[default]
    Partial,
    /// Nothing but the length.
    Full,
}

pub fn mask(value: &str, style: MaskStyle) -> String {
    let chars: Vec<char> = value.chars().collect();
    let n = chars.len();
    match style {
        MaskStyle::Card => {
            let d: Vec<char> = chars.iter().copied().filter(char::is_ascii_digit).collect();
            if d.len() < 13 {
                return "*".repeat(d.len());
            }
            let head: String = d[..6].iter().collect();
            let tail: String = d[d.len() - 4..].iter().collect();
            format!("{head}{}{tail}", "*".repeat(d.len() - 10))
        }
        MaskStyle::Secret => {
            let head: String = chars.iter().take(4.min(n / 4)).collect();
            format!("{head}…[{n} chars]")
        }
        MaskStyle::Partial => {
            if n <= 6 {
                return "*".repeat(n);
            }
            let head: String = chars[..2].iter().collect();
            let tail: String = chars[n - 2..].iter().collect();
            format!("{head}{}{tail}", "*".repeat(n - 4))
        }
        MaskStyle::Full => format!("[{n} chars]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_mask_matches_spec_example() {
        assert_eq!(
            mask("4111111111111111", MaskStyle::Card),
            "411111******1111"
        );
        assert_eq!(
            mask("4111 1111 1111 1111", MaskStyle::Card),
            "411111******1111"
        );
    }

    #[test]
    fn secret_mask_never_reveals_more_than_a_quarter() {
        let m = mask(concat!("AKIA", "ABCDEFGHIJKLMNOP"), MaskStyle::Secret);
        assert_eq!(m, "AKIA…[20 chars]");
        assert_eq!(mask("abcd", MaskStyle::Secret), "a…[4 chars]");
    }

    #[test]
    fn partial_mask_short_values_fully_hidden() {
        assert_eq!(mask("abc", MaskStyle::Partial), "***");
        assert_eq!(
            mask("someone@example.com", MaskStyle::Partial),
            "so***************om"
        );
    }
}
