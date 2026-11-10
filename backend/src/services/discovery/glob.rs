//! Tag value matching (`specs/spinoff-local-scan.md`, section 5; decision 15).
//!
//! A source's tag value is an exact tag, or a pattern when it contains `*` or `?`. Only these
//! two forms exist: no exclusions, no regular expressions, no classes, no braces. `*` is zero or
//! more characters, `?` is exactly one, every other character is literal, and the match is
//! against the whole tag and is case-sensitive.

use crate::error::AppError;
use crate::services::registry::grammar::validate_tag;

/// The longest pattern: the same 128 bytes as a tag.
pub const MAX_PATTERN_BYTES: usize = 128;

/// A parsed tag value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagPattern {
    /// An exact tag that passed the tag grammar.
    Exact(String),
    /// A pattern with at least one `*` or `?`.
    Glob(String),
}

impl TagPattern {
    /// Parses and checks a source's tag value. A digest reference (`:` or `@`), an empty value,
    /// a pattern over 128 bytes, and any character outside the tag characters plus `*` and `?`
    /// are refused.
    pub fn parse(value: &str) -> Result<Self, AppError> {
        if value.contains(['*', '?']) {
            let chars_ok = value.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'*' | b'?')
            });
            if chars_ok && value.len() <= MAX_PATTERN_BYTES {
                Ok(TagPattern::Glob(value.to_owned()))
            } else {
                Err(bad_value())
            }
        } else {
            validate_tag(value).map_err(|_| bad_value())?;
            Ok(TagPattern::Exact(value.to_owned()))
        }
    }

    /// True when `tag` matches the whole value.
    pub fn matches(&self, tag: &str) -> bool {
        match self {
            TagPattern::Exact(exact) => exact == tag,
            TagPattern::Glob(pattern) => glob_match(pattern.as_bytes(), tag.as_bytes()),
        }
    }
}

fn bad_value() -> AppError {
    AppError::ValidationFailed("The tag value is not valid.".to_owned())
}

/// Linear-space glob match with one backtrack point, so a hostile pattern cannot blow up.
fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(b'?') => {
                p += 1;
                t += 1;
            }
            Some(&c) if c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((star_p, star_t)) => {
                    p = star_p + 1;
                    t = star_t + 1;
                    star = Some((star_p, star_t + 1));
                }
                None => return false,
            },
        }
    }
    while pattern.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn glob(value: &str) -> TagPattern {
        match TagPattern::parse(value) {
            Ok(pattern) => pattern,
            Err(err) => panic!("{value} should parse: {err:?}"),
        }
    }

    #[test]
    fn section_five_examples_for_one_two_star() {
        let pattern = glob("1.2.*");
        assert!(pattern.matches("1.2.0"));
        assert!(pattern.matches("1.2.3-rc1"));
        assert!(pattern.matches("1.2."));
        assert!(!pattern.matches("1.2"));
        assert!(!pattern.matches("1.20.0"));
        assert!(!pattern.matches("v1.2.0"));
    }

    #[test]
    fn matching_is_case_sensitive_and_a_dot_is_literal() {
        assert!(!glob("Latest*").matches("latest"));
        assert!(glob("Latest*").matches("Latest-2"));
        assert!(!glob("1.2.*").matches("1x2x3"));
    }

    #[test]
    fn question_mark_is_exactly_one_character() {
        let pattern = glob("v1.?");
        assert!(pattern.matches("v1.2"));
        assert!(!pattern.matches("v1."));
        assert!(!pattern.matches("v1.22"));
    }

    #[test]
    fn star_can_sit_anywhere_and_backtracks() {
        assert!(glob("*").matches("anything-1.0"));
        assert!(glob("a*b*c").matches("aXXbYYbZc"));
        assert!(!glob("a*b*c").matches("aXXbYY"));
        assert!(glob("*-alpine").matches("3.19-alpine"));
        assert!(!glob("*-alpine").matches("3.19-alpine3"));
    }

    #[test]
    fn an_exact_tag_matches_only_itself() {
        let pattern = glob("1.2.3");
        assert_eq!(pattern, TagPattern::Exact("1.2.3".to_owned()));
        assert!(pattern.matches("1.2.3"));
        assert!(!pattern.matches("1.2.30"));
    }

    #[test]
    fn a_digest_reference_and_bad_grammar_are_refused() {
        for bad in [
            "",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "repo@sha256:abc",
            "1.2.*:x",
            "1.2/*",
            "1.2.{a,b}",
            "[0-9]*",
            "!1.2.*",
            "1.2 *",
            "-bad",
            ".bad",
        ] {
            assert!(TagPattern::parse(bad).is_err(), "{bad:?} should be refused");
        }
        let long = format!("{}*", "a".repeat(MAX_PATTERN_BYTES));
        assert!(TagPattern::parse(&long).is_err());
        let longest = format!("{}*", "a".repeat(MAX_PATTERN_BYTES - 1));
        assert!(TagPattern::parse(&longest).is_ok());
    }
}
