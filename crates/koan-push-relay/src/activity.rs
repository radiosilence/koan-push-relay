//! What a server may put on a Live Activity, and what the relay lets through.
//!
//! iOS draws a Live Activity's state in the app's widget without passing it
//! through the app, so nothing here can be encrypted or checked by the app
//! first. The relay is where it is bounded: a server sends the fields the
//! widget's `ContentState` has and nothing else, every string is capped and
//! stripped of what could disguise it, the art must be a small JPEG, and the
//! times Apple orders and dims the activity by are the relay's.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

/// The longest a device name may be, in UTF-8 bytes.
pub const MAX_DEVICE: usize = 48;
/// The longest a title, artist or album may be, in UTF-8 bytes. With the
/// art, the whole payload stays within Apple's 4 KB.
pub const MAX_TEXT: usize = 256;
/// The longest track, in milliseconds.
const MAX_DURATION_MS: u64 = 24 * 60 * 60 * 1000;
/// The art, base64: a Live Activity cannot fetch anything, and Apple's limit
/// for the whole payload is 4 KB.
pub const MAX_ART: usize = 2600;
/// How far behind the relay's clock a server's playhead time may be. A
/// playhead older than this is the relay's own time.
const MAX_AGE_SECS: f64 = 60.0 * 60.0;
/// How far ahead: a server's clock a little fast is not refused.
const MAX_AHEAD_SECS: f64 = 60.0;
/// The longest the state may be as JSON: Apple's 4 KB for the payload, less
/// the envelope around it. Escaping can double a string's bytes, so the caps
/// above do not bound this on their own.
const MAX_STATE_JSON: usize = 3900;
/// A Live Activity nobody has updated in this long shows as stale.
pub const STALE_SECS: u64 = 8 * 60 * 60;

/// What a server sends for a Live Activity. The field names are the widget's
/// `RemoteActivity.ContentState`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivityState {
    pub device: String,
    pub linked: bool,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub artist: Option<String>,
    #[serde(default)]
    pub album: Option<String>,
    pub playing: bool,
    pub position_ms: u64,
    pub duration_ms: u64,
    /// When `position_ms` was true, in Unix seconds.
    pub at: f64,
    /// The sleeve, a small JPEG, base64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub art: Option<String>,
}

impl ActivityState {
    /// The state as the relay will send it, with `now` in Unix seconds; or
    /// why it is refused.
    pub fn bounded(self, now: f64) -> Result<Self, &'static str> {
        let art = match self.art {
            Some(art) if !is_jpeg(&art) => return Err("the art is not a small base64 JPEG"),
            art => art,
        };
        let duration_ms = self.duration_ms.min(MAX_DURATION_MS);
        let at = if self.at.is_finite()
            && (now - MAX_AGE_SECS..=now + MAX_AHEAD_SECS).contains(&self.at)
        {
            self.at
        } else {
            now
        };
        let bounded = Self {
            device: text(&self.device, MAX_DEVICE),
            linked: self.linked,
            title: self.title.map(|t| text(&t, MAX_TEXT)),
            artist: self.artist.map(|t| text(&t, MAX_TEXT)),
            album: self.album.map(|t| text(&t, MAX_TEXT)),
            playing: self.playing,
            position_ms: self.position_ms.min(duration_ms),
            duration_ms,
            at,
            art,
        };
        match serde_json::to_vec(&bounded) {
            Ok(json) if json.len() <= MAX_STATE_JSON => Ok(bounded),
            _ => Err("the state is too large for Apple"),
        }
    }
}

/// `s` with control and formatting characters gone (the ones that reorder
/// text or hide it, among them), runs of whitespace made one space, and cut
/// at a character to at most `max` bytes.
fn text(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max));
    let mut space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            space = !out.is_empty();
            continue;
        }
        if c.is_control() || is_format(c) {
            continue;
        }
        if out.len() + usize::from(space) + c.len_utf8() > max {
            break;
        }
        if space {
            out.push(' ');
            space = false;
        }
        out.push(c);
    }
    out
}

/// Unicode's format characters (general category Cf): they change how text
/// reads rather than what it says, and some reorder or hide it. Kept are the
/// zero-width joiner and non-joiner, which only join: emoji sequences and
/// Persian, Sinhala or Indic titles need them.
fn is_format(c: char) -> bool {
    matches!(c,
        '\u{00AD}'
        | '\u{0600}'..='\u{0605}'
        | '\u{061C}'
        | '\u{06DD}'
        | '\u{070F}'
        | '\u{0890}'..='\u{0891}'
        | '\u{08E2}'
        | '\u{180E}'
        | '\u{200B}'
        | '\u{200E}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206F}'
        | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{110BD}'
        | '\u{110CD}'
        | '\u{13430}'..='\u{1343F}'
        | '\u{1BCA0}'..='\u{1BCA3}'
        | '\u{1D173}'..='\u{1D17A}'
        | '\u{E0001}'
        | '\u{E0020}'..='\u{E007F}')
}

/// Whether `art` is base64 of no more than `MAX_ART` characters holding a
/// whole JPEG.
fn is_jpeg(art: &str) -> bool {
    if art.len() > MAX_ART {
        return false;
    }
    let Ok(bytes) = STANDARD.decode(art) else {
        return false;
    };
    bytes.len() >= 4 && bytes.starts_with(&[0xFF, 0xD8, 0xFF]) && bytes.ends_with(&[0xFF, 0xD9])
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: f64 = 1_800_000_000.0;

    fn state() -> ActivityState {
        ActivityState {
            device: "Desk".into(),
            linked: true,
            title: Some("Blue in Green".into()),
            artist: Some("Miles Davis".into()),
            album: Some("Kind of Blue".into()),
            playing: true,
            position_ms: 1000,
            duration_ms: 337_000,
            at: NOW - 1.0,
            art: None,
        }
    }

    #[test]
    fn a_plain_state_goes_through_as_it_is() {
        assert_eq!(state().bounded(NOW).unwrap(), state());
    }

    #[test]
    fn text_is_capped_and_stripped_of_what_could_disguise_it() {
        let s = ActivityState {
            title: Some(format!("a\u{202E}b\u{200B}c\n\t d{}", "x".repeat(500))),
            device: "D\u{0007}esk".into(),
            ..state()
        }
        .bounded(NOW)
        .unwrap();
        let title = s.title.unwrap();
        assert!(title.starts_with("abc d"));
        assert_eq!(title.len(), MAX_TEXT);
        assert_eq!(s.device, "Desk");
    }

    #[test]
    fn joiners_stay_and_other_format_characters_go() {
        let flag = "\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}";
        assert_eq!(text(flag, 64), flag);
        assert_eq!(text("m\u{200C}i", 64), "m\u{200C}i");
        assert_eq!(text("a\u{0600}b\u{1D173}c\u{E0041}d", 64), "abcd");
    }

    #[test]
    fn a_state_that_escapes_past_apples_limit_is_refused() {
        // Quotes and backslashes are two bytes each once escaped.
        let worst = ActivityState {
            device: "\"".repeat(MAX_DEVICE),
            title: Some("\\".repeat(MAX_TEXT)),
            artist: Some("\"".repeat(MAX_TEXT)),
            album: Some("\\".repeat(MAX_TEXT)),
            art: Some(STANDARD.encode(jpeg(1940))),
            ..state()
        };
        assert!(worst.bounded(NOW).is_err());
        // And whatever is accepted fits, as the whole payload.
        let fits = ActivityState {
            title: Some("\\".repeat(MAX_TEXT)),
            art: Some(STANDARD.encode(jpeg(1940))),
            ..state()
        };
        let state = fits.bounded(NOW).unwrap();
        let payload = crate::apns::payload(
            crate::apns::Kind::Activity,
            None,
            &crate::apns::Content::Activity(state),
            NOW as u64,
        );
        assert!(serde_json::to_vec(&payload).unwrap().len() <= 4096);
    }

    fn jpeg(len: usize) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xD8, 0xFF];
        bytes.resize(len - 2, 0);
        bytes.extend_from_slice(&[0xFF, 0xD9]);
        bytes
    }

    #[test]
    fn whitespace_at_the_ends_goes() {
        assert_eq!(text("  a   b  ", 10), "a b");
        assert_eq!(text("ab cd", 3), "ab");
    }

    #[test]
    fn the_playhead_stays_within_the_track_and_the_relays_clock() {
        let s = ActivityState {
            position_ms: u64::MAX,
            duration_ms: u64::MAX,
            at: NOW + 3600.0,
            ..state()
        }
        .bounded(NOW)
        .unwrap();
        assert_eq!(s.duration_ms, MAX_DURATION_MS);
        assert_eq!(s.position_ms, MAX_DURATION_MS);
        assert_eq!(s.at, NOW);
        let s = ActivityState {
            at: f64::NAN,
            ..state()
        }
        .bounded(NOW)
        .unwrap();
        assert_eq!(s.at, NOW);
    }

    #[test]
    fn art_must_be_a_small_jpeg() {
        let jpeg = STANDARD.encode([0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0xFF, 0xD9]);
        assert!(
            ActivityState {
                art: Some(jpeg),
                ..state()
            }
            .bounded(NOW)
            .is_ok()
        );
        for art in [
            STANDARD.encode(b"<svg onload=x>"),
            "not base64!".to_string(),
            STANDARD.encode([0xFF, 0xD8, 0xFF].repeat(1000)),
        ] {
            assert!(
                ActivityState {
                    art: Some(art),
                    ..state()
                }
                .bounded(NOW)
                .is_err()
            );
        }
    }

    #[test]
    fn unknown_fields_are_refused() {
        let mut v = serde_json::to_value(state()).unwrap();
        v["alert"] = serde_json::json!("hello");
        assert!(serde_json::from_value::<ActivityState>(v).is_err());
    }
}
