//! A client for kōan's push relay, for kōan's apps and servers.
//!
//! The app registers its device token, and each Live Activity's, and gives
//! servers the handles it gets back; a server pushes to a handle by kind. The
//! relay writes everything Apple is sent. The protocol is specified in
//! `docs/push-relay.md` in this crate's repository.
//!
//! The types are what the relay itself reads and writes. The `client`
//! feature, on by default, adds `Client`: blocking, so call it from a thread
//! that may wait on the network.

use serde::{Deserialize, Serialize};

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "client")]
pub use client::{Client, Error, Push};

/// The relay kōan's apps use.
pub const DEFAULT_URL: &str = "https://push.koan.rocks";

/// The longest blob a notification may carry, base64url. Apple's limit is
/// 4 KB for the whole payload; this leaves room for the relay's own part.
pub const MAX_BLOB: usize = 3072;

/// Sixteen bytes the app chooses for one server and keeps for it.
pub type Slot = [u8; 16];

/// What a push asks of a device, as the relay reads it.
///
/// Not `non_exhaustive`: the relay matches on it, so a new kind is handled
/// wherever kinds are. Callers build pushes with `Push`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// Wake the app to link and take what waits for it.
    Wake,
    /// The same, for something that is no use an hour late.
    WakeNow,
    /// A notification asking to be tapped.
    Summon,
    /// A notification carrying a command the app runs when it is tapped.
    Notify,
    /// An update to a Live Activity, through an activity's handle.
    Activity,
}

/// What a Live Activity shows. The field names are the widget's
/// `RemoteActivity.ContentState`; the relay bounds them before Apple sees
/// them, and sends only these fields, so a field it does not know is
/// dropped rather than refused.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityState {
    pub device: String,
    pub linked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artist: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

/// What a registration returns. Its `Debug` shows neither secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registered {
    /// For one server, to push through.
    pub handle: String,
    /// For the app alone: revokes the device, and registers its activities.
    pub revoker: String,
    /// Unix seconds after which neither opens. Register again at half of it.
    pub expires: u64,
}

impl std::fmt::Debug for Registered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registered")
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

/// What registering a Live Activity returns. Its `Debug` hides the handle.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredActivity {
    pub handle: String,
    pub expires: u64,
}

impl std::fmt::Debug for RegisteredActivity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredActivity")
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

/// What an App Attest assertion for a registration signs: the relay's
/// challenge, the device token, the slot and the gateway, so the assertion
/// registers exactly these. The app hashes it (SHA-256) and passes the hash
/// to `DCAppAttestService.generateAssertion`.
pub fn client_data(challenge: &str, token: &[u8], slot: &Slot, sandbox: bool) -> Vec<u8> {
    let mut data = b"koan-relay register 1\0".to_vec();
    data.extend_from_slice(challenge.as_bytes());
    data.push(0);
    data.extend_from_slice(token);
    data.extend_from_slice(slot);
    data.push(u8::from(sandbox));
    data
}

/// Whether `blob` is something a notification may carry: base64url without
/// padding, of at most `MAX_BLOB` characters.
pub fn is_blob(blob: &str) -> bool {
    !blob.is_empty()
        && blob.len() <= MAX_BLOB
        && blob
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
