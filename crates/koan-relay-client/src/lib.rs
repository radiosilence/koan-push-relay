//! A client for kōan's push relay, for kōan's apps and servers.
//!
//! The app registers its device token, and each Live Activity's, and gives
//! servers the handles it gets back; a server pushes to a handle by kind. The
//! relay writes everything Apple is sent. The protocol is specified in
//! `docs/push-relay.md` in this crate's repository.
//!
//! Blocking, so call it from a thread that may wait on the network.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The relay kōan's apps use.
pub const DEFAULT_URL: &str = "https://push.koan.rocks";

/// Sixteen bytes the app chooses for one server and keeps for it.
pub type Slot = [u8; 16];

/// What a server asks of a device.
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
/// them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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

/// What a registration returns.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Registered {
    /// For one server, to push through.
    pub handle: String,
    /// For the app alone: revokes the device, and registers its activities.
    pub revoker: String,
    /// Unix seconds after which neither opens. Register again at half of it.
    pub expires: u64,
}

/// What registering a Live Activity returns.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RegisteredActivity {
    pub handle: String,
    pub expires: u64,
}

/// Why the relay did not do what was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The request is malformed, or the relay serves no such gateway.
    Bad(String),
    /// The handle or revoker no longer opens, or Apple says the app or the
    /// activity is gone: forget it.
    Gone,
    /// A quota is spent: try again after this long.
    Limited(Duration),
    /// The relay or Apple cannot take it now: try again after this long.
    Unavailable(Duration),
    /// The relay could not be reached, or answered with something else.
    Transport(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Bad(why) => write!(f, "refused: {why}"),
            Error::Gone => f.write_str("gone"),
            Error::Limited(after) => write!(f, "rate limited for {}s", after.as_secs()),
            Error::Unavailable(after) => write!(f, "unavailable for {}s", after.as_secs()),
            Error::Transport(why) => write!(f, "relay unreachable: {why}"),
        }
    }
}

impl std::error::Error for Error {}

pub struct Client {
    base: String,
    http: reqwest::blocking::Client,
}

impl Client {
    /// A client for the relay at `base`, such as `DEFAULT_URL`.
    pub fn new(base: &str) -> Result<Self, Error> {
        let http = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            http,
        })
    }

    /// Register a device token, for the server the app gave `slot`.
    /// `sandbox` is true for development builds.
    pub fn register(&self, token: &[u8], slot: &Slot, sandbox: bool) -> Result<Registered, Error> {
        let body = serde_json::json!({
            "token": hex::encode(token),
            "slot": hex::encode(slot),
            "sandbox": sandbox,
        });
        self.call("/v1/register", &body)?
            .json()
            .map_err(|e| Error::Transport(e.to_string()))
    }

    /// Register a Live Activity's token, on the device `revoker` is for, for
    /// the server the app gave `slot`.
    pub fn register_activity(
        &self,
        revoker: &str,
        token: &[u8],
        slot: &Slot,
    ) -> Result<RegisteredActivity, Error> {
        let body = serde_json::json!({
            "revoker": revoker,
            "token": hex::encode(token),
            "slot": hex::encode(slot),
        });
        self.call("/v1/register-activity", &body)?
            .json()
            .map_err(|e| Error::Transport(e.to_string()))
    }

    /// Retire every handle and revoker the device has been given.
    pub fn revoke(&self, revoker: &str) -> Result<(), Error> {
        self.call("/v1/revoke", &serde_json::json!({ "revoker": revoker }))
            .map(drop)
    }

    /// Send a wake or a notification through `handle`, with a blob the app's
    /// extension decrypts for a notification.
    pub fn push(&self, handle: &str, kind: Kind, blob: Option<&str>) -> Result<(), Error> {
        let mut body = serde_json::json!({ "handle": handle, "kind": kind });
        if let Some(blob) = blob {
            body["blob"] = blob.into();
        }
        self.call("/v1/push", &body).map(drop)
    }

    /// Update a Live Activity through its handle.
    pub fn update_activity(&self, handle: &str, state: &ActivityState) -> Result<(), Error> {
        let body = serde_json::json!({ "handle": handle, "kind": Kind::Activity, "state": state });
        self.call("/v1/push", &body).map(drop)
    }

    fn call(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::blocking::Response, Error> {
        let response = self
            .http
            .post(format!("{}{path}", self.base))
            .json(body)
            .send()
            // The URL holds nothing secret, but the body would; neither goes
            // into the error.
            .map_err(|e| Error::Transport(e.without_url().to_string()))?;
        let status = response.status().as_u16();
        let retry = || {
            let secs = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
                .unwrap_or(60);
            Duration::from_secs(secs)
        };
        match status {
            200..=299 => Ok(response),
            410 => Err(Error::Gone),
            429 => Err(Error::Limited(retry())),
            503 => Err(Error::Unavailable(retry())),
            400 | 408 | 413 | 415 => {
                let why = response
                    .json::<serde_json::Value>()
                    .ok()
                    .and_then(|v| v["error"].as_str().map(str::to_owned))
                    .unwrap_or_else(|| format!("{status}"));
                Err(Error::Bad(why))
            }
            _ => Err(Error::Transport(format!("unexpected {status}"))),
        }
    }
}
