use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::{ActivityState, Attested, Kind, Registered, RegisteredActivity, Slot, is_blob};

/// An App Attest assertion over one registration.
#[derive(Clone, Copy)]
pub struct Assertion<'a> {
    /// The attested key, as `Client::attest` returned it.
    pub key: &'a str,
    /// The challenge the assertion was made for.
    pub challenge: &'a str,
    /// What `generateAssertion` returned.
    pub assertion: &'a [u8],
}

/// A push to a device's handle. Live Activity updates go through
/// `Client::update_activity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push<'a> {
    /// Wake the app to link and take what waits for it.
    Wake,
    /// The same, for something that is no use an hour late.
    WakeNow,
    /// A notification asking to be tapped, with a blob the app's extension
    /// decrypts (`is_blob`).
    Summon { blob: Option<&'a str> },
    /// A notification carrying a command, with a blob the app's extension
    /// decrypts (`is_blob`).
    Notify { blob: Option<&'a str> },
}

/// Why the relay did not do what was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The request is malformed, or the relay serves no such gateway: sending
    /// it again will not help.
    Bad(String),
    /// The handle or revoker no longer opens, or Apple says the app or the
    /// activity is gone: forget it.
    Gone,
    /// A quota is spent: try again after this long.
    Limited(Duration),
    /// The relay or Apple cannot take it now, or the request did not arrive
    /// in time: try again after this long.
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

/// How long to wait before trying again when the relay says nothing.
const DEFAULT_RETRY: Duration = Duration::from_secs(5);

pub struct Client {
    base: reqwest::Url,
    http: reqwest::blocking::Client,
}

impl Client {
    /// A client for the relay at `base`, such as `DEFAULT_URL`. It must be
    /// https: handles, revokers and tokens are credentials. Plain http is
    /// allowed only to a loopback address.
    pub fn new(base: &str) -> Result<Self, Error> {
        let base = reqwest::Url::parse(base).map_err(|e| Error::Bad(format!("relay URL: {e}")))?;
        let loopback = match base.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(name)) => name == "localhost",
            None => false,
        };
        if base.scheme() != "https" && !(base.scheme() == "http" && loopback) {
            return Err(Error::Bad("the relay URL must be https".into()));
        }
        let http = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(Self { base, http })
    }

    /// Register a device token, for the server the app gave `slot`.
    /// `sandbox` is true for development builds. Only the sandbox gateway
    /// takes a registration without App Attest: see `register_attested`.
    pub fn register(&self, token: &[u8], slot: &Slot, sandbox: bool) -> Result<Registered, Error> {
        self.register_with(token, slot, sandbox, None)
    }

    /// Register a device token with an App Attest assertion: what the
    /// production gateway requires. `assertion.assertion` is what
    /// `DCAppAttestService.generateAssertion` returned for the SHA-256 of
    /// `client_data(challenge, token, slot, sandbox)`.
    pub fn register_attested(
        &self,
        token: &[u8],
        slot: &Slot,
        sandbox: bool,
        assertion: &Assertion<'_>,
    ) -> Result<Registered, Error> {
        self.register_with(token, slot, sandbox, Some(assertion))
    }

    fn register_with(
        &self,
        token: &[u8],
        slot: &Slot,
        sandbox: bool,
        assertion: Option<&Assertion<'_>>,
    ) -> Result<Registered, Error> {
        let mut body = serde_json::json!({
            "token": hex::encode(token),
            "slot": hex::encode(slot),
            "sandbox": sandbox,
        });
        if let Some(a) = assertion {
            body["attest"] = serde_json::json!({
                "key": a.key,
                "challenge": a.challenge,
                "assertion": URL_SAFE_NO_PAD.encode(a.assertion),
            });
        }
        self.call("v1/register", &body)?
            .json()
            .map_err(|e| Error::Transport(e.to_string()))
    }

    /// A challenge for an attestation or an assertion, good for five
    /// minutes.
    pub fn challenge(&self) -> Result<String, Error> {
        let answer: serde_json::Value = self
            .call("v1/challenge", &serde_json::json!({}))?
            .json()
            .map_err(|e| Error::Transport(e.to_string()))?;
        answer["challenge"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| Error::Transport("no challenge".into()))
    }

    /// Have the relay verify an App Attest key: `key_id` from
    /// `DCAppAttestService.generateKey`, and `attestation` from `attestKey`
    /// for the SHA-256 of `challenge`'s bytes. The returned key is what
    /// `register_attested` takes; keep it until it expires.
    pub fn attest(
        &self,
        key_id: &[u8],
        attestation: &[u8],
        challenge: &str,
    ) -> Result<Attested, Error> {
        let body = serde_json::json!({
            "key_id": URL_SAFE_NO_PAD.encode(key_id),
            "attestation": URL_SAFE_NO_PAD.encode(attestation),
            "challenge": challenge,
        });
        self.call("v1/attest", &body)?
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
        self.call("v1/register-activity", &body)?
            .json()
            .map_err(|e| Error::Transport(e.to_string()))
    }

    /// Retire every handle and revoker the device has been given.
    pub fn revoke(&self, revoker: &str) -> Result<(), Error> {
        self.call("v1/revoke", &serde_json::json!({ "revoker": revoker }))
            .map(drop)
    }

    /// Send a wake or a notification through a device's `handle`.
    pub fn push(&self, handle: &str, push: Push<'_>) -> Result<(), Error> {
        let (kind, blob) = match push {
            Push::Wake => (Kind::Wake, None),
            Push::WakeNow => (Kind::WakeNow, None),
            Push::Summon { blob } => (Kind::Summon, blob),
            Push::Notify { blob } => (Kind::Notify, blob),
        };
        let mut body = serde_json::json!({ "handle": handle, "kind": kind });
        if let Some(blob) = blob {
            if !is_blob(blob) {
                return Err(Error::Bad(format!(
                    "a blob is base64url of at most {} characters",
                    crate::MAX_BLOB
                )));
            }
            body["blob"] = blob.into();
        }
        self.call("v1/push", &body).map(drop)
    }

    /// Update a Live Activity through its handle.
    pub fn update_activity(&self, handle: &str, state: &ActivityState) -> Result<(), Error> {
        let body = serde_json::json!({ "handle": handle, "kind": Kind::Activity, "state": state });
        self.call("v1/push", &body).map(drop)
    }

    fn call(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::blocking::Response, Error> {
        let url = self
            .base
            .join(path)
            .map_err(|e| Error::Bad(format!("relay URL: {e}")))?;
        let response = self
            .http
            .post(url)
            .json(body)
            .send()
            // The body holds credentials and never goes into the error.
            .map_err(|e| Error::Transport(e.without_url().to_string()))?;
        let status = response.status().as_u16();
        let retry = || {
            response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
                .map_or(DEFAULT_RETRY, Duration::from_secs)
        };
        match status {
            200..=299 => Ok(response),
            410 => Err(Error::Gone),
            429 => Err(Error::Limited(retry())),
            // 408: the body did not arrive in time, or the request waited too
            // long on Apple. Both pass.
            408 | 503 => Err(Error::Unavailable(retry())),
            400 | 413 | 415 => {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_relay_is_reached_over_https_or_loopback_only() {
        assert!(Client::new("https://push.koan.rocks").is_ok());
        assert!(Client::new("http://127.0.0.1:8080").is_ok());
        assert!(Client::new("http://[::1]:8080").is_ok());
        assert!(Client::new("http://localhost:8080").is_ok());
        for bad in [
            "http://push.koan.rocks",
            "ftp://push.koan.rocks",
            "push.koan.rocks",
            "",
        ] {
            assert!(matches!(Client::new(bad), Err(Error::Bad(_))), "{bad}");
        }
    }

    #[test]
    fn a_relay_under_a_path_keeps_it() {
        let c = Client::new("https://example.org/relay/").unwrap();
        assert_eq!(
            c.base.join("v1/push").unwrap().as_str(),
            "https://example.org/relay/v1/push"
        );
    }

    #[test]
    fn a_blob_that_cannot_be_sent_is_refused_before_sending() {
        let c = Client::new("http://127.0.0.1:9").unwrap();
        for blob in [
            "",
            "has spaces",
            "padded==",
            &"A".repeat(crate::MAX_BLOB + 1),
        ] {
            let r = c.push("handle", Push::Notify { blob: Some(blob) });
            assert!(matches!(r, Err(Error::Bad(_))), "{blob:?}");
        }
    }

    #[test]
    fn registrations_never_print_their_secrets() {
        let r = Registered {
            handle: "the-handle".into(),
            revoker: "the-revoker".into(),
            expires: 1,
        };
        let shown = format!("{r:?}");
        assert!(!shown.contains("the-handle") && !shown.contains("the-revoker"));
    }
}
