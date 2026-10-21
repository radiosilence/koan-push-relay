//! App Attest: telling kōan's app from a script.
//!
//! Without it, anyone can make the relay prove a made-up token to Apple under
//! the developer's key, bounded only by rate. With it, a registration carries
//! an assertion from a key that Apple has certified lives in the Secure
//! Enclave of a real device running this app, and nothing reaches Apple
//! without one.
//!
//! The relay stays stateless. A challenge is the time it was issued, sealed
//! with an HMAC; an attested key is sealed into a handle-like token the app
//! keeps. The assertion's counter is not tracked: an assertion is bound to a
//! challenge that lapses in minutes and to the exact token, slot and gateway
//! it registers, so replaying one only repeats the same registration.
//!
//! See Apple's "Validating apps that connect to your server".

use aws_lc_rs::{digest, hmac, signature};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::Value;
use x509_parser::prelude::*;

/// Apple's App Attestation root, valid until 2045.
const APPLE_ROOT: &str = include_str!("apple-app-attestation-root.pem");
/// The extension in the credential certificate holding the attestation's
/// nonce.
const NONCE_OID: &str = "1.2.840.113635.100.8.2";
/// How long a challenge may be used for.
pub const CHALLENGE_LIFE_MS: u64 = 5 * 60 * 1000;
const CHALLENGE_LEN: usize = 8 + 16 + 16;
/// The authenticator data's AAGUID for each App Attest environment.
const AAGUID_DEVELOPMENT: &[u8; 16] = b"appattestdevelop";
const AAGUID_PRODUCTION: &[u8; 16] = b"appattest\0\0\0\0\0\0\0";
/// Relying party hash, flags, counter.
const AUTH_DATA_HEADER: usize = 32 + 1 + 4;

/// A key Apple has certified, and in which environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedKey {
    /// The P-256 public key, uncompressed (65 bytes).
    pub public_key: Vec<u8>,
    /// Production (TestFlight and App Store builds) rather than development.
    pub production: bool,
}

pub struct Attestor {
    app_id_hash: [u8; 32],
    root: Vec<u8>,
    challenges: hmac::Key,
}

impl Attestor {
    /// For the app `app_id` (team id, a dot, the bundle id), trusting `root`
    /// (PEM) in place of Apple's root when given, with `secret` keying
    /// challenges.
    pub fn new(app_id: &str, root: Option<&str>, secret: &[u8; 32]) -> Result<Self, String> {
        let pem = root.unwrap_or(APPLE_ROOT);
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
            .map_err(|e| format!("the App Attest root is not PEM: {e}"))?;
        X509Certificate::from_der(&pem.contents)
            .map_err(|e| format!("the App Attest root is not a certificate: {e}"))?;
        let mut app_id_hash = [0u8; 32];
        app_id_hash.copy_from_slice(digest::digest(&digest::SHA256, app_id.as_bytes()).as_ref());
        // Its own key, apart from any other the relay holds.
        let challenges = hmac::Key::new(
            hmac::HMAC_SHA256,
            hmac::sign(
                &hmac::Key::new(hmac::HMAC_SHA256, secret),
                b"koan-relay challenges",
            )
            .as_ref(),
        );
        Ok(Self {
            app_id_hash,
            root: pem.contents,
            challenges,
        })
    }

    /// A challenge issued at `now_ms`: the time, sixteen random bytes, and a
    /// tag over both, base64url.
    pub fn challenge(&self, now_ms: u64) -> String {
        let mut body = [0u8; 24];
        body[..8].copy_from_slice(&now_ms.to_be_bytes());
        aws_lc_rs::rand::fill(&mut body[8..]).expect("the system's random source failed");
        let tag = hmac::sign(&self.challenges, &body);
        let mut out = body.to_vec();
        out.extend_from_slice(&tag.as_ref()[..16]);
        URL_SAFE_NO_PAD.encode(out)
    }

    /// The challenge's bytes, if this relay issued it within its life.
    pub fn check_challenge(&self, challenge: &str, now_ms: u64) -> Result<Vec<u8>, &'static str> {
        let bytes = URL_SAFE_NO_PAD
            .decode(challenge)
            .ok()
            .filter(|b| b.len() == CHALLENGE_LEN)
            .ok_or("not a challenge")?;
        let tag = hmac::sign(&self.challenges, &bytes[..24]);
        if !constant_eq(&tag.as_ref()[..16], &bytes[24..]) {
            return Err("not a challenge");
        }
        let issued = u64::from_be_bytes(bytes[..8].try_into().expect("eight bytes"));
        if issued > now_ms.saturating_add(60_000)
            || now_ms.saturating_sub(issued) > CHALLENGE_LIFE_MS
        {
            return Err("the challenge has lapsed");
        }
        Ok(bytes)
    }

    /// Verify an attestation of `key_id` made for `challenge` (its bytes),
    /// as of `now_secs`.
    pub fn attest(
        &self,
        key_id: &[u8],
        attestation: &[u8],
        challenge: &[u8],
        now_secs: i64,
    ) -> Result<AttestedKey, &'static str> {
        let value: Value = ciborium::from_reader(attestation).map_err(|_| "not CBOR")?;
        let map = value.as_map().ok_or("not an attestation")?;
        let field = |name: &str| {
            map.iter()
                .find(|(k, _)| k.as_text() == Some(name))
                .map(|(_, v)| v)
        };
        if field("fmt").and_then(Value::as_text) != Some("apple-appattest") {
            return Err("not an App Attest attestation");
        }
        let statement = field("attStmt")
            .and_then(Value::as_map)
            .ok_or("no statement")?;
        let x5c = statement
            .iter()
            .find(|(k, _)| k.as_text() == Some("x5c"))
            .and_then(|(_, v)| v.as_array())
            .ok_or("no certificates")?;
        let auth_data = field("authData")
            .and_then(Value::as_bytes)
            .ok_or("no authenticator data")?;
        let [leaf, intermediate, ..] = x5c.as_slice() else {
            return Err("too few certificates");
        };
        let leaf = leaf.as_bytes().ok_or("not a certificate")?;
        let intermediate = intermediate.as_bytes().ok_or("not a certificate")?;

        // The chain: the credential certificate, signed by the intermediate,
        // signed by the root, each valid now.
        let (_, leaf) = X509Certificate::from_der(leaf).map_err(|_| "not a certificate")?;
        let (_, intermediate) =
            X509Certificate::from_der(intermediate).map_err(|_| "not a certificate")?;
        let (_, root) = X509Certificate::from_der(&self.root).map_err(|_| "no root")?;
        let now = ASN1Time::from_timestamp(now_secs).map_err(|_| "no time")?;
        if !leaf.validity().is_valid_at(now) || !intermediate.validity().is_valid_at(now) {
            return Err("a certificate is not valid now");
        }
        intermediate
            .verify_signature(Some(root.public_key()))
            .map_err(|_| "the chain does not lead to Apple")?;
        leaf.verify_signature(Some(intermediate.public_key()))
            .map_err(|_| "the chain does not lead to Apple")?;

        // The nonce: the authenticator data and the challenge, as the
        // credential certificate records them.
        let client_data_hash = digest::digest(&digest::SHA256, challenge);
        let mut nonce_input = auth_data.to_vec();
        nonce_input.extend_from_slice(client_data_hash.as_ref());
        let nonce = digest::digest(&digest::SHA256, &nonce_input);
        let extension = leaf
            .iter_extensions()
            .find(|e| e.oid.to_id_string() == NONCE_OID)
            .ok_or("no nonce")?;
        if nonce_of(extension.value) != Some(nonce.as_ref()) {
            return Err("the nonce does not match");
        }

        // The key: what the app says it attested.
        let public_key = leaf.public_key().subject_public_key.data.to_vec();
        if public_key.len() != 65 || digest::digest(&digest::SHA256, &public_key).as_ref() != key_id
        {
            return Err("the key does not match its id");
        }

        // The authenticator data: this app, a fresh key, its environment, and
        // the credential being that key.
        if auth_data.len() < AUTH_DATA_HEADER + 16 + 2 || auth_data[..32] != self.app_id_hash {
            return Err("not this app");
        }
        if auth_data[33..37] != [0, 0, 0, 0] {
            return Err("the key has been used before");
        }
        let aaguid = &auth_data[37..53];
        let production = if aaguid == AAGUID_PRODUCTION {
            true
        } else if aaguid == AAGUID_DEVELOPMENT {
            false
        } else {
            return Err("an unknown App Attest environment");
        };
        let id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        if auth_data.get(55..55 + id_len) != Some(key_id) {
            return Err("the credential is not the key");
        }
        Ok(AttestedKey {
            public_key,
            production,
        })
    }

    /// Verify an assertion over `client_data` by the attested `public_key`.
    pub fn assert(
        &self,
        public_key: &[u8],
        assertion: &[u8],
        client_data: &[u8],
    ) -> Result<(), &'static str> {
        let value: Value = ciborium::from_reader(assertion).map_err(|_| "not CBOR")?;
        let map = value.as_map().ok_or("not an assertion")?;
        let field = |name: &str| {
            map.iter()
                .find(|(k, _)| k.as_text() == Some(name))
                .and_then(|(_, v)| v.as_bytes())
        };
        let signature_der = field("signature").ok_or("no signature")?;
        let auth_data = field("authenticatorData").ok_or("no authenticator data")?;
        if auth_data.len() < AUTH_DATA_HEADER || auth_data[..32] != self.app_id_hash {
            return Err("not this app");
        }
        let client_data_hash = digest::digest(&digest::SHA256, client_data);
        let mut nonce_input = auth_data.to_vec();
        nonce_input.extend_from_slice(client_data_hash.as_ref());
        let nonce = digest::digest(&digest::SHA256, &nonce_input);
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key)
            .verify(nonce.as_ref(), signature_der)
            .map_err(|_| "the assertion's signature does not verify")
    }
}

/// The nonce in the credential certificate's extension:
/// `SEQUENCE { [1] EXPLICIT OCTET STRING }`.
fn nonce_of(der: &[u8]) -> Option<&[u8]> {
    let (tag, body, _) = tlv(der)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, body, _) = tlv(body)?;
    if tag != 0xA1 {
        return None;
    }
    let (tag, body, _) = tlv(body)?;
    (tag == 0x04).then_some(body)
}

/// One DER element: its tag, its contents and what follows it.
fn tlv(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 2 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, b| acc << 8 | *b as usize);
        (len, &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, IsCa, Issuer, KeyPair as RcKey,
        PKCS_ECDSA_P384_SHA384,
    };

    pub const APP_ID: &str = "TEAM123456.cc.blit.koan";
    const NOW: i64 = 1_800_000_000;
    const SECRET: [u8; 32] = [9; 32];

    /// A stand-in for Apple: a root, an intermediate it signed, and a device
    /// key whose attestations the intermediate signs.
    pub struct FakeApple {
        pub root_pem: String,
        intermediate: Issuer<'static, RcKey>,
        intermediate_der: Vec<u8>,
        device_pkcs8: Vec<u8>,
        pub device: EcdsaKeyPair,
    }

    impl FakeApple {
        pub fn new() -> Self {
            let root_key = RcKey::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
            let mut root = CertificateParams::new(Vec::<String>::new()).unwrap();
            root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let root_cert = root.self_signed(&root_key).unwrap();
            let root_issuer = Issuer::new(root, root_key);
            let inter_key = RcKey::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
            let mut inter = CertificateParams::new(Vec::<String>::new()).unwrap();
            inter.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let inter_cert = inter.signed_by(&inter_key, &root_issuer).unwrap();
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                .unwrap()
                .as_ref()
                .to_vec();
            let device = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8).unwrap();
            Self {
                root_pem: root_cert.pem(),
                intermediate: Issuer::new(inter, inter_key),
                intermediate_der: inter_cert.der().to_vec(),
                device_pkcs8: pkcs8,
                device,
            }
        }

        pub fn key_id(&self) -> Vec<u8> {
            digest::digest(&digest::SHA256, self.device.public_key().as_ref())
                .as_ref()
                .to_vec()
        }

        /// An attestation's authenticator data, for `app_id`.
        pub fn auth_data(&self, app_id: &str, counter: u32, aaguid: &[u8; 16]) -> Vec<u8> {
            let key_id = self.key_id();
            let mut data = digest::digest(&digest::SHA256, app_id.as_bytes())
                .as_ref()
                .to_vec();
            data.push(0x40);
            data.extend_from_slice(&counter.to_be_bytes());
            data.extend_from_slice(aaguid);
            data.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
            data.extend_from_slice(&key_id);
            data
        }

        /// An attestation of the device key for `challenge`, over
        /// `auth_data`.
        pub fn attestation(&self, auth_data: &[u8], challenge: &[u8]) -> Vec<u8> {
            let mut input = auth_data.to_vec();
            input.extend_from_slice(digest::digest(&digest::SHA256, challenge).as_ref());
            let nonce = digest::digest(&digest::SHA256, &input);
            let mut ext = vec![0x30, 0x24, 0xA1, 0x22, 0x04, 0x20];
            ext.extend_from_slice(nonce.as_ref());
            let device = RcKey::try_from(self.device_pkcs8.as_slice()).unwrap();
            let mut leaf = CertificateParams::new(Vec::<String>::new()).unwrap();
            leaf.custom_extensions = vec![CustomExtension::from_oid_content(
                &[1, 2, 840, 113635, 100, 8, 2],
                ext,
            )];
            let leaf = leaf.signed_by(&device, &self.intermediate).unwrap();
            let value = Value::Map(vec![
                (
                    Value::Text("fmt".into()),
                    Value::Text("apple-appattest".into()),
                ),
                (
                    Value::Text("attStmt".into()),
                    Value::Map(vec![(
                        Value::Text("x5c".into()),
                        Value::Array(vec![
                            Value::Bytes(leaf.der().to_vec()),
                            Value::Bytes(self.intermediate_der.clone()),
                        ]),
                    )]),
                ),
                (
                    Value::Text("authData".into()),
                    Value::Bytes(auth_data.to_vec()),
                ),
            ]);
            let mut out = Vec::new();
            ciborium::into_writer(&value, &mut out).unwrap();
            out
        }

        /// An assertion by the device key over `client_data`, for `app_id`.
        pub fn assertion(&self, app_id: &str, client_data: &[u8]) -> Vec<u8> {
            let mut auth_data = digest::digest(&digest::SHA256, app_id.as_bytes())
                .as_ref()
                .to_vec();
            auth_data.push(0x40);
            auth_data.extend_from_slice(&1u32.to_be_bytes());
            let mut input = auth_data.clone();
            input.extend_from_slice(digest::digest(&digest::SHA256, client_data).as_ref());
            let nonce = digest::digest(&digest::SHA256, &input);
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let signature = self.device.sign(&rng, nonce.as_ref()).unwrap();
            let value = Value::Map(vec![
                (
                    Value::Text("signature".into()),
                    Value::Bytes(signature.as_ref().to_vec()),
                ),
                (
                    Value::Text("authenticatorData".into()),
                    Value::Bytes(auth_data),
                ),
            ]);
            let mut out = Vec::new();
            ciborium::into_writer(&value, &mut out).unwrap();
            out
        }
    }

    fn attestor(apple: &FakeApple) -> Attestor {
        Attestor::new(APP_ID, Some(&apple.root_pem), &SECRET).unwrap()
    }

    #[test]
    fn apples_own_root_loads() {
        assert!(Attestor::new(APP_ID, None, &SECRET).is_ok());
    }

    #[test]
    fn a_challenge_lasts_five_minutes_and_cannot_be_made_up() {
        let apple = FakeApple::new();
        let a = attestor(&apple);
        let c = a.challenge(1_000);
        assert!(a.check_challenge(&c, 1_000 + CHALLENGE_LIFE_MS).is_ok());
        assert!(a.check_challenge(&c, 1_001 + CHALLENGE_LIFE_MS).is_err());
        let other = Attestor::new(APP_ID, Some(&apple.root_pem), &[1; 32]).unwrap();
        assert!(other.check_challenge(&c, 1_000).is_err(), "another relay's");
        assert!(a.check_challenge("AAAA", 1_000).is_err());
    }

    #[test]
    fn an_attestation_from_the_root_is_accepted_with_its_environment() {
        let apple = FakeApple::new();
        let a = attestor(&apple);
        for (aaguid, production) in [(AAGUID_PRODUCTION, true), (AAGUID_DEVELOPMENT, false)] {
            let auth = apple.auth_data(APP_ID, 0, aaguid);
            let key = a
                .attest(
                    &apple.key_id(),
                    &apple.attestation(&auth, b"challenge"),
                    b"challenge",
                    NOW,
                )
                .unwrap();
            assert_eq!(key.production, production);
            assert_eq!(key.public_key, apple.device.public_key().as_ref());
        }
    }

    #[test]
    fn an_attestation_wrong_in_any_way_is_refused() {
        let apple = FakeApple::new();
        let a = attestor(&apple);
        let good = apple.auth_data(APP_ID, 0, AAGUID_PRODUCTION);
        let id = apple.key_id();
        let refused = |key_id: &[u8], attestation: Vec<u8>, challenge: &[u8]| {
            a.attest(key_id, &attestation, challenge, NOW).is_err()
        };
        assert!(
            refused(&id, apple.attestation(&good, b"one"), b"other"),
            "another challenge"
        );
        let other_app = apple.auth_data("TEAM123456.other", 0, AAGUID_PRODUCTION);
        assert!(
            refused(&id, apple.attestation(&other_app, b"c"), b"c"),
            "another app"
        );
        let used = apple.auth_data(APP_ID, 1, AAGUID_PRODUCTION);
        assert!(
            refused(&id, apple.attestation(&used, b"c"), b"c"),
            "a used key"
        );
        let unknown = apple.auth_data(APP_ID, 0, b"somethingelse\0\0\0");
        assert!(
            refused(&id, apple.attestation(&unknown, b"c"), b"c"),
            "no environment"
        );
        assert!(
            refused(&[0; 32], apple.attestation(&good, b"c"), b"c"),
            "another key id"
        );
        let stranger = FakeApple::new();
        let theirs = stranger.auth_data(APP_ID, 0, AAGUID_PRODUCTION);
        assert!(
            refused(
                &stranger.key_id(),
                stranger.attestation(&theirs, b"c"),
                b"c"
            ),
            "a chain from another root"
        );
        assert!(refused(&id, b"not cbor".to_vec(), b"c"));
    }

    #[test]
    fn an_assertion_holds_only_for_what_it_signed() {
        let apple = FakeApple::new();
        let a = attestor(&apple);
        let key = apple.device.public_key().as_ref().to_vec();
        let signed = apple.assertion(APP_ID, b"register this");
        assert!(a.assert(&key, &signed, b"register this").is_ok());
        assert!(a.assert(&key, &signed, b"register that").is_err());
        assert!(
            a.assert(&key, &apple.assertion("TEAM123456.other", b"x"), b"x")
                .is_err()
        );
        let stranger = FakeApple::new();
        assert!(
            a.assert(
                stranger.device.public_key().as_ref(),
                &signed,
                b"register this"
            )
            .is_err()
        );
    }

    #[test]
    fn the_nonce_is_read_from_its_der() {
        let mut ext = vec![0x30, 0x24, 0xA1, 0x22, 0x04, 0x20];
        ext.extend_from_slice(&[7; 32]);
        assert_eq!(nonce_of(&ext), Some(&[7u8; 32][..]));
        assert_eq!(nonce_of(&ext[..10]), None);
        assert_eq!(nonce_of(&[0x04, 0x01, 0x00]), None);
    }
}
