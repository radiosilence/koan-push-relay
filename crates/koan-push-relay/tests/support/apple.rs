//! A stand-in for Apple's App Attest: a root, an intermediate it signed, and
//! a device key whose attestations and assertions it makes. Shared by the
//! relay's unit tests and its integration tests.

#![allow(dead_code)]

use aws_lc_rs::digest;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use ciborium::Value;
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, IsCa, Issuer, KeyPair as RcKey,
    PKCS_ECDSA_P384_SHA384,
};

pub const APP_ID: &str = "TEAM123456.cc.blit.koan";
pub const PRODUCTION: &[u8; 16] = b"appattest\0\0\0\0\0\0\0";
pub const DEVELOPMENT: &[u8; 16] = b"appattestdevelop";

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
