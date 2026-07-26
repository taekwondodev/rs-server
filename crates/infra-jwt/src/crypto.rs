use std::time::Duration;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use domain_auth::{AccessTokenClaims, DomainError, RefreshTokenClaims};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use sha2::Sha256;

const ACCESS_TOKEN_DURATION: Duration = Duration::from_secs(5 * 60);
const REFRESH_TOKEN_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// Holds the derived signing/verification key material and encodes/decodes
/// the domain claim structs. All crypto concerns (HKDF derivation, Ed25519 /
/// HS256 keys, hand-rolled PKCS8/SPKI PEM wrapping) live here as inherent
/// methods operating on `domain_auth::AccessTokenClaims`/`RefreshTokenClaims`'s
/// public fields — the claim structs themselves carry none of this.
pub(crate) struct JwtCrypto {
    pub(crate) issuer: Box<str>,
    pub(crate) audience: Box<str>,
    access_encoding_key: EncodingKey,
    access_decoding_key: DecodingKey,
    refresh_encoding_key: EncodingKey,
    refresh_decoding_key: DecodingKey,
    pub(crate) access_token_duration: Duration,
    pub(crate) refresh_token_duration: Duration,
}

impl JwtCrypto {
    pub(crate) fn from_secret(secret: &[u8], issuer: &str, audience: &str) -> Self {
        let hk = Hkdf::<Sha256>::new(None, secret);

        let mut access_key_bytes = [0u8; 32];
        hk.expand(b"access-token", &mut access_key_bytes)
            .expect("HKDF expand failed for access key");

        let mut refresh_key_bytes = [0u8; 32];
        hk.expand(b"refresh-token", &mut refresh_key_bytes)
            .expect("HKDF expand failed for refresh key");

        let signing_key = SigningKey::from_bytes(&access_key_bytes);
        let verifying_key = signing_key.verifying_key();

        let access_encoding_key = EncodingKey::from_ed_pem(&ed25519_to_pem(&signing_key))
            .expect("Failed to create encoding key from Ed25519 private key");

        let access_decoding_key = DecodingKey::from_ed_pem(&ed25519_public_to_pem(&verifying_key))
            .expect("Failed to create decoding key from Ed25519 public key");

        let refresh_encoding_key = EncodingKey::from_secret(&refresh_key_bytes);
        let refresh_decoding_key = DecodingKey::from_secret(&refresh_key_bytes);

        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            access_encoding_key,
            access_decoding_key,
            refresh_encoding_key,
            refresh_decoding_key,
            access_token_duration: ACCESS_TOKEN_DURATION,
            refresh_token_duration: REFRESH_TOKEN_DURATION,
        }
    }

    pub(crate) fn encode_access(&self, claims: &AccessTokenClaims) -> Box<str> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some("JWT".to_string());

        encode(&header, claims, &self.access_encoding_key)
            .expect("Invalid token type for access token creation")
            .into_boxed_str()
    }

    pub(crate) fn decode_access(&self, token: &str) -> Result<AccessTokenClaims, DomainError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        let token_data = decode::<AccessTokenClaims>(token, &self.access_decoding_key, &validation)
            .map_err(|_| DomainError::Unauthorized("Invalid token"))?;
        Ok(token_data.claims)
    }

    pub(crate) fn encode_refresh(&self, claims: &RefreshTokenClaims) -> Box<str> {
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("JWT".to_string());

        encode(&header, claims, &self.refresh_encoding_key)
            .expect("Expected Refresh token claims")
            .into_boxed_str()
    }

    /// Decodes and verifies signature/issuer/audience/expiry only — no
    /// session/family lookup. `Jwt::validate_refresh` (in `service.rs`) layers
    /// the redis session check + reuse-detection revocation on top, since
    /// that needs the full `Jwt` (crypto + redis), not just `JwtCrypto`.
    pub(crate) fn decode_refresh_unchecked(&self, token: &str) -> Result<RefreshTokenClaims, DomainError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        let token_data = decode::<RefreshTokenClaims>(token, &self.refresh_decoding_key, &validation)
            .map_err(|_| DomainError::Unauthorized("Invalid token"))?;
        Ok(token_data.claims)
    }
}

fn ed25519_to_pem(signing_key: &SigningKey) -> Vec<u8> {
    let private_key_bytes = signing_key.to_bytes();

    let mut pkcs8 = vec![
        0x30, 0x2e, // SEQUENCE (46 bytes)
        0x02, 0x01, 0x00, // INTEGER (version = 0)
        0x30, 0x05, // SEQUENCE (5 bytes)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID for Ed25519
        0x04, 0x22, // OCTET STRING (34 bytes)
        0x04, 0x20, // OCTET STRING (32 bytes)
    ];
    pkcs8.extend_from_slice(&private_key_bytes);

    let encoded = BASE64_STANDARD.encode(&pkcs8);

    let mut pem = Vec::new();
    pem.extend_from_slice(b"-----BEGIN PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.extend_from_slice(chunk);
        pem.push(b'\n');
    }
    pem.extend_from_slice(b"-----END PRIVATE KEY-----\n");
    pem
}

fn ed25519_public_to_pem(verifying_key: &VerifyingKey) -> Vec<u8> {
    let public_key_bytes = verifying_key.to_bytes();

    let mut spki = vec![
        0x30, 0x2a, // SEQUENCE (42 bytes)
        0x30, 0x05, // SEQUENCE (5 bytes)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID for Ed25519
        0x03, 0x21, // BIT STRING (33 bytes)
        0x00, // no unused bits
    ];
    spki.extend_from_slice(&public_key_bytes);

    let encoded = BASE64_STANDARD.encode(&spki);

    let mut pem = Vec::new();
    pem.extend_from_slice(b"-----BEGIN PUBLIC KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.extend_from_slice(chunk);
        pem.push(b'\n');
    }
    pem.extend_from_slice(b"-----END PUBLIC KEY-----\n");
    pem
}
