//! Domain-type tests for recovery-code generation and verification.
//!
//! These exercise the pure functions in `crate::recovery` — the character-set
//! and length invariants, the salt+hash round-trip, and constant-time
//! verification. Expected values are independent of the implementation's
//! internal reasoning (fixed character sets, structural assertions).

use crate::recovery::crypto::{
    generate_recovery_codes, generate_salt, hash_code, verify_code,
};
use crate::recovery::{CODE_LENGTH, CODES_PER_BATCH};

#[test]
fn batch_has_expected_count_and_unique_codes() {
    let codes = generate_recovery_codes(CODES_PER_BATCH);

    assert_eq!(codes.len(), CODES_PER_BATCH);
    let unique: std::collections::HashSet<&String> = codes.iter().collect();
    assert_eq!(unique.len(), CODES_PER_BATCH, "codes must be unique");
}

#[test]
fn codes_match_length_and_character_set() {
    let codes = generate_recovery_codes(10);
    // The alphabet excludes 0/O and 1/I/l to avoid transcription ambiguity.
    const ALLOWED: &str = "23456789ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";

    for code in &codes {
        assert_eq!(code.len(), CODE_LENGTH, "code length");
        assert!(
            code.chars().all(|c| ALLOWED.contains(c)),
            "code must only contain unambiguous alphabet chars"
        );
    }
}

#[test]
fn hash_verify_round_trips() {
    let code = generate_recovery_codes(1)[0].clone();
    let salt = generate_salt();
    let hash = hash_code(&code, &salt);

    assert!(verify_code(&code, &salt, &hash), "correct code verifies");
}

#[test]
fn verify_rejects_wrong_code_and_wrong_salt() {
    let correct = generate_recovery_codes(1)[0].clone();
    let salt = generate_salt();
    let hash = hash_code(&correct, &salt);

    assert!(!verify_code("AAAAAAAAAAAAAAAA", &salt, &hash), "wrong code rejected");
    assert!(
        !verify_code(&correct, &[0u8; 16], &hash),
        "wrong salt yields a different hash"
    );
}

#[test]
fn same_code_different_salt_different_hash() {
    // The per-code salt must make the same code produce different hashes for
    // different users/positions (defeats rainbow tables / cross-user oracle).
    let code = generate_recovery_codes(1)[0].clone();
    let salt_a = generate_salt();
    let salt_b = generate_salt();

    let hash_a = hash_code(&code, &salt_a);
    let hash_b = hash_code(&code, &salt_b);
    assert_ne!(hash_a, hash_b);
}

#[test]
fn hash_is_sha256_length() {
    // 32 bytes = SHA-256 output; locks the hash primitive contract so a
    // downstream change (e.g. a KDF) is a visible, reviewed change.
    let code = generate_recovery_codes(1)[0].clone();
    let hash = hash_code(&code, &[0u8; 16]);
    assert_eq!(hash.len(), 32);
}
