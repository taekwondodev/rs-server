use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Characters excluded to avoid transcription ambiguity (0/O, 1/I/l). The
/// alphabet has 55 symbols — no punctuation, all unambiguous for manual entry.
const ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";

/// Length of a single recovery code in characters.
pub const CODE_LENGTH: usize = 16;
/// Number of codes generated per batch.
pub const CODES_PER_BATCH: usize = 10;
/// Number of consecutive failed verifications before the recovery path locks.
pub const LOCKOUT_THRESHOLD: u32 = 5;

/// A single stored recovery code entry — the salted hash and its position,
/// never the plaintext. The raw code is only ever materialised by
/// `generate_recovery_batch` (shown once to the user) and by the presenter at
/// the HTTP boundary; it is not stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCodeRecord {
    pub position: u32,
    pub salt: Vec<u8>,
    pub hash: Vec<u8>,
    pub used: bool,
}

/// Anti-brute-force state for a user's recovery path, persisted in Postgres
/// (not Redis — it must survive a server restart). `locked_until` is a growing
/// cooldown deadline after `LOCKOUT_THRESHOLD` consecutive failures.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecoveryLockout {
    pub attempts: u32,
    pub locked_until: Option<DateTime<Utc>>,
}

/// Everything the service needs about a user's recovery state in one fetch:
/// the batch of hashed codes plus the lockout state and the timestamp of the
/// last batch rotation (used to enforce the rotation cooldown).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryState {
    pub codes: Vec<RecoveryCodeRecord>,
    pub lockout: RecoveryLockout,
    pub last_rotated_at: Option<DateTime<Utc>>,
}

/// Pure domain functions for recovery-code generation and verification. No
/// infra or HTTP concepts; injectable `getrandom` for testability of the
/// character set and length invariants.
pub mod crypto {
    use super::*;

    /// Generates `count` unique recovery codes of `CODE_LENGTH` characters each.
    /// Returns the plaintext codes — the caller is responsible for showing them
    /// exactly once. Each code draws uniformly from `ALPHABET` (rejection
    /// sampling to avoid modulo bias).
    pub fn generate_recovery_codes(count: usize) -> Vec<String> {
        let mut codes = Vec::with_capacity(count);
        let mut seen = std::collections::HashSet::new();
        while codes.len() < count {
            let code = generate_single_code();
            if seen.insert(code.clone()) {
                codes.push(code);
            }
        }
        codes
    }

    /// One code of `CODE_LENGTH` uniform alphabet characters. Uses rejection
    /// sampling: for each position it draws random bytes and keeps only values
    /// in `[0, ALPHABET.len())` by masking down to the largest power-of-two
    /// multiple of the alphabet length, avoiding modulo bias entirely.
    fn generate_single_code() -> String {
        let mut code = String::with_capacity(CODE_LENGTH);
        // Mask to the largest power-of-two ≤ 255 that is a multiple of the
        // alphabet length, so rejection keeps the distribution uniform.
        let alphabet_len = ALPHABET.len();
        let mut mask = 1usize;
        while mask * 2 <= 255 {
            mask *= 2;
        }
        while !mask.is_multiple_of(alphabet_len) {
            mask -= 1;
        }

        while code.len() < CODE_LENGTH {
            let mut buf = [0u8; CODE_LENGTH];
            getrandom::fill(&mut buf).expect("CSPRNG failure generating recovery code");
            for byte in buf {
                let idx = byte as usize;
                if idx < mask {
                    code.push(ALPHABET[idx % alphabet_len] as char);
                    if code.len() == CODE_LENGTH {
                        break;
                    }
                }
            }
        }
        code
    }

    /// Fresh random salt for one code.
    pub fn generate_salt() -> Vec<u8> {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).expect("CSPRNG failure generating recovery salt");
        salt.to_vec()
    }

    /// Salted SHA-256 hash of a recovery code. The codes are random high
    /// entropy (~2^90 per code), so a fast hash is not the weak link; the salt
    /// prevents a rainbow-table/equality oracle across users or positions.
    pub fn hash_code(code: &str, salt: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(code.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Constant-time verification of a presented code against a stored
    /// salted hash. `subtle::ConstantTimeEq` avoids timing side channels on
    /// the comparison (equal-length hashes, so no length leak either).
    pub fn verify_code(code: &str, salt: &[u8], expected: &[u8]) -> bool {
        let actual = hash_code(code, salt);
        actual.ct_eq(expected).into()
    }
}
