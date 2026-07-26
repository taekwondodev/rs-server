use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Shared-kernel identifier for a user, referenced across bounded contexts
/// (e.g. a future `domain-payments` crate needs to say "which user paid" without
/// depending on the whole `domain-auth` crate). Keep this crate to identifiers
/// and other cross-context value objects only — anything with auth-specific
/// business rules belongs in `domain-auth`, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(Uuid);

impl UserId {
    pub fn new(id: Uuid) -> Self {
        Self(id)
    }

    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for UserId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<UserId> for Uuid {
    fn from(id: UserId) -> Self {
        id.0
    }
}
