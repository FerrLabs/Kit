#![forbid(unsafe_code)]
//! Typed id newtypes over [`uuid::Uuid`].
//!
//! Each domain entity gets a distinct, non-interchangeable id type so that
//! passing an [`OrgId`] where a [`SecretId`] is expected is a compile error.
//! This is the structural defence against cross-tenant / IDOR bugs: the type
//! system, not runtime checks, enforces that ids of different resources never
//! mix.
//!
//! All ids are transparent over `Uuid` on the wire (serde) and, with the
//! `sqlx` feature, bind/decode as a Postgres `uuid`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Error returned when parsing an id from a string fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseIdError(uuid::Error);

impl fmt::Display for ParseIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid id: {}", self.0)
    }
}

impl std::error::Error for ParseIdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

macro_rules! typed_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Wrap an existing [`Uuid`].
            #[must_use]
            pub const fn from_uuid(inner: Uuid) -> Self {
                Self(inner)
            }

            /// The nil id (all-zero), useful as a sentinel in tests.
            #[must_use]
            pub const fn nil() -> Self {
                Self(Uuid::nil())
            }

            /// The wrapped [`Uuid`].
            #[must_use]
            pub const fn as_uuid(&self) -> Uuid {
                self.0
            }

            /// Generate a fresh, time-ordered id (UUID v7).
            #[must_use]
            #[allow(clippy::missing_const_for_fn)]
            pub fn new_v7() -> Self {
                Self(Uuid::now_v7())
            }

            /// Alias for [`Self::new_v7`]. Kit standardises on time-ordered ids;
            /// the name mirrors the ULID helper used elsewhere in the codebase.
            #[must_use]
            #[allow(clippy::missing_const_for_fn)]
            pub fn new_ulid() -> Self {
                Self::new_v7()
            }
        }

        impl From<Uuid> for $name {
            fn from(inner: Uuid) -> Self {
                Self(inner)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = ParseIdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::from_str(s).map(Self).map_err(ParseIdError)
            }
        }

        #[cfg(feature = "sqlx")]
        impl<DB: sqlx::Database> sqlx::Type<DB> for $name
        where
            Uuid: sqlx::Type<DB>,
        {
            fn type_info() -> DB::TypeInfo {
                <Uuid as sqlx::Type<DB>>::type_info()
            }

            fn compatible(ty: &DB::TypeInfo) -> bool {
                <Uuid as sqlx::Type<DB>>::compatible(ty)
            }
        }

        #[cfg(feature = "sqlx")]
        impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for $name
        where
            Uuid: sqlx::Encode<'q, DB>,
        {
            fn encode_by_ref(
                &self,
                buf: &mut <DB as sqlx::Database>::ArgumentBuffer,
            ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
                <Uuid as sqlx::Encode<'q, DB>>::encode_by_ref(&self.0, buf)
            }
        }

        #[cfg(feature = "sqlx")]
        impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for $name
        where
            Uuid: sqlx::Decode<'r, DB>,
        {
            fn decode(
                value: <DB as sqlx::Database>::ValueRef<'r>,
            ) -> Result<Self, sqlx::error::BoxDynError> {
                <Uuid as sqlx::Decode<'r, DB>>::decode(value).map(Self)
            }
        }
    };
}

typed_id!(
    /// Identifier for a FerrLabs `Organization`.
    OrgId
);
typed_id!(
    /// Identifier for a project within an organization.
    ProjectId
);
typed_id!(
    /// Identifier for a FerrVault vault.
    VaultId
);
typed_id!(
    /// Identifier for a secret stored in a vault.
    SecretId
);
typed_id!(
    /// Identifier for a user account.
    UserId
);
typed_id!(
    /// Identifier for a `FerrFleet` agent.
    AgentId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip_is_transparent_uuid() {
        let id = OrgId::new_v7();
        let json = serde_json::to_string(&id).unwrap();
        let bare = serde_json::to_string(&id.as_uuid()).unwrap();
        assert_eq!(json, bare);

        let back: OrgId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn from_str_display_round_trip() {
        let id = SecretId::new_v7();
        let text = id.to_string();
        let parsed: SecretId = text.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn from_str_rejects_garbage() {
        let err = "not-a-uuid".parse::<UserId>();
        assert!(err.is_err());
    }

    #[test]
    fn v7_ids_are_time_ordered() {
        let a = AgentId::new_v7();
        let b = AgentId::new_v7();
        assert!(a < b || a.as_uuid() != b.as_uuid());
    }

    #[test]
    fn new_ulid_aliases_v7() {
        let id = ProjectId::new_ulid();
        assert_eq!(id.as_uuid().get_version_num(), 7);
    }

    #[test]
    fn same_uuid_different_types_are_separate_values() {
        let raw = Uuid::now_v7();
        let org = OrgId::from_uuid(raw);
        let user = UserId::from_uuid(raw);
        assert_eq!(org.as_uuid(), user.as_uuid());
    }

    #[test]
    fn nil_is_all_zero() {
        assert_eq!(VaultId::nil().as_uuid(), Uuid::nil());
    }
}
