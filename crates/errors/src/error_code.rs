#![allow(dead_code)]
//! Stable machine-readable error codes, grouped by domain.
//!
//! Codes are `SCREAMING_SNAKE_CASE` strings, prefixed with the domain. They are
//! part of the public API contract — renaming one is a breaking change.
//!
//! Domains:
//!   * AUTH_*       — authentication / session
//!   * USER_*       — user profile / account
//!   * ORG_*        — organizations / members
//!   * PROJECT_*    — projects
//!   * ISSUE_*      — issues / comments / labels
//!   * VAULT_*      — vaults / secrets
//!   * CLUSTER_*    — cluster identities
//!   * INSTALL_*    — self-host installs
//!   * BILLING_*    — Stripe / plan
//!   * ADMIN_*      — staff-only endpoints
//!   * RATE_*       — rate-limit family
//!   * VALIDATION_* — payload validation
//!   * INTERNAL_*   — unexpected server-side failures
//!
//! Some constants below are not yet consumed — they stake out names for
//! endpoints that will be migrated in follow-up passes.

pub const AUTH_INVALID_CREDENTIALS: &str = "AUTH_INVALID_CREDENTIALS";
pub const AUTH_EMAIL_NOT_VERIFIED: &str = "AUTH_EMAIL_NOT_VERIFIED";
pub const AUTH_VERIFICATION_CODE_INVALID: &str = "AUTH_VERIFICATION_CODE_INVALID";
pub const AUTH_VERIFICATION_CODE_EXPIRED: &str = "AUTH_VERIFICATION_CODE_EXPIRED";
pub const AUTH_VERIFICATION_TOO_MANY_ATTEMPTS: &str = "AUTH_VERIFICATION_TOO_MANY_ATTEMPTS";
pub const AUTH_SESSION_EXPIRED: &str = "AUTH_SESSION_EXPIRED";
pub const AUTH_UNAUTHORIZED: &str = "AUTH_UNAUTHORIZED";
pub const AUTH_FORBIDDEN: &str = "AUTH_FORBIDDEN";
pub const AUTH_EMAIL_ALREADY_VERIFIED: &str = "AUTH_EMAIL_ALREADY_VERIFIED";
pub const AUTH_PASSWORD_RESET_TOKEN_INVALID: &str = "AUTH_PASSWORD_RESET_TOKEN_INVALID";
pub const AUTH_PASSWORD_RESET_TOKEN_EXPIRED: &str = "AUTH_PASSWORD_RESET_TOKEN_EXPIRED";
pub const AUTH_ACCOUNT_TEMPORARILY_LOCKED: &str = "AUTH_ACCOUNT_TEMPORARILY_LOCKED";
pub const AUTH_DELETION_TOKEN_INVALID: &str = "AUTH_DELETION_TOKEN_INVALID";
pub const AUTH_DELETION_TOKEN_EXPIRED: &str = "AUTH_DELETION_TOKEN_EXPIRED";

pub const USER_EMAIL_TAKEN: &str = "USER_EMAIL_TAKEN";
pub const USER_NOT_FOUND: &str = "USER_NOT_FOUND";
pub const USER_INVALID_TIMEZONE: &str = "USER_INVALID_TIMEZONE";
pub const USER_INVALID_LOCALE: &str = "USER_INVALID_LOCALE";
pub const USER_PREFERENCES_TOO_LARGE: &str = "USER_PREFERENCES_TOO_LARGE";
pub const USER_PASSWORD_IN_BREACH_CORPUS: &str = "USER_PASSWORD_IN_BREACH_CORPUS";
pub const USER_PASSWORD_TOO_WEAK: &str = "USER_PASSWORD_TOO_WEAK";

pub const ORG_NOT_FOUND: &str = "ORG_NOT_FOUND";
pub const ORG_SLUG_TAKEN: &str = "ORG_SLUG_TAKEN";
pub const ORG_MEMBER_ALREADY_EXISTS: &str = "ORG_MEMBER_ALREADY_EXISTS";
pub const ORG_LAST_OWNER: &str = "ORG_LAST_OWNER";
pub const ORG_CANNOT_REMOVE_SELF: &str = "ORG_CANNOT_REMOVE_SELF";

pub const PROJECT_NOT_FOUND: &str = "PROJECT_NOT_FOUND";
pub const PROJECT_SLUG_TAKEN: &str = "PROJECT_SLUG_TAKEN";

pub const ISSUE_NOT_FOUND: &str = "ISSUE_NOT_FOUND";

pub const VAULT_NOT_FOUND: &str = "VAULT_NOT_FOUND";
pub const VAULT_NAME_TAKEN: &str = "VAULT_NAME_TAKEN";
pub const SECRET_NOT_FOUND: &str = "SECRET_NOT_FOUND";

pub const CLUSTER_NOT_FOUND: &str = "CLUSTER_NOT_FOUND";
pub const CLUSTER_NAME_TAKEN: &str = "CLUSTER_NAME_TAKEN";
pub const CLUSTER_AUTHORIZATION_DUPLICATE: &str = "CLUSTER_AUTHORIZATION_DUPLICATE";
pub const CLUSTER_AUTHORIZATION_NOT_FOUND: &str = "CLUSTER_AUTHORIZATION_NOT_FOUND";
pub const CLUSTER_PERMISSION_UNKNOWN: &str = "CLUSTER_PERMISSION_UNKNOWN";

pub const INSTALL_NOT_FOUND: &str = "INSTALL_NOT_FOUND";
pub const INSTALL_NAME_TAKEN: &str = "INSTALL_NAME_TAKEN";

pub const BILLING_UNSUPPORTED_DEPLOYMENT_MODE: &str = "BILLING_UNSUPPORTED_DEPLOYMENT_MODE";

pub const ADMIN_STAFF_ONLY: &str = "ADMIN_STAFF_ONLY";

pub const RATE_LIMIT_EXCEEDED: &str = "RATE_LIMIT_EXCEEDED";

pub const VALIDATION_FAILED: &str = "VALIDATION_FAILED";
pub const BAD_REQUEST: &str = "BAD_REQUEST";
pub const GONE: &str = "GONE";
pub const PLAN_LIMIT_EXCEEDED: &str = "PLAN_LIMIT_EXCEEDED";

pub const INTERNAL_DATABASE: &str = "INTERNAL_DATABASE";
pub const INTERNAL_SERVER_ERROR: &str = "INTERNAL_SERVER_ERROR";
