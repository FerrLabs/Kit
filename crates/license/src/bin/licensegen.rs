//! Offline license-minting tool for `FerrLabs` self-host editions.
//!
//! Internal: signs a license token with the private key, which never leaves the
//! offline signing host. Built only with the `cli` feature.
//!
//! ```text
//! # keypair (one-off, kept offline):
//! openssl genpkey -algorithm ed25519 -out license-private.pem
//! openssl pkey -in license-private.pem -pubout -out license-public.pem
//!
//! # mint:
//! cargo run -p ferrlabs-license --features cli --bin licensegen -- \
//!   --key license-private.pem --id lic_acme_001 --product ferrvault \
//!   --kind customer --tier team --org acme --seats 25 \
//!   --features dynamic_secrets,audit_export --expires-in-days 365
//! ```

use std::fs;
use std::process::ExitCode;

use chrono::{Duration, Utc};
use clap::{Parser, ValueEnum};
use ferrlabs_license::{LicenseKind, LicenseSigner, LicenseSpec, LicenseTier};

#[derive(Parser)]
#[command(about = "Mint an offline FerrLabs license token", long_about = None)]
struct Args {
    /// Path to the ed25519 `PKCS#8` private key PEM.
    #[arg(long)]
    key: String,
    /// License id — your own reference, e.g. `lic_acme_001`.
    #[arg(long)]
    id: String,
    /// Product the license unlocks, e.g. ferrvault.
    #[arg(long)]
    product: String,
    #[arg(long, value_enum, default_value_t = KindArg::Customer)]
    kind: KindArg,
    #[arg(long, value_enum, default_value_t = TierArg::Pro)]
    tier: TierArg,
    /// Org name or id (display only).
    #[arg(long)]
    org: Option<String>,
    /// Seat cap; omit for unlimited.
    #[arg(long)]
    seats: Option<u32>,
    /// Comma-separated feature flags.
    #[arg(long, default_value = "")]
    features: String,
    /// Days until the license expires.
    #[arg(long)]
    expires_in_days: i64,
}

#[derive(Clone, Copy, ValueEnum)]
enum KindArg {
    Admin,
    Customer,
}

#[derive(Clone, Copy, ValueEnum)]
enum TierArg {
    Free,
    Pro,
    Team,
    Enterprise,
}

impl From<KindArg> for LicenseKind {
    fn from(k: KindArg) -> Self {
        match k {
            KindArg::Admin => Self::Admin,
            KindArg::Customer => Self::Customer,
        }
    }
}

impl From<TierArg> for LicenseTier {
    fn from(t: TierArg) -> Self {
        match t {
            TierArg::Free => Self::Free,
            TierArg::Pro => Self::Pro,
            TierArg::Team => Self::Team,
            TierArg::Enterprise => Self::Enterprise,
        }
    }
}

fn parse_features(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .map(String::from)
        .collect()
}

fn main() -> ExitCode {
    let args = Args::parse();

    let key = match fs::read(&args.key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("reading key {}: {e}", args.key);
            return ExitCode::FAILURE;
        }
    };
    let signer = match LicenseSigner::from_ed25519_pem(&key) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("loading signer: {e}");
            return ExitCode::FAILURE;
        }
    };

    let now = Utc::now();
    let spec = LicenseSpec {
        id: args.id,
        product: args.product,
        org: args.org,
        kind: args.kind.into(),
        tier: args.tier.into(),
        seats: args.seats,
        features: parse_features(&args.features),
        issued_at: now,
        expires_at: now + Duration::days(args.expires_in_days),
    };

    match signer.sign(&spec) {
        Ok(token) => {
            println!("{token}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("signing: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_features_trims_and_drops_empties() {
        assert_eq!(parse_features("a, b ,,c "), vec!["a", "b", "c"]);
        assert!(parse_features("").is_empty());
        assert!(parse_features("  ,  ").is_empty());
    }
}
