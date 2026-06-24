use ferrlabs_errors::ApiError;

/// Errors raised by the billing client and webhook verifier.
#[derive(Debug, thiserror::Error)]
pub enum BillingError {
    /// The Stripe API rejected the request or was unreachable.
    #[error("stripe api error: {0}")]
    Stripe(#[from] stripe::StripeError),

    /// The `Stripe-Signature` header was missing, malformed, or did not match
    /// the request body under the configured signing secret.
    #[error("webhook signature verification failed: {0}")]
    SignatureVerification(#[from] SignatureError),

    /// A webhook event was received but its payload did not deserialize into
    /// the shape we expect for that event type.
    #[error("malformed webhook payload: {0}")]
    MalformedPayload(String),

    /// A field this crate needs (e.g. the `org_id`/`product` metadata we set
    /// when creating the customer or subscription) was absent.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
}

/// Why a webhook signature was rejected. Kept separate from [`BillingError`]
/// so the verifier can be unit-tested against each failure mode precisely.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignatureError {
    #[error("Stripe-Signature header is absent")]
    MissingHeader,

    #[error("Stripe-Signature header is malformed")]
    MalformedHeader,

    #[error("signature timestamp is outside the allowed tolerance")]
    TimestampOutOfTolerance,

    #[error("no signature in the header matched the expected value")]
    NoMatch,
}

impl From<BillingError> for ApiError {
    fn from(err: BillingError) -> Self {
        match err {
            BillingError::SignatureVerification(_) => ApiError::Unauthorized,
            BillingError::MalformedPayload(msg) => ApiError::BadRequest(msg),
            BillingError::MissingField(field) => ApiError::BadRequest(field.to_string()),
            BillingError::Stripe(e) => ApiError::Internal(anyhow::anyhow!("stripe: {e}")),
        }
    }
}
