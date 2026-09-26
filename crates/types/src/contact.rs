use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SUBJECT_MAX: usize = 200;
pub const MESSAGE_MAX: usize = 10_000;
pub const EMAIL_MAX: usize = 254;
pub const NAME_MAX: usize = 100;
pub const FROM_URL_MAX: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactProduct {
    Ferrlabs,
    Ferrflow,
    Ferrvault,
    Ferrtrack,
    Ferrgrowth,
    Ferrfleet,
    Ferrlens,
    Ferrgames,
    AwesomeAlternatives,
}

impl ContactProduct {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Ferrlabs => "ferrlabs",
            Self::Ferrflow => "ferrflow",
            Self::Ferrvault => "ferrvault",
            Self::Ferrtrack => "ferrtrack",
            Self::Ferrgrowth => "ferrgrowth",
            Self::Ferrfleet => "ferrfleet",
            Self::Ferrlens => "ferrlens",
            Self::Ferrgames => "ferrgames",
            Self::AwesomeAlternatives => "awesome-alternatives",
        }
    }

    #[must_use]
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Ferrlabs => "FerrLabs",
            Self::Ferrflow => "FerrFlow",
            Self::Ferrvault => "FerrVault",
            Self::Ferrtrack => "FerrTrack",
            Self::Ferrgrowth => "FerrGrowth",
            Self::Ferrfleet => "FerrFleet",
            Self::Ferrlens => "FerrLens",
            Self::Ferrgames => "FerrGames",
            Self::AwesomeAlternatives => "awesome-alternatives",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    Question,
    Bug,
    Billing,
    Security,
    Privacy,
    Other,
}

impl RequestKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Question => "question",
            Self::Bug => "bug",
            Self::Billing => "billing",
            Self::Security => "security",
            Self::Privacy => "privacy",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactRequest {
    pub request_id: Uuid,
    pub product: ContactProduct,
    pub kind: RequestKind,
    pub subject: String,
    pub message: String,
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidContact {
    Subject,
    Message,
    Email,
    Name,
    FromUrl,
}

impl std::fmt::Display for InvalidContact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Subject => write!(f, "subject must be 1 to {SUBJECT_MAX} characters"),
            Self::Message => write!(f, "message must be 1 to {MESSAGE_MAX} characters"),
            Self::Email => f.write_str("email is not a valid address"),
            Self::Name => write!(f, "name must be at most {NAME_MAX} characters"),
            Self::FromUrl => write!(
                f,
                "from_url must be an https URL of at most {FROM_URL_MAX} characters"
            ),
        }
    }
}

impl std::error::Error for InvalidContact {}

fn filled_within(text: &str, max: usize) -> bool {
    !text.trim().is_empty() && text.chars().count() <= max
}

fn plausible_email(email: &str) -> bool {
    if email.chars().count() > EMAIL_MAX || email.chars().any(char::is_whitespace) {
        return false;
    }
    let Some((local, domain)) = email.rsplit_once('@') else {
        return false;
    };
    !local.is_empty() && !domain.starts_with('.') && !domain.ends_with('.') && domain.contains('.')
}

fn https_url(url: &str) -> bool {
    url.chars().count() <= FROM_URL_MAX
        && url
            .strip_prefix("https://")
            .is_some_and(|rest| !rest.is_empty() && !rest.chars().any(char::is_whitespace))
}

impl ContactRequest {
    pub fn check(&self) -> Result<(), InvalidContact> {
        if !filled_within(&self.subject, SUBJECT_MAX) {
            return Err(InvalidContact::Subject);
        }
        if !filled_within(&self.message, MESSAGE_MAX) {
            return Err(InvalidContact::Message);
        }
        if !plausible_email(&self.email) {
            return Err(InvalidContact::Email);
        }
        if self
            .name
            .as_deref()
            .is_some_and(|name| name.chars().count() > NAME_MAX)
        {
            return Err(InvalidContact::Name);
        }
        if self.from_url.as_deref().is_some_and(|url| !https_url(url)) {
            return Err(InvalidContact::FromUrl);
        }
        Ok(())
    }

    #[must_use]
    pub fn labels(&self) -> [&'static str; 3] {
        ["contact", self.product.label(), self.kind.label()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ContactRequest {
        ContactRequest {
            request_id: Uuid::nil(),
            product: ContactProduct::Ferrtrack,
            kind: RequestKind::Bug,
            subject: "Board does not load".into(),
            message: "It spins forever.".into(),
            email: "ada@example.com".into(),
            name: None,
            org_id: None,
            from_url: None,
        }
    }

    #[test]
    fn a_complete_request_passes() {
        assert_eq!(request().check(), Ok(()));
    }

    #[test]
    fn blank_or_oversized_text_is_refused() {
        let blank = ContactRequest {
            subject: "   ".into(),
            ..request()
        };
        assert_eq!(blank.check(), Err(InvalidContact::Subject));
        let long = ContactRequest {
            message: "x".repeat(MESSAGE_MAX + 1),
            ..request()
        };
        assert_eq!(long.check(), Err(InvalidContact::Message));
        let padded = ContactRequest {
            subject: format!("   {}   ", "x".repeat(SUBJECT_MAX)),
            ..request()
        };
        assert_eq!(
            padded.check(),
            Err(InvalidContact::Subject),
            "a value the crate accepts must fit a column sized from its max"
        );
    }

    #[test]
    fn an_implausible_email_is_refused() {
        for email in [
            "ada",
            "ada@",
            "@example.com",
            "ada@example",
            "a da@example.com",
            "ada@.com",
        ] {
            let r = ContactRequest {
                email: email.into(),
                ..request()
            };
            assert_eq!(r.check(), Err(InvalidContact::Email), "{email}");
        }
    }

    #[test]
    fn the_origin_must_be_an_https_url() {
        for url in [
            "http://app.ferrtrack.com",
            "javascript:alert(1)",
            "https://",
            "https://a b",
        ] {
            let r = ContactRequest {
                from_url: Some(url.into()),
                ..request()
            };
            assert_eq!(r.check(), Err(InvalidContact::FromUrl), "{url}");
        }
        let ok = ContactRequest {
            from_url: Some("https://app.ferrtrack.com/projects/web".into()),
            ..request()
        };
        assert_eq!(ok.check(), Ok(()));
    }

    #[test]
    fn the_wire_format_is_snake_case_and_tolerates_fields_a_newer_sender_adds() {
        let json = r#"{"request_id":"00000000-0000-0000-0000-000000000000","product":"awesome_alternatives","kind":"billing","subject":"s","message":"m","email":"ada@example.com"}"#;
        let parsed: ContactRequest = serde_json::from_str(json).expect("a valid request");
        assert_eq!(
            parsed.labels(),
            ["contact", "awesome-alternatives", "billing"]
        );

        let newer = json.replace('}', r#","attachment_count":2}"#);
        assert_eq!(
            serde_json::from_str::<ContactRequest>(&newer).expect("an extra field is ignored"),
            parsed
        );
    }
}
