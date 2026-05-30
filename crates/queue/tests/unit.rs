use ferrlabs_queue::{JobStatus, Payload, backoff_seconds};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DummyPayload {
    user_id: uuid::Uuid,
    template: String,
    retries: u8,
}

impl Payload for DummyPayload {
    const QUEUE: &'static str = "test.dummy";
}

#[test]
fn payload_round_trip_through_json() {
    let original = DummyPayload {
        user_id: uuid::Uuid::nil(),
        template: "welcome".to_owned(),
        retries: 2,
    };
    let value = serde_json::to_value(&original).expect("serialize");
    let back: DummyPayload = serde_json::from_value(value).expect("deserialize");
    assert_eq!(original, back);
    assert_eq!(DummyPayload::QUEUE, "test.dummy");
}

#[test]
fn backoff_is_exponential_then_capped() {
    assert_eq!(backoff_seconds(0), 1);
    assert_eq!(backoff_seconds(1), 2);
    assert_eq!(backoff_seconds(2), 4);
    assert_eq!(backoff_seconds(3), 8);
    assert_eq!(backoff_seconds(10), 1024);
    assert_eq!(backoff_seconds(11), 2048);
    assert_eq!(backoff_seconds(12), 3600, "should saturate at 1 hour");
    assert_eq!(backoff_seconds(50), 3600, "far past cap stays capped");
    assert_eq!(backoff_seconds(u32::MAX), 3600, "overflow stays capped");
}

#[test]
fn status_round_trips_via_string() {
    for s in [
        JobStatus::Queued,
        JobStatus::Running,
        JobStatus::Done,
        JobStatus::Failed,
        JobStatus::Cancelled,
        JobStatus::Dead,
    ] {
        let str_form = s.as_str();
        let parsed: JobStatus = str_form.parse().expect("parse");
        assert_eq!(s, parsed);
        assert_eq!(s.to_string(), str_form);
    }
}

#[test]
fn status_rejects_unknown_strings() {
    let err = "exploded".parse::<JobStatus>().unwrap_err();
    assert!(err.to_string().contains("exploded"));
}

#[test]
fn terminal_statuses_are_correct() {
    assert!(JobStatus::Done.is_terminal());
    assert!(JobStatus::Cancelled.is_terminal());
    assert!(JobStatus::Dead.is_terminal());
    assert!(!JobStatus::Queued.is_terminal());
    assert!(!JobStatus::Running.is_terminal());
    assert!(!JobStatus::Failed.is_terminal());
}
