#![no_main]

use arbitrary::Arbitrary;
use ferrlabs_billing::verify_signature;
use hmac::{Hmac, KeyInit, Mac};
use libfuzzer_sys::fuzz_target;
use sha2::Sha256;

#[derive(Arbitrary, Debug)]
struct Input {
    payload: Vec<u8>,
    secret: Vec<u8>,
    header: String,
    timestamp: i32,
    now: i32,
    tolerance: i32,
    flip: u8,
}

fn sign(secret: &[u8], timestamp: i64, payload: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

fuzz_target!(|input: Input| {
    let timestamp = i64::from(input.timestamp);
    let now = i64::from(input.now);
    let tolerance = i64::from(input.tolerance);

    let _ = verify_signature(
        &input.payload,
        &input.header,
        &input.secret,
        now,
        tolerance,
    );

    let header = format!("t={timestamp},v1={}", sign(&input.secret, timestamp, &input.payload));
    let within = now.abs_diff(timestamp) <= tolerance.max(0).unsigned_abs();
    let result = verify_signature(&input.payload, &header, &input.secret, now, tolerance);
    assert_eq!(result.is_ok(), within);
    if let Ok(verified) = result {
        assert_eq!(verified, timestamp);
    }

    let mut tampered = input.payload.clone();
    if tampered.is_empty() {
        tampered.push(input.flip);
    } else {
        let at = usize::from(input.flip) % tampered.len();
        tampered[at] ^= 1;
    }
    assert!(verify_signature(&tampered, &header, &input.secret, now, tolerance).is_err());
});
