#![no_main]

use arbitrary::Arbitrary;
use ferrlabs_webhooks::{
    sign_github, sign_timestamped, verify_github, verify_hex, verify_timestamped,
};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    secret: Vec<u8>,
    body: Vec<u8>,
    header: String,
    timestamp_header: String,
    timestamp: i32,
    now: i32,
    skew: i32,
    flip: u8,
}

fuzz_target!(|input: Input| {
    let _ = verify_hex(&input.secret, &input.body, &input.header);
    let _ = verify_github(&input.secret, &input.body, &input.header);
    let _ = verify_timestamped(
        &input.secret,
        &input.body,
        &input.timestamp_header,
        &input.header,
        i64::from(input.now),
        i64::from(input.skew),
    );

    let signature = sign_github(&input.secret, &input.body);
    assert!(verify_github(&input.secret, &input.body, &signature).is_ok());

    let mut tampered = input.body.clone();
    if tampered.is_empty() {
        tampered.push(input.flip);
    } else {
        let at = usize::from(input.flip) % tampered.len();
        tampered[at] ^= 1;
    }
    assert!(verify_github(&input.secret, &tampered, &signature).is_err());

    let timestamp = i64::from(input.timestamp);
    let now = i64::from(input.now);
    let skew = i64::from(input.skew);
    let signed = sign_timestamped(&input.secret, timestamp, &input.body);
    let result = verify_timestamped(
        &input.secret,
        &input.body,
        &timestamp.to_string(),
        &signed,
        now,
        skew,
    );
    assert_eq!(
        result.is_ok(),
        now.abs_diff(timestamp) <= skew.unsigned_abs()
    );
});
