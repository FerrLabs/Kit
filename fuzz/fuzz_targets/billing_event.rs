#![no_main]

use ferrlabs_billing::parse_event;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|payload: &[u8]| {
    let _ = parse_event(payload);
});
