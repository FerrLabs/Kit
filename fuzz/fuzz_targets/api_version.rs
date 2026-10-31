#![no_main]

use ferrlabs_api_version::ApiVersion;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|raw: &str| {
    if let Ok(version) = raw.parse::<ApiVersion>() {
        assert_eq!(version.to_string(), raw);
        assert_eq!(version.to_string().parse::<ApiVersion>(), Ok(version));
    }
});
