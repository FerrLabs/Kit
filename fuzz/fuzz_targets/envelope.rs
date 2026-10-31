#![no_main]

use arbitrary::Arbitrary;
use ferrlabs_crypto::{decrypt_value, encrypt_value, generate_dek, parse_kek};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
    key: Vec<u8>,
    hex_key: String,
    flip: u8,
}

fuzz_target!(|input: Input| {
    if let Ok(kek) = parse_kek(&input.hex_key) {
        assert_eq!(kek.len(), 32);
    }

    let _ = decrypt_value(&input.ciphertext, &input.key);

    let dek = generate_dek();
    let _ = decrypt_value(&input.ciphertext, &dek);

    let sealed = encrypt_value(&input.plaintext, &dek).unwrap();
    assert_eq!(decrypt_value(&sealed, &dek).unwrap(), input.plaintext);

    let mut tampered = sealed.clone();
    let at = usize::from(input.flip) % tampered.len();
    tampered[at] ^= 1;
    assert!(decrypt_value(&tampered, &dek).is_err());

    assert_eq!(
        encrypt_value(&input.plaintext, &input.key).is_ok(),
        input.key.len() == 32
    );
});
