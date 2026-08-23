use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use ferrlabs_crypto::{decrypt_value, encrypt_value, generate_dek};

const SIZES: [(&str, usize); 4] = [
    ("32B_api_key", 32),
    ("256B_connection_string", 256),
    ("4KB_certificate", 4 * 1024),
    ("64KB_service_account", 64 * 1024),
];

fn bench_encrypt(c: &mut Criterion) {
    let dek = generate_dek();
    for (label, size) in SIZES {
        let plaintext = vec![0x5a_u8; size];
        c.bench_function(&format!("encrypt_value/{label}"), |b| {
            b.iter(|| {
                black_box(encrypt_value(black_box(&plaintext), black_box(&dek)).unwrap());
            });
        });
    }
}

fn bench_decrypt(c: &mut Criterion) {
    let dek = generate_dek();
    for (label, size) in SIZES {
        let encrypted = encrypt_value(&vec![0x5a_u8; size], &dek).unwrap();
        c.bench_function(&format!("decrypt_value/{label}"), |b| {
            b.iter(|| {
                black_box(decrypt_value(black_box(&encrypted), black_box(&dek)).unwrap());
            });
        });
    }
}

fn bench_dek_generation(c: &mut Criterion) {
    c.bench_function("generate_dek", |b| {
        b.iter(|| black_box(generate_dek()));
    });
}

criterion_group!(benches, bench_encrypt, bench_decrypt, bench_dek_generation);
criterion_main!(benches);
