use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use ferrlabs_permissions::{Scope, ScopeSet};

fn scope_strings(count: usize) -> Vec<&'static str> {
    let all = [
        "org:member",
        "org:auditor",
        "org:billing",
        "secrets:read",
        "secrets:write",
        "issues:read",
        "issues:write",
        "sites:read",
        "sites:write",
        "org:admin",
    ];
    all.iter().cycle().take(count).copied().collect()
}

fn bench_has(c: &mut Criterion) {
    for count in [1_usize, 4, 10] {
        let set = ScopeSet::from_strings(scope_strings(count));

        c.bench_function(&format!("scope_set_has/granted/{count}_scopes"), |b| {
            b.iter(|| black_box(set.has(black_box(Scope::SecretsRead))));
        });

        c.bench_function(&format!("scope_set_has/denied/{count}_scopes"), |b| {
            b.iter(|| black_box(set.has(black_box(Scope::StaffAccess))));
        });
    }
}

fn bench_from_strings(c: &mut Criterion) {
    for count in [1_usize, 4, 10] {
        let strings = scope_strings(count);
        c.bench_function(&format!("scope_set_from_strings/{count}_scopes"), |b| {
            b.iter(|| black_box(ScopeSet::from_strings(black_box(&strings))));
        });
    }
}

fn bench_require(c: &mut Criterion) {
    let set = ScopeSet::from_strings(scope_strings(10));
    c.bench_function("scope_set_require/granted", |b| {
        b.iter(|| black_box(set.require(black_box(Scope::SecretsRead)).is_ok()));
    });
    c.bench_function("scope_set_require/denied", |b| {
        b.iter(|| black_box(set.require(black_box(Scope::StaffAccess)).is_err()));
    });
}

criterion_group!(benches, bench_has, bench_from_strings, bench_require);
criterion_main!(benches);
