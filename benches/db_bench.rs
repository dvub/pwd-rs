use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pwd_rs::{
    models::NewPassword,
    ops::{encrypt_and_insert, establish_connection},
};
pub fn criterion_benchmark(c: &mut Criterion) {
    let mut connection = establish_connection().unwrap();

    c.bench_function("fib 20", |b| {
        b.iter(|| {
            encrypt_and_insert(
                &mut connection,
                black_box("mymasterpassword"),
                black_box("test_info"),
                black_box(Some("user123".to_string())),
                black_box(Some("tester@test.com".to_string())),
                black_box(Some("mycoolpassword".to_string())),
                black_box(Some("some notes".to_string())),
            )
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
