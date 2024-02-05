use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mbedtls::{bignum::Mpi, ecp::EcPoint};

fn ecp_equal(a: &EcPoint, b: &EcPoint) {
    assert!(!a.eq(&b).unwrap());
}

fn ecp_equal_const_time(a: &EcPoint, b: &EcPoint) {
    assert!(!a.eq_const_time(&b));
}

fn criterion_benchmark(c: &mut Criterion) {
    let one = Mpi::new(1).unwrap();
    let zero = Mpi::new(0).unwrap();
    let p_0_1_1 = EcPoint::from_components(zero.clone(), one.clone()).unwrap();
    let p_1_0_1 = EcPoint::from_components(one.clone(), zero.clone()).unwrap();
    let p_1_1_0 = EcPoint::new().unwrap();
    let p_1_1_1 = EcPoint::from_components(one.clone(), one.clone()).unwrap();
    c.bench_function("EcpPoint X not equal", |b| {
        b.iter(|| ecp_equal(black_box(&p_0_1_1), &p_1_1_1))
    });
    c.bench_function("EcpPoint Y not equal", |b| {
        b.iter(|| ecp_equal(black_box(&p_1_0_1), &p_1_1_1))
    });
    c.bench_function("EcpPoint Z not equal", |b| {
        b.iter(|| ecp_equal(black_box(&p_1_1_0), &p_1_1_1))
    });
    c.bench_function("EcpPoint X not equal const time", |b| {
        b.iter(|| ecp_equal_const_time(black_box(&p_0_1_1), &p_1_1_1))
    });
    c.bench_function("EcpPoint Y not equal const time", |b| {
        b.iter(|| ecp_equal_const_time(black_box(&p_1_0_1), &p_1_1_1))
    });
    c.bench_function("EcpPoint Z not equal const time", |b| {
        b.iter(|| ecp_equal_const_time(black_box(&p_1_1_0), &p_1_1_1))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
