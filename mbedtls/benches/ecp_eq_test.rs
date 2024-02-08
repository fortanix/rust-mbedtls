use criterion::{black_box, criterion_main, Criterion};
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

    let mut group = c.benchmark_group("EcpPoint equal");

    group.bench_function("X not equal", |b| b.iter(|| ecp_equal(black_box(&p_0_1_1), &p_1_1_1)));
    group.bench_function("Y not equal", |b| b.iter(|| ecp_equal(black_box(&p_1_0_1), &p_1_1_1)));
    group.bench_function("Z not equal", |b| b.iter(|| ecp_equal(black_box(&p_1_1_0), &p_1_1_1)));

    group.bench_function("X not equal const_time", |b| {
        b.iter(|| ecp_equal_const_time(black_box(&p_0_1_1), &p_1_1_1))
    });
    group.bench_function("Y not equal const_time", |b| {
        b.iter(|| ecp_equal_const_time(black_box(&p_1_0_1), &p_1_1_1))
    });
    group.bench_function("Z not equal const_time", |b| {
        b.iter(|| ecp_equal_const_time(black_box(&p_1_1_0), &p_1_1_1))
    });
}

pub fn benches() {
    let mut criterion = Criterion::default().sample_size(10_000).configure_from_args();
    criterion_benchmark(&mut criterion);
}
criterion_main!(benches);
