use auris::parsers::uri;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("URI Parsing");

    let string = "foo://user:pass@hotdog.com";
    let size = string.len() as u32;
    let _f = uri(string);
    group.throughput(Throughput::Elements(size as u64));

    group.bench_function("parsers::uri", |b| {
        b.iter(|| uri(string));
    });
}

fn bench_f(c: &mut Criterion) {
    let mut group = c.benchmark_group("My own parser ffuu");

    let string = "foo://user:pass@hotdog.com";
    group.bench_function("parsers::uri", |b| {
        b.iter(|| auris::parsers::f(string));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = 
        criterion_benchmark,
        bench_f
}
criterion_main!(benches);
