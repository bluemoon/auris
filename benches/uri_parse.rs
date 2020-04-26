use auris::parsers::uri;
use auris::URI;
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

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
