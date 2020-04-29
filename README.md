# Auris, URI parser for Rust

[![crates.io](https://img.shields.io/crates/v/auris.svg)](https://crates.io/crates/auris)

- Uses only safe features in rust
- Working towards `rfc2396` & `rfc3986` compliance

### Parses structure:

```notrust
    foo://example.com:8042/over/there?name=ferret#nose
    \_/   \______________/\_________/ \_________/ \__/
     |           |            |            |        |
  scheme     authority       path        query   fragment
```


## Usage

```rust
use auris::URI;

"postgres://user:password@host".parse::<URI<String>>();

"https://crates.io/crates/auris".parse::<URI<String>>();
```

### Query strings

We also parse query strings into HashMaps:

```rust
"postgres://user:password@example.com/db?replication=true".parse::<URI<String>>();
```

In the case of duplicated query string tags the last one wins:
```rust
"scheme://host/path?a=1&a=2".parse::<URI<String>>();
```

## Documentation
- https://docs.rs/auris

## Todo

- [x] Ports
- [x] Split up into multiple files
- [x] Domains with .
- [x] Rendering of URIs and Authority with fmt::Display
- [ ] Parsing IPv4, IPv6
- [ ] Parsing fragments
- [ ] Percent encoding and decoding
- [ ] QuickCheck?
