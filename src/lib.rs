//! **auris** is an experimental URI parsing library
//!
//! - Uses only safe features in rust.
//! - `rfc2396` & `rfc3986` compliant (incomplete)
//!
//!
//! ## Parses structure:
//!
//! ```notrust
//!     foo://example.com:8042/over/there?name=ferret#nose
//!     \_/   \______________/\_________/ \_________/ \__/
//!      |           |            |            |        |
//!   scheme     authority       path        query   fragment
//! ```
//!
//! # Usage
//!
//! ```
//! use auris::URI;
//!
//! "postgres://user:password@host".parse::<URI<String>>();
//!
//! "https://crates.io/crates/auris".parse::<URI<String>>();
//! ```
//!
//! ## Query strings
//!
//! We also parse query strings into HashMaps:
//!
//! ```
//! # use auris::URI;
//! "postgres://user:password@example.com/db?replication=true".parse::<URI<String>>();
//! ```
//!
//! In the case of duplicated query string tags the last one wins:
//! ```
//! # use auris::URI;
//! "scheme://host/path?a=1&a=2".parse::<URI<String>>();
//! ```
extern crate nom;
use std::str;

use core::hash::Hash;
use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub mod parsers;

#[derive(Debug)]
pub enum AurisParseErrorKind {
    Failed,
}

#[derive(Debug)]
pub struct ParseError {
    kind: AurisParseErrorKind,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.kind {
            AurisParseErrorKind::Failed => write!(f, "Parsing failed"),
        }
    }
}

/// Make impossible authentication states unrepresentable
#[derive(Debug, PartialEq, Eq)]
pub enum UserInfo<T> {
    User(T),
    UserAndPassword(T, T),
}

impl UserInfo<&str> {
    fn to_owned(&self) -> UserInfo<String> {
        match self {
            UserInfo::User(d) => UserInfo::User((*d).to_string()),
            UserInfo::UserAndPassword(u, p) => {
                UserInfo::UserAndPassword((*u).to_string(), (*p).to_string())
            }
        }
    }
}

impl fmt::Display for UserInfo<String> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserInfo::User(user) => write!(f, "{}", user),
            UserInfo::UserAndPassword(user, password) => write!(f, "{}:{}", user, password),
        }
    }
}

/// Authority section of the URI
#[derive(Debug, PartialEq, Eq)]
pub struct Authority<T>
where
    T: Ord + Hash,
{
    //TODO(bradford): IPV6, IPV4, DNS enum
    pub host: T,
    pub userinfo: Option<UserInfo<T>>,
    pub port: Option<u16>,
}

impl Authority<&str> {
    fn to_owned(&self) -> Authority<String> {
        Authority {
            host: self.host.to_string(),
            userinfo: self.userinfo.as_ref().map(|u| u.to_owned()),
            port: self.port,
        }
    }
}

/// Converts the URI struct back to a string
///
/// # Examples
/// ```
/// use auris::{Authority, UserInfo};
///
/// assert_eq!("a:b@bob.com:443",
///     format!("{}", Authority {
///       host: "bob.com".to_string(),
///       userinfo: Some(UserInfo::UserAndPassword("a".to_string(), "b".to_string())),
///       port: Some(443),
///     }));
/// ```
impl fmt::Display for Authority<String> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut formatted = String::new();
        // using a match as this feels cleaner than a map
        let userinfo_string = match self.userinfo.as_ref() {
            Some(userinfo) => format!("{}@", userinfo),
            None => String::new(),
        };
        formatted.push_str(&userinfo_string);
        formatted.push_str(&self.host);
        let port_string = match self.port.as_ref() {
            Some(port) => format!(":{}", port),
            None => String::new(),
        };
        formatted.push_str(&port_string);
        write!(f, "{}", formatted)
    }
}

/// URI is the whole URI object
///
/// # Examples
///
/// When parsing whole URIs:
///
/// ```
/// use auris::URI;
/// "http://bob.com".parse::<URI<String>>();
/// ```
///
#[derive(Debug, PartialEq, Eq)]
pub struct URI<T>
where
    T: Ord + Hash,
{
    pub scheme: T,
    pub authority: Authority<T>,
    pub path: Option<Vec<T>>,
    pub qs: Option<HashMap<T, T>>,
    pub fragment: Option<T>,
}

impl URI<&str> {
    fn to_owned(&self) -> URI<String> {
        URI {
            scheme: self.scheme.to_owned(),
            authority: self.authority.to_owned(),
            path: self
                .path
                .as_ref()
                .map(|p: &Vec<&str>| p.iter().map(|f| String::from(*f)).collect()),
            qs: self.qs.as_ref().map(|qs| {
                qs.iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect()
            }),
            fragment: self.fragment.map(|f| f.to_string()),
        }
    }
}

impl FromStr for URI<String> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match parsers::uri(s) {
            Ok((_, obj)) => Ok(obj.to_owned()),
            Err(_) => Err(ParseError {
                kind: AurisParseErrorKind::Failed,
            }),
        }
    }
}
/// Converts the URI struct back to a string
///
/// # Examples
/// ```
/// use auris::URI;
///
/// let parsed = "http://bob.com/path?key=value#section".parse::<URI<String>>().unwrap();
///
/// assert_eq!("http://bob.com/path?key=value#section",
///     format!("{}", parsed));
/// ```
impl fmt::Display for URI<String> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut formatted = String::new();
        formatted.push_str(&self.scheme);
        formatted.push_str("://");
        formatted.push_str(&format!("{}", self.authority));

        if let Some(ref path) = self.path {
            for segment in path {
                formatted.push('/');
                formatted.push_str(segment);
            }
        }

        if let Some(ref qs) = self.qs {
            formatted.push('?');
            let pairs: Vec<String> = qs.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
            formatted.push_str(&pairs.join("&"));
        }

        if let Some(ref fragment) = self.fragment {
            formatted.push('#');
            formatted.push_str(fragment);
        }

        write!(f, "{}", formatted)
    }
}

// The host name of an URL.
pub enum Host<S = String> {
    Domain(S),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_roundtrip_simple() {
        let uri_str = "http://example.com";
        let parsed: URI<String> = uri_str.parse().unwrap();
        assert_eq!(format!("{}", parsed), uri_str);
    }

    #[test]
    fn test_display_roundtrip_with_path() {
        let parsed: URI<String> = "http://example.com/path/to/resource".parse().unwrap();
        assert_eq!(format!("{}", parsed), "http://example.com/path/to/resource");
    }

    #[test]
    fn test_display_roundtrip_with_userinfo() {
        let parsed: URI<String> = "ftp://user:pass@ftp.example.com/file".parse().unwrap();
        assert_eq!(
            format!("{}", parsed),
            "ftp://user:pass@ftp.example.com/file"
        );
    }

    #[test]
    fn test_display_roundtrip_with_port() {
        let parsed: URI<String> = "http://example.com:8080/api".parse().unwrap();
        assert_eq!(format!("{}", parsed), "http://example.com:8080/api");
    }

    #[test]
    fn test_display_with_fragment() {
        let parsed: URI<String> = "http://example.com/page#section".parse().unwrap();
        assert_eq!(format!("{}", parsed), "http://example.com/page#section");
    }

    #[test]
    fn test_display_full_uri() {
        let parsed: URI<String> = "https://user:pass@example.com:443/path/to/resource#top"
            .parse()
            .unwrap();
        let displayed = format!("{}", parsed);
        // Verify all components are present
        assert!(displayed.starts_with("https://"));
        assert!(displayed.contains("user:pass@"));
        assert!(displayed.contains("example.com:443"));
        assert!(displayed.contains("/path/to/resource"));
        assert!(displayed.contains("#top"));
    }
}

#[cfg(test)]
mod quickcheck_tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;

    /// Generate a valid scheme (lowercase alpha, optionally followed by alphanumeric, +, -, .)
    fn gen_scheme(g: &mut Gen) -> String {
        let first = *g.choose(&['a', 'b', 'c', 'h', 'f', 's', 'm', 't']).unwrap();
        let schemes = ["http", "https", "ftp", "mailto", "ssh", "file", "tcp"];
        if bool::arbitrary(g) {
            schemes[usize::arbitrary(g) % schemes.len()].to_string()
        } else {
            first.to_string()
        }
    }

    /// Generate a valid hostname (alphanumeric with dots and hyphens)
    fn gen_host(g: &mut Gen) -> String {
        let parts = ["example", "test", "localhost", "foo", "bar", "api", "www"];
        let tlds = ["com", "org", "net", "io", "dev"];
        let part = parts[usize::arbitrary(g) % parts.len()];
        if bool::arbitrary(g) {
            format!("{}.{}", part, tlds[usize::arbitrary(g) % tlds.len()])
        } else {
            part.to_string()
        }
    }

    /// Generate a valid path segment (alphanumeric, -, _, .)
    fn gen_path_segment(g: &mut Gen) -> String {
        let segments = [
            "path", "to", "resource", "api", "v1", "users", "123", "file.txt",
        ];
        segments[usize::arbitrary(g) % segments.len()].to_string()
    }

    /// Generate a valid userinfo component
    fn gen_userinfo(g: &mut Gen) -> Option<(String, Option<String>)> {
        if bool::arbitrary(g) {
            let users = ["user", "admin", "test", "guest"];
            let user = users[usize::arbitrary(g) % users.len()].to_string();
            let password = if bool::arbitrary(g) {
                let passwords = ["pass", "secret", "1234", "pwd"];
                Some(passwords[usize::arbitrary(g) % passwords.len()].to_string())
            } else {
                None
            };
            Some((user, password))
        } else {
            None
        }
    }

    /// Generate a valid fragment
    fn gen_fragment(g: &mut Gen) -> Option<String> {
        if bool::arbitrary(g) {
            let fragments = ["top", "section", "anchor", "main", "content"];
            Some(fragments[usize::arbitrary(g) % fragments.len()].to_string())
        } else {
            None
        }
    }

    /// A wrapper to generate valid URI strings
    #[derive(Debug, Clone)]
    struct ValidUri(String);

    impl Arbitrary for ValidUri {
        fn arbitrary(g: &mut Gen) -> Self {
            let scheme = gen_scheme(g);
            let host = gen_host(g);
            let userinfo = gen_userinfo(g);
            let port: Option<u16> = if bool::arbitrary(g) {
                Some(*g.choose(&[80, 443, 8080, 3000, 5432, 27017]).unwrap())
            } else {
                None
            };

            // Build path
            let path_segments: Vec<String> = if bool::arbitrary(g) {
                let count = usize::arbitrary(g) % 4;
                (0..count).map(|_| gen_path_segment(g)).collect()
            } else {
                vec![]
            };

            let fragment = gen_fragment(g);

            // Construct the URI string
            let mut uri = format!("{}://", scheme);

            if let Some((user, pass)) = userinfo {
                uri.push_str(&user);
                if let Some(p) = pass {
                    uri.push(':');
                    uri.push_str(&p);
                }
                uri.push('@');
            }

            uri.push_str(&host);

            if let Some(p) = port {
                uri.push(':');
                uri.push_str(&p.to_string());
            }

            for seg in &path_segments {
                uri.push('/');
                uri.push_str(seg);
            }

            if let Some(frag) = fragment {
                uri.push('#');
                uri.push_str(&frag);
            }

            ValidUri(uri)
        }
    }

    /// Property: All generated valid URIs should parse successfully
    #[quickcheck]
    fn prop_valid_uri_parses(uri: ValidUri) -> bool {
        uri.0.parse::<URI<String>>().is_ok()
    }

    /// Property: Parsed URI scheme matches the original
    #[quickcheck]
    fn prop_scheme_preserved(uri: ValidUri) -> bool {
        if let Ok(parsed) = uri.0.parse::<URI<String>>() {
            uri.0.starts_with(&format!("{}://", parsed.scheme))
        } else {
            false
        }
    }

    /// Property: Parsed URI host is contained in original
    #[quickcheck]
    fn prop_host_in_original(uri: ValidUri) -> bool {
        if let Ok(parsed) = uri.0.parse::<URI<String>>() {
            uri.0.contains(&parsed.authority.host)
        } else {
            false
        }
    }

    /// Property: Display -> Parse roundtrip preserves structure
    #[quickcheck]
    fn prop_display_parse_roundtrip(uri: ValidUri) -> bool {
        if let Ok(parsed1) = uri.0.parse::<URI<String>>() {
            let displayed = format!("{}", parsed1);
            if let Ok(parsed2) = displayed.parse::<URI<String>>() {
                parsed1.scheme == parsed2.scheme
                    && parsed1.authority.host == parsed2.authority.host
                    && parsed1.authority.port == parsed2.authority.port
                    && parsed1.authority.userinfo == parsed2.authority.userinfo
                    && parsed1.path == parsed2.path
                    && parsed1.fragment == parsed2.fragment
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Property: Port when present is correctly parsed
    #[quickcheck]
    fn prop_port_preserved(uri: ValidUri) -> bool {
        if let Ok(parsed) = uri.0.parse::<URI<String>>() {
            if let Some(port) = parsed.authority.port {
                uri.0.contains(&format!(":{}", port))
            } else {
                true
            }
        } else {
            false
        }
    }

    /// Property: Fragment when present is correctly parsed
    #[quickcheck]
    fn prop_fragment_preserved(uri: ValidUri) -> bool {
        if let Ok(parsed) = uri.0.parse::<URI<String>>() {
            if let Some(ref frag) = parsed.fragment {
                uri.0.ends_with(&format!("#{}", frag))
            } else {
                !uri.0.contains('#')
            }
        } else {
            false
        }
    }
}
