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

/// Authority section of the URI
#[derive(Debug, PartialEq, Eq)]
pub struct Authority<T>
where
    T: Ord + Hash,
{
    //TODO(bradford): IPV6, IPV4, DNS enum
    pub host: T,
    pub username: Option<T>,
    pub password: Option<T>,
    pub port: Option<u16>,
}

impl Authority<&str> {
    fn to_owned(&self) -> Authority<String> {
        Authority {
            host: self.host.to_string(),
            username: self.username.map(|u| u.to_string()),
            password: self.password.map(|p| p.to_string()),
            port: self.port,
        }
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
/// let parsed = "http://bob.com".parse::<URI<String>>().unwrap();
///
/// assert_eq!("http://bob.com",
///     format!("{}", parsed));
///
impl fmt::Display for URI<String> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://", self.scheme)
    }
}

// The host name of an URL.
pub enum Host<S = String> {
    Domain(S),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}
