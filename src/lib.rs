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
pub enum ParseError {
    Failed,
}

#[derive(Debug)]
pub struct AurisErr {
    kind: ParseError,
}

impl fmt::Display for AurisErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.kind {
            ParseError::Failed => write!(f, "Parsing failed"),
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
    type Err = AurisErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match parsers::uri(s) {
            Ok((_, obj)) => Ok(obj.to_owned()),
            Err(_) => Err(AurisErr {
                kind: ParseError::Failed,
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
/// ```
impl fmt::Display for URI<String> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut formatted = String::new();
        formatted.push_str(&self.scheme);
        formatted.push_str("://");
        formatted.push_str(&format!("{}", self.authority));
        write!(f, "{}", formatted)
    }
}

// The host name of an URL.
pub enum Host<S = String> {
    Domain(S),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}
