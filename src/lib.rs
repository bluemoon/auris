//! **auris** is an experimental URI parsing library
//!
//! - Uses only safe features in rust.
//! - `rfc2396` & `rfc3986` compliant (incomplete)
//!
//! # Usage
//!
//! ```
//! use auris::parsers;
//!
//! parsers::uri("https://crates.io/crates/auris");
//! ```
extern crate nom;
use std::str;

use core::hash::Hash;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_till, take_while},
    character::complete::{alpha1, digit1},
    character::{is_alphabetic, is_digit},
    combinator::{all_consuming, cut, map, opt},
    multi::{many0, many_till},
    sequence::tuple,
    IResult,
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub enum AurisParseErrorKind {
    Failed,
}

pub struct ParseError {
    kind: AurisParseErrorKind,
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
/// When parsing whole URIs you can use:
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

// The host name of an URL.
pub enum Host<S = String> {
    Domain(S),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}
