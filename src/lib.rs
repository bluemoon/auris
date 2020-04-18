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

use core::hash::Hash;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_till},
    character::complete::alpha1,
    combinator::{all_consuming, cut, map, opt},
    multi::many0,
    sequence::tuple,
    IResult,
};
use std::collections::HashMap;
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
///
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
                .map(|p| p.into_iter().map(|f| String::from(*f)).collect()),
            qs: self.qs.as_ref().map(|qs| {
                qs.into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect()
            }),
        }
    }
}

/// Parses structure:
///
/// ```notrust
///     foo://example.com:8042/over/there?name=ferret#nose
///     \_/   \______________/\_________/ \_________/ \__/
///      |           |            |            |        |
///   scheme     authority       path        query   fragment
/// ```
///
pub mod parsers {
    use super::*;

    /// Parse out the scheme
    fn scheme(input: &str) -> IResult<&str, &str> {
        // postgres://
        // bob://
        let (remaining, scheme_chunk) = take_till(|c| c == ':')(input)?;
        let (remaining_post_scheme, _) = tag("://")(remaining)?;
        Ok((remaining_post_scheme, scheme_chunk))
    }

    fn user_pw_combinator(i: &str) -> IResult<&str, (Option<&str>, Option<&str>)> {
        // user:pw@
        let (remain_chunk_1, user) = cut(alpha1)(i)?;
        let (remain_chunk_2, _) = tag(":")(remain_chunk_1)?;
        let (remain_chunk_3, password) = cut(alpha1)(remain_chunk_2)?;
        let (remain_chunk_4, _) = tag("@")(remain_chunk_3)?;
        Ok((remain_chunk_4, (Some(user), Some(password))))
    }

    fn user_combinator(input: &str) -> IResult<&str, (Option<&str>, Option<&str>)> {
        let (remain_chunk_1, user) = cut(alpha1)(input)?;
        let (remain_chunk_2, _) = tag("@")(remain_chunk_1)?;
        Ok((remain_chunk_2, (Some(user), None)))
    }

    /// Parse the user credentials from the authority section. We can
    /// always expect this function to return a tuple of options. Instead of using
    /// `Option<(Option<&str>, Option<&str>)>`, `(Option<&str>, Option<&str>)` is used
    fn authority_credentials(input: &str) -> IResult<&str, (Option<&str>, Option<&str>)> {
        // The whole statement may fail if there is no match
        // we flatten this out so that you will just get (None, None)
        let (remain, alt_opt) = opt(alt((user_pw_combinator, user_combinator)))(input)?;
        match alt_opt {
            Some(options) => Ok((remain, options)),
            None => Ok((remain, (None, None))),
        }
    }

    /// Parse a single path chunk
    fn path_part(input: &str) -> IResult<&str, &str> {
        let (remain, (_, chunk)) = tuple((tag("/"), alpha1))(input)?;
        Ok((remain, chunk))
    }

    /// Parse the whole path chunk
    pub fn path(input: &str) -> IResult<&str, Vec<&str>> {
        // /a/b/c
        many0(path_part)(input)
    }

    fn query_part(input: &str) -> IResult<&str, (&str, &str)> {
        let (remain, (key, _, value, _)) = tuple((alpha1, tag("="), alpha1, opt(tag("&"))))(input)?;
        Ok((remain, (key, value)))
    }

    /// Parses ?k=v&k1=v1 into a HashMap
    pub fn query<'a>(input: &'a str) -> IResult<&'a str, HashMap<&'a str, &'a str>> {
        let (post_q, _) = tag("?")(input)?;
        let (remain, vec) = many0(query_part)(post_q)?;
        Ok((remain, vec.into_iter().collect()))
    }

    /// Parses the authority section of the URI
    ///
    /// # Examples
    ///
    /// Here we parse a full authority segment:
    /// ```
    /// use auris::parsers;
    /// parsers::authority("bob:pass@bob.com");
    /// ```
    ///
    /// This works with partial segements as well:
    /// ```
    /// use auris::parsers;
    /// parsers::authority("bob@hotdog.com");
    /// ```
    // http://example.com
    // postgres://user:pw@host:5432/db
    pub fn authority(input: &str) -> IResult<&str, Authority<&str>> {
        match all_consuming(tuple((authority_credentials, take_till(|c| c == '/'))))(input) {
            Ok((remaining_input, ((username, password), host))) => Ok((
                remaining_input,
                Authority {
                    host: host,
                    password: password,
                    port: None,
                    username: username,
                },
            )),
            Err(e) => Err(e),
        }
    }

    /// Parses a full URI
    ///
    /// # Examples
    ///
    /// ```
    /// use auris::parsers;
    /// parsers::uri("scheme://user:pw@host.pizza/path1/path2/?k=v&k1=v1");
    /// ```
    pub fn uri(input: &str) -> IResult<&str, URI<&str>> {
        map(
            all_consuming(tuple((
                scheme,
                authority_credentials,
                take_till(|c| c == '/'),
                path,
                opt(query),
            ))),
            |f| match f {
                (scheme, (username, password), host, path, query) => URI {
                    scheme: scheme,
                    authority: Authority {
                        host: host,
                        username: username.map(|f| f),
                        password: password.map(|f| f),
                        port: None,
                    },
                    path: Some(path),
                    qs: query,
                },
            },
        )(input)
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn test_authority() {
            assert_eq!(
                parsers::authority("bob:bob@bob"),
                Ok((
                    "",
                    Authority {
                        host: "bob".as_ref(),
                        password: Some("bob".as_ref()),
                        username: Some("bob".as_ref()),
                        port: None
                    }
                ))
            );
            assert_eq!(
                parsers::authority("b"),
                Ok((
                    "",
                    Authority {
                        host: "b".as_ref(),
                        password: None,
                        port: None,
                        username: None
                    }
                ))
            )
        }

        #[test]
        fn test_user_info() {
            assert_eq!(
                parsers::authority_credentials("bob:password@host"),
                Ok(("host", (Some("bob"), Some("password"))))
            )
        }

        #[test]
        fn test_bad_user_info() {
            assert_eq!(
                parsers::authority_credentials("iamnotahost"),
                Ok(("iamnotahost", (None, None)))
            )
        }

        #[test]
        fn test_path() {
            let matched_path = vec!["f", "g", "h"];
            assert_eq!(
                parsers::path("/f/g/h?i=h"),
                Ok((
                    "?i=h",
                    matched_path.into_iter().map(|f| f.as_ref()).collect()
                ))
            )
        }

        #[test]
        fn test_full_absolute_uri() {
            let query_string_map = [("i".as_ref(), "j".as_ref()), ("k".as_ref(), "l".as_ref())]
                .iter()
                .cloned()
                .collect();

            assert_eq!(
                parsers::uri("a://b:c@d.e/f/g/h?i=j&k=l"),
                Ok((
                    "",
                    URI {
                        scheme: "a".as_ref(),
                        authority: Authority {
                            host: "d.e".as_ref(),
                            username: Some("b".as_ref()),
                            password: Some("c".as_ref()),
                            port: None
                        },
                        path: Some(vec!("f".as_ref(), "g".as_ref(), "h".as_ref())),
                        qs: Some(query_string_map)
                    }
                ))
            )
        }
    }
}
