//! **auris** is an experimental URI parsing library
//!
//! - Uses only safe features in rust.
//! - `rfc2396` & `rfc3986` compliant (incomplete)
//!
extern crate nom;

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

/// Authority section of the URI
#[derive(Debug, PartialEq)]
pub struct Authority {
    //TODO(bradford): IPV6, IPV4, DNS enum
    host: String,
    username: Option<String>,
    password: Option<String>,
    port: Option<u16>,
}

/// URI is the whole URI object
#[derive(Debug, PartialEq)]
pub struct URI {
    scheme: String,
    authority: Authority,
    path: Option<Vec<String>>,
    qs: Option<HashMap<String, String>>,
}

pub mod parsers {
    //! Parses structure:
    //!
    //!     foo://example.com:8042/over/there?name=ferret#nose
    //!     \_/   \______________/\_________/ \_________/ \__/
    //!      |           |            |            |        |
    //!   scheme     authority       path        query   fragment
    //!
    use super::*;

    /// Parse out the scheme
    fn scheme(input: &str) -> IResult<&str, &str> {
        // postgres://
        // bob://
        let scheme_tuple = tuple((take_till(|c| c == ':'), tag("://")));
        map(scheme_tuple, |tuple| match tuple {
            (scheme, _) => scheme,
        })(input)
    }

    /// Parse the user credentials from the authority section. We can
    /// always expect this function to return a tuple of options. Instead of using
    /// `Option<(Option<&str>, Option<&str>)>`, `(Option<&str>, Option<&str>)` is used
    fn authority_credentials(input: &str) -> IResult<&str, (Option<&str>, Option<&str>)> {
        // user:pw@
        let user_pw_combinator = tuple((cut(alpha1), tag(":"), cut(alpha1), tag("@")));
        let user_pw_tuple = map(user_pw_combinator, |f| match f {
            (user, _, pw, _) => (Some(user), Some(pw)),
        });

        // user@
        let user_combinator = tuple((cut(alpha1), tag("@")));
        let user_tuple = map(user_combinator, |f| match f {
            (user, _) => (Some(user), None),
        });

        // The whole statement may fail if there is no match
        // we flatten this out so that you will just get (None, None)
        let alt_opt = opt(alt((user_pw_tuple, user_tuple)));
        map(alt_opt, |f: Option<(Option<&str>, Option<&str>)>| match f {
            Some(tup) => tup,
            None => (None, None),
        })(input)
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
    pub fn query(input: &str) -> IResult<&str, HashMap<String, String>> {
        let (post_q, _) = tag("?")(input)?;
        let (remain, vec) = many0(query_part)(post_q)?;
        Ok((
            remain,
            vec.into_iter()
                .map(|f| match f {
                    (key, value) => (key.to_string(), value.to_string()),
                })
                .collect(),
        ))
    }

    /// Parses the authority section of the URI
    ///
    /// # Examples
    ///
    /// ```
    /// parsers::authority("bob://bob:pass@bob.com")
    /// ```
    // http://example.com
    // postgres://user:pw@host:5432/db
    pub fn authority(input: &str) -> IResult<&str, Authority> {
        match all_consuming(tuple((authority_credentials, take_till(|c| c == '/'))))(input) {
            Ok((remaining_input, ((username, password), host))) => Ok((
                remaining_input,
                Authority {
                    host: host.to_string(),
                    password: password.map(|f| f.to_string()),
                    port: None,
                    username: username.map(|f| f.to_string()),
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
    /// parsers::uri("scheme://user:pw@host.pizza/path1/path2/?k=v&k1=v1")
    /// ```
    pub fn uri(input: &str) -> IResult<&str, URI> {
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
                    scheme: scheme.to_string(),
                    authority: Authority {
                        host: host.to_string(),
                        username: username.map(|f| f.to_string()),
                        password: password.map(|f| f.to_string()),
                        port: None,
                    },
                    path: Some(path.into_iter().map(|f| f.to_string()).collect()),
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
                        host: "bob".to_string(),
                        password: Some("bob".to_string()),
                        username: Some("bob".to_string()),
                        port: None
                    }
                ))
            );
            assert_eq!(
                parsers::authority("b"),
                Ok((
                    "",
                    Authority {
                        host: "b".to_string(),
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
            let query_string_map = [
                ("i".to_string(), "j".to_string()),
                ("k".to_string(), "l".to_string()),
            ]
            .iter()
            .cloned()
            .collect();

            assert_eq!(
                parsers::uri("a://b:c@d.e/f/g/h?i=j&k=l"),
                Ok((
                    "",
                    URI {
                        scheme: "a".to_string(),
                        authority: Authority {
                            host: "d.e".to_string(),
                            username: Some("b".to_string()),
                            password: Some("c".to_string()),
                            port: None
                        },
                        path: Some(vec!("f".to_string(), "g".to_string(), "h".to_string())),
                        qs: Some(query_string_map)
                    }
                ))
            )
        }
    }
}
