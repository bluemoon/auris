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
    combinator::{all_consuming, cut, map, map_opt, opt},
    sequence::tuple,
    IResult,
};

/// Authority section of the URI
#[derive(Debug, PartialEq)]
pub struct Authority {
    scheme: String,
    host: String,
    password: Option<String>,
    port: Option<u16>,
    username: Option<String>,
}

/// Path e.g. /a/b/c
pub struct Path {
    path: String,
}

/// QueryString is the part of a URI which assigns values to specified parameters.
#[derive(Debug)]
pub struct QueryString {
    qs: String,
}

/// URI is the whole URI object
pub struct URI {
    authority: Authority,
    path: Option<Path>,
    query_string: Option<QueryString>,
}

pub mod parsers {
    use super::*;

    // postgres://
    // bob://
    fn scheme(input: &str) -> IResult<&str, &str> {
        let scheme_tuple = tuple((take_till(|c| c == ':'), tag("://")))(input);
        match scheme_tuple {
            Ok((remaining, (scheme, _))) => Ok((remaining, scheme)),
            Err(e) => Err(e),
        }
    }

    // user:pw@
    // user@
    fn user_info(input: &str) -> IResult<&str, (Option<&str>, Option<&str>)> {
        let user_pw_combinator = tuple((cut(alpha1), tag(":"), cut(alpha1), tag("@")));
        let user_pw_tuple = map(user_pw_combinator, |f| match f {
            (user, _, pw, _) => (Some(user), Some(pw)),
        });

        let user_combinator = tuple((cut(alpha1), tag("@")));
        let user_tuple = map(user_combinator, |f| match f {
            (user, _) => (Some(user), None),
        });

        let alt_opt = opt(alt((user_pw_tuple, user_tuple)));
        map(alt_opt, |f: Option<(Option<&str>, Option<&str>)>| match f {
            Some(tup) => tup,
            None => (None, None),
        })(input)
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
        match all_consuming(tuple((scheme, user_info, take_till(|c| c == '/'))))(input) {
            Ok((remaining_input, (scheme, (username, password), host))) => Ok((
                remaining_input,
                Authority {
                    scheme: scheme.to_string(),
                    host: host.to_string(),
                    password: password.map(|f| f.to_string()),
                    port: None,
                    username: username.map(|f| f.to_string()),
                },
            )),
            Err(e) => Err(e),
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn test_authority() {
            assert_eq!(
                parsers::authority("postgres://bob:bob@bob/bob"),
                Ok((
                    "",
                    Authority {
                        scheme: "postgres".to_string(),
                        host: "bob".to_string(),
                        password: None,
                        port: None,
                        username: None
                    }
                ))
            );
            assert_eq!(
                parsers::authority("a://b"),
                Ok((
                    "",
                    Authority {
                        scheme: "a".to_string(),
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
                parsers::user_info("bob:password@host"),
                Ok(("host", (Some("bob"), Some("password"))))
            )
        }

        #[test]
        fn test_bad_user_info() {
            assert_eq!(
                parsers::user_info("iamnotahost"),
                Ok(("iamnotahost", (None, None)))
            )
        }
    }
}
