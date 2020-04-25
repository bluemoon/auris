use nom::{
    branch::alt,
    bytes::complete::{tag, take_till},
    character::complete::{alpha1, digit1},
    combinator::{all_consuming, cut, map, opt},
    multi::many0,
    sequence::tuple,
    IResult,
};

use crate::{Authority, URI};
use std::collections::HashMap;
use std::str;

/// Parses structure:
///
/// ```notrust
///     foo://example.com:8042/over/there?name=ferret#nose
///     \_/   \______________/\_________/ \_________/ \__/
///      |           |            |            |        |
///   scheme     authority       path        query   fragment
/// ```
///

/// Parse out the scheme
///
/// # Examples
///
/// ```
/// use auris::parsers;
/// parsers::scheme("bob+postgres://");
/// parsers::scheme("bob-postgres://");
/// parsers::scheme("bob.postgres://");
/// ```
///
// Guidelines for URL schemes
// https://tools.ietf.org/html/rfc2718
pub fn scheme(input: &str) -> IResult<&str, &str> {
    // postgres://
    // bob://
    let (remaining, scheme_chunk) = take_till(|c| c == ':')(input)?;
    // :// is the hier part
    let (remaining_post_scheme, _) = tag("://")(remaining)?;
    Ok((remaining_post_scheme, scheme_chunk))
}

fn host_port_combinator<'a>(input: &'a str) -> IResult<&'a str, (&'a str, Option<u16>)> {
    let port_combinator = |i: &'a str| -> IResult<&str, u16> {
        let (remain_chunk_1, _) = tag(":")(i)?;
        let (remain_chunk_2, digits) = digit1(remain_chunk_1)?;
        Ok((remain_chunk_2, digits.parse::<u16>().unwrap()))
    };

    let domain =
        |i: &'a str| -> IResult<&'a str, &'a str> { take_till(|c| c == '/' || c == '?')(i) };

    // asdf.com:1234
    let (i, host) = domain(input)?;
    let (i, port) = opt(port_combinator)(i)?;
    Ok((i, (host, port)))
}

/// Parse the user credentials from the authority section. We can
/// always expect this function to return a tuple of options. Instead of using
/// `Option<(Option<&str>, Option<&str>)>`, `(Option<&str>, Option<&str>)` is used
fn authority_credentials<'a>(
    input: &'a str,
) -> IResult<&'a str, (Option<&'a str>, Option<&'a str>)> {
    let user_pw_combinator = |i: &'a str| -> IResult<&str, (Option<&str>, Option<&str>)> {
        // user:pw@
        let (remain_chunk_1, user) = cut(alpha1)(i)?;
        let (remain_chunk_2, _) = tag(":")(remain_chunk_1)?;
        let (remain_chunk_3, password) = cut(alpha1)(remain_chunk_2)?;
        let (remain_chunk_4, _) = tag("@")(remain_chunk_3)?;
        Ok((remain_chunk_4, (Some(user), Some(password))))
    };

    // Parse user string without a password
    let user_combinator = |i: &'a str| -> IResult<&str, (Option<&str>, Option<&str>)> {
        let (remain_chunk_1, user) = cut(alpha1)(i)?;
        let (remain_chunk_2, _) = tag("@")(remain_chunk_1)?;
        Ok((remain_chunk_2, (Some(user), None)))
    };
    // The whole statement may fail if there is no match
    // we flatten this out so that you will just get (None, None)
    let (remain, alt_opt) = opt(alt((user_pw_combinator, user_combinator)))(input)?;
    match alt_opt {
        Some(options) => Ok((remain, options)),
        None => Ok((remain, (None, None))),
    }
}

/// Parse the whole path chunk
pub fn path<'a>(input: &'a str) -> IResult<&'a str, Vec<&'a str>> {
    // Parse a single path chunk
    let path_part = |i: &'a str| -> IResult<&str, &str> {
        let (remain, (_, chunk)) = tuple((tag("/"), alpha1))(i)?;
        Ok((remain, chunk))
    };
    // /a/b/c
    many0(path_part)(input)
}

/// Parses ?k=v&k1=v1 into a HashMap
pub fn query<'a>(input: &'a str) -> IResult<&'a str, HashMap<&'a str, &'a str>> {
    let part = |i: &'a str| -> IResult<&str, (&str, &str)> {
        let (remain, (key, _, value, _)) = tuple((alpha1, tag("="), alpha1, opt(tag("&"))))(i)?;
        Ok((remain, (key, value)))
    };

    let (post_q, _) = tag("?")(input)?;
    let (remain, vec) = many0(part)(post_q)?;
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
    match all_consuming(tuple((authority_credentials, host_port_combinator)))(input) {
        Ok((remaining_input, ((username, password), (host, port)))) => Ok((
            remaining_input,
            Authority {
                host,
                password,
                port,
                username,
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
            host_port_combinator,
            path,
            opt(query),
        ))),
        |f| match f {
            (scheme, (username, password), (host, port), path, query) => URI {
                scheme,
                authority: Authority {
                    host,
                    username,
                    password,
                    port,
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
            authority("bob:bob@bob"),
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
            authority("b"),
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
            authority_credentials("bob:password@host"),
            Ok(("host", (Some("bob"), Some("password"))))
        )
    }

    #[test]
    fn test_bad_user_info() {
        assert_eq!(
            authority_credentials("iamnotahost.com"),
            Ok(("iamnotahost.com", (None, None)))
        )
    }

    #[test]
    fn test_path() {
        let matched_path = vec!["f", "g", "h"];
        assert_eq!(
            path("/f/g/h?i=h"),
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
            uri("a://b:c@d.e/f/g/h?i=j&k=l"),
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
