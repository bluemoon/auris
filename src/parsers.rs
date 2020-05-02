use nom::{
    branch::alt,
    bytes::complete::{tag, take_till},
    character::complete::{alpha1, digit1},
    combinator::{all_consuming, cut, opt},
    multi::many0,
    sequence::tuple,
    IResult,
};

use crate::{Authority, UserInfo, URI, ParseError};
use std::collections::HashMap;
use std::str;

use bumpalo::Bump;
use bumpalo::collections::String as BString;

#[inline]
pub fn is_alphabetic(chr:u8) -> bool {
  (chr >= 0x41 && chr <= 0x5A) || (chr >= 0x61 && chr <= 0x7A)
}

#[inline]
pub fn is_digit(chr: u8) -> bool {
  chr >= 0x30 && chr <= 0x39
}

#[inline]
pub fn is_alphanumeric(chr: u8) -> bool {
  is_alphabetic(chr) || is_digit(chr)
}

pub fn span<'i>(input: &'i str, i_pos: usize, rest_pos: usize) -> &'i str {
    &input[..i_pos - rest_pos]
}

fn take<'a,  F: Fn(char) -> bool>(f: F) -> impl Fn(&'a str) -> Result<(&'a str, &'a str), (ParseError, &str)> {
    move |i: &str| {
        let mut iter = i.chars();
        loop {
            let rest = iter.as_str();
            match iter.next() {
                Some(c) if f(c) => {}
                _ => {
                    let rest_len = rest.len();
                    let i_len = i.len();
                    return if rest_len != i_len {
                        Ok((span(i, i_len, rest_len), rest))
                    } else {
                        Err((ParseError::Failed, i))
                    }; 
                }
            }
        }
    }
}

pub fn f(i: &str) -> Result<(&str, &str), (ParseError, &str)> {
    let (i, scheme) = take(|f| is_alphanumeric(f as u8) && f != ':')(i)?;
    Ok((i, scheme))
}

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
pub fn scheme<'a>(input: &'a str) -> IResult<&'a str, &'a str>{
    // postgres://
    // bob://
    // let bump = Bump::new();
    // let bstr = BString::from_str_in(input, &bump);

    // let r = take(":")(&bstr)?;
    // 
    // Ok(r)
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

/// Parse the user credentials from the authority section.
fn authority_credentials<'a>(input: &'a str) -> IResult<&'a str, Option<UserInfo<&'a str>>> {
    let user_pw_combinator = |i: &'a str| -> IResult<&str, UserInfo<&str>> {
        // user:pw@
        let (remain_chunk_1, user) = cut(alpha1)(i)?;
        let (remain_chunk_2, _) = tag(":")(remain_chunk_1)?;
        let (remain_chunk_3, password) = cut(alpha1)(remain_chunk_2)?;
        let (remain_chunk_4, _) = tag("@")(remain_chunk_3)?;
        Ok((remain_chunk_4, UserInfo::UserAndPassword(user, password)))
    };

    // Parse user string without a password
    let user_combinator = |i: &'a str| -> IResult<&str, UserInfo<&str>> {
        let (remain_chunk_1, user) = cut(alpha1)(i)?;
        let (remain_chunk_2, _) = tag("@")(remain_chunk_1)?;
        Ok((remain_chunk_2, UserInfo::User(user)))
    };
    // The whole statement may fail if there is no match
    // we flatten this out so that you will just get (None, None)
    opt(alt((user_pw_combinator, user_combinator)))(input)
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

    let mut map: HashMap<&str, &str> = HashMap::with_capacity(vec.len());
    for (k, v) in vec.into_iter() {
        map.insert(k, v);
    }
    //vec.into_iter().map(|(k, v)| map.entry(k).or_insert(v));
    Ok((remain, map))
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
        Ok((remaining_input, (userinfo, (host, port)))) => Ok((
            remaining_input,
            Authority {
                host,
                userinfo,
                port,
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
    let (i, scheme) = scheme(input)?;
    let (i, userinfo) = authority_credentials(i)?;
    let (i, (host, port)) = host_port_combinator(i)?;
    let (i, path) = path(i)?;
    let (i, query) = opt(query)(i)?;

    Ok((
        i,
        URI {
            scheme,
            authority: Authority {
                host,
                userinfo,
                port,
            },
            path: Some(path),
            qs: query,
        },
    ))
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
                    userinfo: Some(UserInfo::UserAndPassword("bob".as_ref(), "bob".as_ref())),
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
                    userinfo: None,
                    port: None,
                }
            ))
        )
    }

    #[test]
    fn test_user_info() {
        assert_eq!(
            authority_credentials("bob:password@host"),
            Ok((
                "host",
                Some(UserInfo::UserAndPassword(
                    "bob".as_ref(),
                    "password".as_ref()
                ))
            ))
        )
    }

    #[test]
    fn test_bad_user_info() {
        assert_eq!(
            authority_credentials("iamnotahost.com"),
            Ok(("iamnotahost.com", None))
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
                        userinfo: Some(UserInfo::UserAndPassword("b".as_ref(), "c".as_ref())),
                        port: None
                    },
                    path: Some(vec!("f".as_ref(), "g".as_ref(), "h".as_ref())),
                    qs: Some(query_string_map)
                }
            ))
        )
    }
}
