use nom::{
    branch::alt,
    bytes::complete::{tag, take_till, take_while1},
    character::complete::digit1,
    combinator::{all_consuming, opt},
    multi::many0,
    sequence::tuple,
    IResult,
};

/// RFC 3986 unreserved characters: ALPHA / DIGIT / "-" / "." / "_" / "~"
fn is_unreserved(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~'
}

/// Characters allowed in userinfo (excluding '@' and ':' which are delimiters)
fn is_userinfo_char(c: char) -> bool {
    is_unreserved(c) || is_sub_delim(c) || c == '%'
}

/// RFC 3986 sub-delims: "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
fn is_sub_delim(c: char) -> bool {
    matches!(
        c,
        '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '='
    )
}

/// Characters allowed in path segments (pchar without delimiters)
fn is_pchar(c: char) -> bool {
    is_unreserved(c) || is_sub_delim(c) || c == '%' || c == ':' || c == '@'
}

/// Characters allowed in query strings and fragments
fn is_query_char(c: char) -> bool {
    is_pchar(c) || c == '/' || c == '?'
}

use crate::{Authority, Host, UserInfo, URI};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str;

/// Parse a host string into a Host enum
/// RFC 3986: host = IP-literal / IPv4address / reg-name
/// IP-literal = "[" ( IPv6address / IPvFuture ) "]"
pub fn parse_host(input: &str) -> Host<String> {
    // Check for IPv6 literal (enclosed in brackets)
    if input.starts_with('[') && input.ends_with(']') {
        let inner = &input[1..input.len() - 1];
        if let Ok(ipv6) = inner.parse::<Ipv6Addr>() {
            return Host::Ipv6(ipv6);
        }
    }

    // Check for IPv4 address
    if let Ok(ipv4) = input.parse::<Ipv4Addr>() {
        return Host::Ipv4(ipv4);
    }

    // Default to domain name
    Host::Domain(input.to_string())
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

    // RFC 3986: IP-literal = "[" ( IPv6address / IPvFuture ) "]"
    // IPv6 addresses are enclosed in brackets, so ':' inside brackets is part of the address
    if input.starts_with('[') {
        // Parse IPv6 literal: find closing bracket
        let ipv6_host_parser = |i: &'a str| -> IResult<&'a str, &'a str> {
            let (remain, _) = tag("[")(i)?;
            let (remain, addr) = take_till(|c| c == ']')(remain)?;
            let (remain, _) = tag("]")(remain)?;
            // Return the full bracketed form including brackets
            let end_pos = 1 + addr.len() + 1; // '[' + addr + ']'
            Ok((remain, &i[..end_pos]))
        };

        let (i, host) = ipv6_host_parser(input)?;
        let (i, port) = opt(port_combinator)(i)?;
        return Ok((i, (host, port)));
    }

    // Regular host (domain or IPv4): stops at ':', '/', '?', or '#'
    let host_parser = |i: &'a str| -> IResult<&'a str, &'a str> {
        take_till(|c| c == '/' || c == '?' || c == ':' || c == '#')(i)
    };

    // example.com:8080/path
    let (i, host) = host_parser(input)?;
    let (i, port) = opt(port_combinator)(i)?;
    Ok((i, (host, port)))
}

/// Parse the user credentials from the authority section.
/// RFC 3986 allows unreserved / pct-encoded / sub-delims in userinfo
fn authority_credentials<'a>(input: &'a str) -> IResult<&'a str, Option<UserInfo<&'a str>>> {
    let user_pw_combinator = |i: &'a str| -> IResult<&str, UserInfo<&str>> {
        // user:pw@
        // Don't use cut on take_while1 - let it backtrack if no valid userinfo chars at start
        let (remain_chunk_1, user) = take_while1(is_userinfo_char)(i)?;
        let (remain_chunk_2, _) = tag(":")(remain_chunk_1)?;
        let (remain_chunk_3, password) = take_while1(is_userinfo_char)(remain_chunk_2)?;
        let (remain_chunk_4, _) = tag("@")(remain_chunk_3)?;
        Ok((remain_chunk_4, UserInfo::UserAndPassword(user, password)))
    };

    // Parse user string without a password
    let user_combinator = |i: &'a str| -> IResult<&str, UserInfo<&str>> {
        let (remain_chunk_1, user) = take_while1(is_userinfo_char)(i)?;
        let (remain_chunk_2, _) = tag("@")(remain_chunk_1)?;
        Ok((remain_chunk_2, UserInfo::User(user)))
    };
    // The whole statement may fail if there is no match
    // we flatten this out so that you will just get (None, None)
    opt(alt((user_pw_combinator, user_combinator)))(input)
}

/// Parse the whole path chunk
/// RFC 3986 pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
pub fn path<'a>(input: &'a str) -> IResult<&'a str, Vec<&'a str>> {
    // Parse a single path chunk
    let path_part = |i: &'a str| -> IResult<&str, &str> {
        let (remain, _) = tag("/")(i)?;
        // Path segment can be empty (for trailing slashes) or contain pchars
        let (remain, chunk) = opt(take_while1(is_pchar))(remain)?;
        Ok((remain, chunk.unwrap_or("")))
    };
    // /a/b/c
    many0(path_part)(input)
}

/// Characters allowed in query keys (subset - no '=' or '&')
fn is_query_key_char(c: char) -> bool {
    is_unreserved(c)
        || c == '%'
        || matches!(
            c,
            '!' | '$' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | ':' | '@' | '/' | '?'
        )
}

/// Characters allowed in query values (subset - no '&' or '#')
fn is_query_value_char(c: char) -> bool {
    is_query_key_char(c) || c == '='
}

/// Parses ?k=v&k1=v1 into a HashMap
/// RFC 3986 allows query = *( pchar / "/" / "?" )
pub fn query<'a>(input: &'a str) -> IResult<&'a str, HashMap<&'a str, &'a str>> {
    let part = |i: &'a str| -> IResult<&str, (&str, &str)> {
        let (remain, key) = take_while1(is_query_key_char)(i)?;
        let (remain, _) = tag("=")(remain)?;
        // Value can be empty or contain query chars (but not '&' or '#')
        let (remain, value) = opt(take_while1(is_query_value_char))(remain)?;
        let (remain, _) = opt(tag("&"))(remain)?;
        Ok((remain, (key, value.unwrap_or(""))))
    };

    let (post_q, _) = tag("?")(input)?;
    let (remain, vec) = many0(part)(post_q)?;

    let mut map: HashMap<&str, &str> = HashMap::with_capacity(vec.len());
    for (k, v) in vec.into_iter() {
        map.insert(k, v);
    }
    Ok((remain, map))
}

/// Parses #fragment from the URI
/// RFC 3986: fragment = *( pchar / "/" / "?" )
pub fn fragment(input: &str) -> IResult<&str, &str> {
    let (remain, _) = tag("#")(input)?;
    let (remain, frag) = take_while1(is_query_char)(remain)?;
    Ok((remain, frag))
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
/// parsers::uri("scheme://user:pw@host.pizza/path1/path2/?k=v&k1=v1#section");
/// ```
pub fn uri(input: &str) -> IResult<&str, URI<&str>> {
    let (i, scheme) = scheme(input)?;
    let (i, userinfo) = authority_credentials(i)?;
    let (i, (host, port)) = host_port_combinator(i)?;
    let (i, path) = path(i)?;
    let (i, query) = opt(query)(i)?;
    let (i, frag) = opt(fragment)(i)?;

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
            fragment: frag,
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
                    qs: Some(query_string_map),
                    fragment: None
                }
            ))
        )
    }

    // RFC 3986 compliance tests

    #[test]
    fn test_fragment_parsing() {
        assert_eq!(fragment("#section1"), Ok(("", "section1")));
        assert_eq!(fragment("#top"), Ok(("", "top")));
        assert_eq!(fragment("#/path/to/element"), Ok(("", "/path/to/element")));
    }

    #[test]
    fn test_uri_with_fragment() {
        let result = uri("http://example.com/page#section");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(parsed.fragment, Some("section"));
    }

    #[test]
    fn test_uri_with_query_and_fragment() {
        let result = uri("http://example.com/search?q=test#results");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(parsed.scheme, "http");
        assert_eq!(parsed.authority.host, "example.com");
        assert!(parsed.qs.is_some());
        assert_eq!(parsed.fragment, Some("results"));
    }

    #[test]
    fn test_userinfo_with_numbers() {
        // RFC 3986: userinfo can contain digits
        let result = uri("ftp://user123:pass456@ftp.example.com/file");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(
            parsed.authority.userinfo,
            Some(UserInfo::UserAndPassword("user123", "pass456"))
        );
    }

    #[test]
    fn test_path_with_numbers() {
        // RFC 3986: path segments can contain digits
        let result = uri("http://example.com/api/v2/users/123");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(parsed.path, Some(vec!["api", "v2", "users", "123"]));
    }

    #[test]
    fn test_query_with_numbers() {
        // RFC 3986: query can contain digits
        let result = uri("http://example.com/search?page=42&limit=100");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        let qs = parsed.qs.unwrap();
        assert_eq!(qs.get("page"), Some(&"42"));
        assert_eq!(qs.get("limit"), Some(&"100"));
    }

    #[test]
    fn test_uri_with_port() {
        let result = uri("http://example.com:8080/path");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(parsed.authority.host, "example.com");
        assert_eq!(parsed.authority.port, Some(8080));
    }

    #[test]
    fn test_rfc3986_example_ftp() {
        // RFC 3986 Section 1.1.2 example
        let result = uri("ftp://ftp.is.co.za/rfc/rfc1808.txt");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(parsed.scheme, "ftp");
        assert_eq!(parsed.authority.host, "ftp.is.co.za");
        assert_eq!(parsed.path, Some(vec!["rfc", "rfc1808.txt"]));
    }

    #[test]
    fn test_rfc3986_example_http() {
        // RFC 3986 Section 1.1.2 example
        let result = uri("http://www.ietf.org/rfc/rfc2396.txt");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(parsed.scheme, "http");
        assert_eq!(parsed.authority.host, "www.ietf.org");
        assert_eq!(parsed.path, Some(vec!["rfc", "rfc2396.txt"]));
    }

    #[test]
    fn test_rfc3986_example_telnet() {
        // RFC 3986 Section 1.1.2 example
        let result = uri("telnet://192.0.2.16:80/");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(parsed.scheme, "telnet");
        assert_eq!(parsed.authority.host, "192.0.2.16");
        assert_eq!(parsed.authority.port, Some(80));
    }

    #[test]
    fn test_special_chars_in_userinfo() {
        // RFC 3986: sub-delims allowed in userinfo
        let result = uri("http://user.name@example.com/");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(parsed.authority.userinfo, Some(UserInfo::User("user.name")));
    }

    #[test]
    fn test_percent_encoded_in_path() {
        // RFC 3986: percent-encoded allowed in path
        let result = uri("http://example.com/path%20with%20spaces");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(parsed.path, Some(vec!["path%20with%20spaces"]));
    }

    #[test]
    fn test_empty_path() {
        let result = uri("http://example.com");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(parsed.path, Some(vec![]));
    }

    #[test]
    fn test_empty_query_value() {
        let result = uri("http://example.com/path?empty=");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        let qs = parsed.qs.unwrap();
        assert_eq!(qs.get("empty"), Some(&""));
    }

    // IPv4 and IPv6 tests

    #[test]
    fn test_ipv4_host() {
        let result = uri("http://192.168.1.1/path");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(parsed.authority.host, "192.168.1.1");
    }

    #[test]
    fn test_ipv4_with_port() {
        let result = uri("http://10.0.0.1:8080/api");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(parsed.authority.host, "10.0.0.1");
        assert_eq!(parsed.authority.port, Some(8080));
    }

    #[test]
    fn test_ipv6_host() {
        // RFC 3986: IPv6 addresses must be enclosed in brackets
        let result = uri("http://[2001:db8::1]/path");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(parsed.authority.host, "[2001:db8::1]");
    }

    #[test]
    fn test_ipv6_with_port() {
        // RFC 3986 Section 1.1.2 example
        let result = uri("ldap://[2001:db8::7]/c=GB?objectClass?one");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(parsed.authority.host, "[2001:db8::7]");
        assert_eq!(parsed.authority.port, None);
    }

    #[test]
    fn test_ipv6_with_port_explicit() {
        let result = uri("http://[::1]:8080/");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(parsed.authority.host, "[::1]");
        assert_eq!(parsed.authority.port, Some(8080));
    }

    #[test]
    fn test_ipv6_loopback() {
        let result = uri("http://[::1]/");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(parsed.authority.host, "[::1]");
    }

    #[test]
    fn test_ipv6_full_address() {
        let result = uri("http://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]/");
        assert!(result.is_ok());
        let (_, parsed) = result.unwrap();
        assert_eq!(
            parsed.authority.host,
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]"
        );
    }

    #[test]
    fn test_parse_host_ipv4() {
        use crate::Host;
        use std::net::Ipv4Addr;

        let host = parse_host("192.168.1.1");
        match host {
            Host::Ipv4(addr) => assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 1)),
            _ => panic!("Expected IPv4 address"),
        }
    }

    #[test]
    fn test_parse_host_ipv6() {
        use crate::Host;
        use std::net::Ipv6Addr;

        let host = parse_host("[::1]");
        match host {
            Host::Ipv6(addr) => assert_eq!(addr, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            _ => panic!("Expected IPv6 address"),
        }
    }

    #[test]
    fn test_parse_host_domain() {
        use crate::Host;

        let host = parse_host("example.com");
        match host {
            Host::Domain(name) => assert_eq!(name, "example.com"),
            _ => panic!("Expected domain name"),
        }
    }
}
