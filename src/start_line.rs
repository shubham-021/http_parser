use crate::ParserConfig;
use crate::cursor::{Cursor, is_header_value_byte, is_tchar, is_uri_char};
use crate::error::{ParseError, ParseResult, Status};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Version {
    Http10, // HTTP/1.0
    Http11, // HTTP/1.1
}

// &str: a string slice is essentially a reference to UTF-8 bytes plus their length
// "HTTP/1.1" is a string literal. String literals are stored in the compiled program's binary and
// have a lifetime of 'static
//
// when we define literals it exists throughout the program
// let s = "HTTP/1.1"
// the string literal "HTTP/1.1" is stored in the program's binary, typically in a read-only data
// section. It exists independently of the function or the block where you referenced it
//
// fn example(){
//      let s = String::from("HTTP/1.1");
// }
// here, s is dropped after the block
//
// fn example(){
//      let s = "HTTP/1.1";
// }
// s (the reference) is dropped here
impl Version {
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method<'buf> {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,
    Custom(&'buf str),
}

impl<'buf> Method<'buf> {
    #[inline]
    pub fn from_token(token: &'buf str) -> Self {
        match token.as_bytes() {
            b"GET" => Self::Get,
            b"HEAD" => Self::Head,
            b"POST" => Self::Post,
            b"PUT" => Self::Put,
            b"DELETE" => Self::Delete,
            b"CONNECT" => Self::Connect,
            b"OPTIONS" => Self::Options,
            b"TRACE" => Self::Trace,
            b"PATCH" => Self::Patch,
            _ => Self::Custom(token),
        }
    }

    #[inline]
    pub const fn as_str(&self) -> &'buf str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Connect => "CONNECT",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Patch => "PATCH",
            Self::Custom(s) => s,
        }
    }

    // returns true if the method is considered safe (read-only) per RFC 9110 Section 9.2.1
    #[inline]
    pub const fn is_safe(&self) -> bool {
        matches!(self, Self::Get | Self::Head | Self::Options | Self::Trace)
    }

    // returns true if method is idempotent per RFC 9110 section 9.2.2
    #[inline]
    pub const fn is_idempotent(&self) -> bool {
        matches!(
            self,
            Self::Get | Self::Head | Self::Put | Self::Delete | Self::Options | Self::Trace
        )
    }
}

// parsed zero-copy HTTP/1.x request line ('GET /index.html HTTP/1.1\r\n')
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLine<'buf> {
    pub method: Method<'buf>,
    pub target: &'buf str,
    pub version: Version,
}

// parsed zero-copy HTTP/1.x response status line ('HTTP/1.1 200 Ok\r\n')
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusLine<'buf> {
    pub version: Version,
    pub status_code: u16,
    pub reason: &'buf [u8],
}

impl<'buf> StatusLine<'buf> {
    // attempts to view the reason-phrase as UTF-8
    //
    // returns `None` if the reason-phrase legacy `obs-text`, that is not valid UTF-8
    #[inline]
    pub fn reason_str(&self) -> Option<&'buf str> {
        core::str::from_utf8(self.reason).ok()
    }
}

// parses an HTTP/1.x 'Version'
//
// rejects invalid prefixes on the very first mismatched byte rather than waiting for all 8
// bytes to arrive
fn parse_version(cursor: &mut Cursor<'_>) -> ParseResult<Version> {
    const PREFIX: &[u8] = b"HTTP/1.";
    let version_offset = cursor.pos();
    let rem = cursor.remaining();

    let check_len = rem.len().min(PREFIX.len());
    // you can compare two slices directly using == , rust performs element-by-element
    // comparision in order
    if rem[..check_len] != PREFIX[..check_len] {
        return Err(ParseError::InvalidVersion {
            offset: version_offset,
        });
    }

    if rem.len() < 8 {
        return Ok(Status::Partial);
    }

    let version = match rem[7] {
        b'0' => Version::Http10,
        b'1' => Version::Http11,
        _ => {
            return Err(ParseError::InvalidVersion {
                offset: version_offset,
            });
        }
    };

    cursor.advance(8);
    Ok(Status::Complete {
        value: version,
        consumed: 8,
    })
}

// parses an HTTP/1.x request-line from the beginning of buf
pub fn parse_request_line<'buf>(
    buf: &'buf [u8],
    config: &ParserConfig,
) -> ParseResult<RequestLine<'buf>> {
    let mut cursor = Cursor::new(buf);

    //1. Parse method (1*tchar followed by a single SP)
    let method_start = cursor.pos();
    loop {
        match cursor.peek() {
            None => return Ok(Status::Partial),
            Some(b' ') => {
                if cursor.pos() == method_start {
                    return Err(ParseError::InvalidMethod {
                        offset: method_start,
                    });
                }
                break;
            }
            Some(b'\r' | b'\n') if cursor.pos() == method_start => {
                return Err(ParseError::InvalidMethod {
                    offset: method_start,
                });
            }
            Some(b) if is_tchar(b) => {
                cursor.advance(1);
                if cursor.pos() - method_start > config.max_method_len {
                    return Err(ParseError::InvalidMethod {
                        offset: method_start,
                    });
                }
            }
            Some(b) => {
                return Err(ParseError::InvalidTokenByte {
                    offset: cursor.pos(),
                    byte: b,
                });
            }
        }
    }

    let method_bytes = cursor.slice_from(method_start);
    let method_str = core::str::from_utf8(method_bytes).map_err(|_| ParseError::InvalidMethod {
        offset: method_start,
    })?;
    let method = Method::from_token(method_str);

    // consume single SP after method
    cursor.advance(1);

    //2. parse request-target (1*uri_char followed by single SP)
    let target_start = cursor.pos();
    loop {
        match cursor.peek() {
            None => return Ok(Status::Partial),
            Some(b' ') => {
                if cursor.pos() == target_start {
                    return Err(ParseError::InvalidRequestTarget {
                        offset: target_start,
                    });
                }
                break;
            }
            Some(b) if is_uri_char(b) => {
                cursor.advance(1);
                if cursor.pos() - target_start > config.max_uri_len {
                    return Err(ParseError::InvalidRequestTarget {
                        offset: target_start,
                    });
                }
            }
            Some(_) => {
                return Err(ParseError::InvalidRequestTarget {
                    offset: cursor.pos(),
                });
            }
        }
    }

    let target_bytes = cursor.slice_from(target_start);
    let target =
        core::str::from_utf8(target_bytes).map_err(|_| ParseError::InvalidRequestTarget {
            offset: target_start,
        })?;

    cursor.advance(1);

    //3. Parse HTTP-Version
    let version_offset = cursor.pos();
    let version = match parse_version(&mut cursor)? {
        Status::Complete { value, .. } => value,
        Status::Partial => return Ok(Status::Partial),
    };

    //4. Require immediate line ending (CRLF, or LF if configured)
    match cursor.peek() {
        None => return Ok(Status::Partial),
        Some(b'\r' | b'\n') => {
            if cursor.consume_newline(config.allow_bare_lf)?.is_partial() {
                return Ok(Status::Partial);
            }
        }
        Some(_) => {
            return Err(ParseError::InvalidVersion {
                offset: version_offset,
            });
        }
    }

    if cursor.pos() > config.max_header_block_bytes {
        return Err(ParseError::HeaderBlockTooLarge {
            max_allowed: config.max_header_block_bytes,
        });
    }

    Ok(Status::Complete {
        value: RequestLine {
            method,
            target,
            version,
        },
        consumed: cursor.pos(),
    })
}

// parse an HTTP/1.x response status-line from the beginning of 'buf'
pub fn parse_status_line<'buf>(
    buf: &'buf [u8],
    config: &ParserConfig,
) -> ParseResult<StatusLine<'buf>> {
    let mut cursor = Cursor::new(buf);

    // 1. http version
    let version_offset = cursor.pos();
    let version = match parse_version(&mut cursor)? {
        Status::Complete { value, .. } => value,
        Status::Partial => return Ok(Status::Partial),
    };

    // SP after http version
    match cursor.next_byte() {
        None => return Ok(Status::Partial),
        Some(b' ') => {}
        Some(_) => {
            return Err(ParseError::InvalidVersion {
                offset: version_offset,
            });
        }
    }

    //2. parse 3-digit status-code followed by a single SP
    let code_offset = cursor.pos();
    let rem = cursor.remaining();
    for &b in rem.iter().take(3) {
        if !b.is_ascii_digit() {
            return Err(ParseError::InvalidStatusCode {
                offset: code_offset,
            });
        }
    }
    if rem.len() < 3 {
        return Ok(Status::Partial);
    }

    //first digit of an http status code cannot be '0'
    if rem[0] == b'0' {
        return Err(ParseError::InvalidStatusCode {
            offset: code_offset,
        });
    }

    let status_code =
        u16::from(rem[0] - b'0') * 100 + u16::from(rem[1] - b'0') * 10 + u16::from(rem[2] - b'0');
    cursor.advance(3);

    // require single SP after status-code
    match cursor.next_byte() {
        None => return Ok(Status::Partial),
        Some(b' ') => {}
        Some(_) => {
            return Err(ParseError::InvalidStatusCode {
                offset: code_offset,
            });
        }
    }

    //3. parse optional reason-phrase (*header_value_byte) upto CRLF
    let reson_start = cursor.pos();
    loop {
        match cursor.peek() {
            None => return Ok(Status::Partial),
            Some(b'\r' | b'\n') => break,
            Some(b) if is_header_value_byte(b) => {
                cursor.advance(1);
                if cursor.pos() > config.max_header_block_bytes {
                    return Err(ParseError::HeaderBlockTooLarge {
                        max_allowed: config.max_header_block_bytes,
                    });
                }
            }
            Some(b) => {
                return Err(ParseError::InvalidHeaderValue {
                    offset: cursor.pos(),
                    byte: b,
                });
            }
        }
    }

    let reason = cursor.slice_from(reson_start);
    if cursor.consume_newline(config.allow_bare_lf)?.is_partial() {
        return Ok(Status::Partial);
    }

    if cursor.pos() > config.max_header_block_bytes {
        return Err(ParseError::HeaderBlockTooLarge {
            max_allowed: config.max_header_block_bytes,
        });
    }

    Ok(Status::Complete {
        value: StatusLine {
            version,
            status_code,
            reason,
        },
        consumed: cursor.pos(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_and_custom_request_lines() {
        let config = ParserConfig::strict();

        let raw = b"GET /api/v1/users?page=2 HTTP/1.1\r\nHost: example.com\r\n";
        let res = parse_request_line(raw, &config).unwrap();
        assert_eq!(
            res,
            Status::Complete {
                value: RequestLine {
                    method: Method::Get,
                    target: "/api/v1/users?page=2",
                    version: Version::Http11
                },
                consumed: raw.len()
            }
        );

        assert!(Method::Get.is_safe());
        assert!(Method::Get.is_idempotent());
        assert!(!Method::Post.is_idempotent());

        let webdav = b"PROPFIND /dav/files HTTP/1.0\r\n";
        let res = parse_request_line(webdav, &config).unwrap();
        assert_eq!(
            res,
            Status::Complete {
                value: RequestLine {
                    method: Method::Custom("PROPFIND"),
                    target: "/dav/files",
                    version: Version::Http10,
                },
                consumed: webdav.len()
            }
        );
    }

    #[test]
    fn request_line_handles_every_byte_boundary_incrementally() {
        let config = ParserConfig::strict();
        let full = b"POST /submit HTTP/1.1\r\n";

        //every prefix before the final \n must return Ok(Status::Partial)
        for cut in 0..full.len() - 1 {
            let prefix = &full[..cut];
            assert_eq!(
                parse_request_line(prefix, &config),
                Ok(Status::Partial),
                "expected Partial for prefix of len {cut}: {:?}",
                core::str::from_utf8(prefix)
            );
        }

        assert!(parse_request_line(full, &config).unwrap().is_complete());
    }
}
