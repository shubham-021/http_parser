use crate::error::{ParseError, ParseResult, Status};

// RFC 9110 Section 5.6.2: Token characters (`tchar`)
//
// `tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
//          "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA`

const TCHAR_TABLE: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0;
    while i < 256 {
        let b = i as u8;
        table[i] = matches!(
            b,
            b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
        );
        i += 1;
    }

    table
};

// RFC 9112 Section 3.2 & RFC 3986: Valid Request-Target (URI) bytes
// Allows 'unreserved', 'pct-encoded', 'sub-delims' and 'gen-delims'
// Strictly rejects whitespaces, ASCII control char ('0x00..0x1F', '0x7F')
// non-ASCII bytes ('>= 0x80') and unencoded injection characters
// (`"`, `<`, `>`, `\`, `^`, `` ` ``, `{`, `|`, `}`)

const URI_CHAR_TABLE: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0;
    while i < 256 {
        let b = i as u8;
        table[i] = matches!(
            b,
            // Unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~"
            b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
            | b'-'
            | b'.'
            | b'_'
            | b'~'
            // Percent-encoding
            | b'%'
            // gen-delims: ":" / "/" / "?" / "#" / "[" / "]" / "@"
            | b':'
            | b'/'
            | b'?'
            | b'#'
            | b'['
            | b']'
            | b'@'
            // sub-delims: "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
        );
        i += 1;
    }

    table
};

// RFC 9110 Section 5.5: Valid Header Field Value bytes ('field-content')
// Allows 'HTAB' ('0x09'), 'SP' ('0x20'), 'VCHAR' ('0x21..=0x7E') and 'obs-text' ('0x80..=0xFF')
// Rejects NUL ('0x00'), CR ('\r'), LF ('\n'), DEL ('0x7F'). and other C0 controls

const HEADER_VALUE_TABLE: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0;
    while i < 256 {
        let b = i as u8;
        table[i] = matches!(b, b'\t' | b' ' | 0x21..=0x7E | 0x80..=0xFF);
        i += 1;
    }

    table
};

// returns true if 'b' is a valid HTTP token character (tchar)
#[inline]
pub const fn is_tchar(b: u8) -> bool {
    TCHAR_TABLE[b as usize]
}

// returns true if 'b' is a valid Request-Target character
#[inline]
pub const fn is_uri_char(b: u8) -> bool {
    URI_CHAR_TABLE[b as usize]
}

// returns true if 'b' is allowed inside an HTTP header field value
#[inline]
pub const fn is_header_value_byte(b: u8) -> bool {
    HEADER_VALUE_TABLE[b as usize]
}

// Returns 'true' if 'b' is RFC 9110 Optional whitespaces ('SP' or 'HTAB')
// Note: Vertical table ('0x0B') and Form feed ('0x0C') are not valid HTTP OWS
#[inline]
pub const fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

// strips trailing optional whitespaces ('SP' and 'HTAB') from a byte slice
#[inline]
pub fn trim_trailing_ows(mut bytes: &[u8]) -> &[u8] {
    while let [rest @ .., last] = bytes {
        if is_ows(*last) {
            bytes = rest;
        } else {
            break;
        }
    }

    bytes
}

// a zero-copy byte reader that tracks the current byte offset into an input buffer
//
// a zero-copy byte cursor is a way of parsing data where you move through an existing byte buffer
// using an index, without copying the bytes into new buffers or strings
//
// A cursor maintains a position (pos) indicating where you are currently reading.
#[derive(Debug, Clone, Copy)]
pub struct Cursor<'buf> {
    buf: &'buf [u8],
    pos: usize,
}

impl<'buf> Cursor<'buf> {
    // new cursor starting at offset 0 of buf
    #[inline]
    pub const fn new(buf: &'buf [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    // creates new cursor starting at a specific byte offset
    #[inline]
    pub const fn with_offset(buf: &'buf [u8], pos: usize) -> Self {
        Self { buf, pos }
    }

    // return the current byte offset from the start of the buffer
    #[inline]
    pub const fn pos(&self) -> usize {
        self.pos
    }

    // returns the total length of the buffer
    #[inline]
    pub const fn len(&self) -> usize {
        self.buf.len()
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    #[inline]
    pub fn remaining(&self) -> &'buf [u8] {
        &self.buf[self.pos..]
    }

    #[inline]
    pub fn slice_from(&self, start: usize) -> &'buf [u8] {
        &self.buf[start..self.pos]
    }

    #[inline]
    pub fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    // .checked_add: normally adding two usize values can overflow. In debug builds, this can panic.
    // checked_add performs the addition safely. Its return type is Option<usize>
    //
    //  .and_then: operates on an Option. It does two things:
    //      - if the previous result is Some(value), it passes the value to the closure
    //      - if the previous result is None, it immediately returns None
    //
    // .get(idx): safely accesses the element at index idx, unlike direct indexing (self.buf[idx]),
    // it doesnt panic if the index is out of the bounds. Its return type is Option<&u8> (when
    // applied on buf which has element of type u8)
    //
    // .copied(): converts Option<&u8> into Option<u8> by copying the value

    #[inline]
    pub fn peek_at(&self, ahead: usize) -> Option<u8> {
        self.pos
            .checked_add(ahead)
            .and_then(|idx| self.buf.get(idx).copied())
    }

    #[inline]
    pub fn next_byte(&mut self) -> Option<u8> {
        let b = self.buf.get(self.pos).copied()?;
        self.pos += 1;
        Some(b)
    }

    #[inline]
    pub fn advance(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.buf.len());
    }

    #[inline]
    pub fn skip_ows(&mut self) {
        while let Some(b) = self.peek() {
            if is_ows(b) {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    // Consumes an HTTP line ending ('\r\n', or bare '\n' if 'allow_bare_lf' is enabled)
    // - If the buffer ends before the line ending is complete (including right after '\r') returns
    // 'Ok(Status::Partial)' without advancing the cursor.
    //
    // - If a bare '\r' is followed by any byte other than '\n', or bare '\n' is seen when
    // 'allow_bare_lf == false', returns 'Err(PareseError::InvalidLineEnding)'
    //
    // CR: Carriage Return (\r)
    // LF: Line feed (\n)
    #[inline]
    pub fn consume_newline(&mut self, allow_bare_lf: bool) -> ParseResult<()> {
        match self.peek() {
            None => Ok(Status::Partial),
            Some(b'\r') => match self.peek_at(1) {
                None => Ok(Status::Partial),
                Some(b'\n') => {
                    self.pos += 2;
                    Ok(Status::Complete {
                        value: (),
                        consumed: 2,
                    })
                }
                Some(_) => Err(ParseError::InvalidLineEnding { offset: self.pos }),
            },
            Some(b'\n') if allow_bare_lf => {
                self.pos += 1;
                Ok(Status::Complete {
                    value: (),
                    consumed: 1,
                })
            }
            Some(_) => Err(ParseError::InvalidLineEnding { offset: self.pos }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tchar_lookup_matches() {
        for b in b"GETPOSTDELETE!#$%'*+-.^_`|~0123456789" {
            assert!(is_tchar(*b), "expected 0x{b:02X} to be valid tchar");
        }

        for b in b" \t\r\n:()/\"<>?@[\\]{}\0\x7F\x80\xFF" {
            assert!(!is_tchar(*b), "expected 0x{b:02X} to be rejected as tchar");
        }
    }

    #[test]
    fn uri_char_lookup_rejects_controls_and_injection_bytes() {
        for b in b"/api/v1/items?filter=a%20b&sort=asc#section-1" {
            assert!(is_uri_char(*b), "expected 0x{b:02X} to be valid URI byte");
        }

        for b in b" \t\r\n\"<>\\^`{|}\0\x7F\x80" {
            assert!(
                !is_uri_char(*b),
                "expected 0x{b:02X} to be rejected in request-target"
            );
        }
    }

    #[test]
    fn header_value_table_allows_obs_text_and_rejects_ctls() {
        assert!(is_header_value_byte(b' '));
        assert!(is_header_value_byte(b'\t'));
        assert!(is_header_value_byte(b'~'));
        assert!(is_header_value_byte(0x80)); // obs-text
        assert!(is_header_value_byte(0xFF)); // obs-text

        // Forbidden control characters
        assert!(!is_header_value_byte(0x00)); // NULL
        assert!(!is_header_value_byte(b'\r'));
        assert!(!is_header_value_byte(b'\n'));
        assert!(!is_header_value_byte(0x0B)); // Vertical Tab
        assert!(!is_header_value_byte(0x7F)); // DEL
    }

    #[test]
    fn consume_newline_handles_split_crlf_and_bare_lf() {
        // 1. clean CRLF
        let mut cursor = Cursor::new(b"\r\nrest");
        assert_eq!(
            cursor.consume_newline(false),
            Ok(Status::Complete {
                value: (),
                consumed: 2
            })
        );
        assert_eq!(cursor.pos(), 2);
        assert_eq!(cursor.remaining(), b"rest");

        // 2. Packet split right after '\r' -> Partial, cursor stays at 0
        let mut split_cursor = Cursor::new(b"\r");
        assert_eq!(split_cursor.consume_newline(false), Ok(Status::Partial));
        assert_eq!(split_cursor.pos(), 0);

        // 3. Bare '\r' followed by non-'\n' -> Error at exact offset
        let mut bad_cr = Cursor::with_offset(b"GET \rX", 4);
        assert_eq!(
            bad_cr.consume_newline(false),
            Err(ParseError::InvalidLineEnding { offset: 4 })
        );

        // 4. Bare '\n' rejected in strict mode, accepted when allow_bare_lf = true
        let mut bare_lf = Cursor::new(b"\n");
        assert_eq!(
            bare_lf.consume_newline(false),
            Err(ParseError::InvalidLineEnding { offset: 0 })
        );
        assert_eq!(
            bare_lf.consume_newline(true),
            Ok(Status::Complete {
                value: (),
                consumed: 1
            })
        );
    }

    #[test]
    fn trim_trailing_ows_preserves_inner_whitespaces() {
        let raw = b"text/html; charset=utf-8 \t ";
        assert_eq!(trim_trailing_ows(raw), b"text/html; charset=utf-8");
    }
}
