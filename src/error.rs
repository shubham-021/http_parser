use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status<T> {
    Complete { value: T, consumed: usize },
    Partial,
}

impl<T> Status<T> {
    #[inline]
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }

    #[inline]
    pub const fn is_partial(&self) -> bool {
        matches!(self, Self::Partial)
    }

    #[inline]
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Status<U> {
        match self {
            Self::Complete { value, consumed } => Status::Complete {
                value: f(value),
                consumed,
            },
            Self::Partial => Status::Partial,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    InvalidLineEnding { offset: usize }, // expected \r\n (CRLF) but encountered a bare \n or invalid byte after '\r'
    InvalidTokenByte { offset: usize, byte: u8 }, // encountered a byte that is not a valid HTTP token character
    InvalidMethod { offset: usize },              // the HTTP method is empty or exceeds the max len
    InvalidRequestTarget { offset: usize }, // the req target is empty, contains control/ whitespaces bytes or exceeds the max URI len
    InvalidVersion { offset: usize },       // invalid HTTP version
    InvalidStatusCode { offset: usize },    // invalid status code
    InvalidHeaderName { offset: usize }, // a header line is missing the colon separator or has an empty field name
    WhitespaceBeforeColon { offset: usize }, // whitespaces before colon is strictly forbidden to prevent req smuggling
    InvalidHeaderValue { offset: usize, byte: u8 }, // a header value contains forbidden control characters (such as NUL '\0', bare '\r' or non printable ASCII )
    ObsFoldDetected { offset: usize }, // Obsolete line folding (`obs-fold`: a header line starting with SP or HTAB)
    TooManyHeaders { max_allowed: usize }, // the number of header exceeded the caller's slice capacity
    HeaderBlockTooLarge { max_allowed: usize }, // total byte size of the start line plus headers exceeded the security limit
    InvalidContentLength { offset: usize },
    // Both `Transfer-Encoding` and `Content-Length` are present in the same message, or `Transfer-Encoding` is malformed
    ConflictingFraming,
    InvalidChunk { offset: usize }, // a chunked transfer-coding size line or trailer is malformed
}

// impl fmt::Display means we are implementing Rust's Display trait for our type, so it can be formatted as human readable text
// For ex:
//      use std::fmt;
//
//      struct User {
//          name: String;
//          age: u8;
//      }
//
//      impl fmt::Display for User {
//          fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//              write!(f, "{} is {} years old", self.name, self.age)
//          }
//      }
//
//      let user = User {
//          name: String::from("Alice"),
//          age: 25,
//      }
//
//      println!("{}", user); -> will print: Alice is 25 years old
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLineEnding { offset } => {
                write!(f, "invalid CRLF line ending at byte offset {offset}")
            }
            // {:02X} is a Rust formatting specifier that displays a u8 as uppercase hexadecimal,
            // padded to at least 2 digits with leading zero
            //
            // : -> begins the format specifier
            // 0 -> pad with zeroes
            // 2 -> min width of 2 characters
            // X -> uppercase hexadecimal
            //
            // for ex:
            //  println!("{:02X}", 0); -> 00
            //  println!("{:02X}", 15); -> 0F
            //  println!("{:02X}", 255); -> FF
            Self::InvalidTokenByte { offset, byte } => {
                write!(f, "invalid token byte 0x{byte:02X} at byte offset {offset}")
            }
            Self::InvalidMethod { offset } => {
                write!(
                    f,
                    "invalid or oversized HTTP method at byte offset {offset}"
                )
            }
            Self::InvalidRequestTarget { offset } => {
                write!(
                    f,
                    "invalid or oversized request target at byte offset {offset}"
                )
            }
            Self::InvalidVersion { offset } => {
                write!(
                    f,
                    "unsupported or malformed HTTP version at byte offset {offset}"
                )
            }
            Self::InvalidStatusCode { offset } => {
                write!(
                    f,
                    "invalid HTTP response status code at byte offset {offset}"
                )
            }
            Self::InvalidHeaderName { offset } => {
                write!(f, "invalid or empty header name at byte offset {offset}")
            }
            Self::WhitespaceBeforeColon { offset } => {
                write!(
                    f,
                    "forbidden whitespace before colon in header at byte offset {offset}"
                )
            }
            Self::InvalidHeaderValue { offset, byte } => {
                write!(
                    f,
                    "invalid byte 0x{byte:02X} in header value at byte offset {offset}"
                )
            }
            Self::ObsFoldDetected { offset } => {
                write!(
                    f,
                    "obsolete line folding (obs-fold) rejected at byte offset {offset}"
                )
            }
            Self::TooManyHeaders { max_allowed } => {
                write!(f, "header count exceeded maximum limit of {max_allowed}")
            }
            Self::HeaderBlockTooLarge { max_allowed } => {
                write!(
                    f,
                    "header block byte size exceeded maximum limit of {max_allowed}"
                )
            }
            Self::InvalidContentLength { offset } => {
                write!(
                    f,
                    "malformed or conflicting Content-Length header at byte offset {offset}"
                )
            }
            Self::ConflictingFraming => {
                write!(
                    f,
                    "conflicting message framing: both Transfer-Encoding and Content-Length present"
                )
            }
            Self::InvalidChunk { offset } => {
                write!(
                    f,
                    "malformed chunked transfer encoding at byte offset {offset}"
                )
            }
        }
    }
}

// this means we are implementing rust's standard Error trait for our ParseError enum
// why is the implementation body empty ?
// the error trait has default implementations for its methods, so you dont need to provide any
// methods if those defaults are sufficient
impl std::error::Error for ParseError {}

pub type ParseResult<T> = Result<Status<T>, ParseError>;
