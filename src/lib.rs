#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, unused_must_use)]

pub mod cursor;
pub mod error;
pub mod start_line;

// pub mod error; -> Exposes the module publicly
// use crate::error::ParseError -> Imports the tyep into the current scope
// pub use crate::error::ParseError -> Re-exports the type publicly
//
// What does pub mod error actually do ?
// 1. Declares error as module
// 2. Makes that module publicly accessible outside your crate
// 3. Allows access to its publicly exposed items, subject to their visibility
//
// for example, another crate can write:
//
// use http_parser::error::ParseError;
// let err = ParseError::new();

pub use error::{ParseError, ParseResult, Status};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParserConfig {
    pub max_method_len: usize, // max len of the HTTP method in bytes, default: 16
    pub max_uri_len: usize,    // max len of the request-target/ uri in bytes, default: 8192
    pub max_header_block_bytes: usize, // max total bytes for the start-line + all headers, default: 65536
    pub allow_bare_lf: bool, // whether to allow bare '\n' (LF) without a preceding '\r' (CR)
                             // RFC 9112 recommends rejecting bare LF by default, (false)
}

// Default is a standard library trait that defines a default value for a type.
// For ex: i32 implements Default, so you can get its default value:
//         let x = i32::default();
//         println!("{x}"); -> 0
impl Default for ParserConfig {
    fn default() -> Self {
        Self {
            max_method_len: 16,
            max_uri_len: 8 * 1024,
            max_header_block_bytes: 64 * 1024,
            allow_bare_lf: false,
        }
    }
}

impl ParserConfig {
    // creates a new default strict configuration
    #[inline]
    pub const fn strict() -> Self {
        Self {
            max_method_len: 16,
            max_uri_len: 8 * 1024,
            max_header_block_bytes: 64 * 1024,
            allow_bare_lf: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping_preserves_consumed_bytes() {
        let status: Status<&str> = Status::Complete {
            value: "GET",
            consumed: 4,
        };

        assert!(status.is_complete());
        assert!(!status.is_partial());

        let mapped = status.map(|method| method.len());
        assert_eq!(
            mapped,
            Status::Complete {
                value: 3,
                consumed: 4
            }
        );
    }

    #[test]
    fn partial_status_propagates_cleanly() {
        let status: Status<&str> = Status::Partial;
        assert!(status.is_partial());
        assert_eq!(status.map(|s| s.len()), Status::Partial);
    }

    #[test]
    fn error_formatting_includes_offset_and_hex() {
        let err = ParseError::InvalidTokenByte {
            offset: 12,
            byte: 0x00,
        };

        assert_eq!(err.to_string(), "invalid token byte 0x00 at byte offset 12");
    }
}
