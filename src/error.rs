use base64;
use std::{array, fmt};

#[derive(Debug)]
pub enum Error {
    OldWPFormat,
    InvalidId(String),
    InvalidPasses(Option<char>),
    DecodeError(base64::DecodeError),
    CopyDecoded(std::array::TryFromSliceError),
}

impl std::error::Error for Error {}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Self::DecodeError(e)
    }
}

impl From<array::TryFromSliceError> for Error {
    fn from(e: array::TryFromSliceError) -> Self {
        Self::CopyDecoded(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::OldWPFormat => write!(f, "Old WP one-pass md5 encoding not supported"),
            Error::InvalidPasses(c) => write!(f, "Found invalid character for passes: {:?}", c),
            Error::InvalidId(s) => write!(f, "Found invalid ID set in crypto: {:?}", s),
            Error::DecodeError(e) => e.fmt(f),
            Error::CopyDecoded(e) => e.fmt(f),
        }
    }
}
