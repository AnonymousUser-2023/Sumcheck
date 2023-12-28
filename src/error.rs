use ark_std::{fmt, string::String};

use core::fmt::Formatter;

/// Error type for this crate
#[derive(fmt::Debug)]
pub enum Error {
    /// protocol rejects proof
    Reject(Option<String>),
    /// IO Error
    IOError,
    /// Catch-all error for various other situations
    OtherError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Self::OtherError(s) = self {
            f.write_str(s)
        } else {
            f.write_fmt(format_args!("{self:?}"))
        }
    }
}

impl ark_std::error::Error for Error {}

impl From<ark_std::io::Error> for Error {
    fn from(_: ark_std::io::Error) -> Self {
        Self::IOError
    }
}