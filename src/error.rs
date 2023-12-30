use nom::error::ErrorKind;
use nom::error::FromExternalError;
use nom::error::ParseError as NomParseError;
use system_error::OsCode;
use thiserror::Error;
use system_error::Error as SystemError;
use system_error::KernelCode;
use anyhow::Result as AnyhowResult;

pub type Result<T> = AnyhowResult<T, anyhow::Error>;

#[derive(Error, Debug)]
pub enum Error<I = &'static [u8]> {
  #[error("Expected length greater than 0")]
  ZeroLength,
  #[error("Dynasm error")]
  DynasmError,
  #[error("Invalid UTF-8 data for string")]
  InvalidUtf8Data,
  #[error("Missing segment (segment name: {0:?})")]
  MissingSegment(String),
  #[error("Parsing error: {0:?}")]
  Parse(Parse<I>),
  #[error("{0:?}")]
  System(SystemError),
}

impl Error<()> {
  pub const fn zero_length() -> Self {
    Self::ZeroLength
  }

  pub const fn dynasm_error() -> Self {
    Self::DynasmError
  }

  pub const fn invalid_utf8_data() -> Self {
    Self::InvalidUtf8Data
  }

  pub fn missing_segment(segment: &str) -> Self {
    Self::MissingSegment(segment.to_string())
  }

  pub fn from_kernel_error(code: KernelCode) -> Self {
    Self::System(SystemError::from_raw_kernel_error(code))
  }

  pub fn from_last_os_error() -> Self {
    Self::System(SystemError::last_os_error())
  }

  pub fn from_os_error(code: OsCode) -> Self {
    Self::System(SystemError::from_raw_os_error(code))
  }
}

impl<I> From<nom::Err<nom::error::Error<I>>> for Error<I> {
    fn from(value: nom::Err<nom::error::Error<I>>) -> Self {
        todo!()
    }
}

#[derive(Debug)]
pub enum Parse<I> {
    InvalidUtf8Data,
    Nom(I, ErrorKind),
}

impl<I> NomParseError<I> for Parse<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        Self::Nom(input, kind)
    }

    fn append(_: I, _: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<I, E> FromExternalError<I, E> for Parse<I> {
    fn from_external_error(input: I, kind: ErrorKind, _: E) -> Self {
        Self::Nom(input, kind)
    }
}
