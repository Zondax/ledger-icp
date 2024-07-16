/*******************************************************************************
*   (c) 2018 - 2024 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
use minicbor::decode::Error;
use nom::error::ErrorKind;

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "derive-debug", derive(Debug))]
pub enum ViewError {
    Unknown,
    NoData,
    Reject,
}

#[repr(u32)]
#[derive(Debug, PartialEq)]
pub enum ParserError {
    // Generic errors
    Ok = 0,
    NoData,
    InitContextEmpty,
    DisplayIdxOutOfRange,
    DisplayPageOutOfRange,
    UnexpectedError,
    NotImplemented,
    // Cbor
    CborUnexpected,
    CborUnexpectedEOF,
    CborNotCanonical,
    // Coin specific
    UnexpectedTxVersion,
    UnexpectedType,
    UnexpectedMethod,
    UnexpectedBufferEnd,
    UnexpectedValue,
    UnexpectedNumberItems,
    UnexpectedCharacters,
    UnexpectedField,
    ValueOutOfRange,
    InvalidAddress,
    // Context related errors
    ContextMismatch,
    ContextUnexpectedSize,
    ContextInvalidChars,
    ContextUnknownPrefix,
    // Required fields
    RequiredNonce,
    RequiredMethod,
    // Special codes
    TypeNotFound,
    InvalidLabel,
    InvalidDelegation,
    InvalidCertificate,
    InvalidTree,
    MiniCborError,
    RecursionLimitReached,
    InvalidTag,
    InvalidMsgMetadata,
    InvalidConsentMsg,
    InvalidUtf8,
    InvalidErrorResponse,
    InvalidResponseType,
}

// minicibor error provides a reach
// error context and also the index
// at which the error occurred,
// we can not handle it here, as ParserError
// is send to C callers
impl From<Error> for ParserError {
    fn from(_: Error) -> Self {
        Self::MiniCborError
    }
}

impl From<ErrorKind> for ParserError {
    fn from(err: ErrorKind) -> Self {
        match err {
            ErrorKind::Eof => ParserError::UnexpectedBufferEnd,
            ErrorKind::Permutation => ParserError::UnexpectedType,
            ErrorKind::TooLarge => ParserError::ValueOutOfRange,
            ErrorKind::Tag => ParserError::InvalidTag,
            _ => ParserError::UnexpectedError,
        }
    }
}

impl<I> nom::error::ParseError<I> for ParserError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        Self::from(kind)
    }

    // We don't have enough memory resources to use here an array with the last
    // N errors to be used as a backtrace, so that, we just propagate here the latest
    // reported error
    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}
impl From<ParserError> for nom::Err<ParserError> {
    fn from(error: ParserError) -> Self {
        nom::Err::Error(error)
    }
}

impl From<nom::Err<Self>> for ParserError {
    fn from(e: nom::Err<Self>) -> Self {
        match e {
            nom::Err::Error(e) => e,
            nom::Err::Failure(e) => e,
            nom::Err::Incomplete(_) => Self::UnexpectedBufferEnd,
        }
    }
}
