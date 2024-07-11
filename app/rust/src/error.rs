use minicbor::decode::Error;

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

