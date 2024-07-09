#[repr(u32)]
pub enum ParserError {
    Ok = 0,
    CborError = 7,
    InvalidLabel = 27,
    InvalidDelegation = 28,
    InvalidCert = 29,
}
