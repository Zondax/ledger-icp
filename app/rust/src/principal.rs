use crate::{
    constants::{DEFAULT_SENDER, PRINCIPAL_MAX_LEN},
    error::ParserError,
};

pub struct Principal {
    data: [u8; PRINCIPAL_MAX_LEN],
    len: usize,
}

impl Principal {
    pub fn new(principal: &[u8]) -> Result<Self, ParserError> {
        let mut data = [0u8; PRINCIPAL_MAX_LEN];
        if principal.len() > PRINCIPAL_MAX_LEN {
            return Err(ParserError::UnexpectedValue);
        }

        data[..principal.len()].copy_from_slice(principal);

        Ok(Self {
            data,
            len: principal.len(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    pub fn is_default(&self) -> bool {
        self.len == 1 && self.data[0] == DEFAULT_SENDER
    }
}

impl AsRef<[u8]> for Principal {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl PartialEq<Principal> for Principal {
    fn eq(&self, other: &Principal) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}
