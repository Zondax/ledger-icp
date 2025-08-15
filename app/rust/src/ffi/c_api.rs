use crate::{constants::PRINCIPAL_MAX_LEN, error::ParserError, Principal};

#[cfg(not(test))]
extern "C" {
    fn c_fill_principal(output: *mut u8, output_len: u16, response_len: *mut u16) -> i8;
}

#[cfg(test)]
fn c_fill_principal(output: *mut u8, output_len: u16, response_len: *mut u16) -> i8 {
    unsafe {
        // The default principal using our testing mnemonic
        const SENDER: &[u8] = &[
            25, 170, 61, 66, 192, 72, 221, 125, 20, 240, 207, 160, 223, 105, 161, 193, 56, 23, 128,
            246, 233, 161, 55, 171, 170, 106, 130, 227, 2,
        ];

        let output = core::slice::from_raw_parts_mut(output, output_len as usize);

        *response_len = SENDER.len() as _;

        if output_len as usize >= SENDER.len() {
            output.copy_from_slice(SENDER);
            0
        } else {
            -1
        }
    }
}

// Get device principal with proper error handling
pub fn device_principal() -> Result<Principal, ParserError> {
    let mut data = [0u8; PRINCIPAL_MAX_LEN];
    let mut response_len = 0u16;

    let buffer_len = data.len();
    if buffer_len > u16::MAX as usize {
        return Err(ParserError::UnexpectedError);
    }
    let rc = unsafe { c_fill_principal(data.as_mut_ptr(), buffer_len as u16, &mut response_len) };
    
    // Check return code for success
    if rc != 0 {
        return Err(ParserError::UnexpectedError);
    }
    
    // Validate response_len is within valid range (1..=PRINCIPAL_MAX_LEN)
    let response_len_usize = response_len as usize;
    if response_len_usize == 0 || response_len_usize > PRINCIPAL_MAX_LEN {
        return Err(ParserError::UnexpectedBufferEnd);
    }
    
    // Use Principal::new and propagate any error
    Principal::new(&data[..response_len_usize])
        .map_err(|_| ParserError::UnexpectedValue)
}
