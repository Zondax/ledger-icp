use crate::{constants::PRINCIPAL_MAX_LEN, Principal};

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

// Get device principal, this is safe to use
// because we ensure proper buffer sizes is passed to C
pub fn device_principal() -> Principal {
    let mut data = [0u8; PRINCIPAL_MAX_LEN];
    let mut response_len = 0;

    unsafe {
        c_fill_principal(data.as_mut_ptr(), data.len() as _, &mut response_len);
    }

    Principal::new(&data[..response_len as usize]).unwrap()
}
