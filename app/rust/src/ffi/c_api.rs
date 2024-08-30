use crate::{constants::PRINCIPAL_MAX_LEN, Principal};

#[cfg(not(test))]
extern "C" {
    // int c_fill_principal(uint8_t *output, uint16_t output_len, uint16_t *response_len) {
    fn c_fill_principal(output: *mut u8, output_len: u16, response_len: *mut u16) -> i8;
}

#[cfg(test)]
fn c_fill_principal(output: *mut u8, output_len: u16, response_len: *mut u16) -> i8 {
    unsafe {
        let output = core::slice::from_raw_parts_mut(output, output_len as usize);
        let response_len = &mut *response_len;

        output.iter_mut().for_each(|x| *x = 1);
        *response_len = output_len;
    }
    0
}

// Get device principal, this is save to use
// because we ensure proper buffer sizes is passed to C
pub fn device_principal() -> Principal {
    let mut data = [0u8; PRINCIPAL_MAX_LEN];
    let mut response_len = 0;

    unsafe {
        c_fill_principal(data.as_mut_ptr(), data.len() as _, &mut response_len);
    }

    Principal::new(&data[..response_len as usize]).unwrap()
}
