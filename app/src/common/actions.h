/*******************************************************************************
*   (c) 2019 Zondax GmbH
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
#pragma once

#include <stdint.h>
#include "crypto.h"
#include "tx.h"
#include "apdu_codes.h"
#include <os_io_seproxyhal.h>
#include "coin.h"
#include "zxerror.h"
// TODO: remove later
#include "rslib.h"

extern uint16_t action_addrResponseLen;

__Z_INLINE void app_sign() {
    uint16_t replyLen = 0;

    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    zxerr_t err = crypto_sign(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, &replyLen);

    if (err != zxerr_ok || replyLen == 0) {
        set_code(G_io_apdu_buffer, 0, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    } else {
        set_code(G_io_apdu_buffer, replyLen, APDU_CODE_OK);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, replyLen + 2);
    }
}

__Z_INLINE void app_sign_combined() {
    uint16_t replyLen = 0;

    zxerr_t err = crypto_sign_combined(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, &G_io_apdu_buffer[0],
                                       &G_io_apdu_buffer[32], &replyLen);

    if (err != zxerr_ok || replyLen == 0) {
        set_code(G_io_apdu_buffer, 0, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    } else {
        set_code(G_io_apdu_buffer, replyLen, APDU_CODE_OK);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, replyLen + 2);
    }
}

__Z_INLINE zxerr_t app_fill_address() {
    // Definition of the private key array
    uint8_t pvk[96] = {136, 241, 121, 119, 242, 65, 192, 110, 129, 119, 65, 77, 158, 13, 150, 144, 28, 235, 33, 208, 173, 221, 78, 19, 60, 123, 224, 65, 6, 100, 121, 203, 211, 101, 20, 169, 44, 125, 233, 145, 41, 91, 200, 233, 176, 158, 87, 101, 14, 124, 251, 239, 197, 63, 193, 29, 63, 169, 173, 27, 106, 244, 66, 35, 18, 131, 154, 12, 85, 56, 162, 240, 100, 125, 155, 115, 241, 135, 95, 223, 191, 44, 141, 140, 9, 202, 43, 152, 228, 117, 44, 46, 126, 194, 128, 157};
    // Definition of the message array
    uint8_t message[11] = {104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100};
    // Definition of the signature array
    uint8_t signature[48]= {139, 118, 54, 85, 203, 37, 178, 69, 140, 15, 123, 156, 250, 54, 205, 107, 22, 254, 170, 98, 234, 151, 252, 248, 245, 75, 211, 209, 237, 75, 135, 119, 53, 244, 174, 38, 241, 127, 34, 154, 2, 92, 174, 10, 73, 110, 128, 24};

    zemu_log_stack("\n calling verify_bls_sign!!!***\n");
    if (verify_bls_sign(message, 11, pvk, signature) == 1)
    {
        zemu_log_stack("\nverify_bls_sign_done!!!***\n");
    }
    else
    {
        zemu_log_stack("\nverify_bls_sign_failed!!!***\n");
    }

    CHECK_APP_CANARY();

    // Put data directly in the apdu buffer
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);

    action_addrResponseLen = 0;
    zxerr_t err = crypto_fillAddress(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, &action_addrResponseLen);

    if (err != zxerr_ok || action_addrResponseLen == 0) {
        THROW(APDU_CODE_EXECUTION_ERROR);
    }

    return zxerr_ok;
}

__Z_INLINE void app_reject() {
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    set_code(G_io_apdu_buffer, 0, APDU_CODE_COMMAND_NOT_ALLOWED);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

__Z_INLINE void app_reply_address() {
    set_code(G_io_apdu_buffer, action_addrResponseLen, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, action_addrResponseLen + 2);
}

__Z_INLINE void app_reply_error() {
    set_code(G_io_apdu_buffer, 0, APDU_CODE_DATA_INVALID);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}
