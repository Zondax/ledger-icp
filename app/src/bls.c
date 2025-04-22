/*******************************************************************************
 *   (c) 2018 -2024 Zondax AG
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

#if defined(BLS_SIGNATURE)
#include "bls.h"

#include "nvdata.h"
#include "rslib.h"
#include "tx.h"
#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX)
#include "cx.h"
#endif

uint8_t *bls_root_key() {
    static uint8_t root_key[ROOT_KEY_LEN];
    static bool initialized = false;

    // Official canister pubkey to use for verifying certificates
    if (!initialized) {
        const uint8_t init_key[ROOT_KEY_LEN] = {
            0x81, 0x4C, 0x0E, 0x6E, 0xC7, 0x1F, 0xAB, 0x58, 0x3B, 0x08, 0xBD, 0x81, 0x37, 0x3C, 0x25, 0x5C,
            0x3C, 0x37, 0x1B, 0x2E, 0x84, 0x86, 0x3C, 0x98, 0xA4, 0xF1, 0xE0, 0x8B, 0x74, 0x23, 0x5D, 0x14,
            0xFB, 0x5D, 0x9C, 0x0C, 0xD5, 0x46, 0xD9, 0x68, 0x5F, 0x91, 0x3A, 0x0C, 0x0B, 0x2C, 0xC5, 0x34,
            0x15, 0x83, 0xBF, 0x4B, 0x43, 0x92, 0xE4, 0x67, 0xDB, 0x96, 0xD6, 0x5B, 0x9B, 0xB4, 0xCB, 0x71,
            0x71, 0x12, 0xF8, 0x47, 0x2E, 0x0D, 0x5A, 0x4D, 0x14, 0x50, 0x5F, 0xFD, 0x74, 0x84, 0xB0, 0x12,
            0x91, 0x09, 0x1C, 0x5F, 0x87, 0xB9, 0x88, 0x83, 0x46, 0x3F, 0x98, 0x09, 0x1A, 0x0B, 0xAA, 0xAE};
        memcpy(root_key, init_key, ROOT_KEY_LEN);
        initialized = true;
    }

    return root_key;
}

zxerr_t bls_saveConsentRequest(void) {
    // Test App State
    if (get_state() != CERT_STATE_INITIAL) {
        return zxerr_unknown;
    }

    // Get Buffer with consent call request
    const uint8_t *message = tx_get_buffer();
    const uint16_t messageLength = tx_get_buffer_length();

    // parse consent
    if (rs_parse_consent_request(message, messageLength) != parser_ok) {
        return zxerr_unknown;
    }

    // Save App State
    zemu_log_stack("bls_saveConsentRequest completed");
    set_state(CERT_STATE_PROCESSED_CONSENT_REQUEST);

    return zxerr_ok;
}

zxerr_t bls_saveCanisterCall(void) {
    // Test App State
    if (get_state() != CERT_STATE_PROCESSED_CONSENT_REQUEST) {
        return zxerr_unknown;
    }

    // Get Buffer with canister call request
    const uint8_t *message = tx_get_buffer();
    const uint16_t messageLength = tx_get_buffer_length();

    // parse canister call
    //  the hash to be signed would be also computed in this step
    //  and stored as part of this type in memory
    if (rs_parse_canister_call_request(message, messageLength) != parser_ok) {
        return zxerr_unknown;
    }

    // Save App State
    set_state(CERT_STATE_PROCESSED_CANISTER_CALL_REQUEST);

    return zxerr_ok;
}

zxerr_t bls_verify() {
    zemu_log_stack("bls_verify");
    // Two possible states, we saved a root key from user, or there was no root
    // key overwriting
    if (get_state() != CERT_STATE_PROCESSED_CANISTER_CALL_REQUEST) {
        return zxerr_unknown;
    }

    // Use official canister root_key by default
    uint8_t *pubkey = bls_root_key();

    // Get Buffer with certificate
    const uint8_t *certificate = tx_get_buffer();
    const uint16_t certificate_len = tx_get_buffer_length();

    // Go into verifications
    zemu_log_stack("rs_verify_cert");
    if (rs_verify_certificate(certificate, certificate_len, pubkey) != parser_ok) {
        return zxerr_invalid_crypto_settings;
    }

    // Reset App State
    state_reset();

    return zxerr_ok;
}

void reset_bls_state() {
    rs_clear_resources();
    state_reset();
}
#endif
