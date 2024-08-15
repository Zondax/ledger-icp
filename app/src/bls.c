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
#include "tx.h"
#include "rslib.h"
#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX)
#include "cx.h"
#include "nvdata.h"
#endif

// define root key with default value
uint8_t alternative_root_key[ROOT_KEY_LEN] = {0};

uint8_t *bls_root_key() {
    static uint8_t root_key[ROOT_KEY_LEN];
    static bool initialized = false;

    // Official canister pubkey in charge of verifying certificates
    // FIXME: This is not the right key
    if (!initialized) {
        const uint8_t init_key[ROOT_KEY_LEN] = {
            0x7A, 0xB3, 0xC1, 0x2F, 0x89, 0x45, 0xE0, 0x6D,
            0x9C, 0x1A, 0x8E, 0xF2, 0x37, 0x5B, 0xD4, 0x0F,
            0x62, 0xA9, 0x4D, 0x83, 0xC7, 0x1E, 0xB5, 0x6F,
            0x3A, 0x9D, 0x2C, 0x7F, 0xE8, 0x51, 0x0B, 0x94,
            0xD6, 0x3E, 0x8A, 0xF1, 0x5C, 0x27, 0xB0, 0x69,
            0x14, 0xA2, 0x7D, 0xC5, 0x9F, 0x4B, 0xE3, 0x58,
            0x0D, 0x86, 0x2A, 0xF9, 0x71, 0xBC, 0x3F, 0xE5,
            0x9A, 0x42, 0xD8, 0x1B, 0x67, 0xC0, 0x5F, 0xA3,
            0x8D, 0x25, 0xF6, 0x4E, 0xB7, 0x30, 0x99, 0x6C,
            0x13, 0xA8, 0x5D, 0xE1, 0x7C, 0x2E, 0xB9, 0x40,
            0xF4, 0x8B, 0x36, 0xD2, 0x0A, 0x75, 0xC9, 0x1F,
            0xE7, 0x53, 0x9B, 0x20, 0x6A, 0xF7, 0x4C, 0xD1
        };
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

    //parse consent
    consent_request_t out_request = {0};
    if (parse_consent_request(message, messageLength, &out_request) != parser_ok) {
        return zxerr_unknown;
    }

    // Save consent request
    CHECK_ZXERR(save_consent_request(&out_request));

    // Save App State
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

    //parse canister call
    // the hash to be signed would be also computed in this step
    // and stored as part of this type in nvm memory
    canister_call_t out_request = {0};
    if (parse_canister_call_request(message, messageLength, &out_request) != parser_ok) {
        return zxerr_unknown;
    }

    // Save canister call request
    CHECK_ZXERR(save_canister_call(&out_request));

    // Save App State
    set_state(CERT_STATE_PROCESSED_CANISTER_CALL_REQUEST);

    return zxerr_ok;
}

zxerr_t bls_saveRootKey(void) {
    // Test App State
    if (get_state() != CERT_STATE_PROCESSED_CANISTER_CALL_REQUEST) {
        return zxerr_unknown;
    }

    // Get Buffer witn root key
    const uint8_t *message = tx_get_buffer();
    const uint16_t messageLength = tx_get_buffer_length();

    if(messageLength != ROOT_KEY_LEN) {
        return zxerr_invalid_crypto_settings;
    }
    // Save root key from user overwriting default value
    MEMCPY(alternative_root_key, message, ROOT_KEY_LEN);

    // Save App State
    set_state(CERT_STATE_PROCESSED_ROOT_KEY);

    return zxerr_ok;
}

zxerr_t bls_verify(parsed_obj_t *cert) {
    // Two possible states, we saved a root key from user, or there was no root key overwriting
    if ( get_state() != CERT_STATE_PROCESSED_ROOT_KEY && get_state() != CERT_STATE_PROCESSED_CANISTER_CALL_REQUEST) {
        return zxerr_unknown;
    }

    // Use official canister root_key by default
    uint8_t *pubkey = bls_root_key();

    // If an alternative root_key was processed
    // then, use it
    if (get_state() == CERT_STATE_PROCESSED_ROOT_KEY) {
        zemu_log("Using root key from user\n");
        pubkey = alternative_root_key;
    }

    // Get Buffer witn certificate
    const uint8_t *certificate = tx_get_buffer();
    const uint16_t certificate_len = tx_get_buffer_length();

    consent_request_t *consent_request = get_consent_request();
    canister_call_t *call_request = get_canister_call();

    //Go into verifications
    if(parser_verify_certificate(certificate, certificate_len, pubkey, call_request, consent_request) != parser_ok) {
        return zxerr_invalid_crypto_settings;
    }

    // Save App State
    // TODO: Set state to CERT_STATE_SIGN
    // and clear any other data
    set_state(CERT_STATE_INITIAL);

    return zxerr_ok;
}
#endif
