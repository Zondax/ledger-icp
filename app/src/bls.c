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

#include "bls.h"
#include "tx.h"
#include "rslib.h"
#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX)
#include "cx.h"
#endif
// define root key with default value
uint8_t root_key[ROOT_KEY_LEN] = {0};

zxerr_t bls_saveConsentRequest(void) {
    // Test App State
    if (get_state() != STATE_INITIAL) {
        return zxerr_unknown;
    }

    // Get Buffer with consent call request
    const uint8_t *message = tx_get_buffer();
    const uint16_t messageLength = tx_get_buffer_length();

    //parse consent
    consent_request_t out_request = {0};
    if (!parse_consent_request(message, messageLength, &out_request)) {
        return zxerr_unknown;
    }

    // Save consent request
    CHECK_ZXERR(save_consent_request(&out_request));

    // Save App State
    set_state(STATE_PROCESSED_CONSENT_REQUEST);

    return zxerr_ok;
}

zxerr_t bls_saveCanisterCall(void) {
    // Test App State
    if (get_state() != STATE_PROCESSED_CONSENT_REQUEST) {
        return zxerr_unknown;
    }

    // Get Buffer with canister call request
    const uint8_t *message = tx_get_buffer();
    const uint16_t messageLength = tx_get_buffer_length();

    uint8_t call_hash[CX_SHA256_SIZE] = {0};
#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX)
    cx_hash_sha256(message, messageLength, call_hash, CX_SHA256_SIZE);
#endif
    // Save hash
    CHECK_ZXERR(save_hash_to_sign(call_hash));

    //parse canister call
    canister_call_t out_request = {0};
    if (!parse_canister_call_request(message, messageLength, &out_request)) {
        return zxerr_unknown;
    }

    // Save canister call request
    CHECK_ZXERR(save_canister_call(&out_request));

    // Save App State
    set_state(STATE_PROCESSED_CANISTER_CALL_REQUEST);

    return zxerr_ok;
}

zxerr_t bls_saveRootKey(void) {
    // Test App State
    if (get_state() != STATE_PROCESSED_CANISTER_CALL_REQUEST) {
        return zxerr_unknown;
    }

    // Get Buffer witn root key
    const uint8_t *message = tx_get_buffer();
    const uint16_t messageLength = tx_get_buffer_length();

    if(messageLength != ROOT_KEY_LEN) {
        return zxerr_invalid_crypto_settings;
    }
    // Save root key from user overwrite default value
    MEMCPY(root_key, message, ROOT_KEY_LEN);

    // Save App State
    set_state(STATE_PROCESSED_ROOT_KEY);

    return zxerr_ok;
}

zxerr_t bls_sign(void) {
    // Two possible states, we saved a root key from user, or there was no root key overwriting
    if ( get_state() != STATE_PROCESSED_ROOT_KEY && get_state() != STATE_PROCESSED_ROOT_KEY) {
        return zxerr_unknown;
    }

    // Get Buffer witn root key
    const uint8_t *certificate = tx_get_buffer();
    const uint16_t CertificateLength = tx_get_buffer_length();

    // Go into parsing call rust code ?

    // Save App State
    set_state(STATE_INITIAL);

    return zxerr_ok;
}
