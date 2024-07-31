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
#include "nvdata.h"
#include "tx.h"

zxerr_t bls_saveConsentRequest(void) {
    // Test App State
    if (get_state() != STATE_INITIAL) {
        return zxerr_unknown;
    }

    // Get Buffer with consent call request
    const uint8_t *message = tx_get_buffer();
    const uint16_t messageLength = tx_get_buffer_length();

    // Save consent Call request
    CHECK_ZXERR(save_consent_request(message, messageLength));

    // Save App State
    set_state(STATE_PROCESSED_CONSENT_REQUEST);

    return zxerr_ok;
}

zxerr_t bls_saveCanisterCall(void) {
    // Test App State
    if (get_state() != STATE_PROCESSED_CONSENT_REQUEST) {
        return zxerr_unknown;
    }

    // Get Buffer witn canister call request
    const uint8_t *message = tx_get_buffer();
    const uint16_t messageLength = tx_get_buffer_length();

    // Save canister call request
    CHECK_ZXERR(save_canister_call(message, messageLength));

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

    // Save root key
    CHECK_ZXERR(save_root_key(message, messageLength));

    // Save App State
    set_state(STATE_PROCESSED_ROOT_KEY);

    return zxerr_ok;
}

zxerr_t bls_sign(void) {
    // Test App State
    if (get_state() != STATE_PROCESSED_ROOT_KEY) {
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
