/*******************************************************************************
 *   (c) 2020-2024 Zondax AG
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

#include "nvdata.h"

#include "app_main.h"
#include "cx.h"
#include "os.h"
#include "view.h"

canister_call_t NV_CONST
N_canister_call_impl __attribute__ ((aligned(64)));
#define N_canister_call (*(NV_VOLATILE canister_call_t *)PIC(&N_canister_call_impl))

consent_request_t NV_CONST
N_consent_request_impl __attribute__ ((aligned(64)));
#define N_consent_request (*(NV_VOLATILE consent_request_t *)PIC(&N_consent_request_impl))

bls_header_t bls_header;

// Save data
zxerr_t save_consent_request(consent_request_t *structure) {
    if (structure == NULL) {
        return zxerr_out_of_bounds;
    }

    // Check if the size of the structure is valid
    if (sizeof(*structure) > sizeof(N_canister_call)) {
        return zxerr_out_of_bounds; // or another appropriate error
    }

    MEMCPY_NV((void *)&N_consent_request, structure, sizeof(*structure));
    return zxerr_ok;
}

zxerr_t save_canister_call(canister_call_t *structure) {
    if (structure == NULL) {
        return zxerr_out_of_bounds;
    }

    // Check if the size of the structure is valid
    if (sizeof(*structure) > sizeof(N_consent_request)) {
        return zxerr_out_of_bounds; // or another appropriate error
    }

    MEMCPY_NV((void *)&N_canister_call, structure, sizeof(*structure));
    return zxerr_ok;
}

// Retrieve data
consent_request_t *get_consent_request() {
    return (consent_request_t *)&N_consent_request;
}

canister_id_t *get_canister_call() {
    return (canister_id_t *)&N_canister_call;
}

// STATE
uint8_t get_state() {
    return bls_header.state;
}

void set_state(uint8_t state) {
    bls_header.state = state;
}

void state_reset() {
    bls_header.state = STATE_INITIAL;
}

void zeroize_data(){
    canister_call_t tmp_call = {0};
    consent_request_t tmp_consent = {0};
    MEMCPY_NV((void *)&N_canister_call, &tmp_call, sizeof(canister_call_t));
    MEMCPY_NV((void *)&N_consent_request, &tmp_consent, sizeof(consent_request_t));
}

void bls_nvm_reset() {
    MEMZERO(&bls_header, sizeof(bls_header_t));
    zeroize_data();
}
