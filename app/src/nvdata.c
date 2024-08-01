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

bls_data_t NV_CONST
N_bls_data_impl __attribute__ ((aligned(64)));
#define N_bls_data (*(NV_VOLATILE bls_data_t *)PIC(&N_bls_data_impl))

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

zxerr_t save_root_key(uint8_t* data, uint16_t data_len) {
    if (data_len == 0 || data_len != ROOT_KEY_LEN) {
        return zxerr_out_of_bounds;
    }

    MEMCPY_NV((void *)&N_bls_data.root_key, data, data_len);
    return zxerr_ok;
}

// Retrieve data
uint8_t *get_consent_request() {
    return (uint8_t *)&N_consent_request;
}

uint8_t *get_canister_call() {
    return (uint8_t *)&N_canister_call;
}

uint8_t *get_root_key() {
    return (uint8_t *)&N_bls_data.root_key;
}

uint8_t get_consent_request_length(void) {
    return bls_header.consent_request_len;
}

uint8_t get_canister_call_length(void) {
    return bls_header.canister_call_len;
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
    uint8_t tmp[MAX_DATA_SIZE] = {0};
    MEMCPY_NV((void *)&N_bls_data.consent_request, tmp, MAX_DATA_SIZE);
    MEMCPY_NV((void *)&N_bls_data.canister_call, tmp, MAX_DATA_SIZE);
    MEMCPY_NV((void *)&N_bls_data.root_key, tmp, ROOT_KEY_LEN);
}

void bls_nvm_reset() {
    MEMZERO(&bls_header, sizeof(bls_header_t));
    zeroize_data();
}
