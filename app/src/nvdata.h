/*******************************************************************************
 *   (c) 2018 -2022 Zondax AG
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
#pragma once

#include "coin.h"
#include "rslib.h"
#include "zxerror.h"

#define ROOT_KEY_LEN 96

// To verify a certificate and sign a payload we need
// to send consent_request,
// canister_call, and an optional root_key
// if this alternative root key is not sent, the application
// would use the "official" one previously stored in memory(hardcoded)
// there is not security risk with this as it is a public key
// and finally the certificate itself
#define CERT_STATE_INITIAL 0
#define CERT_STATE_PROCESSED_CONSENT_REQUEST 1
#define CERT_STATE_PROCESSED_CANISTER_CALL_REQUEST 2
#define CERT_STATE_PROCESSED_ROOT_KEY 3
// Once certificate is verified, and all the checks with call-request anc
// consent response passes, then, we are ready to sign the call request payload
#define CERT_STATE_SIGN 4

typedef struct {
    uint8_t state;
} bls_header_t;

void bls_nvm_reset();

// statemachine API
uint8_t get_state();

void state_reset();

void set_state(uint8_t state);
#endif
