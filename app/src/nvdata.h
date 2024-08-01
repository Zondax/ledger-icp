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
#pragma once

#include "coin.h"
#include "zxerror.h"
#include "rslib.h"

// TODO: WE NEED TO DEFINE THIS SIZE ???
#define MAX_DATA_SIZE   300
#define ROOT_KEY_LEN    96

typedef struct {
    uint8_t consent_request[MAX_DATA_SIZE];
    uint8_t canister_call[MAX_DATA_SIZE];
    uint8_t root_key[ROOT_KEY_LEN];
} bls_data_t;

typedef struct {
    uint8_t state;
    uint16_t consent_request_len;
    uint16_t canister_call_len;
} bls_header_t;

zxerr_t save_consent_request(consent_request_t *structure);
zxerr_t save_canister_call(canister_call_t *structure);
zxerr_t save_root_key(uint8_t* data, uint16_t data_len);

void bls_nvm_reset();

// statemachine API
uint8_t get_state();

void state_reset();

void set_state(uint8_t state);

#define STATE_INITIAL                           0
#define STATE_PROCESSED_CONSENT_REQUEST         1
#define STATE_PROCESSED_CANISTER_CALL_REQUEST   2
#define STATE_PROCESSED_ROOT_KEY                3


