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

transaction_header_t transaction_header;


// STATE
uint8_t get_state() {
    return transaction_header.state;
}

void set_state(uint8_t state) {
    transaction_header.state = state;
}

void state_reset() {
    transaction_header.state = STATE_INITIAL;
}


void bls_nvm_reset() {
    MEMZERO(&transaction_header, sizeof(transaction_header_t));
}
