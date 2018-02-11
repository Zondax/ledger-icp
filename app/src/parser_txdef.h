/*******************************************************************************
*  (c) 2019 Zondax GmbH
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

#include <coin.h>
#include <zxtypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

typedef struct {
    int8_t *ptr;
    int32_t len;
} parser_u8Array_t;

typedef struct {
    parser_u8Array_t request_type;
    parser_u8Array_t nonce;

    uint64_t ingress_expiry;

    int8_t *ptr_canister_id;            // 10 bytes? TODO: Confirm
    int8_t *ptr_sender_id;              // 29 bytes? TODO: Confirm

    parser_u8Array_t method_name;
    parser_u8Array_t arg;
} parser_tx_t;

#ifdef __cplusplus
}
#endif
