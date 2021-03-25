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
    uint8_t data[29];
    size_t len;
} sender_t;

typedef struct {
    uint8_t data[10];
    size_t len;
} canister_t;

typedef struct {
    char data[10];
    size_t len;
} request_t;

typedef struct {
    char data[20];
    size_t len;
} method_t;

typedef struct {
    uint8_t data[32];
    size_t len;
} nonce_t;

typedef struct {
    uint8_t data[100];
    size_t len;
} arg_t;


typedef struct {
    request_t request_type;
    nonce_t nonce;

    uint64_t ingress_expiry;

    canister_t canister_id;
    sender_t sender;

    method_t method_name;
    arg_t arg;

    uint8_t txtype;

} parser_tx_t;

#ifdef __cplusplus
}
#endif
