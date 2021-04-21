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

#define NUM_MAP_TYPE0 7
#define NUM_MAP_TYPE1 4


#define SENDER_MAX_LEN 29
#define CANISTER_MAX_LEN 10
#define REQUEST_MAX_LEN 10
#define METHOD_MAX_LEN 20
#define NONCE_MAX_LEN 32
#define ARG_MAX_LEN 100
#define PATH_MAX_LEN 40
#define PATH_MAX_ARRAY 5

typedef struct {
    uint8_t data[SENDER_MAX_LEN + 1];
    size_t len;
} sender_t;

typedef struct {
    uint8_t data[CANISTER_MAX_LEN + 1];
    size_t len;
} canister_t;

typedef struct {
    char data[REQUEST_MAX_LEN + 1];
    size_t len;
} request_t;

typedef struct {
    char data[METHOD_MAX_LEN + 1];
    size_t len;
} method_t;

typedef struct {
    uint8_t data[NONCE_MAX_LEN + 1];
    size_t len;
} nonce_t;

typedef struct {
    uint8_t data[ARG_MAX_LEN + 1];
    size_t len;
} arg_t;

typedef struct {
    uint8_t data[PATH_MAX_LEN + 1];
    size_t len;
} path_t;

typedef struct {
    path_t paths[PATH_MAX_ARRAY + 1];
    size_t arrayLen;
} pathArray_t;


typedef struct {
    request_t request_type;
    nonce_t nonce;

    uint64_t ingress_expiry;

    canister_t canister_id;
    sender_t sender;

    method_t method_name;
    arg_t arg;

    pathArray_t paths;

    uint8_t txtype;

} parser_tx_t;

#ifdef __cplusplus
}
#endif
