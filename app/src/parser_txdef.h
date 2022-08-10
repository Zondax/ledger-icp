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

#define ZX_NO_CPP

#include "protobuf/dfinity.pb.h"
#include "protobuf/governance.pb.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "candid_types.h"

#include <stdint.h>
#include <stddef.h>

#define SENDER_MAX_LEN 29
#define CANISTER_MAX_LEN 10
#define REQUEST_MAX_LEN 10
#define METHOD_MAX_LEN 20
#define NONCE_MAX_LEN 32
#define ARG_MAX_LEN 1000
#define PATH_MAX_LEN 40
#define PATH_MAX_ARRAY 2

typedef enum {
    unknown = 0x00,                 // default is not accepted
    call = 0x01,
    state_transaction_read = 0x02,
} txtype_e;

typedef enum {
    pb_unknown = 0x00,          //default is not accepted
    pb_sendrequest = 0x01,
    pb_manageneuron = 0x02,
    pb_listneurons = 0x03,
    pb_claimneurons = 0x04,

    candid_manageneuron = 0xF002,
    candid_updatenodeprovider = 0xF003,
} method_type_e;

typedef enum {
    wrong_operation = 0,          //default is not accepted

    Configure = 2,
    Configure_IncreaseDissolveDelay = 2001,
    Configure_StartDissolving = 2002,
    Configure_StopDissolving = 2003,
    Configure_AddHotKey = 2004,
    Configure_RemoveHotKey = 2005,
    Configure_JoinCommunityFund = 2007,

////
    Disburse = 3,
    Spawn = 4,
    Follow = 5,
    RegisterVote = 7,
    MergeMaturity = 13,

//    Follow = 9,
//    Register_Vote = 10,
    Split = 11,
//    DisburseToNeuron = 12,
//    ClaimOrRefresh = 13,

    Merge = 1000
} manageNeuron_e;

typedef enum {
    invalid = 0x00,
    normal_transaction = 0x01,
    neuron_stake_transaction = 0x02,
} special_transfer_e;

typedef struct {
    uint8_t data[SENDER_MAX_LEN + 1];
    size_t len;
} sender_t;

typedef struct {
    uint8_t data[CANISTER_MAX_LEN + 1];
    size_t len;
} canister_id_t;

typedef struct {
    char data[REQUEST_MAX_LEN + 1];
    size_t len;
} request_t;

typedef struct {
    char data[METHOD_MAX_LEN + 1];
    size_t len;
} method_name_t;

typedef struct {
    uint8_t data[NONCE_MAX_LEN + 1];
    size_t len;
} nonce_t;

typedef struct {
    uint8_t data[ARG_MAX_LEN + 1];
    size_t len;
} method_arg_t;

typedef struct {
    uint8_t data[PATH_MAX_LEN + 1];
    size_t len;
} path_t;

typedef struct {
    path_t paths[PATH_MAX_ARRAY + 1];
    size_t arrayLen;
} pathArray_t;

typedef struct {
    nonce_t nonce;
    bool has_nonce;

    uint64_t ingress_expiry;
    uint64_t neuron_creation_memo;

    canister_id_t canister_id;
    sender_t sender;

    method_name_t method_name;
    method_type_e method_type;
    method_arg_t method_args;

    union {
        ic_nns_governance_pb_v1_ManageNeuron ic_nns_governance_pb_v1_ManageNeuron;
        candid_ManageNeuron_t candid_manageNeuron;
        candid_UpdateNodeProvider_t candid_updateNodeProvider;
        SendRequest SendRequest;
        ListNeurons ListNeurons;
    } data;
} call_t;

typedef struct {
    uint64_t ingress_expiry;
    sender_t sender;
    pathArray_t paths;
} state_read_t;

///
///

typedef struct {
    uint16_t typetableCurrent;
    uint16_t typetableSize;
} candid_state_t;

typedef struct {
    txtype_e txtype;            // union selector

    request_t request_type;
    special_transfer_e special_transfer_type;

    union {
        call_t call;
        state_read_t stateRead;
    } tx_fields;

    candid_state_t candid_state;
} parser_tx_t;

#ifdef __cplusplus
}
#endif
