/*******************************************************************************
*   (c) 2022 Zondax AG
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

#ifdef __cplusplus
extern "C" {
#endif

#include <zxmacros.h>
#include <zxerror.h>

typedef enum {
    Null = -1,
    Bool = -2,
    Nat = -3,
    Int = -4,

    Nat8 = -5,
    Nat16 = -6,
    Nat32 = -7,
    Nat64 = -8,

    Int8 = -9,
    Int16 = -10,
    Int32 = -11,
    Int64 = -12,

    Float32 = -13,
    Float64 = -14,
    Text = -15,
    Reserved = -16,
    Empty = -17,
    Opt = -18,
    Vector = -19,
    Record = -20,
    Variant = -21,
    Func = -22,
    Service = -23,
    Principal = -24,
} IDLTypes_e;

typedef enum {
    command_Invalid = 0,

    command_Spawn = 0,
    command_Split = 1,
    command_Follow = 2,
    command_ClaimOrRefresh = 3,
    command_Configure = 4,
    command_RegisterVote = 5,
    command_Merge = 6,
} command_variant_e;

typedef enum {
    operation_Invalid = 0,
    operation_IncreaseDissolveDelay = 1,
    operation_StartDissolving = 2,
    operation_StopDissolving = 3,
    operation_AddHotKey = 4,
    operation_RemoveHotKey = 5,
    operation_SetDissolvedTimestamp = 6,
    operation_JoinCommunityFund = 7,
} operation_variant_e;

typedef struct {
    uint64_t len;
    const uint8_t *p;
} sizedBuffer_t;

typedef struct {
    uint64_t id;
} candid_NeuronId;

typedef struct {
    uint64_t dissolve_timestamp_seconds;
} candid_SetDissolveTimestamp_t;

typedef struct {
    uint64_t which;
    union {
        candid_SetDissolveTimestamp_t setDissolveTimestamp;
    };
} candid_Operation_t;

typedef struct {
    uint64_t amount_e8s;
} candid_Split_t;

typedef struct {
    uint8_t has_source;
    candid_NeuronId source;
} candid_Merge_t;

typedef struct {
    uint8_t has_operation;
    candid_Operation_t operation;
} candid_Configure_t;

typedef struct {
    uint64_t variant;
    union {
        candid_Split_t split;
        candid_Merge_t merge;
        candid_Configure_t configure;
    };
} candid_Command_t;

typedef struct {
    uint64_t which;
    union {
        sizedBuffer_t subaccount;
        candid_NeuronId neuronId;
    };
} candid_Neuron_id_or_subaccount_t;

typedef struct {
    uint8_t has_id;
    candid_NeuronId id;

    uint8_t has_command;
    candid_Command_t command;

    uint8_t has_neuron_id_or_subaccount;
    candid_Neuron_id_or_subaccount_t neuron_id_or_subaccount;
} candid_ManageNeuron_t;


typedef struct {
    uint8_t has_reward_account;
    sizedBuffer_t account_identifier;
} candid_UpdateNodeProvider_t;

#ifdef __cplusplus
}
#endif
