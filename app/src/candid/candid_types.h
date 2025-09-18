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

#include <zxerror.h>
#include <zxmacros.h>

#include "coin.h"

#define YEAR_2100_IN_SECONDS 4102444800

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
    hash_id = 23515,
    hash_hash = 1158164430,
    hash_reward_account = 2095839389,
    hash_amount_e8s = 2147809209,
    hash_command = 2171433291,
    hash_neuron_id_or_subaccount = 3506626033,
    hash_source_neuron_id = 3123627971,
    hash_operation = 2688582695,
    hash_dissolve_timestamp_seconds = 2863826760,
    hash_subaccount = 1193510733,
    hash_neuron_id = 2323144526,
    hash_neuron_ids = 2024218412,
    hash_include_neurons_readable_by_caller = 3639893594,
    hash_percentage_to_spawn = 809978428,
    hash_new_controller = 2460987739,
    hash_nonce = 2680573167,
    hash_percentage_to_stake = 854334011,
    hash_setting_auto_stake_maturity = 3470422224,
    hash_setting_increse_dissolve_delay = 913088909,
    hash_field_disburse_account = 1937583785,
    hash_opt_amount = 3573748184,
    hash_setting_addhotkey = 3570462350,
    hash_setting_remove_hotkey = 2202409078,
    hash_field_vote = 1314114794,
    hash_field_proposal = 3000310834,
    hash_field_follow_topic = 338645423,
    hash_field_follow_followees = 3407357762,
    hash_field_visibility = 3540889042,
} txn_hash_fields;

typedef enum {
    sns_hash_subaccount = 1349681965,
    sns_hash_command = 2171433291,
    sns_hash_permissions_to_add = 425878456,
    sns_hash_principal_id = 3211002892,
    sns_hash_permissions_to_remove = 3210478349,
    sns_hash_operation = 2688582695,

    sns_hash_neuron_permission_list = 248806532,

    sns_hash_disburse_to_account = 1937583785,
    sns_hash_opt_principal = 947296307,
    sns_hash_opt_amount = 3573748184,
} sns_hash_fields;

typedef enum {
    transfer_hash_to = 25979,
    transfer_hash_fee = 5094982,
    transfer_hash_memo = 1213809850,
    transfer_hash_from_subaccount = 1835347746,
    transfer_hash_timestamp = 3258775938,
    transfer_hash_amount = 3573748184,
} transfer_hash_fields;

typedef enum {
    icrc_hash_to = 25979,
    icrc_hash_owner = 947296307,
    icrc_hash_subaccount = 1349681965,
    icrc_hash_fee = 5094982,
    icrc_hash_memo = 1213809850,
    icrc_hash_from_subaccount = 1835347746,
    icrc_hash_created_at_time = 3258775938,
    icrc_hash_amount = 3573748184,
    // next 3 constants for icrc2_approve
    icrc_hash_spender = 3868658507,
    icrc_hash_expected_allowance = 3622243857,
    icrc_hash_expires_at = 3680359390,
} icrc_hash_fields;

typedef enum {
    hash_command_Spawn = 345247259,
    hash_command_Split = 345791162,
    hash_command_Follow = 774571409,
    hash_command_ClaimOrRefresh = 1349619708,
    hash_command_Configure = 1647237574,
    hash_command_RegisterVote = 2455066893,
    hash_command_Merge = 2566132376,
    hash_command_DisburseToNeuron = 2803800337,
    hash_command_RefreshVotingPower = 971637731,
    hash_command_MakeProposal = 3217030240,
    hash_command_StakeMaturity = 3582720395,
    hash_command_MergeMaturity = 3865893897,
    hash_command_Disburse = 4121967011,
} command_variant_hash_e;

typedef enum {
    sns_hash_command_Split = 345791162,
    sns_hash_command_Follow = 774571409,
    sns_hash_command_DisburseMaturity = 914851348,
    sns_hash_command_Configure = 1647237574,
    // sns_hash_command_RegisterVote = 1647237574,
    sns_hash_command_SyncCommand = 2455066893,
    sns_hash_command_MakeProposal = 3217030240,
    sns_hash_command_StakeMaturity = 3582720395,
    sns_hash_command_RemoveNeuronPermissions = 3664916941,
    sns_hash_command_AddNeuronPermissions = 3723163536,
    sns_hash_command_MergeMaturity = 3865893897,
    sns_hash_command_Disburse = 4121967011,
} sns_hash_commands;

typedef enum {
    // Check these hashes
    hash_operation_Invalid = 971299358,
    hash_operation_StopDissolving = 1954991536,
    hash_operation_IncreaseDissolveDelay = 2143729936,
    hash_operation_AddHotkey = 628424947,
    hash_operation_RemoveHotkey = 45994902,
    hash_operation_JoinNeuronsFund = 3248805476,
    hash_operation_ChangeAutoStakeMaturity = 1906071820,

    hash_operation_StartDissolving = 1977744848,
    hash_operation_LeaveNeuronsFund = 3675510135,
    hash_operation_SetDissolvedTimestamp = 3913126211,
    hash_operation_SetVisibility = 3161865204,
} operation_variant_hash_e;

typedef enum {
    FOLLOW_TOPIC_UNSPECIFIED = 0,
    FOLLOW_TOPIC_NEURON_MANAGEMENT = 1,
    FOLLOW_TOPIC_EXCHANGE_RATE = 2,
    FOLLOW_TOPIC_NETWORK_ECONOMICS = 3,
    FOLLOW_TOPIC_GOVERNANCE = 4,
    FOLLOW_TOPIC_NODE_ADMIN = 5,
    FOLLOW_TOPIC_PARTICIPANT_MANAGEMENT = 6,
    FOLLOW_TOPIC_SUBNET_MANAGEMENT = 7,
    FOLLOW_TOPIC_NETWORK_CANISTER_MANAGEMENT = 8,
    FOLLOW_TOPIC_KYC = 9,
    FOLLOW_TOPIC_NODE_PROVIDER_REWARDS = 10,
    FOLLOW_TOPIC_SNS_DECENTRALIZATION_SALE = 11,
    FOLLOW_TOPIC_SUBNET_REPLICA_VERSION_MANAGEMENT = 12,
    FOLLOW_TOPIC_REPLICA_VERSION_MANAGEMENT = 13,
    FOLLOW_TOPIC_SNS_AND_NEURONS_FUND = 14,
} candid_FollowTopics_e;

// Permissions ENUM
// https://github.com/dfinity/ic-js/blob/d82310ec5519160b5fa2ec94fd82200485bd3ccc/packages/sns/src/enums/governance.enums.ts#L2
typedef enum {
    NEURON_PERMISSION_TYPE_UNSPECIFIED = 0,
    NEURON_PERMISSION_TYPE_CONFIGURE_DISSOLVE_STATE = 1,
    NEURON_PERMISSION_TYPE_MANAGE_PRINCIPALS = 2,
    NEURON_PERMISSION_TYPE_SUBMIT_PROPOSAL = 3,
    NEURON_PERMISSION_TYPE_VOTE = 4,
    NEURON_PERMISSION_TYPE_DISBURSE = 5,
    NEURON_PERMISSION_TYPE_SPLIT = 6,
    NEURON_PERMISSION_TYPE_MERGE_MATURITY = 7,
    NEURON_PERMISSION_TYPE_DISBURSE_MATURITY = 8,
    NEURON_PERMISSION_TYPE_STAKE_MATURITY = 9,
    NEURON_PERMISSION_TYPE_MANAGE_VOTING_PERMISSION = 10,
} sns_permissions_e;

typedef struct {
    uint64_t len;
    const uint8_t *p;
} sizedBuffer_t;

typedef struct {
    uint64_t id;
} candid_NeuronId;

typedef struct {
    uint8_t requested_setting_for_auto_stake_maturity;
} candid_ChangeAutoStakeMaturity_t;

typedef struct {
    uint64_t dissolve_timestamp_seconds;
} candid_SetDissolveTimestamp_t;

typedef struct {
    uint32_t dissolve_timestamp_seconds;
} candid_IncreaseDissolveDelay_t;

typedef struct {
    uint8_t len;
    uint8_t ptr[30];
} candid_Principal_t;

typedef struct {
    uint8_t has_principal;
    candid_Principal_t principal;
} candid_AddRemoveHotkey_t;

// This is a neuron configure operation
typedef struct {
    uint8_t has_visibility;
    int32_t visibility;
} candid_SetVisibility_t;

typedef struct {
    uint64_t which;
    uint64_t hash;
    union {
        candid_SetDissolveTimestamp_t setDissolveTimestamp;
        candid_ChangeAutoStakeMaturity_t autoStakeMaturity;
        candid_IncreaseDissolveDelay_t increaseDissolveDelay;
        candid_AddRemoveHotkey_t hotkey;
        candid_SetVisibility_t set_visibility;
    };
} candid_Operation_t;

typedef struct {
    uint8_t has_percentage_to_spawn;
    uint32_t percentage_to_spawn;

    uint8_t has_controller;
    candid_Principal_t new_controller;

    uint8_t has_nonce;
    uint64_t nonce;
} candid_Spawn_t;

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
    uint8_t has_percentage_to_stake;
    uint32_t percentage_to_stake;
} candid_StakeMaturity_t;

typedef struct {
    uint8_t has_account_identifier;
    sizedBuffer_t account_identifier;

    uint8_t has_amount;
    uint64_t amount;
} candid_Disburse_t;

typedef struct {
    int32_t vote;

    uint8_t has_proposal;
    candid_NeuronId proposal;
} candid_RegisterVote_t;

typedef struct {
    int32_t topic;

    uint8_t followees_size;
    const uint8_t *followees_ptr;
} candid_Follow_t;

typedef struct {
    // Not used
    candid_NeuronId neuron_id;
} candid_RefreshVotingPower_t;

typedef struct {
    uint8_t list_size;
    const uint8_t *permissions_list_ptr;
} sns_NeuronPermissionList_t;

typedef struct {
    uint8_t has_permissionList;
    sns_NeuronPermissionList_t permissionList;

    uint8_t has_principal;
    candid_Principal_t principal;
} sns_NeuronPermissions_t;

typedef struct {
    uint8_t has_owner;
    candid_Principal_t owner;

    uint8_t has_subaccount;
    sizedBuffer_t subaccount;
} Account_t;

typedef struct {
    uint64_t memo;
    uint64_t amount;
    uint64_t fee;

    uint8_t has_from_subaccount;
    sizedBuffer_t from_subaccount;

    uint8_t to[DFINITY_ADDR_LEN];

    uint8_t has_timestamp;
    uint64_t timestamp;
} candid_transfer_t;

typedef struct {
    uint8_t icp_canister;
    Account_t account;

    uint8_t has_fee;
    uint64_t fee;

    uint8_t has_memo;
    sizedBuffer_t memo;

    uint8_t has_from_subaccount;
    sizedBuffer_t from_subaccount;

    uint8_t has_created_at_time;
    uint64_t created_at_time;

    uint64_t amount;

} icrc_transfer_t;
// typedef struct {
//   uint8_t has_owner;
//   candid_Principal_t owner;
//
//   uint8_t has_subaccount;
//   sizedBuffer_t subaccount;
// } Account_t;

typedef struct {
    uint8_t icp_canister;
    Account_t spender;

    uint8_t has_fee;
    uint64_t fee;

    uint8_t has_memo;
    sizedBuffer_t memo;

    uint8_t has_from_subaccount;
    sizedBuffer_t from_subaccount;

    uint8_t has_created_at_time;
    uint64_t created_at_time;

    uint64_t amount;  // The approved amount

    uint8_t has_expected_allowance;
    uint64_t expected_allowance;

    uint8_t has_expires_at;
    uint64_t expires_at;

} icrc2_approve_t;

typedef struct {
    uint8_t has_account;
    Account_t account;

    uint8_t has_amount;
    uint64_t amount;
} sns_Disburse_t;

typedef struct {
    uint64_t variant;
    uint64_t hash;
    union {
        candid_Spawn_t spawn;
        candid_Split_t split;
        candid_Merge_t merge;
        candid_Configure_t configure;
        candid_StakeMaturity_t stake;
        candid_Disburse_t disburse;
        candid_RegisterVote_t vote;
        candid_Follow_t follow;
        candid_RefreshVotingPower_t refresh_voting_power;

        sns_NeuronPermissions_t neuronPermissions;
        sns_Disburse_t sns_disburse;
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
    sizedBuffer_t subaccount;

    uint8_t has_command;
    candid_Command_t command;
} sns_ManageNeuron_t;

typedef struct {
    uint8_t has_reward_account;
    sizedBuffer_t account_identifier;
} candid_UpdateNodeProvider_t;

typedef struct {
    uint8_t neuron_ids_size;
    const uint8_t *neuron_ids_ptr;

    uint8_t has_include_empty_neurons_readable_by_caller;
    uint8_t include_empty_neurons_readable_by_caller;
    uint8_t include_neurons_readable_by_caller;
} candid_ListNeurons_t;

#ifdef __cplusplus
}
#endif
