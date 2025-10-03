/*******************************************************************************
 *   (c) 2018 - 2023 Zondax AG
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
#include "parser_print_candid.h"

#include <zxformat.h>

#include "app_mode.h"
#include "candid_parser.h"
#include "parser_print_helper.h"
#include "parser_print_strings.h"
#include "parser_txdef.h"
#include "timeutils.h"
#include "token_info.h"

#define DEFAULT_MAXIMUM_FEES 10000

__Z_INLINE parser_error_t print_permission(int32_t permission, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                           uint8_t *pageCount) {
    switch (permission) {
        case NEURON_PERMISSION_TYPE_UNSPECIFIED:
            pageString(outVal, outValLen, "Unspecified", pageIdx, pageCount);
            break;
        case NEURON_PERMISSION_TYPE_CONFIGURE_DISSOLVE_STATE:
            pageString(outVal, outValLen, "Configure Dissolve State", pageIdx, pageCount);
            break;
        case NEURON_PERMISSION_TYPE_MANAGE_PRINCIPALS:
            pageString(outVal, outValLen, "Manage Principals", pageIdx, pageCount);
            break;
        case NEURON_PERMISSION_TYPE_SUBMIT_PROPOSAL:
            pageString(outVal, outValLen, "Submit Proposal", pageIdx, pageCount);
            break;
        case NEURON_PERMISSION_TYPE_VOTE:
            pageString(outVal, outValLen, "Vote", pageIdx, pageCount);
            break;
        case NEURON_PERMISSION_TYPE_DISBURSE:
            pageString(outVal, outValLen, "Disburse Neuron", pageIdx, pageCount);
            break;
        case NEURON_PERMISSION_TYPE_SPLIT:
            pageString(outVal, outValLen, "Split Neuron", pageIdx, pageCount);
            break;
        case NEURON_PERMISSION_TYPE_MERGE_MATURITY:
            pageString(outVal, outValLen, "Merge Maturity", pageIdx, pageCount);
            break;
        case NEURON_PERMISSION_TYPE_DISBURSE_MATURITY:
            pageString(outVal, outValLen, "Disburse Maturity", pageIdx, pageCount);
            break;
        case NEURON_PERMISSION_TYPE_STAKE_MATURITY:
            pageString(outVal, outValLen, "Stake Maturity", pageIdx, pageCount);
            break;
        case NEURON_PERMISSION_TYPE_MANAGE_VOTING_PERMISSION:
            pageString(outVal, outValLen, "Manage Voting Permission", pageIdx, pageCount);
            break;

        default:
            return parser_unexpected_value;
    }

    return parser_ok;
}

__Z_INLINE parser_error_t print_follow_topic(int32_t topic, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                             uint8_t *pageCount) {
    switch (topic) {
        case FOLLOW_TOPIC_UNSPECIFIED:
            pageString(outVal, outValLen, "Default", pageIdx, pageCount);
            break;
        case FOLLOW_TOPIC_NEURON_MANAGEMENT:
            pageString(outVal, outValLen, "Neuron Management", pageIdx, pageCount);
            break;
        case FOLLOW_TOPIC_EXCHANGE_RATE:
            pageString(outVal, outValLen, "Exchange Rate", pageIdx, pageCount);
            break;
        case FOLLOW_TOPIC_NETWORK_ECONOMICS:
            pageString(outVal, outValLen, "Network Economics", pageIdx, pageCount);
            break;
        case FOLLOW_TOPIC_GOVERNANCE:
            pageString(outVal, outValLen, "Governance", pageIdx, pageCount);
            break;
        case FOLLOW_TOPIC_NODE_ADMIN:
            pageString(outVal, outValLen, "Node Admin", pageIdx, pageCount);
            break;
        case FOLLOW_TOPIC_PARTICIPANT_MANAGEMENT:
            pageString(outVal, outValLen, "Participant Management", pageIdx, pageCount);
            break;
        case FOLLOW_TOPIC_SUBNET_MANAGEMENT:
            pageString(outVal, outValLen, "Subnet Management", pageIdx, pageCount);
            break;
        case FOLLOW_TOPIC_NETWORK_CANISTER_MANAGEMENT:
            pageString(outVal, outValLen, "Network Canister Management", pageIdx, pageCount);
            break;
        case FOLLOW_TOPIC_KYC:
            pageString(outVal, outValLen, "KYC", pageIdx, pageCount);
            break;
        case FOLLOW_TOPIC_NODE_PROVIDER_REWARDS:
            pageString(outVal, outValLen, "Node Provider Rewards", pageIdx, pageCount);
            break;
        case FOLLOW_TOPIC_SNS_DECENTRALIZATION_SALE:
            pageString(outVal, outValLen, "SNS Decentralization Swap", pageIdx, pageCount);
            break;
        case FOLLOW_TOPIC_SUBNET_REPLICA_VERSION_MANAGEMENT:
            pageString(outVal, outValLen, "Subnet Replica Version Management", pageIdx, pageCount);
            break;
        case FOLLOW_TOPIC_REPLICA_VERSION_MANAGEMENT:
            pageString(outVal, outValLen, "Replica Version Management", pageIdx, pageCount);
            break;
        case FOLLOW_TOPIC_SNS_AND_NEURONS_FUND:
            pageString(outVal, outValLen, "SNS & Neurons' Fund", pageIdx, pageCount);
            break;

        default:
            return parser_unexpected_value;
    }

    return parser_ok;
}

// Stick to the spec for printing accounts
// https://internetcomputer.org/docs/current/references/icrc1-standard#textual-encoding-of-accounts
__Z_INLINE parser_error_t print_accountBytes(sender_t sender, const candid_transfer_t *sendrequest, char *outVal,
                                             uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    // First check if we have a subaccount and if it's non-zero
    bool has_subaccount = sendrequest->has_from_subaccount;
    bool is_default_subaccount = true;

    if (has_subaccount) {
        // Check if subaccount is all zeros
        for (uint16_t i = 0; i < sendrequest->from_subaccount.len; i++) {
            if (sendrequest->from_subaccount.p[i] != 0) {
                is_default_subaccount = false;
                break;
            }
        }
    }

    // If no subaccount or all zeros, just print the principal
    if (!has_subaccount || is_default_subaccount) {
        return print_principal(sender.data, (uint16_t)sender.len, outVal, outValLen, pageIdx, pageCount);
    }

    // For non-default subaccount, we need to handle the full format
    uint8_t subaccount[32] = {0};
    if (has_subaccount) {
        MEMCPY(subaccount, sendrequest->from_subaccount.p, (size_t)sendrequest->from_subaccount.len);
    }

    return page_principal_with_subaccount(sender.data, (uint16_t)sender.len, subaccount, sizeof(subaccount), outVal,
                                          outValLen, pageIdx, pageCount, false);
}

static parser_error_t parser_getItemSetDissolveTimestamp(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                                         uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    const candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    PARSER_ASSERT_OR_ERROR(fields->command.hash == hash_command_Configure, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.has_operation, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.hash == hash_operation_SetDissolvedTimestamp,
                           parser_unexpected_value)

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        pageString(outVal, outValLen, "Set Dissolve Delay", pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        // Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Dissolve Time");
        uint64_t dissolve_timestamp_seconds =
            fields->command.configure.operation.setDissolveTimestamp.dissolve_timestamp_seconds;

        timedata_t td;
        zxerr_t zxerr = decodeTime(&td, dissolve_timestamp_seconds);
        if (zxerr != zxerr_ok) {
            return parser_unexpected_value;
        }

        char buffer[PRINT_BUFFER_SMALL_LEN] = {0};
        // YYYYmmdd HH:MM:SS
        snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d UTC", td.tm_year, td.tm_mon, td.tm_day, td.tm_hour,
                 td.tm_min, td.tm_sec);

        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemChangeAutoStakeMaturity(uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                                            char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                                            uint8_t *pageCount) {
    *pageCount = 1;

    const candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    PARSER_ASSERT_OR_ERROR(fields->command.hash == hash_command_Configure, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.has_operation, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.hash == hash_operation_ChangeAutoStakeMaturity,
                           parser_unexpected_value)

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        pageString(outVal, outValLen, "Set Auto Stake Maturity", pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        // Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Auto stake");
        snprintf(outVal, outValLen,
                 fields->command.configure.operation.autoStakeMaturity.requested_setting_for_auto_stake_maturity ? "true"
                                                                                                                 : "false");
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemDisburseCandid(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                                   uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    const candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    const uint8_t *canister_id = (const uint8_t *)parser_tx_obj.tx_fields.call.canister_id.data;
    const uint8_t canister_id_len = parser_tx_obj.tx_fields.call.canister_id.len;
    const token_info_t *token = get_token(canister_id, canister_id_len);

    uint8_t decimals = 0;

    if (token != NULL) {
        decimals = token->decimals;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        pageString(outVal, outValLen, "Disburse Neuron", pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron Id");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        // Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Disburse To ");
        if (fields->command.disburse.has_account_identifier) {
            return page_hexstring_with_delimiters(fields->command.disburse.account_identifier.p,
                                                  fields->command.disburse.account_identifier.len, outVal, outValLen,
                                                  pageIdx, pageCount);
        }
        snprintf(outVal, outValLen, "Self");
        return parser_ok;
    }

    if (displayIdx == 3) {
        if (token != NULL) {
            snprintf(outKey, outKeyLen, "Amount (%s)", token->token_symbol);
        } else {
            snprintf(outKey, outKeyLen, "Amount (Tokens)");
        }
        if (fields->command.disburse.has_amount) {
            return print_Amount(fields->command.disburse.amount, outVal, outValLen, pageIdx, pageCount, decimals);
        } else {
            snprintf(outVal, outValLen, "%s", "All");
            return parser_ok;
        }
    }

    return parser_no_data;
}

static parser_error_t parser_getItemRegisterVoteCandid(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                                       uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    const candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        pageString(outVal, outValLen, "Register Vote", pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        // Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Proposal ID");
        return print_u64(fields->command.vote.proposal.id, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Vote");
        snprintf(outVal, outValLen, fields->command.vote.vote == 1 ? "Yes" : "No");
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemFollowCandid(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                                 uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    const candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        pageString(outVal, outValLen, "Follow", pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        // Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Topic");
        return print_follow_topic(fields->command.follow.topic, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 3 && fields->command.follow.followees_size == 0) {
        snprintf(outKey, outKeyLen, "Followees");
        snprintf(outVal, outValLen, "None");
        return parser_ok;
    }

    displayIdx -= 2;  // now displayIdx 1 ==> Followee 1

    if (displayIdx <= fields->command.follow.followees_size) {
        snprintf(outKey, outKeyLen, "Followees (%d/%d) ", displayIdx, fields->command.follow.followees_size);
        uint64_t followee = 0;
        CHECK_PARSER_ERR(getCandidNat64FromVec(fields->command.follow.followees_ptr, &followee,
                                               fields->command.follow.followees_size,
                                               displayIdx - 1))  // Followee 1 ==> array idx 0
        return print_u64(followee, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemIncreaseDissolveDelayCandid(uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                                                char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                                                uint8_t *pageCount) {
    *pageCount = 1;

    const candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    PARSER_ASSERT_OR_ERROR(fields->command.hash == hash_command_Configure, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.has_operation, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.hash == hash_operation_IncreaseDissolveDelay,
                           parser_unexpected_value)

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        pageString(outVal, outValLen, INCREASE_DISSOLVE_DELAY, pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        // Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Additional Delay");

        if (fields->command.configure.operation.increaseDissolveDelay.dissolve_timestamp_seconds == 0) {
            snprintf(outVal, outValLen, "0s");
            return parser_ok;
        }

        char buffer[PRINT_BUFFER_SMALL_LEN] = {0};
        uint64_t value = 0;
        MEMCPY(&value, &fields->command.configure.operation.increaseDissolveDelay.dissolve_timestamp_seconds, 4);

        CHECK_PARSER_ERR(parser_printDelay(value, buffer, sizeof(buffer)))
        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemConfigureAddRemoveHotkeyCandid(uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                                                   char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                                                   uint8_t *pageCount) {
    *pageCount = 1;
    const uint64_t hash = parser_tx_obj.tx_fields.call.data.candid_manageNeuron.command.configure.operation.hash;
    const candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");

        if (hash == hash_operation_AddHotkey) {
            pageString(outVal, outValLen, "Add Hotkey", pageIdx, pageCount);
        } else if (hash == hash_operation_RemoveHotkey) {
            pageString(outVal, outValLen, "Remove Hotkey", pageIdx, pageCount);
        } else {
            return parser_unexpected_value;
        }
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        // Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Principal ");
        return print_principal(fields->command.configure.operation.hotkey.principal.ptr,
                               fields->command.configure.operation.hotkey.principal.len, outVal, outValLen, pageIdx,
                               pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemSpawnCandid(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                                uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    const candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;

    const uint8_t has_percentage_to_spawn = fields->command.spawn.has_percentage_to_spawn;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Spawn Neuron");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        // Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2 && has_percentage_to_spawn) {
        snprintf(outKey, outKeyLen, "Percentage to spawn");
        snprintf(outVal, outValLen, "%d", fields->command.spawn.percentage_to_spawn);
        return parser_ok;
    }

    if ((displayIdx == 2 && !has_percentage_to_spawn) || (displayIdx == 3 && has_percentage_to_spawn)) {
        snprintf(outKey, outKeyLen, "Controller");
        if (!fields->command.spawn.has_controller) {
            snprintf(outVal, outValLen, "Self");
            return parser_ok;
        }

        // Paged fields need space ending
        snprintf(outKey, outKeyLen, "Controller ");
        return print_principal(fields->command.spawn.new_controller.ptr, fields->command.spawn.new_controller.len, outVal,
                               outValLen, pageIdx, pageCount);
    }

    if (fields->command.spawn.has_nonce && ((displayIdx == 3 && !has_percentage_to_spawn) || displayIdx == 4)) {
        snprintf(outKey, outKeyLen, "Nonce");
        return print_u64(fields->command.spawn.nonce, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemStakeMaturityCandid(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                                        uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    const candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;

    const uint8_t has_percentage_to_stake = fields->command.stake.has_percentage_to_stake;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        pageString(outVal, outValLen, "Stake Maturity", pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        // Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2 && has_percentage_to_stake) {
        snprintf(outKey, outKeyLen, "Percentage to stake");
        snprintf(outVal, outValLen, "%d", fields->command.stake.percentage_to_stake);
        return parser_ok;
    }
    return parser_no_data;
}

static parser_error_t parser_getItemSplit(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                          uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    const candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    PARSER_ASSERT_OR_ERROR(fields->command.hash == hash_command_Split, parser_unexpected_value)

    const uint8_t *canister_id = (const uint8_t *)parser_tx_obj.tx_fields.call.canister_id.data;
    const uint8_t canister_id_len = parser_tx_obj.tx_fields.call.canister_id.len;
    const token_info_t *token = get_token(canister_id, canister_id_len);

    uint8_t decimals = 0;

    if (token != NULL) {
        decimals = token->decimals;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Split Neuron");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        // Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        if (token != NULL) {
            snprintf(outKey, outKeyLen, "Amount (%s)", token->token_symbol);
        } else {
            snprintf(outKey, outKeyLen, "Amount (Tokens)");
        }
        return print_Amount(fields->command.split.amount_e8s, outVal, outValLen, pageIdx, pageCount, decimals);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemMerge(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                          uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    const candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    PARSER_ASSERT_OR_ERROR(fields->command.hash == hash_command_Merge, parser_unexpected_value)

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Merge Neuron");
        return parser_ok;
    }

    if (displayIdx == 1) {
        if (!fields->command.merge.has_source) {
            return parser_no_data;
        }

        snprintf(outKey, outKeyLen, "Neuron ID");
        return print_u64(fields->command.merge.source.id, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Into Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        // Only accept neuron_id
        return parser_unexpected_type;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemDisburseMaturity(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                                     uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    const candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    PARSER_ASSERT_OR_ERROR(fields->command.hash == hash_command_DisburseMaturity, parser_unexpected_value)

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Disburse Maturity");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Pct to Disburse");
        uint32_to_str(outVal, outValLen, fields->command.disburseMaturity.percentage_to_disburse);
        uint16_t written_value = strlen(outVal);
        snprintf(outVal + written_value, outValLen - written_value, "%s", "%");

        return parser_ok;
    }

    if (!fields->command.disburseMaturity.has_to_account && !fields->command.disburseMaturity.has_to_account_identifier) {
        displayIdx++;
    }
    if (displayIdx == 3) {
#if defined(TARGET_NANOS)
        snprintf(outKey, outKeyLen, "To ");
#else
        snprintf(outKey, outKeyLen, "To Account ");
#endif
        if (fields->command.disburseMaturity.has_to_account_identifier) {
            const uint8_t *to_account_identifier = fields->command.disburseMaturity.to_account_identifier.p;
            const uint16_t to_account_identifierLen = (uint16_t)fields->command.disburseMaturity.to_account_identifier.len;

            return page_hexstring_with_delimiters(to_account_identifier, to_account_identifierLen, outVal, outValLen,
                                                  pageIdx, pageCount);
        } else {
            const uint8_t *owner = fields->command.disburseMaturity.to_account.owner.ptr;
            const uint16_t ownerLen = (uint16_t)fields->command.disburseMaturity.to_account.owner.len;
            const uint8_t *subaccount = fields->command.disburseMaturity.to_account.subaccount.p;
            const uint16_t subaccountLen = (uint16_t)fields->command.disburseMaturity.to_account.subaccount.len;

            return page_principal_with_subaccount(owner, ownerLen, subaccount, subaccountLen, outVal, outValLen, pageIdx,
                                                  pageCount, true);
        }
    }

    return parser_no_data;
}

static parser_error_t parser_getItemListNeuronsCandid(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                                      uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    const candid_ListNeurons_t *fields = &parser_tx_obj.tx_fields.call.data.candid_listNeurons;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "List Own Neurons");
        return parser_ok;
    }
    if (displayIdx <= fields->neuron_ids_size) {
        snprintf(outKey, outKeyLen, "Neuron ID %d", displayIdx);
        uint64_t neuron_id = 0;
        CHECK_PARSER_ERR(getCandidNat64FromVec(fields->neuron_ids_ptr, &neuron_id, fields->neuron_ids_size, displayIdx - 1))
        return print_u64(neuron_id, outVal, outValLen, pageIdx, pageCount);
    }
    return parser_no_data;
}

static parser_error_t parser_getItemListUpdateNodeProvider(uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                                           char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                                           uint8_t *pageCount) {
    *pageCount = 1;

    const candid_UpdateNodeProvider_t *fields = &parser_tx_obj.tx_fields.call.data.candid_updateNodeProvider;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        pageString(outVal, outValLen, "Set Node Provider : Reward Account", pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Reward Account ");
        return page_hexstring_with_delimiters(fields->account_identifier.p, fields->account_identifier.len, outVal,
                                              outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemConfigureNoElementsCandid(uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                                              char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                                              uint8_t *pageCount) {
    *pageCount = 1;
    const uint64_t hash = parser_tx_obj.tx_fields.call.data.candid_manageNeuron.command.configure.operation.hash;
    const candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");

        if (hash == hash_operation_StartDissolving) {
            pageString(outVal, outValLen, "Start Dissolving", pageIdx, pageCount);
        } else if (hash == hash_operation_StopDissolving) {
            pageString(outVal, outValLen, "Stop Dissolving", pageIdx, pageCount);
        } else if (hash == hash_operation_JoinNeuronsFund) {
            pageString(outVal, outValLen, "Join Neurons' Fund", pageIdx, pageCount);
        } else if (hash == hash_operation_LeaveNeuronsFund) {
            pageString(outVal, outValLen, "Leave Neurons' Fund", pageIdx, pageCount);
        } else {
            return parser_unexpected_value;
        }
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        // Only accept neuron_id
        return parser_unexpected_type;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemConfigureDissolvingSNS(uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                                           char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                                           uint8_t *pageCount) {
    *pageCount = 1;
    const candid_Command_t *command = &parser_tx_obj.tx_fields.call.data.sns_manageNeuron.command;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");

        if (command->configure.operation.hash == hash_operation_StartDissolving) {
            pageString(outVal, outValLen, "Start Dissolving", pageIdx, pageCount);
        } else if (command->configure.operation.hash == hash_operation_StopDissolving) {
            pageString(outVal, outValLen, "Stop Dissolving", pageIdx, pageCount);
        } else {
            return parser_unexpected_value;
        }
        return parser_ok;
    }

    if (displayIdx == 1) {
        const uint8_t *canisterId = (const uint8_t *)parser_tx_obj.tx_fields.call.canister_id.data;
        const uint8_t canisterIdSize = (uint8_t)parser_tx_obj.tx_fields.call.canister_id.len;

        snprintf(outKey, outKeyLen, "Canister Id");
        return print_principal(canisterId, canisterIdSize, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Neuron Id ");
        return page_hexstring_with_delimiters(parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.p,
                                              parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.len, outVal,
                                              outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemNeuronPermissions(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                                      uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    const sns_NeuronPermissions_t *fields = &parser_tx_obj.tx_fields.call.data.sns_manageNeuron.command.neuronPermissions;
    const candid_Command_t *command = &parser_tx_obj.tx_fields.call.data.sns_manageNeuron.command;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");

        if (command->hash == sns_hash_command_AddNeuronPermissions) {
            pageString(outVal, outValLen, "Add Permissions", pageIdx, pageCount);
        } else if (command->hash == sns_hash_command_RemoveNeuronPermissions) {
            pageString(outVal, outValLen, "Remove Permissions", pageIdx, pageCount);
        } else {
            return parser_unexpected_value;
        }
        return parser_ok;
    }

    if (displayIdx == 1) {
        const uint8_t *canisterId = (const uint8_t *)parser_tx_obj.tx_fields.call.canister_id.data;
        const uint8_t canisterIdSize = (uint8_t)parser_tx_obj.tx_fields.call.canister_id.len;

        snprintf(outKey, outKeyLen, "Canister Id");
        return print_principal(canisterId, canisterIdSize, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Neuron Id ");
        return page_hexstring_with_delimiters(parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.p,
                                              parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.len, outVal,
                                              outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 3 && fields->has_principal) {
        snprintf(outKey, outKeyLen, "Principal Id ");
        return print_principal(fields->principal.ptr, fields->principal.len, outVal, outValLen, pageIdx, pageCount);
    }

    displayIdx -= fields->has_principal ? 4 : 3;
    if (displayIdx < fields->permissionList.list_size || (!fields->has_permissionList && displayIdx == 0)) {
        if (command->hash == sns_hash_command_AddNeuronPermissions) {
            snprintf(outKey, outKeyLen, "Add Permission");
        } else if (command->hash == sns_hash_command_RemoveNeuronPermissions) {
            snprintf(outKey, outKeyLen, "Remove Permission");
        } else {
            return parser_unexpected_value;
        }

        // If permission list is empty, print None
        if (!fields->has_permissionList) {
            snprintf(outVal, outValLen, "None");
            return parser_ok;
        }

        int32_t permission = 0;
        CHECK_PARSER_ERR(getCandidInt32FromVec(fields->permissionList.permissions_list_ptr, &permission,
                                               fields->permissionList.list_size, displayIdx))

        return print_permission(permission, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemCandidTransfer(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                                   uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");
    *pageCount = 1;

    const call_t *fields = &parser_tx_obj.tx_fields.call;

    const bool is_stake_tx = parser_tx_obj.special_transfer_type == neuron_stake_transaction;

    const uint8_t *canister_id = (const uint8_t *)fields->canister_id.data;
    const uint8_t canister_id_len = fields->canister_id.len;
    const token_info_t *token = get_token(canister_id, canister_id_len);

    uint8_t decimals = 0;
    if (token != NULL) {
        decimals = token->decimals;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, is_stake_tx ? "Stake Neuron" : "Send ICP");
        return parser_ok;
    }

    if (app_mode_expert()) {
        if (displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Sender ");
            return print_principal(fields->sender.data, (uint16_t)fields->sender.len, outVal, outValLen, pageIdx, pageCount);
        }

        if (displayIdx == 2) {
            snprintf(outKey, outKeyLen, "Subaccount ");
            if (fields->data.candid_transfer.has_from_subaccount) {
                return page_hexstring_with_delimiters(fields->data.candid_transfer.from_subaccount.p,
                                                      fields->data.candid_transfer.from_subaccount.len, outVal, outValLen,
                                                      pageIdx, pageCount);
            }
            snprintf(outVal, outValLen, "Not set");
            return parser_ok;
        }
        displayIdx -= 2;
    }

    if (displayIdx == 1) {
// The "From account" title might be truncated on Nano devices
// due to the device's limited screen space.
#if defined(TARGET_NANOS)
        snprintf(outKey, outKeyLen, "From ");
#else
        snprintf(outKey, outKeyLen, "From account ");
#endif
        return print_accountBytes(fields->sender, &fields->data.candid_transfer, outVal, outValLen, pageIdx, pageCount);
    }

    if (is_stake_tx) {
        displayIdx++;  // skip field To account
    }

    if (displayIdx == 2) {
// The "To account" title might be truncated on Nano devices
// due to the device's limited screen space.
#if defined(TARGET_NANOS)
        snprintf(outKey, outKeyLen, "To ");
#else
        snprintf(outKey, outKeyLen, "To account ");
#endif
        return page_hexstring_with_delimiters(fields->data.candid_transfer.to, DFINITY_ADDR_LEN, outVal, outValLen, pageIdx,
                                              pageCount);
    }

    if (displayIdx == 3) {
        if (token != NULL) {
            snprintf(outKey, outKeyLen, "Amount (%s)", token->token_symbol);
        } else {
            snprintf(outKey, outKeyLen, "Amount (Tokens)");
        }
        return print_Amount(fields->data.candid_transfer.amount, outVal, outValLen, pageIdx, pageCount, decimals);
    }

    if (displayIdx == 4) {
        if (token != NULL) {
            snprintf(outKey, outKeyLen, "Max fee (%s)", token->token_symbol);
        } else {
            snprintf(outKey, outKeyLen, "Max fee (Tokens)");
        }
        return print_Amount(fields->data.candid_transfer.fee, outVal, outValLen, pageIdx, pageCount, decimals);
    }

    if (displayIdx == 5) {
        snprintf(outKey, outKeyLen, "Memo");
        return print_u64(fields->data.candid_transfer.memo, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemICRCTransfer(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                                 uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    call_t *call = &parser_tx_obj.tx_fields.call;
    const bool icp_canisterId = call->data.icrcTransfer.icp_canister;
    const bool is_stake_tx = parser_tx_obj.special_transfer_type == neuron_stake_transaction;

    const uint8_t *canister_id = (const uint8_t *)call->canister_id.data;
    const uint8_t canister_id_len = call->canister_id.len;
    const token_info_t *token = get_token(canister_id, canister_id_len);

    uint8_t decimals = 0;

    if (token != NULL) {
        decimals = token->decimals;
    }

    if (displayIdx == 0) {
        if (icp_canisterId) {
            snprintf(outKey, outKeyLen, "Transaction type");
            snprintf(outVal, outValLen, is_stake_tx ? "Stake Neuron" : "Send ICP");
        } else {
            if (token != NULL) {
                snprintf(outKey, outKeyLen, "Transaction type");
                snprintf(outVal, outValLen, "Send %s", token->token_symbol);
            } else {
                snprintf(outKey, outKeyLen, "Transaction type");
                snprintf(outVal, outValLen, "Send Tokens");
            }
        }
        return parser_ok;
    }

    // Don't display Canister Id if ICP canister
    if (icp_canisterId) {
        displayIdx++;
    }

    if (displayIdx == 1) {
        const uint8_t *canisterId = (const uint8_t *)call->canister_id.data;
        const uint8_t canisterIdLen = (uint8_t)call->canister_id.len;
        snprintf(outKey, outKeyLen, "Canister Id");

        return print_principal(canisterId, canisterIdLen, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
// The "From account" title might be truncated on Nano devices
// due to the device's limited screen space.
#if defined(TARGET_NANOS)
        snprintf(outKey, outKeyLen, "From ");
#else
        snprintf(outKey, outKeyLen, "From account ");
#endif
        const uint8_t *sender = (uint8_t *)call->sender.data;
        const uint16_t senderLen = (uint16_t)call->sender.len;
        const uint8_t *fromSubaccount = call->data.icrcTransfer.from_subaccount.p;
        const uint16_t fromSubaccountLen = (uint16_t)call->data.icrcTransfer.from_subaccount.len;

        return page_principal_with_subaccount(sender, senderLen, fromSubaccount, fromSubaccountLen, outVal, outValLen,
                                              pageIdx, pageCount, false);
    }

    if (is_stake_tx) {
        displayIdx++;  // skip field To account
    }

    if (displayIdx == 3) {
// The "To account" title might be truncated on Nano devices
// due to the device's limited screen space.
#if defined(TARGET_NANOS)
        snprintf(outKey, outKeyLen, "To ");
#else
        snprintf(outKey, outKeyLen, "To account ");
#endif
        const candid_Principal_t *owner = &call->data.icrcTransfer.account.owner;
        const uint8_t *subaccount = call->data.icrcTransfer.account.subaccount.p;
        const uint16_t subaccountLen = (uint16_t)call->data.icrcTransfer.account.subaccount.len;

        return page_principal_with_subaccount(owner->ptr, owner->len, subaccount, subaccountLen, outVal, outValLen, pageIdx,
                                              pageCount, false);
    }

    if (displayIdx == 4) {
        if (token != NULL) {
            snprintf(outKey, outKeyLen, "Amount (%s)", token->token_symbol);
        } else {
            snprintf(outKey, outKeyLen, "Amount (Tokens)");
        }

        return print_Amount(call->data.icrcTransfer.amount, outVal, outValLen, pageIdx, pageCount, decimals);
    }

    // Skip fee if not present and not icp canister id
    if (!(call->data.icrcTransfer.has_fee || icp_canisterId)) {
        displayIdx++;
    }

    if (displayIdx == 5) {
        char title[50] = {0};
        if (token != NULL) {
            snprintf(title, sizeof(title), "Max fee (%s)", token->token_symbol);
        } else {
            snprintf(title, sizeof(title), "Max fee (Tokens)");
        }

        snprintf(outKey, outKeyLen, "%s", title);
        uint64_t fees = call->data.icrcTransfer.has_fee ? call->data.icrcTransfer.fee : DEFAULT_MAXIMUM_FEES;
        return print_Amount(fees, outVal, outValLen, pageIdx, pageCount, decimals);
    }

    if (displayIdx == 6) {
        snprintf(outKey, outKeyLen, "Memo");
        if (call->data.icrcTransfer.has_memo && call->data.icrcTransfer.memo.len != 0) {
            uint64_t memo = 0;
            // we already checked that len is, at max, 8
            for (uint8_t i = 0; i < (uint8_t)call->data.icrcTransfer.memo.len; i++) {
                memo <<= 8u;
                memo += call->data.icrcTransfer.memo.p[i];
            }
            return print_u64(memo, outVal, outValLen, pageIdx, pageCount);
        }
        snprintf(outVal, outValLen, "0");
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemICRC2Approve(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                                 uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    zemu_log("parser_getItemICRC2Approve\n");
    *pageCount = 1;
    call_t *call = &parser_tx_obj.tx_fields.call;
    const bool icp_canisterId = call->data.icrc2_approve.icp_canister;

    uint8_t *canister_id = call->canister_id.data;
    uint8_t canister_id_len = (uint8_t)call->canister_id.len;
    const token_info_t *token = get_token(canister_id, canister_id_len);

    uint8_t decimals = 0;

    if (token != NULL) {
        decimals = token->decimals;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type ");
#if defined(TARGET_NANOS)
        snprintf(outVal, outValLen, "Allow account to withdraw tokens");
#else
        char title[50] = {0};
        if (token != NULL) {
            snprintf(title, sizeof(title), "Allow another account to withdraw %s", token->token_symbol);
        } else {
            snprintf(title, sizeof(title), "Allow another account to withdraw tokens");
        }

        pageString(outVal, outValLen, title, pageIdx, pageCount);
#endif
        return parser_ok;
    }

    // Don't display Canister Id if ICP canister
    if (icp_canisterId) displayIdx++;

    if (displayIdx == 1) {
        const uint8_t *canisterId = (const uint8_t *)call->canister_id.data;
        const uint8_t canisterIdLen = (uint8_t)call->canister_id.len;
        snprintf(outKey, outKeyLen, "Canister Id");

        return print_principal(canisterId, canisterIdLen, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
#if defined(TARGET_NANOS)
        snprintf(outKey, outKeyLen, "From ");
#else
        snprintf(outKey, outKeyLen, "From account ");
#endif
        const uint8_t *sender = (uint8_t *)call->sender.data;
        const uint16_t senderLen = (uint16_t)call->sender.len;
        const uint8_t *fromSubaccount = call->data.icrc2_approve.from_subaccount.p;
        const uint16_t fromSubaccountLen = (uint16_t)call->data.icrc2_approve.from_subaccount.len;

        return page_principal_with_subaccount(sender, senderLen, fromSubaccount, fromSubaccountLen, outVal, outValLen,
                                              pageIdx, pageCount, true);
    }

    if (displayIdx == 3) {
#if defined(TARGET_NANOS)
        // Removed the allowed part of the tittle
        // nanos screen is too small
        snprintf(outKey, outKeyLen, "Spender ");
#else
        snprintf(outKey, outKeyLen, "Allowed Spender ");
#endif
        const candid_Principal_t *owner = &call->data.icrc2_approve.spender.owner;
        const uint8_t *subaccount = call->data.icrc2_approve.spender.subaccount.p;
        const uint16_t subaccountLen = (uint16_t)call->data.icrc2_approve.spender.subaccount.len;

        return page_principal_with_subaccount(owner->ptr, owner->len, subaccount, subaccountLen, outVal, outValLen, pageIdx,
                                              pageCount, true);
    }

    if (displayIdx == 4) {
        if (token != NULL) {
            snprintf(outKey, outKeyLen, "Amount (%s)", token->token_symbol);
        } else {
            snprintf(outKey, outKeyLen, "Amount (Tokens)");
        }

        if (call->data.icrc2_approve.amount == 0) {
            snprintf(outVal, outValLen, "0");
            return parser_ok;
        }
        return print_Amount(call->data.icrc2_approve.amount, outVal, outValLen, pageIdx, pageCount, decimals);
    }

    // Skip allowance if not present and not icp canister id
    if (!(call->data.icrc2_approve.has_expected_allowance)) displayIdx++;

    if (displayIdx == 5) {
        char title[50] = {0};
        if (token != NULL) {
            snprintf(title, sizeof(title), "Allowance (%s)", token->token_symbol);
        } else {
            snprintf(title, sizeof(title), "Allowance (Tokens)");
        }

        snprintf(outKey, outKeyLen, "%s", title);
        uint64_t allowance = call->data.icrc2_approve.expected_allowance;
        if (allowance == 0) {
            snprintf(outVal, outValLen, "0");
            return parser_ok;
        }
        return print_Amount(allowance, outVal, outValLen, pageIdx, pageCount, decimals);
    }

    // Skip fee if not present and not icp canister id
    if (!(call->data.icrc2_approve.has_fee || icp_canisterId)) displayIdx++;

    if (displayIdx == 6) {
        char title[50] = {0};
        if (token != NULL) {
            snprintf(title, sizeof(title), "Max fee (%s)", token->token_symbol);
        } else {
            snprintf(title, sizeof(title), "Max fee (Tokens)");
        }

        snprintf(outKey, outKeyLen, "%s", title);
        uint64_t fees = call->data.icrc2_approve.has_fee ? call->data.icrc2_approve.fee : DEFAULT_MAXIMUM_FEES;
        if (fees == 0) {
            snprintf(outVal, outValLen, "0");
            return parser_ok;
        }
        return print_Amount(fees, outVal, outValLen, pageIdx, pageCount, decimals);
    }

    if (displayIdx == 7) {
        snprintf(outKey, outKeyLen, "Memo");
        if (call->data.icrc2_approve.has_memo && call->data.icrc2_approve.memo.len != 0) {
            uint64_t memo = 0;
            // we already checked that len is, at max, 8
            for (uint8_t i = 0; i < (uint8_t)call->data.icrc2_approve.memo.len; i++) {
                memo <<= 8u;
                memo += call->data.icrc2_approve.memo.p[i];
            }
            return print_u64(memo, outVal, outValLen, pageIdx, pageCount);
        }
        snprintf(outVal, outValLen, "0");
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemDisburseSNS(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                                uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    const sns_Disburse_t *fields = &parser_tx_obj.tx_fields.call.data.sns_manageNeuron.command.sns_disburse;

    uint8_t *canister_id = parser_tx_obj.tx_fields.call.canister_id.data;
    uint8_t canister_id_len = sizeof(parser_tx_obj.tx_fields.call.canister_id);
    const token_info_t *token = get_token(canister_id, canister_id_len);

    uint8_t decimals = 0;

    if (token != NULL) {
        decimals = token->decimals;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Disburse Neuron");
        return parser_ok;
    }

    if (displayIdx == 1) {
        const uint8_t *canisterId = (uint8_t *)&parser_tx_obj.tx_fields.call.canister_id.data;
        const uint8_t canisterIdSize = (uint8_t)parser_tx_obj.tx_fields.call.canister_id.len;

        snprintf(outKey, outKeyLen, "Canister Id");
        return print_principal(canisterId, canisterIdSize, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Neuron Id ");
        return page_hexstring_with_delimiters(parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.p,
                                              parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.len, outVal,
                                              outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Disburse to ");
        if (!fields->has_account) {
            return print_principal(parser_tx_obj.tx_fields.call.sender.data, DFINITY_PRINCIPAL_LEN, outVal, outValLen,
                                   pageIdx, pageCount);
        }
        // assume has_account
        const uint8_t *principal =
            fields->account.has_owner ? fields->account.owner.ptr : parser_tx_obj.tx_fields.call.sender.data;
        const uint8_t principalLen = fields->account.has_owner ? fields->account.owner.len : DFINITY_PRINCIPAL_LEN;
        if (fields->account.has_subaccount) {
            return page_principal_with_subaccount(principal, principalLen, fields->account.subaccount.p,
                                                  (uint16_t)fields->account.subaccount.len, outVal, outValLen, pageIdx,
                                                  pageCount, false);
        } else {
            return print_principal(principal, DFINITY_PRINCIPAL_LEN, outVal, outValLen, pageIdx, pageCount);
        }
    }
    if (displayIdx == 4) {
        if (token != NULL) {
            snprintf(outKey, outKeyLen, "Amount (%s)", token->token_symbol);
        } else {
            snprintf(outKey, outKeyLen, "Amount (Tokens)");
        }
        if (fields->has_amount) {
            return print_Amount(fields->amount, outVal, outValLen, pageIdx, pageCount, decimals);
        } else {
            snprintf(outVal, outValLen, "%s", "All");
            return parser_ok;
        }
    }
    return parser_no_data;
}

static parser_error_t parser_getItemSNSStakeMaturity(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                                     uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    const candid_StakeMaturity_t *fields = &parser_tx_obj.tx_fields.call.data.sns_manageNeuron.command.stake;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        pageString(outVal, outValLen, "Stake Maturity", pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 1) {
        const uint8_t *canisterId = (uint8_t *)&parser_tx_obj.tx_fields.call.canister_id.data;
        const uint8_t canisterIdSize = (uint8_t)parser_tx_obj.tx_fields.call.canister_id.len;

        snprintf(outKey, outKeyLen, "Canister Id");
        return print_principal(canisterId, canisterIdSize, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Neuron Id ");
        return page_hexstring_with_delimiters(parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.p,
                                              parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.len, outVal,
                                              outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 3 && fields->has_percentage_to_stake) {
        snprintf(outKey, outKeyLen, "Percentage to stake");
        snprintf(outVal, outValLen, "%d", fields->percentage_to_stake);
        return parser_ok;
    }
    return parser_no_data;
}

static parser_error_t parser_getItemSNSSetDissolveDelay(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                                        uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        pageString(outVal, outValLen, "Set Dissolve Delay", pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 1) {
        const uint8_t *canisterId = (uint8_t *)&parser_tx_obj.tx_fields.call.canister_id.data;
        const uint8_t canisterIdSize = (uint8_t)parser_tx_obj.tx_fields.call.canister_id.len;

        snprintf(outKey, outKeyLen, "Canister Id");
        return print_principal(canisterId, canisterIdSize, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Neuron Id ");
        return page_hexstring_with_delimiters(parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.p,
                                              parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.len, outVal,
                                              outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Dissolve Time");
        uint64_t dissolve_timestamp_seconds = parser_tx_obj.tx_fields.call.data.sns_manageNeuron.command.configure.operation
                                                  .setDissolveTimestamp.dissolve_timestamp_seconds;

        timedata_t td = {0};
        zxerr_t zxerr = decodeTime(&td, dissolve_timestamp_seconds);
        if (zxerr != zxerr_ok) {
            return parser_unexpected_value;
        }

        char buffer[PRINT_NUMBER_BUFFER_LEN] = {0};
        // YYYYmmdd HH:MM:SS
        snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d UTC", td.tm_year, td.tm_mon, td.tm_day, td.tm_hour,
                 td.tm_min, td.tm_sec);

        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }
    return parser_no_data;
}

static parser_error_t parser_getItemRefreshNeuronVotingPower(uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                                             char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                                             uint8_t *pageCount) {
    *pageCount = 1;
    const candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        pageString(outVal, outValLen, "Refresh Neuron Voting Power", pageIdx, pageCount);
        return parser_ok;
    }
    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        return parser_unexpected_type;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemSetNeuronVisibility(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal,
                                                        uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    const candid_SetVisibility_t *neuron_visibility =
        &parser_tx_obj.tx_fields.call.data.candid_manageNeuron.command.configure.operation.set_visibility;

    const candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;

    // Just in case, this check was done at parsing
    if (neuron_visibility->has_visibility && (neuron_visibility->visibility < 1 || neuron_visibility->visibility > 2)) {
        return parser_unexpected_value;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        // visibility: 2 -> public
        // visibility: 1 -> private
        // visibility value enforced at parsing
        snprintf(outVal, outValLen, "%s", neuron_visibility->visibility == 2 ? "Make Neuron Public" : "Make Neuron Private");

        return parser_ok;
    }
    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        return parser_unexpected_type;
    }

    return parser_no_data;
}

__Z_INLINE parser_error_t parser_getItemManageNeuron(const parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                     uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                                     uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");
    *pageCount = 1;

    const uint8_t num_items = _getNumItems(ctx, &parser_tx_obj);
    PARSER_ASSERT_OR_ERROR(num_items > 0, parser_unexpected_number_items)
    CHECK_APP_CANARY()

    manageNeuron_e mn_type;
    CHECK_PARSER_ERR(getManageNeuronType(&parser_tx_obj, &mn_type))

    switch (mn_type) {
        case Configure_SetDissolvedTimestamp: {
            return parser_getItemSetDissolveTimestamp(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        case Configure_ChangeAutoStakeMaturity: {
            return parser_getItemChangeAutoStakeMaturity(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                         pageCount);
        }
        case SpawnCandid: {
            return parser_getItemSpawnCandid(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        case Split: {
            return parser_getItemSplit(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        case Merge: {
            return parser_getItemMerge(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        case DisburseMaturity: {
            return parser_getItemDisburseMaturity(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }

        case StakeMaturityCandid: {
            return parser_getItemStakeMaturityCandid(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        case DisburseCandid:
            return parser_getItemDisburseCandid(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        case RegisterVoteCandid:
            return parser_getItemRegisterVoteCandid(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        case FollowCandid:
            return parser_getItemFollowCandid(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        case Configure_IncreaseDissolveDelayCandid: {
            return parser_getItemIncreaseDissolveDelayCandid(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                             pageCount);
        }
        case Configure_AddHotkeyCandid:
        case Configure_RemoveHotkeyCandid:
            return parser_getItemConfigureAddRemoveHotkeyCandid(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                                pageCount);
        case Configure_JoinNeuronsFundCandid:
        case Configure_LeaveNeuronsFundCandid:
        case Configure_StartDissolvingCandid:
        case Configure_StopDissolvingCandid:
            return parser_getItemConfigureNoElementsCandid(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                           pageCount);
        case Configure_SetVisibility:
            return parser_getItemSetNeuronVisibility(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        case SNS_Configure_StartDissolving:
        case SNS_Configure_StopDissolving:
            return parser_getItemConfigureDissolvingSNS(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                        pageCount);
        case SNS_AddNeuronPermissions:
        case SNS_RemoveNeuronPermissions: {
            return parser_getItemNeuronPermissions(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        case SNS_Disburse:
            return parser_getItemDisburseSNS(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        case SNS_StakeMaturity:
            return parser_getItemSNSStakeMaturity(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        case SNS_Configure_SetDissolveDelay:
            return parser_getItemSNSSetDissolveDelay(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        case NNS_RefreshVotingPower:
            return parser_getItemRefreshNeuronVotingPower(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                          pageCount);

        default:
            return parser_no_data;
    }
}

parser_error_t parser_getItemCandid(const parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                    char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);

    *pageCount = 1;
    switch (parser_tx_obj.tx_fields.call.method_type) {
        case candid_manageneuron: {
            return parser_getItemManageNeuron(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }

        case candid_updatenodeprovider: {
            return parser_getItemListUpdateNodeProvider(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                        pageCount);
        }

        case candid_listneurons: {
            return parser_getItemListNeuronsCandid(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }

        case candid_transfer:
            return parser_getItemCandidTransfer(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case candid_icrc_transfer:
            return parser_getItemICRCTransfer(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case candid_icrc2_approve:
            return parser_getItemICRC2Approve(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        default:
            zemu_log("Candid type not supported\n");
            break;
    }

    return parser_unexpected_type;
}
