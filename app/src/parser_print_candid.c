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
#include "parser_print_helper.h"
#include "candid_parser.h"
#include "parser_txdef.h"
#include "timeutils.h"
#include <zxformat.h>

#define DEFAULT_MAXIMUM_FEES 10000

__Z_INLINE parser_error_t print_permission(int32_t permission, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    switch (permission)
    {
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

static parser_error_t parser_getItemLeaveCommunityFund(uint8_t displayIdx,
                                                       char *outKey, uint16_t outKeyLen,
                                                       char *outVal, uint16_t outValLen,
                                                       uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    PARSER_ASSERT_OR_ERROR(fields->command.hash == hash_command_Configure, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.has_operation, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.hash == hash_operation_LeaveCommunityFund,
                           parser_unexpected_value)

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Leave Community Fund");
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

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemSetDissolveTimestamp(uint8_t displayIdx,
                                                         char *outKey, uint16_t outKeyLen,
                                                         char *outVal, uint16_t outValLen,
                                                         uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    PARSER_ASSERT_OR_ERROR(fields->command.hash == hash_command_Configure, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.has_operation, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.hash == hash_operation_SetDissolvedTimestamp,
                           parser_unexpected_value)

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Set Dissolve Delay");
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

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Dissolve Time");
        uint64_t dissolve_timestamp_seconds = fields->command.configure.operation.setDissolveTimestamp.dissolve_timestamp_seconds;

        timedata_t td;
        zxerr_t zxerr = decodeTime(&td, dissolve_timestamp_seconds);
        if (zxerr != zxerr_ok) {
            return parser_unexpected_value;
        }

        char tmpBuffer[100];
        // YYYYmmdd HH:MM:SS
        snprintf(tmpBuffer, sizeof(tmpBuffer), "%04d-%02d-%02d %02d:%02d:%02d UTC",
                 td.tm_year, td.tm_mon, td.tm_day,
                 td.tm_hour, td.tm_min, td.tm_sec
        );

        pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemChangeAutoStakeMaturity(uint8_t displayIdx,
                                                            char *outKey, uint16_t outKeyLen,
                                                            char *outVal, uint16_t outValLen,
                                                            uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    PARSER_ASSERT_OR_ERROR(fields->command.hash == hash_command_Configure, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.has_operation, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.hash == hash_operation_ChangeAutoStakeMaturity,
                           parser_unexpected_value)

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Set Auto Stake Maturity");
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

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Auto stake");
        snprintf(outVal, outValLen, fields->command.configure.operation.autoStakeMaturity.requested_setting_for_auto_stake_maturity ? "true" : "false");
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemIncreaseDissolveDelayCandid(uint8_t displayIdx,
                                                            char *outKey, uint16_t outKeyLen,
                                                            char *outVal, uint16_t outValLen,
                                                            uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    PARSER_ASSERT_OR_ERROR(fields->command.hash == hash_command_Configure, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.has_operation, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.hash == hash_operation_IncreaseDissolveDelay,
                           parser_unexpected_value)

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Increase Dissolve Delay");
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

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Additional Delay");

        if (fields->command.configure.operation.increaseDissolveDelay.dissolve_timestamp_seconds == 0) {
            snprintf(outVal, outValLen, "0s");
            return parser_ok;
        }

        char buffer[100];
        MEMZERO(buffer, sizeof(buffer));
        uint64_t value = 0;
        MEMCPY(&value,
               &fields->command.configure.operation.increaseDissolveDelay.dissolve_timestamp_seconds,
               4);

        CHECK_PARSER_ERR(parser_printDelay(value, buffer, sizeof(buffer)))
        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemSpawnCandid(uint8_t displayIdx,
                                          char *outKey, uint16_t outKeyLen,
                                          char *outVal, uint16_t outValLen,
                                          uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;

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

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2 && has_percentage_to_spawn) {
        snprintf(outKey, outKeyLen, "Percentage to spawn");
        snprintf(outVal, outValLen, "%d", fields->command.spawn.percentage_to_spawn);
        return parser_ok;
    }

    if ((displayIdx == 2 && !has_percentage_to_spawn) ||
        (displayIdx == 3 && has_percentage_to_spawn)) {
        snprintf(outKey, outKeyLen, "Controller");
        if (!fields->command.spawn.has_controller) {

            snprintf(outVal, outValLen, "Self");
            return parser_ok;
        }

        //Paged fields need space ending
        snprintf(outKey, outKeyLen, "Controller ");
        return print_textual(fields->command.spawn.new_controller,
                             29,
                             outVal, outValLen,
                             pageIdx, pageCount);
    }

    if (fields->command.spawn.has_nonce &&
        ((displayIdx == 3 && !has_percentage_to_spawn) || displayIdx == 4)) {
        snprintf(outKey, outKeyLen, "Nonce");
        return print_u64(fields->command.spawn.nonce, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemStakeMaturityCandid(uint8_t displayIdx,
                                                        char *outKey, uint16_t outKeyLen,
                                                        char *outVal, uint16_t outValLen,
                                                        uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;

    const uint8_t has_percentage_to_stake = fields->command.stake.has_percentage_to_stake;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Stake Maturity Neuron");
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

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2 && has_percentage_to_stake) {
        snprintf(outKey, outKeyLen, "Percentage to stake");
        snprintf(outVal, outValLen, "%d", fields->command.stake.percentage_to_stake);
        return parser_ok;
    }
    return parser_no_data;
}

static parser_error_t parser_getItemSplit(uint8_t displayIdx,
                                          char *outKey, uint16_t outKeyLen,
                                          char *outVal, uint16_t outValLen,
                                          uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    PARSER_ASSERT_OR_ERROR(fields->command.hash == hash_command_Split, parser_unexpected_value)

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

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Amount (ICP)");
        return print_ICP(fields->command.split.amount_e8s, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemMerge(uint8_t displayIdx,
                                          char *outKey, uint16_t outKeyLen,
                                          char *outVal, uint16_t outValLen,
                                          uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
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

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemListNeuronsCandid(uint8_t displayIdx,
                                                      char *outKey, uint16_t outKeyLen,
                                                      char *outVal, uint16_t outValLen,
                                                      uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    candid_ListNeurons_t *fields = &parser_tx_obj.tx_fields.call.data.candid_listNeurons;

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

static parser_error_t parser_getItemListUpdateNodeProvider(__Z_UNUSED const parser_context_t *_ctx,
                                                           uint8_t displayIdx,
                                                           char *outKey, uint16_t outKeyLen,
                                                           char *outVal, uint16_t outValLen,
                                                           uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    candid_UpdateNodeProvider_t *fields = &parser_tx_obj.tx_fields.call.data.candid_updateNodeProvider;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Set Node Provider : Reward Account");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Reward Account ");
        char buffer[100];
        zxerr_t err = print_hexstring(buffer, sizeof(buffer),
                                      fields->account_identifier.p,
                                      fields->account_identifier.len);
        if (err != zxerr_ok) {
            return parser_unexpected_error;
        }

        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemConfigureDissolving(uint8_t displayIdx,
                                                        char *outKey, uint16_t outKeyLen,
                                                        char *outVal, uint16_t outValLen,
                                                        uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    candid_Command_t *command = &parser_tx_obj.tx_fields.call.data.sns_manageNeuron.command;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");

        if (command->configure.operation.hash == hash_operation_StartDissolving) {
            snprintf(outVal, outValLen, "Start Dissolve Neuron");
        } else if (command->configure.operation.hash == hash_operation_StopDissolving) {
            snprintf(outVal, outValLen, "Stop Dissolve Neuron");
        } else {
            return parser_unexpected_value;
        }
        return parser_ok;
    }

    if (displayIdx == 1) {
        const uint8_t *canisterId = (const uint8_t*) parser_tx_obj.tx_fields.call.canister_id.data;
        const size_t canisterIdSize = parser_tx_obj.tx_fields.call.canister_id.len;

        snprintf(outKey, outKeyLen, "Canister Id");
        return print_canisterId(canisterId, canisterIdSize,
                                outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Neuron Id ");
        const uint8_t CHARS_PER_PAGE = 24;
        uint8_t buffer[100] = {0};
        subaccount_hexstring(parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.p,
                                  parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.len,
                                  buffer, sizeof(buffer), pageCount);
        snprintf(outVal, CHARS_PER_PAGE + 1, "%s", (const char*) buffer + pageIdx * CHARS_PER_PAGE);

        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemNeuronPermissions(uint8_t displayIdx,
                                                        char *outKey, uint16_t outKeyLen,
                                                        char *outVal, uint16_t outValLen,
                                                        uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    sns_NeuronPermissions_t *fields = &parser_tx_obj.tx_fields.call.data.sns_manageNeuron.command.neuronPermissions;
    candid_Command_t *command = &parser_tx_obj.tx_fields.call.data.sns_manageNeuron.command;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");

        if (command->hash == sns_hash_command_AddNeuronPermissions) {
            pageString(outVal, outValLen, "Add Neuron Permissions", pageIdx, pageCount);
        } else if (command->hash == sns_hash_command_RemoveNeuronPermissions) {
            pageString(outVal, outValLen, "Remove Neuron Permissions", pageIdx, pageCount);
        } else {
            return parser_unexpected_value;
        }
        return parser_ok;
    }

    if (displayIdx == 1) {
        const uint8_t *canisterId = (const uint8_t*) parser_tx_obj.tx_fields.call.canister_id.data;
        const size_t canisterIdSize = parser_tx_obj.tx_fields.call.canister_id.len;

        snprintf(outKey, outKeyLen, "Canister Id");
        return print_canisterId(canisterId, canisterIdSize,
                                outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Neuron Id ");
        const uint8_t CHARS_PER_PAGE = 24;
        uint8_t buffer[100] = {0};
        subaccount_hexstring(parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.p,
                                  parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.len,
                                  buffer, sizeof(buffer), pageCount);
        snprintf(outVal, CHARS_PER_PAGE + 1, "%s", (const char*) buffer + pageIdx * CHARS_PER_PAGE);

        return parser_ok;
    }

    if (displayIdx == 3 && fields->has_principal) {
        snprintf(outKey, outKeyLen, "Principal Id ");
        return print_textual(fields->principal, DFINITY_PRINCIPAL_LEN, outVal, outValLen, pageIdx, pageCount);
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

static parser_error_t parser_getItemICRCTransfer(uint8_t displayIdx,
                                                 char *outKey, uint16_t outKeyLen,
                                                 char *outVal, uint16_t outValLen,
                                                 uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    call_t *call = &parser_tx_obj.tx_fields.call;
    const bool icp_canisterId = call->data.icrcTransfer.icp_canister;

    if (displayIdx == 0) {
        if (icp_canisterId) {
            snprintf(outKey, outKeyLen, "Send ICP");
        } else {
            snprintf(outKey, outKeyLen, "Send Tokens");
        }
        return parser_ok;
    }

    // Don't display Canister Id if ICP canister
    if (icp_canisterId) displayIdx++;

    if (displayIdx == 1) {
        const uint8_t *canisterId = (const uint8_t*) call->canister_id.data;
        const size_t canisterIdLen = call->canister_id.len;
        snprintf(outKey, outKeyLen, "Canister Id");

        return print_canisterId(canisterId, canisterIdLen,
                                outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "From account ");
        const uint8_t *sender = (uint8_t*) call->sender.data;
        const size_t senderLen = call->sender.len;
        const uint8_t *fromSubaccount = (uint8_t*) call->data.icrcTransfer.from_subaccount.p;
        const size_t fromSubaccountLen = call->data.icrcTransfer.from_subaccount.len;

        return print_principal_with_subaccount(sender, senderLen, fromSubaccount, fromSubaccountLen,
                                               outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "To account ");
        const uint8_t *owner = call->data.icrcTransfer.account.owner;
        const uint8_t *subaccount = call->data.icrcTransfer.account.subaccount.p;
        const uint16_t subaccountLen = call->data.icrcTransfer.account.subaccount.len;

        return print_principal_with_subaccount(owner, DFINITY_PRINCIPAL_LEN, subaccount, subaccountLen,
                                               outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 4) {
        const char *title = icp_canisterId ? "Payment (ICP)" : "Payment (Tokens)";
        snprintf(outKey, outKeyLen, "%s", title);

        return print_ICP(call->data.icrcTransfer.amount, outVal, outValLen, pageIdx, pageCount);
    }

    // Skip fee if not present and not icp canister id
    if (!(call->data.icrcTransfer.has_fee || icp_canisterId)) displayIdx++;
    if (displayIdx == 5) {
        const char *title = icp_canisterId ? "Maximum fee (ICP)" : "Maximum fee (Tokens)";
        snprintf(outKey, outKeyLen, "%s", title);

        uint64_t fees = call->data.icrcTransfer.has_fee ? call->data.icrcTransfer.fee : DEFAULT_MAXIMUM_FEES;
        return print_ICP(fees, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 6) {
        snprintf(outKey, outKeyLen, "Memo");
        if (call->data.icrcTransfer.has_memo) {
            uint64_t memo = uint64_from_BEarray(call->data.icrcTransfer.memo.p);
            return print_u64(memo, outVal, outValLen, pageIdx, pageCount);
        }
        snprintf(outVal, outValLen, "0");
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemDisburse(uint8_t displayIdx,
                                             char *outKey, uint16_t outKeyLen,
                                             char *outVal, uint16_t outValLen,
                                             uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    sns_Disburse_t *fields = &parser_tx_obj.tx_fields.call.data.sns_manageNeuron.command.disburse;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Disburse Neuron");
        return parser_ok;
    }

    if (displayIdx == 1) {
        uint8_t *canisterId = (uint8_t*) &parser_tx_obj.tx_fields.call.canister_id.data;
        const size_t canisterIdSize = parser_tx_obj.tx_fields.call.canister_id.len;

        snprintf(outKey, outKeyLen, "Canister Id");
        return print_canisterId(canisterId, canisterIdSize,
                                outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Neuron Id ");
        const uint8_t CHARS_PER_PAGE = 24;
        uint8_t buffer[100] = {0};
        subaccount_hexstring(parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.p,
                                  parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.len,
                                  buffer, sizeof(buffer), pageCount);
        snprintf(outVal, CHARS_PER_PAGE + 1, "%s", (const char*) buffer + pageIdx * CHARS_PER_PAGE);

        return parser_ok;
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Disburse to ");
        if (!fields->has_account) {
            return print_textual(parser_tx_obj.tx_fields.call.sender.data, DFINITY_PRINCIPAL_LEN,
                                   outVal, outValLen, pageIdx, pageCount);
        }
        // assume has_account
        const uint8_t *principal = fields->account.has_owner
            ? fields->account.owner
            : parser_tx_obj.tx_fields.call.sender.data;
        if (fields->account.has_subaccount) {
            return print_principal_with_subaccount(principal, DFINITY_PRINCIPAL_LEN,
                                                   fields->account.subaccount.p, fields->account.subaccount.len,
                                                   outVal, outValLen, pageIdx, pageCount);
        } else {
            return print_textual((uint8_t *)principal, DFINITY_PRINCIPAL_LEN,
                                   outVal, outValLen, pageIdx, pageCount);
        }
    }
    if (displayIdx == 4) {
        snprintf(outKey, outKeyLen, "Amount");
        if (fields->has_amount) {
            return print_ICP(fields->amount, outVal, outValLen, pageIdx, pageCount);
        } else {
            snprintf(outVal, outValLen, "All");
            return parser_ok;
        }
    }
    return parser_no_data;
}

static parser_error_t parser_getItemSNSStakeMaturity(uint8_t displayIdx,
                                             char *outKey, uint16_t outKeyLen,
                                             char *outVal, uint16_t outValLen,
                                             uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    candid_StakeMaturity_t *fields = &parser_tx_obj.tx_fields.call.data.sns_manageNeuron.command.stake;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Stake Maturity Neuron");
        return parser_ok;
    }

    if (displayIdx == 1) {
        uint8_t *canisterId = (uint8_t*) &parser_tx_obj.tx_fields.call.canister_id.data;
        const size_t canisterIdSize = parser_tx_obj.tx_fields.call.canister_id.len;

        snprintf(outKey, outKeyLen, "Canister Id");
        return print_canisterId(canisterId, canisterIdSize,
                                outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Neuron Id ");
        const uint8_t CHARS_PER_PAGE = 24;
        uint8_t buffer[100] = {0};
        subaccount_hexstring(parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.p,
                                  parser_tx_obj.tx_fields.call.data.sns_manageNeuron.subaccount.len,
                                  buffer, sizeof(buffer), pageCount);
        snprintf(outVal, CHARS_PER_PAGE + 1, "%s", (const char*) buffer + pageIdx * CHARS_PER_PAGE);

        return parser_ok;
    }

    if (displayIdx == 3 && fields->has_percentage_to_stake) {
        snprintf(outKey, outKeyLen, "Percentage to stake");
        snprintf(outVal, outValLen, "%d", fields->percentage_to_stake);
        return parser_ok;
    }
    return parser_no_data;
}

__Z_INLINE parser_error_t parser_getItemManageNeuron(const parser_context_t *ctx,
                                                     uint8_t displayIdx,
                                                     char *outKey, uint16_t outKeyLen,
                                                     char *outVal, uint16_t outValLen,
                                                     uint8_t pageIdx, uint8_t *pageCount) {

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
        case Configure_LeaveCommunityFund: {
            return parser_getItemLeaveCommunityFund(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        case Configure_SetDissolvedTimestamp: {
            return parser_getItemSetDissolveTimestamp(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        case Configure_ChangeAutoStakeMaturity: {
            return parser_getItemChangeAutoStakeMaturity(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
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
        case StakeMaturityCandid: {
            return parser_getItemStakeMaturityCandid(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        case Configure_IncreaseDissolveDelayCandid: {
            return parser_getItemIncreaseDissolveDelayCandid(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        case SNS_Configure_StartDissolving:
        case SNS_Configure_StopDissolving:
            return parser_getItemConfigureDissolving(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        case SNS_AddNeuronPermissions:
        case SNS_RemoveNeuronPermissions: {
            return parser_getItemNeuronPermissions(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        case SNS_Disburse:
            return parser_getItemDisburse(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        case SNS_StakeMaturity:
            return parser_getItemSNSStakeMaturity(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        default:
            return parser_no_data;
    }
}

parser_error_t parser_getItemCandid(const parser_context_t *ctx,
                                    uint8_t displayIdx,
                                    char *outKey, uint16_t outKeyLen,
                                    char *outVal, uint16_t outValLen,
                                    uint8_t pageIdx, uint8_t *pageCount) {

    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);

    *pageCount = 1;
    switch (parser_tx_obj.tx_fields.call.method_type) {
        case candid_manageneuron: {
            return parser_getItemManageNeuron(ctx, displayIdx,
                                                outKey, outKeyLen,
                                                outVal, outValLen,
                                                pageIdx, pageCount);
        }

        case candid_updatenodeprovider: {
            return parser_getItemListUpdateNodeProvider(ctx, displayIdx,
                                                        outKey, outKeyLen,
                                                        outVal, outValLen,
                                                        pageIdx, pageCount);
        }

        case candid_listneurons: {
            return parser_getItemListNeuronsCandid(displayIdx,
                                                    outKey, outKeyLen,
                                                    outVal, outValLen,
                                                    pageIdx, pageCount);
        }

        case candid_icrc_transfer: {
            return parser_getItemICRCTransfer(displayIdx,
                                              outKey, outKeyLen,
                                              outVal, outValLen,
                                              pageIdx, pageCount);
        }

        default:
            ZEMU_LOGF(50, "Candid type not supported\n")
            break;
    }

    return parser_unexpected_type;
}
