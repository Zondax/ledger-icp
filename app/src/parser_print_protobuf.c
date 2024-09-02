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
#include "parser_print_protobuf.h"
#include "parser_print_helper.h"
#include "parser_print_strings.h"
#include "parser_txdef.h"
#include <zxformat.h>
#include <app_mode.h>

__Z_INLINE parser_error_t print_accountBytes(sender_t sender,
                                             const SendRequest *sendrequest,
                                             char *outVal, uint16_t outValLen,
                                             uint8_t pageIdx, uint8_t *pageCount) {
    uint8_t address[32];
    MEMZERO(address, sizeof(address));

    zxerr_t err = crypto_principalToSubaccount(sender.data, (uint16_t) sender.len,
                                               sendrequest->from_subaccount.sub_account, 32,
                                               address, sizeof(address));
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    return page_hexstring_with_delimiters(address, sizeof(address), outVal, outValLen, pageIdx, pageCount);
}

static parser_error_t parser_getItemTokenTransfer(uint8_t displayIdx,
                                                  char *outKey, uint16_t outKeyLen,
                                                  char *outVal, uint16_t outValLen,
                                                  uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");
    *pageCount = 1;

    const call_t *fields = &parser_tx_obj.tx_fields.call;

    const bool is_stake_tx = parser_tx_obj.special_transfer_type == neuron_stake_transaction;
    if (is_stake_tx) {
        return parser_unexpected_error;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Send ICP");
        return parser_ok;
    }

    if (app_mode_expert()) {
        if (displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Sender ");
            return print_principal(fields->sender.data, (uint16_t) fields->sender.len, outVal, outValLen, pageIdx, pageCount);
        }

        if (displayIdx == 2) {
            snprintf(outKey, outKeyLen, "Subaccount ");
            if (fields->data.SendRequest.has_from_subaccount) {
                return page_hexstring_with_delimiters(fields->data.SendRequest.from_subaccount.sub_account,
                                                      DFINITY_ADDR_LEN, outVal, outValLen, pageIdx, pageCount);
            }
            snprintf(outVal, outValLen, "Not set");
            return parser_ok;
        }
        displayIdx -= 2;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "From account");
        return print_accountBytes(fields->sender, &fields->data.SendRequest,
                                  outVal, outValLen,
                                  pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        PARSER_ASSERT_OR_ERROR(fields->data.SendRequest.has_to, parser_unexpected_number_items)
        snprintf(outKey, outKeyLen, "To account ");
        return page_hexstring_with_delimiters(fields->data.SendRequest.to.hash, 32,
                                              outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Amount (ICP)");
        PARSER_ASSERT_OR_ERROR(fields->data.SendRequest.payment.has_receiver_gets, parser_unexpected_number_items)
        return print_ICP(fields->data.SendRequest.payment.receiver_gets.e8s,
                         outVal, outValLen,
                         pageIdx, pageCount);
    }

    if (displayIdx == 4) {
        snprintf(outKey, outKeyLen, "Maximum fee (ICP)");
        PARSER_ASSERT_OR_ERROR(fields->data.SendRequest.has_max_fee, parser_unexpected_number_items)
        return print_ICP(fields->data.SendRequest.max_fee.e8s,
                         outVal, outValLen,
                         pageIdx, pageCount);
    }

    if (displayIdx == 5) {
        snprintf(outKey, outKeyLen, "Memo");
        PARSER_ASSERT_OR_ERROR(fields->data.SendRequest.has_memo, parser_unexpected_number_items)
        return print_u64(fields->data.SendRequest.memo.memo, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemStakeNeuron(uint8_t displayIdx,
                                                char *outKey, uint16_t outKeyLen,
                                                char *outVal, uint16_t outValLen,
                                                uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");
    *pageCount = 1;

    const call_t *fields = &parser_tx_obj.tx_fields.call;

    const bool is_stake_tx = parser_tx_obj.special_transfer_type == neuron_stake_transaction;
    if (!is_stake_tx) {
        return parser_unexpected_error;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Stake Neuron");
        return parser_ok;
    }

    if (app_mode_expert()) {
        if (displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Sender ");
            return print_principal(fields->sender.data, (uint16_t) fields->sender.len, outVal, outValLen, pageIdx, pageCount);
        }

        if (displayIdx == 2) {
            snprintf(outKey, outKeyLen, "Subaccount ");
            if (fields->data.SendRequest.has_from_subaccount) {
                return page_hexstring_with_delimiters(fields->data.SendRequest.from_subaccount.sub_account, 32,
                                                      outVal, outValLen, pageIdx, pageCount);
            }
            snprintf(outVal, outValLen, "Not set");
            return parser_ok;
        }
        displayIdx -= 2;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "From account");
        return print_accountBytes(fields->sender, &fields->data.SendRequest,
                                  outVal, outValLen,
                                  pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Amount (ICP)");
        PARSER_ASSERT_OR_ERROR(fields->data.SendRequest.payment.has_receiver_gets, parser_unexpected_number_items)
        return print_ICP(fields->data.SendRequest.payment.receiver_gets.e8s,
                         outVal, outValLen,
                         pageIdx, pageCount);
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Maximum fee (ICP)");
        PARSER_ASSERT_OR_ERROR(fields->data.SendRequest.has_max_fee, parser_unexpected_number_items)
        return print_ICP(fields->data.SendRequest.max_fee.e8s,
                         outVal, outValLen,
                         pageIdx, pageCount);
    }

    if (displayIdx == 4) {
        snprintf(outKey, outKeyLen, "Memo");
        PARSER_ASSERT_OR_ERROR(fields->data.SendRequest.has_memo, parser_unexpected_number_items)
        return print_u64(fields->data.SendRequest.memo.memo, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemClaimNeuron(uint8_t displayIdx,
                                                char *outKey, uint16_t outKeyLen,
                                                char *outVal, uint16_t outValLen) {
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Claim Neurons");
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemListNeurons(uint8_t displayIdx,
                                                char *outKey, uint16_t outKeyLen,
                                                char *outVal, uint16_t outValLen) {
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "List Own Neurons");
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemIncreaseNeuronTimer(uint8_t displayIdx,
                                                        char *outKey, uint16_t outKeyLen,
                                                        char *outVal, uint16_t outValLen,
                                                        uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    const ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, INCREASE_DISSOLVE_DELAY);
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        PARSER_ASSERT_OR_ERROR(!(fields->has_id && (fields->which_neuron_id_or_subaccount == 12 ||
                                                    fields->which_neuron_id_or_subaccount == 11)),
                               parser_unexpected_number_items)

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->which_neuron_id_or_subaccount == 12) {
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Additional Delay");

        if (fields->command.configure.operation.increase_dissolve_delay.additional_dissolve_delay_seconds == 0) {
            snprintf(outVal, outValLen, "0s");
            return parser_ok;
        }

        char buffer[100];
        MEMZERO(buffer, sizeof(buffer));
        uint64_t value = 0;
        MEMCPY(&value,
               &fields->command.configure.operation.increase_dissolve_delay.additional_dissolve_delay_seconds,
               4);

        CHECK_PARSER_ERR(parser_printDelay(value, buffer, sizeof(buffer)))
        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }
    return parser_no_data;
}

static parser_error_t parser_getItemJoinNeuronsFund(uint8_t displayIdx,
                                                      char *outKey, uint16_t outKeyLen,
                                                      char *outVal, uint16_t outValLen,
                                                      uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    const ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Join Neurons' Fund");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        PARSER_ASSERT_OR_ERROR(!(fields->has_id && (fields->which_neuron_id_or_subaccount == 12 ||
                                                    fields->which_neuron_id_or_subaccount == 11)),
                               parser_unexpected_number_items)

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->which_neuron_id_or_subaccount == 12) {
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemStartStopDissolve(uint8_t displayIdx,
                                                      char *outKey, uint16_t outKeyLen,
                                                      char *outVal, uint16_t outValLen,
                                                      uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    const ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");

        manageNeuron_e mn_type;
        CHECK_PARSER_ERR(getManageNeuronType(&parser_tx_obj, &mn_type))

        if (mn_type == Configure_StartDissolving) {
            snprintf(outVal, outValLen, "Start Dissolving");
        } else {
            snprintf(outVal, outValLen, "Stop Dissolving");
        }
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        PARSER_ASSERT_OR_ERROR(!(fields->has_id && (fields->which_neuron_id_or_subaccount == 12 ||
                                                    fields->which_neuron_id_or_subaccount == 11)),
                               parser_unexpected_number_items)

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        } else if (fields->which_neuron_id_or_subaccount == 12) {
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        } else {
            //Only accept neuron_id
            return parser_unexpected_type;
        }
    }

    return parser_no_data;
}

static parser_error_t parser_getItemSpawn(uint8_t displayIdx,
                                          char *outKey, uint16_t outKeyLen,
                                          char *outVal, uint16_t outValLen,
                                          uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    const ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Spawn Neuron");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        PARSER_ASSERT_OR_ERROR(!(fields->has_id && (fields->which_neuron_id_or_subaccount == 12 ||
                                                    fields->which_neuron_id_or_subaccount == 11)),
                               parser_unexpected_number_items)

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->which_neuron_id_or_subaccount == 12) {
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Controller ");
        if (!fields->command.spawn.has_new_controller) {

            snprintf(outVal, outValLen, "Self");
            return parser_ok;
        }

        PARSER_ASSERT_OR_ERROR(fields->command.spawn.new_controller.serialized_id.size <= 29,
                               parser_value_out_of_range)

        return print_principal(fields->command.spawn.new_controller.serialized_id.bytes,
                             DFINITY_PRINCIPAL_LEN,
                             outVal, outValLen,
                             pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemAddRemoveHotkey(uint8_t displayIdx,
                                                    char *outKey, uint16_t outKeyLen,
                                                    char *outVal, uint16_t outValLen,
                                                    uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    const ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");

        manageNeuron_e mn_type;
        CHECK_PARSER_ERR(getManageNeuronType(&parser_tx_obj, &mn_type))

        if (mn_type == Configure_AddHotKey) {
            snprintf(outVal, outValLen, "Add Hotkey");
        } else {
            snprintf(outVal, outValLen, "Remove Hotkey");
        }

        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        PARSER_ASSERT_OR_ERROR(!(fields->has_id && (fields->which_neuron_id_or_subaccount == 12 ||
                                                    fields->which_neuron_id_or_subaccount == 11)),
                               parser_unexpected_number_items)

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->which_neuron_id_or_subaccount == 12) {
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }


    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Principal ");
        manageNeuron_e mn_type;
        CHECK_PARSER_ERR(getManageNeuronType(&parser_tx_obj, &mn_type))

        if (mn_type == Configure_AddHotKey) {
            PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.add_hot_key.has_new_hot_key,
                                   parser_unexpected_number_items)
            PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.add_hot_key.new_hot_key.serialized_id.size <= 29,
                                   parser_value_out_of_range)
            return print_principal(fields->command.configure.operation.add_hot_key.new_hot_key.serialized_id.bytes, 29,
                                 outVal, outValLen, pageIdx, pageCount);
        }

        PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.remove_hot_key.has_hot_key_to_remove,
                               parser_unexpected_number_items)
        PARSER_ASSERT_OR_ERROR(
                fields->command.configure.operation.remove_hot_key.hot_key_to_remove.serialized_id.size <= 29,
                parser_value_out_of_range)

        return print_principal(
                fields->command.configure.operation.remove_hot_key.hot_key_to_remove.serialized_id.bytes, 29,
                outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemDisburse(uint8_t displayIdx,
                                             char *outKey, uint16_t outKeyLen,
                                             char *outVal, uint16_t outValLen,
                                             uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    const ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Disburse Neuron");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        PARSER_ASSERT_OR_ERROR(!(fields->has_id && (fields->which_neuron_id_or_subaccount == 12 ||
                                                    fields->which_neuron_id_or_subaccount == 11)),
                               parser_unexpected_number_items)
        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->which_neuron_id_or_subaccount == 12) {
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Disburse To ");

        if (!fields->command.disburse.has_to_account) {
            snprintf(outVal, outValLen, "Self");
            return parser_ok;
        }

        PARSER_ASSERT_OR_ERROR(fields->command.disburse.to_account.hash.size == 32, parser_context_unexpected_size)

        return page_hexstring_with_delimiters(fields->command.disburse.to_account.hash.bytes,
                                              fields->command.disburse.to_account.hash.size,
                                              outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Amount (ICP)");

        if (!fields->command.disburse.has_amount) {
            snprintf(outVal, outValLen, "All");
            return parser_ok;
        }

        return print_ICP(fields->command.disburse.amount.e8s, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemRegisterVote(uint8_t displayIdx,
                                                 char *outKey, uint16_t outKeyLen,
                                                 char *outVal, uint16_t outValLen,
                                                 uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    const ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Register Vote");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        PARSER_ASSERT_OR_ERROR(!(fields->has_id && (fields->which_neuron_id_or_subaccount == 12 ||
                                                    fields->which_neuron_id_or_subaccount == 11)),
                               parser_unexpected_number_items)

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->which_neuron_id_or_subaccount == 12) {
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Proposal ID");
        char buffer[100];
        MEMZERO(buffer, sizeof(buffer));
        uint64_t value = 0;
        MEMCPY(&value, &fields->command.register_vote.proposal.id, 8);
        return print_u64(value, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Vote");
        ic_nns_governance_pb_v1_Vote v = fields->command.register_vote.vote;

        if (v == 0) {
            return parser_unexpected_value;
        }

        snprintf(outVal, outValLen, v == 1 ? "Yes" : "No");
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemFollow(uint8_t displayIdx,
                                           char *outKey, uint16_t outKeyLen,
                                           char *outVal, uint16_t outValLen,
                                           uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    const ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Follow");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        PARSER_ASSERT_OR_ERROR(!(fields->has_id && (fields->which_neuron_id_or_subaccount == 12 ||
                                                    fields->which_neuron_id_or_subaccount == 11)),
                               parser_unexpected_number_items)

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->which_neuron_id_or_subaccount == 12) {
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Topic");
        ic_nns_governance_pb_v1_Topic topic = fields->command.follow.topic;

        switch (topic) {
            case ic_nns_governance_pb_v1_Topic_TOPIC_UNSPECIFIED : {
                snprintf(outVal, outValLen, "Default");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_NEURON_MANAGEMENT : {
                snprintf(outVal, outValLen, "Neuron Management");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_EXCHANGE_RATE : {
                snprintf(outVal, outValLen, "Exchange Rate");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_NETWORK_ECONOMICS : {
                snprintf(outVal, outValLen, "Network Economics");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_GOVERNANCE : {
                snprintf(outVal, outValLen, "Governance");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_NODE_ADMIN : {
                snprintf(outVal, outValLen, "Node Admin");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_PARTICIPANT_MANAGEMENT : {
                snprintf(outVal, outValLen, "Participant Management");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_SUBNET_MANAGEMENT : {
                snprintf(outVal, outValLen, "Subnet Management");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_NETWORK_CANISTER_MANAGEMENT : {
                snprintf(outVal, outValLen, "Network Canister Management");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_KYC : {
                snprintf(outVal, outValLen, "KYC");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_NODE_PROVIDER_REWARDS : {
                snprintf(outVal, outValLen, "Node Provider Rewards");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_SNS_DECENTRALIZATION_SALE : {
                snprintf(outVal, outValLen, "SNS Decentralization Swap");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_SUBNET_REPLICA_VERSION_MANAGEMENT : {
                snprintf(outVal, outValLen, "Subnet Replica Version Management");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_REPLICA_VERSION_MANAGEMENT : {
                snprintf(outVal, outValLen, "Replica Version Management");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_SNS_AND_COMMUNITY_FUND : {
                snprintf(outVal, outValLen, "SNS & Neurons' Fund");
                return parser_ok;
            }
            default: {
                return parser_unexpected_type;
            }
        }
    }

    uint8_t new_displayIdx = displayIdx - 3;
    pb_size_t follow_count = fields->command.follow.followees_count;

    if (follow_count > 99) {
        //check for number of chars, but the real limit is lower
        return parser_unexpected_number_items;
    }

    if (follow_count == 0) {
        if (new_displayIdx == 0) {
            snprintf(outKey, outKeyLen, "Followees");
            snprintf(outVal, outValLen, "None");
            return parser_ok;
        }

        return parser_unexpected_number_items;
    }

    if (new_displayIdx < follow_count) {
        uint64_t id = fields->command.follow.followees[new_displayIdx].id;
        new_displayIdx++; //higher by 1
        char buffer[100];
        MEMZERO(buffer, sizeof(buffer));
        uint16_t index = 0;
        MEMCPY(buffer, (char *) "Followees (", 11);
        index += 11;

        uint8_t tens = new_displayIdx / 10;
        if (tens > 0) {
            char ten = (char) ('0' + tens);
            MEMCPY(buffer + index, &ten, 1);
            index++;
        }

        uint8_t ones = new_displayIdx % 10;
        char one = (char) ('0' + ones);
        MEMCPY(buffer + index, &one, 1);
        index++;
        MEMCPY(buffer + index, ")", 1);
        snprintf(outKey, outKeyLen, "%s", buffer);
        return print_u64(id, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemManageNeuron(uint8_t displayIdx,
                                                 char *outKey, uint16_t outKeyLen,
                                                 char *outVal, uint16_t outValLen,
                                                 uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");
    *pageCount = 1;

    manageNeuron_e mn_type;
    CHECK_PARSER_ERR(getManageNeuronType(&parser_tx_obj, &mn_type))

    switch (mn_type) {
        case Configure_IncreaseDissolveDelay:
            return parser_getItemIncreaseNeuronTimer(displayIdx,
                                                     outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        case Configure_JoinNeuronsFund :
            return parser_getItemJoinNeuronsFund(displayIdx,
                                                 outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        case Configure_StopDissolving :
        case Configure_StartDissolving : {
            return parser_getItemStartStopDissolve(displayIdx,
                                                   outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        case Spawn : {
            return parser_getItemSpawn(displayIdx,
                                       outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        case Configure_RemoveHotKey:
        case Configure_AddHotKey:
            return parser_getItemAddRemoveHotkey(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case Disburse :
            return parser_getItemDisburse(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case RegisterVote :
            return parser_getItemRegisterVote(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case Follow:
            return parser_getItemFollow(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        default:
            return parser_no_data;
    }
}

parser_error_t parser_getItemProtobuf(uint8_t displayIdx,
                                      char *outKey, uint16_t outKeyLen,
                                      char *outVal, uint16_t outValLen,
                                      uint8_t pageIdx, uint8_t *pageCount) {

    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);

     *pageCount = 1;
    switch (parser_tx_obj.tx_fields.call.method_type) {
        case pb_sendrequest : {
            const bool is_stake_tx = parser_tx_obj.special_transfer_type == neuron_stake_transaction;

            if (is_stake_tx) {
                return parser_getItemStakeNeuron(displayIdx,
                                                 outKey, outKeyLen,
                                                 outVal, outValLen,
                                                 pageIdx, pageCount);
            }

            return parser_getItemTokenTransfer( displayIdx,
                                                outKey, outKeyLen,
                                                outVal, outValLen,
                                                pageIdx, pageCount);
        }

        case pb_manageneuron: {
            return parser_getItemManageNeuron(displayIdx,
                                              outKey, outKeyLen,
                                              outVal, outValLen,
                                              pageIdx, pageCount);
        }

        case pb_listneurons : {
            return parser_getItemListNeurons(displayIdx,
                                                outKey, outKeyLen,
                                                outVal, outValLen);
        }

        case pb_claimneurons : {
            return parser_getItemClaimNeuron(displayIdx,
                                                outKey, outKeyLen,
                                                outVal, outValLen);
        }

        default:
            ZEMU_LOGF(50, "Protobuf type not supported\n")
            break;
    }

    return parser_unexpected_type;
}
