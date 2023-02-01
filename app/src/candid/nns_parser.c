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
#include "nns_parser.h"

__Z_INLINE parser_error_t readCandidWhichVariant(parser_context_t *ctx, uint64_t *t) {
    CHECK_PARSER_ERR(readCandidLEB128(ctx, t))
    return parser_ok;
}

__Z_INLINE parser_error_t readCommandSplit(parser_context_t *ctx, candid_transaction_t *txn, candid_ManageNeuron_t* val) {
    // Check sanity Split
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))
    if (txn->txn_length != 1) {
        return parser_unexpected_value;
    }
    txn->element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
    if (txn->element.field_hash != hash_amount_e8s || txn->element.implementation != Nat64) {
        return parser_unexpected_type;
    }

    // Read Split
    CHECK_PARSER_ERR(readCandidNat64(ctx, &val->command.split.amount_e8s))

    return parser_ok;
}

__Z_INLINE parser_error_t readCommandMerge(parser_context_t *ctx, candid_transaction_t *txn, candid_ManageNeuron_t* val) {
    // Check sanity Merge
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))
    if (txn->txn_length != 1) {
        return parser_unexpected_value;
    }
    txn->element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))

    if (txn->element.field_hash != hash_source_neuron_id) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(txn))

    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))
    if (txn->txn_length != 1) {
        return parser_unexpected_value;
    }
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))

    if (txn->element.field_hash != hash_id || txn->element.implementation != Nat64) {
        return parser_unexpected_type;
    }

    // Read Merge
    CHECK_PARSER_ERR(readCandidByte(ctx, &val->command.merge.has_source))
    if (!val->command.merge.has_source) {
        // https://github.com/Zondax/ledger-icp/issues/149
        // indicates that missing source should be rejected
        return parser_unexpected_value;
    }
    CHECK_PARSER_ERR(readCandidNat64(ctx, &val->command.merge.source.id))

    return parser_ok;
}

__Z_INLINE parser_error_t readCommandSpawn(parser_context_t *ctx, candid_transaction_t *txn, candid_ManageNeuron_t* val) {
    // Check sanity
    const int64_t spawnRoot = txn->element.implementation;
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))
    if (txn->txn_length != 3) {
        return parser_unexpected_value;
    }

    txn->element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
    if (txn->element.field_hash != hash_percentage_to_spawn) {
        return parser_unexpected_type;
    }
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(txn))
    if (txn->element.implementation != Nat32) {
        return parser_unexpected_type;
    }

    // reset txn
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, spawnRoot))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))

    txn->element.variant_index = 1;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
    if (txn->element.field_hash != hash_new_controller) {
        return parser_unexpected_type;
    }
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(txn))
    if (txn->element.implementation != Principal) {
        return parser_unexpected_type;
    }

    // reset txn
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, spawnRoot))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))

    txn->element.variant_index = 2;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
    if (txn->element.field_hash != hash_nonce) {
        return parser_unexpected_type;
    }
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(txn))
    if (txn->element.implementation != Nat64) {
        return parser_unexpected_type;
    }

    // now let's read
    // Percentage to spawn
    CHECK_PARSER_ERR(readCandidByte(ctx, &val->command.spawn.has_percentage_to_spawn))
    if (val->command.spawn.has_percentage_to_spawn) {
        CHECK_PARSER_ERR(readCandidNat32(ctx, &val->command.spawn.percentage_to_spawn))
        // Sanity check
        if (val->command.spawn.percentage_to_spawn == 0 || val->command.spawn.percentage_to_spawn > 100) {
            return parser_value_out_of_range;
        }
    }

    // Controller
    CHECK_PARSER_ERR(readCandidByte(ctx, &val->command.spawn.has_controller))
    if (val->command.spawn.has_controller) {
        uint8_t has_principal = 0;
        uint8_t principalSize = 0;
        CHECK_PARSER_ERR(readCandidByte(ctx, &has_principal))
        if(has_principal) {
            CHECK_PARSER_ERR(readCandidByte(ctx, &principalSize))
            CHECK_PARSER_ERR(readCandidBytes(ctx, val->command.spawn.new_controller, principalSize))
        }
    }

    // Nonce
    CHECK_PARSER_ERR(readCandidByte(ctx, &val->command.spawn.has_nonce))
    if (val->command.spawn.has_nonce) {
        CHECK_PARSER_ERR(readCandidNat64(ctx, &val->command.spawn.nonce))
    }

    return parser_ok;
}

__Z_INLINE parser_error_t readCommandStakeMaturity(parser_context_t *ctx, candid_transaction_t *txn, candid_ManageNeuron_t* val) {
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))
    if (txn->txn_length != 1) {
        return parser_unexpected_value;
    }

    txn->element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
    if (txn->element.field_hash != hash_percentage_to_stake) {
        return parser_unexpected_type;
    }
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(txn))
    if (txn->element.implementation != Nat32) {
        return parser_unexpected_type;
    }

    // now let's read
    CHECK_PARSER_ERR(readCandidByte(ctx, &val->command.stake.has_percentage_to_stake))
    if (val->command.stake.has_percentage_to_stake) {
        CHECK_PARSER_ERR(readCandidNat32(ctx, &val->command.stake.percentage_to_stake))
        // Sanity check
        if (val->command.stake.percentage_to_stake == 0 || val->command.stake.percentage_to_stake > 100) {
            return parser_value_out_of_range;
        }
    }

    return parser_ok;
}

__Z_INLINE parser_error_t readOperationSetDissolveTimestamp(parser_context_t *ctx, candid_transaction_t *txn, candid_Operation_t* operation) {
    // Check sanity SetDissolvedTimestamp
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))
    if (txn->txn_length > 1) {
        return parser_unexpected_number_items;
    }

    txn->element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
    if (txn->element.field_hash != hash_dissolve_timestamp_seconds || txn->element.implementation != Nat64) {
        return parser_unexpected_type;
    }

    // Read SetDissolvedTimestamp
    CHECK_PARSER_ERR(readCandidNat64(ctx, &operation->setDissolveTimestamp.dissolve_timestamp_seconds))

    if (operation->setDissolveTimestamp.dissolve_timestamp_seconds >= 4102444800) {
        return parser_value_out_of_range;
    }

    return parser_ok;
}

__Z_INLINE parser_error_t readOperationLeaveCommunityFund(parser_context_t *ctx, candid_transaction_t *txn, candid_Operation_t* operation) {
    // Check sanity LeaveCommunityFund
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))
    if (txn->txn_length != 0) {
        return parser_unexpected_number_items;
    }
    // Empty record

    return parser_ok;
}

__Z_INLINE parser_error_t readOperationChangeAutoStakeMaturity(parser_context_t *ctx, candid_transaction_t *txn, candid_Operation_t* operation) {
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))
    if (txn->txn_length != 1) {
        return parser_unexpected_number_items;
    }
    txn->element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
    if (txn->element.field_hash != hash_setting_auto_stake_maturity
        || txn->element.implementation != Bool) {
        return parser_unexpected_type;
    }
    // let's read
    CHECK_PARSER_ERR(readCandidByte(ctx, &operation->autoStakeMaturity.requested_setting_for_auto_stake_maturity))

    return parser_ok;
}

__Z_INLINE parser_error_t readOperationIncreaseDissolveDelay(parser_context_t *ctx, candid_transaction_t *txn, candid_Operation_t* operation) {
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))
    if (txn->txn_length != 1) {
        return parser_unexpected_number_items;
    }
    txn->element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
    if (txn->element.field_hash != hash_setting_increse_dissolve_delay
        || txn->element.implementation != Nat32) {
        return parser_unexpected_type;
    }
    // let's read
    CHECK_PARSER_ERR(readCandidNat32(ctx, &operation->increaseDissolveDelay.dissolve_timestamp_seconds))

    return parser_ok;
}
parser_error_t readNNSManageNeuron(parser_context_t *ctx, candid_transaction_t *txn) {
    if (ctx == NULL || txn == NULL || txn->txn_length != 3) {
        return parser_unexpected_error;
    }

    candid_ManageNeuron_t *val = &ctx->tx_obj->tx_fields.call.data.candid_manageNeuron;

    // Check sanity Id
    txn->element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
    if (txn->element.field_hash != hash_id) {
        return parser_unexpected_type;
    }
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(txn))

    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))
    if (txn->txn_length != 1) {
        return parser_unexpected_value;
    }
    txn->element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
    if (txn->element.field_hash != hash_id || txn->element.implementation != Nat64) {
        return parser_unexpected_type;
    }
    // Read Id
    CHECK_PARSER_ERR(readCandidByte(ctx, &val->has_id))
    if (val->has_id) {
        CHECK_PARSER_ERR(readCandidNat64(ctx, &val->id.id))
    }

    // Check sanity Command
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, ctx->tx_obj->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))

    txn->element.variant_index = 1;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
    if (txn->element.field_hash != hash_command) {
        return parser_unexpected_type;
    }
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(txn))

    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    if (txn->txn_type != Variant) {
        return parser_unexpected_type;
    }

    // Reset pointers and read Command
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, ctx->tx_obj->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))
    txn->element.variant_index = 1;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))

    CHECK_PARSER_ERR(readCandidByte(ctx, &val->has_command))
    if (val->has_command) {
        CHECK_PARSER_ERR(readCandidNat(ctx, &val->command.variant))
        CHECK_PARSER_ERR(getHash(txn, val->command.variant, &val->command.hash))

        switch (val->command.hash) {
            case hash_command_Split: {
                CHECK_PARSER_ERR(readCommandSplit(ctx, txn, val))
                break;
            }

            case hash_command_Merge: {
                CHECK_PARSER_ERR(readCommandMerge(ctx, txn, val))
                break;
            }

            case hash_command_Configure: {
                // Save this type
                const int64_t txn_element_implementation = txn->element.implementation;

                // Check sanity Configure
                CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
                CHECK_PARSER_ERR(readCandidRecordLength(txn))
                if (txn->txn_length != 1) {
                    return parser_unexpected_value;
                }
                txn->element.variant_index = 0;
                CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
                if (txn->element.field_hash != hash_operation) {
                    return parser_unexpected_type;
                }

                CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
                CHECK_PARSER_ERR(readCandidOptional(txn))

                CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
                if (txn->txn_type != Variant) {
                    return parser_unexpected_type;
                }

                // Read Configure / Operation
                CHECK_PARSER_ERR(readCandidByte(ctx, &val->command.configure.has_operation))
                if (!val->command.configure.has_operation) {
                    return parser_unexpected_value;
                }
                candid_Operation_t *operation = &val->command.configure.operation;
                CHECK_PARSER_ERR(readCandidWhichVariant(ctx, &operation->which))

                // Restore saved type
                txn->element.implementation = txn_element_implementation;
                CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
                CHECK_PARSER_ERR(readCandidRecordLength(txn))
                if (txn->txn_length > 1) {
                    return parser_unexpected_number_items;
                }

                txn->element.variant_index = 0;
                CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
                CHECK_PARSER_ERR(getHash(txn, operation->which, &operation->hash))

                switch (operation->hash) {
                    case hash_operation_SetDissolvedTimestamp: {
                        CHECK_PARSER_ERR(readOperationSetDissolveTimestamp(ctx, txn, operation))
                        break;
                    }
                    case hash_operation_LeaveCommunityFund: {
                        CHECK_PARSER_ERR(readOperationLeaveCommunityFund(ctx, txn, operation))
                        break;
                    }
                    case hash_operation_ChangeAutoStakeMaturity:
                        CHECK_PARSER_ERR(readOperationChangeAutoStakeMaturity(ctx, txn, operation))
                        break;
                    case hash_operation_IncreaseDissolveDelay:
                        CHECK_PARSER_ERR(readOperationIncreaseDissolveDelay(ctx, txn, operation))
                        break;

                    default:
                        ZEMU_LOGF(100, "Unimplemented operation | Hash: %llu\n", operation->hash)
                        return parser_unexpected_value;
                }
                break;
            }
            case hash_command_Spawn: {
                CHECK_PARSER_ERR(readCommandSpawn(ctx, txn, val))
                break;
            }
            case hash_command_StakeMaturity:
                CHECK_PARSER_ERR(readCommandStakeMaturity(ctx, txn, val))
                break;

            default:
                ZEMU_LOGF(100, "Unimplemented command | Hash: %llu\n", val->command.hash)
                return parser_unexpected_type;
        }
    }

    // Check sanity Neuron id or subaccount
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, ctx->tx_obj->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))
    txn->element.variant_index = 2;

    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
    if (txn->element.field_hash != hash_neuron_id_or_subaccount) {
        return parser_unexpected_type;
    }

    const int64_t savedElementImplementation = txn->element.implementation;

    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(txn))
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    if (txn->txn_type != Variant) {
        return parser_unexpected_type;
    }

    // Read neuron id or subaccount
    CHECK_PARSER_ERR(readCandidByte(ctx, &val->has_neuron_id_or_subaccount))
    if (val->has_neuron_id_or_subaccount) {
        CHECK_PARSER_ERR(readCandidWhichVariant(ctx, &val->neuron_id_or_subaccount.which))

        txn->element.implementation = savedElementImplementation;
        uint64_t neuron_id_or_subaccount_hash = 0;
        CHECK_PARSER_ERR(getHash(txn, val->neuron_id_or_subaccount.which, &neuron_id_or_subaccount_hash))

        switch (neuron_id_or_subaccount_hash) {
            case hash_subaccount: {
                CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
                if (txn->txn_type != Vector) {
                    return parser_unexpected_type;
                }

                // Read subaccount
                CHECK_PARSER_ERR(readCandidText(ctx, &val->neuron_id_or_subaccount.subaccount))
                break;
            }
            case hash_neuron_id: {
                CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
                CHECK_PARSER_ERR(readCandidRecordLength(txn))
                if (txn->txn_length != 1) {
                    return parser_unexpected_value;
                }

                // Read neuron id
                CHECK_PARSER_ERR(readCandidNat64(ctx, &val->neuron_id_or_subaccount.neuronId.id))
                break;
            }
            default:
                return parser_value_out_of_range;
        }

    }

    if (ctx->bufferLen - ctx->offset > 0) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}
