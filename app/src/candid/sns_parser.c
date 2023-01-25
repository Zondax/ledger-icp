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
#include "sns_parser.h"
#include "candid_helper.h"


__Z_INLINE parser_error_t readSNSCommandNeuronPermissions(parser_context_t *ctx, candid_transaction_t *txn, uint64_t hash_permission_to) {
    const int64_t neuronPermissionsRoot = txn->element.implementation;
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, neuronPermissionsRoot))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))
    if (txn->txn_length != 2) {
        return parser_unexpected_value;
    }

    // Check PermissionsToAdd
    txn->element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
    if (txn->element.field_hash != hash_permission_to) {
        return parser_unexpected_type;
    }
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(txn))

    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    if (txn->txn_type != Record) {
        return parser_unexpected_type;
    }
    CHECK_PARSER_ERR(readCandidRecordLength(txn))
    if (txn->txn_length != 1) {
        return parser_unexpected_value;
    }

    txn->element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
    if (txn->element.field_hash != sns_hash_neuron_permission_list) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    if (txn->txn_type != Vector) {
        return parser_unexpected_type;
    }

    // reset txn
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, neuronPermissionsRoot))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))

    txn->element.variant_index = 1;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
    if (txn->element.field_hash != sns_hash_principal_id) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(txn))

    if (txn->element.implementation != Principal) {
        return parser_unexpected_type;
    }

    // Read data
    sns_NeuronPermissions_t *val = &ctx->tx_obj->tx_fields.call.data.sns_manageNeuron.command.neuronPermissions;

    // Read Permissiones
    CHECK_PARSER_ERR(readCandidByte(ctx, &val->has_permissionList))
    if (val->has_permissionList) {
        int32_t tmp_permission = 0;
        CHECK_PARSER_ERR(readCandidByte(ctx, &val->permissionList.list_size))

        val->permissionList.permissions_list_ptr = ctx->buffer + ctx->offset;
        for (uint8_t i = 0; i < val->permissionList.list_size; i++) {
            CHECK_PARSER_ERR(readCandidInt32(ctx, &tmp_permission))
            if (tmp_permission > NEURON_PERMISSION_TYPE_MANAGE_VOTING_PERMISSION) {
                return parser_unexpected_value;
            }
        }
    }

    // Read Principal ID
    CHECK_PARSER_ERR(readCandidByte(ctx, &val->has_principal))
    if (val->has_principal) {
        uint8_t has_principal = 0;
        uint8_t principalSize = 0;
        CHECK_PARSER_ERR(readCandidByte(ctx, &has_principal))
        if(has_principal) {
            CHECK_PARSER_ERR(readCandidByte(ctx, &principalSize))
            if (principalSize != DFINITY_PRINCIPAL_LEN) {
                return parser_unexpected_value;
            }
            CHECK_PARSER_ERR(readCandidBytes(ctx, val->principal, principalSize))
        }
    }

    return parser_ok;
}

parser_error_t readSNSManageNeuron(parser_context_t *ctx, candid_transaction_t *txn) {
    if (ctx == NULL || txn == NULL || txn->txn_length != 2) {
        return parser_unexpected_error;
    }

    // Check sanity Id
    txn->element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
    if (txn->element.field_hash != sns_hash_subaccount) {
        return parser_unexpected_type;
    }
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))
    if (txn->txn_type != Vector) {
        return parser_unexpected_type;
    }

    sns_ManageNeuron_t *val = &ctx->tx_obj->tx_fields.call.data.sns_manageNeuron;

    // Read subaccount
    CHECK_PARSER_ERR(readCandidText(ctx, &val->subaccount))

    // Check sanity Command
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, ctx->tx_obj->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(txn))

    txn->element.variant_index = 1;
    CHECK_PARSER_ERR(readCandidInnerElement(txn, &txn->element))
    if (txn->element.field_hash != sns_hash_command) {
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
            case sns_hash_command_AddNeuronPermissions: {
                CHECK_PARSER_ERR(readSNSCommandNeuronPermissions(ctx, txn, sns_hash_permissions_to_add))
                break;
            }
            case sns_hash_command_RemoveNeuronPermissions: {
                CHECK_PARSER_ERR(readSNSCommandNeuronPermissions(ctx, txn, sns_hash_permissions_to_remove))
                break;
            }
            case sns_hash_command_Disburse: {

                break;
            }
        }
    }

    if (ctx->bufferLen - ctx->offset > 0) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}
