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
#include "candid_parser.h"
#include "leb128.h"

#include "candid_helper.h"
#include "sns_parser.h"
#include "nns_parser.h"
#include "crypto.h"

// Good reference:  https://github.com/dfinity/agent-js/tree/main/packages/candid
// https://github.com/dfinity/candid/blob/master/spec/Candid.md#deserialisation


#define CREATE_CTX(__CTX, __TX, __INPUT, __INPUT_SIZE) \
    parser_context_t __CTX; \
    ctx.buffer = __INPUT; \
    ctx.bufferLen = __INPUT_SIZE; \
    ctx.offset = 0; \
    ctx.tx_obj = __TX;

parser_error_t getCandidNat64FromVec(const uint8_t *buf, uint64_t *v, uint8_t size, uint8_t idx) {
    if (buf == NULL || v == NULL || idx >= size) {
        return parser_unexpected_value;
    }
    *v = 0;
    buf = buf + 8 * idx;

    for (uint8_t i = 0; i < 8; i++) {
        *v += (uint64_t) *(buf + i) << 8 * i;
    }
    return parser_ok;
}

parser_error_t getCandidInt32FromVec(const uint8_t *buf, int32_t *v, uint8_t size, uint8_t idx) {
    if (buf == NULL || v == NULL || idx >= size) {
        return parser_unexpected_value;
    }
    *v = 0;
    buf = buf + 4 * idx;

    for (uint8_t i = 0; i < 4; i++) {
        *v += (int32_t) *(buf + i) << 8 * i;
    }
    return parser_ok;
}

parser_error_t readCandidListNeurons(parser_tx_t *tx, const uint8_t *input, uint16_t inputSize) {
    // Create context and auxiliary ctx
    CREATE_CTX(ctx, tx, input, inputSize)
    candid_transaction_t txn;
    txn.ctx.buffer = ctx.buffer;
    txn.ctx.bufferLen = ctx.bufferLen;
    txn.ctx.tx_obj = ctx.tx_obj;

    CHECK_PARSER_ERR(readCandidHeader(&ctx, &txn))
    CHECK_PARSER_ERR(readAndCheckRootType(&ctx))
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))

    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    if (txn.txn_length != 2) {
        return parser_unexpected_value;
    }
    txn.element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != hash_neuron_ids) {
        return parser_unexpected_type;
    }

    // reset txn
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))

    txn.element.variant_index = 1;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != hash_include_neurons_readable_by_caller ||
        txn.element.implementation != Bool) {
        return parser_unexpected_type;
    }

    // let's read
    candid_ListNeurons_t *val = &tx->tx_fields.call.data.candid_listNeurons;
    uint64_t tmp_neuron_id = 0;
    CHECK_PARSER_ERR(readCandidByte(&ctx, &val->neuron_ids_size))

    val->neuron_ids_ptr = ctx.buffer + ctx.offset;
    for (uint8_t i = 0; i < val->neuron_ids_size; i++) {
        CHECK_PARSER_ERR(readCandidNat64(&ctx, &tmp_neuron_id))
    }

    CHECK_PARSER_ERR(readCandidByte(&ctx, &val->include_neurons_readable_by_caller))
    return parser_ok;
}

parser_error_t readCandidManageNeuron(parser_tx_t *tx, const uint8_t *input, uint16_t inputSize) {
    // Create context and auxiliary ctx
    CREATE_CTX(ctx, tx, input, inputSize)
    candid_transaction_t txn;
    txn.ctx.buffer = ctx.buffer;
    txn.ctx.bufferLen = ctx.bufferLen;
    txn.ctx.tx_obj = ctx.tx_obj;

    CHECK_PARSER_ERR(readCandidHeader(&ctx, &txn))

    CHECK_PARSER_ERR(readAndCheckRootType(&ctx))


    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))

    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    switch (txn.txn_length)
    {
        case 2: // SNS
            tx->tx_fields.call.is_sns = 1;
            return readSNSManageNeuron(&ctx, &txn);
        case 3: // NNS
            return readNNSManageNeuron(&ctx, &txn);

        default:
            ZEMU_LOGF(100, "Error: transaction type not supported\n")
    }

    return parser_unexpected_value;
}

parser_error_t readCandidUpdateNodeProvider(parser_tx_t *tx, const uint8_t *input, uint16_t inputSize) {
    CREATE_CTX(ctx, tx, input, inputSize)
    candid_transaction_t txn;
    txn.ctx.buffer = ctx.buffer;
    txn.ctx.bufferLen = ctx.bufferLen;
    txn.ctx.tx_obj = ctx.tx_obj;

    CHECK_PARSER_ERR(readCandidHeader(&ctx, &txn))


    CHECK_PARSER_ERR(readAndCheckRootType(&ctx))
    candid_UpdateNodeProvider_t *val = &tx->tx_fields.call.data.candid_updateNodeProvider;

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))

    // Check sanity
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    if (txn.txn_length != 1) {
        return parser_unexpected_value;
    }
    txn.element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != hash_reward_account) {
        return parser_unexpected_type;
    }

    // Now read
    CHECK_PARSER_ERR(readCandidByte(&ctx, &val->has_reward_account))
    if (!val->has_reward_account) {
        return parser_unexpected_value;
    }

    // Check sanity
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(&txn))

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    if (txn.txn_length != 1) {
        return parser_unexpected_value;
    }
    txn.element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != hash_hash) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    if (txn.txn_type != Vector) {
        return parser_unexpected_type;
    }

    // Now read
    CHECK_PARSER_ERR(readCandidText(&ctx, &val->account_identifier))
    if (val->account_identifier.len != 32) {
        return parser_unexpected_number_items;
    }

    if (ctx.bufferLen - ctx.offset > 0) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}

parser_error_t readCandidICRCTransfer(parser_tx_t *tx, const uint8_t *input, uint16_t inputSize) {
    // Create context and auxiliary ctx
    CREATE_CTX(ctx, tx, input, inputSize)
    candid_transaction_t txn;
    txn.ctx.buffer = ctx.buffer;
    txn.ctx.bufferLen = ctx.bufferLen;
    txn.ctx.tx_obj = ctx.tx_obj;

    CHECK_PARSER_ERR(readCandidHeader(&ctx, &txn))
    CHECK_PARSER_ERR(readAndCheckRootType(&ctx))
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))

    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    if (txn.txn_length != 6) {
        return parser_unexpected_value;
    }

    txn.element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != icrc_hash_to) {
        return parser_unexpected_type;
    }

    const int64_t accountIndex = txn.element.implementation;
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, accountIndex))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    if (txn.txn_length != 2) {
        return parser_unexpected_value;
    }

    txn.element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != icrc_hash_owner || txn.element.implementation != Principal) {
        return parser_unexpected_type;
    }
    // Account -> Owner (Principal) -> OK

    // -----------------------------------------------------------------------
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, accountIndex))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))

    txn.element.variant_index = 1;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != icrc_hash_subaccount) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(&txn))

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    if (txn.txn_type != Vector) {
        return parser_unexpected_type;
    }
    // Account -> Subaccount (Vec<Nat8>) -> OK

    // -----------------------------------------------------------------------
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))

    txn.element.variant_index = 1;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != icrc_hash_fee) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(&txn))
    if (txn.txn_type != Opt || txn.element.implementation != Nat) {
        return parser_unexpected_type;
    }
    // Fee -> OK

    // -----------------------------------------------------------------------
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))

    txn.element.variant_index = 2;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != icrc_hash_memo) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(&txn))

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    if (txn.txn_type != Vector) {
        return parser_unexpected_type;
    }
    // memo -> OK

    // -----------------------------------------------------------------------
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))

    txn.element.variant_index = 3;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != icrc_hash_from_subaccount) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(&txn))

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    if (txn.txn_type != Vector) {
        return parser_unexpected_type;
    }
    // from_subaccount -> OK

    // -----------------------------------------------------------------------
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))

    txn.element.variant_index = 4;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != icrc_hash_created_at_time) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(&txn))

    if (txn.txn_type != Opt || txn.element.implementation != Nat64) {
        return parser_unexpected_type;
    }
    // Created at time -> OK

    // -----------------------------------------------------------------------
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))

    txn.element.variant_index = 5;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != icrc_hash_amount || txn.element.implementation != Nat) {
        return parser_unexpected_type;
    }

    icrc_transfer_t *icrc = &ctx.tx_obj->tx_fields.call.data.icrcTransfer;

    // Read to (Account)
    CHECK_PARSER_ERR(readCandidByte(&ctx, &icrc->account.has_owner))
    if (icrc->account.has_owner) {
        uint8_t ownerSize = 0;
        CHECK_PARSER_ERR(readCandidByte(&ctx, &ownerSize))
        if (ownerSize != DFINITY_PRINCIPAL_LEN) {
            return parser_unexpected_value;
        }
        CHECK_PARSER_ERR(readCandidBytes(&ctx, icrc->account.owner, ownerSize))
    }

    CHECK_PARSER_ERR(readCandidByte(&ctx, &icrc->account.has_subaccount))
    if (icrc->account.has_subaccount) {
        CHECK_PARSER_ERR(readCandidText(&ctx, &icrc->account.subaccount))
    }

    // Read fee
    CHECK_PARSER_ERR(readCandidByte(&ctx, &icrc->has_fee))
    if (icrc->has_fee) {
        CHECK_PARSER_ERR(readCandidLEB128(&ctx, &icrc->fee))
    }

    // Read memo
    CHECK_PARSER_ERR(readCandidByte(&ctx, &icrc->has_memo))
    if (icrc->has_memo) {
        uint8_t tmp = 0;
        CHECK_PARSER_ERR(readCandidNat(&ctx, &icrc->memo.len))

        icrc->memo.p = ctx.buffer + ctx.offset;
        for (uint8_t i = 0; i < icrc->memo.len; i++) {
            CHECK_PARSER_ERR(readCandidByte(&ctx, &tmp))
        }
    }

    // Read from_subaccount
    CHECK_PARSER_ERR(readCandidByte(&ctx, &icrc->has_from_subaccount))
    if (icrc->has_from_subaccount) {
        CHECK_PARSER_ERR(readCandidText(&ctx, &icrc->from_subaccount))
    }

    // Read has_created_at_time
    CHECK_PARSER_ERR(readCandidByte(&ctx, &icrc->has_created_at_time))
    if (!icrc->has_created_at_time) {
        return parser_required_method;
    }
    CHECK_PARSER_ERR(readCandidNat64(&ctx, &icrc->created_at_time)) // assume has_created_at_time

    // Read amount
    CHECK_PARSER_ERR(readCandidLEB128(&ctx, &icrc->amount))

    if (ctx.bufferLen - ctx.offset > 0) {
        return parser_unexpected_characters;
    }

    // Check if the transaction has ICP canister
    const uint8_t *canisterId = ctx.tx_obj->tx_fields.call.canister_id.data;
    const size_t canisterIdSize = ctx.tx_obj->tx_fields.call.canister_id.len;
    char canister_textual[50] = {0};
    uint16_t outLen = sizeof(canister_textual);
    if (canisterIdSize > 255) return parser_unexpected_value;
    crypto_principalToTextual(canisterId,
                              (uint8_t) canisterIdSize,
                              canister_textual,
                              &outLen);

    icrc->icp_canister = (strncmp((const char*) &canister_textual, "ryjl3tyaaaaaaaaaaabacai", 23) == 0) ? 1 : 0;

    return parser_ok;
}
