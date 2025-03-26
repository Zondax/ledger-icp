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

#include "candid_helper.h"
#include "crypto.h"
#include "leb128.h"
#include "nns_parser.h"
#include "sns_parser.h"

// Good reference: https://github.com/dfinity/agent-js/tree/main/packages/candid
// https://github.com/dfinity/candid/blob/master/spec/Candid.md#deserialisation

#define MAX_FIELDS 25
#define TYPE_OPT 0
#define TYPE_NEURONS_IDS 1
#define TYPE_CALLER 2

#define CREATE_CTX(__CTX, __TX, __INPUT, __INPUT_SIZE) \
    parser_context_t __CTX;                            \
    ctx.buffer = __INPUT;                              \
    ctx.bufferLen = __INPUT_SIZE;                      \
    ctx.offset = 0;                                    \
    ctx.tx_obj = __TX;

parser_error_t getCandidNat64FromVec(const uint8_t *buf, uint64_t *v, uint8_t size, uint8_t idx) {
    if (buf == NULL || v == NULL || idx >= size) {
        return parser_unexpected_value;
    }
    *v = 0;
    buf = buf + 8 * idx;

    for (uint8_t i = 0; i < 8; i++) {
        *v += (uint64_t) * (buf + i) << 8 * i;
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
        *v += (int32_t) * (buf + i) << 8 * i;
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
    // at least we need to have the 2 non opt fields already defined in the did
    // file
    if (txn.txn_length < 2) {
        return parser_unexpected_value;
    }
    uint64_t n_fields = txn.txn_length;

    // Array to save opt fields position in the record
    uint8_t opt_fields_pos[MAX_FIELDS] = {0};

    // Check types before parsing
    for (uint64_t i = 0; i < n_fields; i++) {
        // reset txn
        CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
        CHECK_PARSER_ERR(readCandidRecordLength(&txn))
        // jump to index
        txn.element.variant_index = i;
        CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))

        // element is not any of the non opt expected fields than its probably an
        // optional
        if (txn.element.field_hash == hash_neuron_ids) {
            opt_fields_pos[i] = TYPE_NEURONS_IDS;
        } else if (txn.element.field_hash == hash_include_neurons_readable_by_caller && txn.element.implementation == Bool) {
            opt_fields_pos[i] = TYPE_CALLER;
        } else {
            CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
            // Check that is an opt(inside the function) if not return error, not an
            // expected type
            CHECK_PARSER_ERR(readCandidOptional(&txn))
            opt_fields_pos[i] = TYPE_OPT;
        }
    }

    // let's read
    candid_ListNeurons_t *val = &tx->tx_fields.call.data.candid_listNeurons;
    uint64_t tmp_neuron_id = 0;
    uint8_t tmp_presence = 0;
    for (uint64_t i = 0; i < n_fields; i++) {
        // If opt_fields_pos is 0 we have a opt field in this position
        switch (opt_fields_pos[i]) {
            case TYPE_OPT:  // read the optional, expect its null or empty if not return
                            // error
                CHECK_PARSER_ERR(readCandidByte(&ctx, &tmp_presence))
                if (tmp_presence) {  // expect empty optionals
                    return parser_unexpected_value;
                }
                break;
            case TYPE_NEURONS_IDS:  // read number os ids
                CHECK_PARSER_ERR(readCandidByte(&ctx, &val->neuron_ids_size))

                val->neuron_ids_ptr = ctx.buffer + ctx.offset;
                for (uint8_t j = 0; j < val->neuron_ids_size; j++) {
                    CHECK_PARSER_ERR(readCandidNat64(&ctx, &tmp_neuron_id))
                }
                break;
            case TYPE_CALLER:  // read bool
                CHECK_PARSER_ERR(readCandidByte(&ctx, &val->include_neurons_readable_by_caller))
                break;
            default:
                return parser_unexpected_value;
        }
    }

    return parser_ok;
}

parser_error_t readCandidManageNeuron(parser_tx_t *tx, const uint8_t *input, uint16_t inputSize) {
    zemu_log("readCandidManageNeuron\n");
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
    switch (txn.txn_length) {
        case 2:  // SNS
            tx->tx_fields.call.is_sns = 1;
            return readSNSManageNeuron(&ctx, &txn);
        case 3:  // NNS
            return readNNSManageNeuron(&ctx, &txn);

        default:
            zemu_log("Error: transaction type not supported\n");
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
        CHECK_PARSER_ERR(readCandidByte(&ctx, &icrc->account.owner.len))
        if (icrc->account.owner.len > DFINITY_PRINCIPAL_LEN) {
            return parser_unexpected_value;
        }
        CHECK_PARSER_ERR(readCandidBytes(&ctx, icrc->account.owner.ptr, icrc->account.owner.len))
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
        // should not be bigger than uint64
        if (icrc->memo.len > 8) {
            return parser_unexpected_value;
        }

        icrc->memo.p = ctx.buffer + ctx.offset;
        for (uint64_t i = 0; i < icrc->memo.len; i++) {
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
    if (icrc->has_created_at_time) {
        CHECK_PARSER_ERR(readCandidNat64(&ctx, &icrc->created_at_time))
    }

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
    if (canisterIdSize > 255) {
        return parser_unexpected_value;
    }

    crypto_principalToTextual(canisterId, (uint8_t)canisterIdSize, canister_textual, &outLen);

    icrc->icp_canister = (strncmp((const char *)&canister_textual, "ryjl3tyaaaaaaaaaaabacai", 23) == 0) ? 1 : 0;

    return parser_ok;
}

parser_error_t readCandidICRC2Approve(parser_tx_t *tx, const uint8_t *input, uint16_t inputSize) {
    zemu_log("readCandidICRC2Approve\n");

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
    if (txn.txn_length != 8) {  // ApproveArgs has 8 fields
        return parser_unexpected_value;
    }

    // 1. Check fee field (first in the transaction)
    txn.element.variant_index = 0;
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

    // 1. Check memo field (second in the transaction)
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))

    txn.element.variant_index = 1;
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

    // 3. Check from_subaccount field
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))

    txn.element.variant_index = 2;
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

    // 3. Check created_at_time field
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))

    txn.element.variant_index = 3;
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

    // 4. Check amount field
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))

    txn.element.variant_index = 4;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))

    if (txn.element.field_hash != icrc_hash_amount || txn.element.implementation != Nat) {
        return parser_unexpected_type;
    }

    // 5. Check expected_allowance field
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))

    txn.element.variant_index = 5;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))

    if (txn.element.field_hash != icrc_hash_expected_allowance) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(&txn))
    if (txn.txn_type != Opt || txn.element.implementation != Nat) {
        return parser_unexpected_type;
    }

    // 6. Check expires_at field
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))

    txn.element.variant_index = 6;  // Should be index 6, not 8
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))

    if (txn.element.field_hash != icrc_hash_expires_at) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(&txn))
    if (txn.txn_type != Opt || txn.element.implementation != Nat64) {
        return parser_unexpected_type;
    }

    // 4. Check spender field
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))

    txn.element.variant_index = 7;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))

    if (txn.element.field_hash != icrc_hash_spender) {
        return parser_unexpected_type;
    }

    const int64_t accountIndex = txn.element.implementation;
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, accountIndex))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    if (txn.txn_length != 2) {
        return parser_unexpected_value;
    }

    // Now extract the actual values into our structure - read in the same order as validation
    icrc2_approve_t *icrc2 = &ctx.tx_obj->tx_fields.call.data.icrc2_approve;

    // 1. Read fee
    CHECK_PARSER_ERR(readCandidByte(&ctx, &icrc2->has_fee))
    if (icrc2->has_fee) {
        CHECK_PARSER_ERR(readCandidLEB128(&ctx, &icrc2->fee))
    }

    // 2. Read memo
    CHECK_PARSER_ERR(readCandidByte(&ctx, &icrc2->has_memo))
    if (icrc2->has_memo) {
        uint8_t tmp = 0;
        CHECK_PARSER_ERR(readCandidNat(&ctx, &icrc2->memo.len))
        // should not be bigger than uint64
        if (icrc2->memo.len > 8) {
            return parser_unexpected_value;
        }

        icrc2->memo.p = ctx.buffer + ctx.offset;
        for (uint64_t i = 0; i < icrc2->memo.len; i++) {
            CHECK_PARSER_ERR(readCandidByte(&ctx, &tmp))
        }
    }

    // 3. Read from_subaccount
    CHECK_PARSER_ERR(readCandidByte(&ctx, &icrc2->has_from_subaccount))
    if (icrc2->has_from_subaccount) {
        CHECK_PARSER_ERR(readCandidText(&ctx, &icrc2->from_subaccount))
    }

    // 4. Read created_at_time
    CHECK_PARSER_ERR(readCandidByte(&ctx, &icrc2->has_created_at_time))
    if (icrc2->has_created_at_time) {
        CHECK_PARSER_ERR(readCandidNat64(&ctx, &icrc2->created_at_time))
    }

    // 5. Read amount
    CHECK_PARSER_ERR(readCandidLEB128(&ctx, &icrc2->amount))

    // 6. Read expected_allowance
    CHECK_PARSER_ERR(readCandidByte(&ctx, &icrc2->has_expected_allowance))
    if (icrc2->has_expected_allowance) {
        CHECK_PARSER_ERR(readCandidLEB128(&ctx, &icrc2->expected_allowance))
    }

    // 7. Read expires_at
    CHECK_PARSER_ERR(readCandidByte(&ctx, &icrc2->has_expires_at))
    if (icrc2->has_expires_at) {
        CHECK_PARSER_ERR(readCandidNat64(&ctx, &icrc2->expires_at))
    }

    // 8. Read spender (Account)
    CHECK_PARSER_ERR(readCandidByte(&ctx, &icrc2->spender.has_owner))
    if (icrc2->spender.has_owner) {
        CHECK_PARSER_ERR(readCandidByte(&ctx, &icrc2->spender.owner.len))
        if (icrc2->spender.owner.len > DFINITY_PRINCIPAL_LEN) {
            return parser_unexpected_value;
        }
        CHECK_PARSER_ERR(readCandidBytes(&ctx, icrc2->spender.owner.ptr, icrc2->spender.owner.len))
    }

    CHECK_PARSER_ERR(readCandidByte(&ctx, &icrc2->spender.has_subaccount))
    if (icrc2->spender.has_subaccount) {
        CHECK_PARSER_ERR(readCandidText(&ctx, &icrc2->spender.subaccount))
    }

    if (ctx.bufferLen - ctx.offset > 0) {
        return parser_unexpected_characters;
    }

    // Check if the transaction has ICP canister
    const uint8_t *canisterId = ctx.tx_obj->tx_fields.call.canister_id.data;
    const size_t canisterIdSize = ctx.tx_obj->tx_fields.call.canister_id.len;
    char canister_textual[50] = {0};
    uint16_t outLen = sizeof(canister_textual);
    if (canisterIdSize > 255) {
        return parser_unexpected_value;
    }

    crypto_principalToTextual(canisterId,
                             (uint8_t) canisterIdSize,
                             canister_textual,
                             &outLen);

    icrc2->icp_canister = (strncmp((const char*) &canister_textual, "ryjl3tyaaaaaaaaaaabacai", 23) == 0) ? 1 : 0;

    zemu_log("readCandidICRC2Approve OK\n");
    return parser_ok;
}

parser_error_t readCandidTransfer(parser_tx_t *tx, const uint8_t *input, uint16_t inputSize) {
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
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    if (txn.element.field_hash != transfer_hash_to || txn.txn_type != Vector) {
        return parser_unexpected_type;
    }
    // To is vec u8, OK

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    txn.element.variant_index = 1;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != transfer_hash_fee) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    txn.element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.implementation != Nat64) {
        return parser_unexpected_type;
    }
    // Fee is u64, OK

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    txn.element.variant_index = 2;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != transfer_hash_memo) {
        return parser_unexpected_type;
    }
    if (txn.element.implementation != Nat64) {
        return parser_unexpected_type;
    }
    // Memo is u64, OK

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    txn.element.variant_index = 3;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != transfer_hash_from_subaccount) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(&txn))
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    if (txn.txn_type != Vector) {
        return parser_unexpected_type;
    }
    // From_subaccount is opt vec u8, OK

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    txn.element.variant_index = 4;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != transfer_hash_timestamp) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(&txn))
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    txn.element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.implementation != Nat64) {
        return parser_unexpected_type;
    }
    // Timestamp is opt u64, OK

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    txn.element.variant_index = 5;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != transfer_hash_amount) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    txn.element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.implementation != Nat64) {
        return parser_unexpected_type;
    }
    // amount is u64, OK

    // let's read!
    candid_transfer_t *transfer = &ctx.tx_obj->tx_fields.call.data.candid_transfer;

    // Read to (AccountIdentifier)
    uint8_t ownerSize = 0;
    CHECK_PARSER_ERR(readCandidByte(&ctx, &ownerSize))
    if (ownerSize != DFINITY_ADDR_LEN) {
        return parser_unexpected_value;
    }
    CHECK_PARSER_ERR(readCandidBytes(&ctx, transfer->to, ownerSize))

    // Read fee (u64)
    CHECK_PARSER_ERR(readCandidNat64(&ctx, &transfer->fee))

    // Read memo (u64)
    CHECK_PARSER_ERR(readCandidNat64(&ctx, &transfer->memo))

    // Read from_subaccount (opt vec u8)
    CHECK_PARSER_ERR(readCandidByte(&ctx, &transfer->has_from_subaccount))
    if (transfer->has_from_subaccount) {
        CHECK_PARSER_ERR(readCandidText(&ctx, &transfer->from_subaccount))
    }

    // Read timestamp (opt u64)
    CHECK_PARSER_ERR(readCandidByte(&ctx, &transfer->has_timestamp))
    if (transfer->has_timestamp) {
        CHECK_PARSER_ERR(readCandidNat64(&ctx, &transfer->timestamp))
    }

    // Read amount
    CHECK_PARSER_ERR(readCandidNat64(&ctx, &transfer->amount))

    if (ctx.bufferLen - ctx.offset > 0) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}
