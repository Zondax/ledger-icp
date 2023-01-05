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
#define APP_TESTING 0
#define CANDID_TESTING 0

#include "candid_parser.h"
#include "leb128.h"

#define MAX_TYPE_TABLE_SIZE 16384

// Good reference:  https://github.com/dfinity/agent-js/tree/main/packages/candid
// https://github.com/dfinity/candid/blob/master/spec/Candid.md#deserialisation

typedef struct {
    uint64_t variant_index;
    uint64_t field_hash;
    int64_t implementation;
} candid_element_t;

typedef struct {
    uint16_t types_entry_point;
    parser_context_t ctx;
    int64_t txn_type;
    uint64_t txn_length;
    candid_element_t element;
} candid_transaction_t;

static parser_error_t checkCandidMAGIC(parser_context_t *ctx) {
    // Check DIDL magic bytes
    if (ctx->bufferLen < 4 + ctx->offset) {
        return parser_no_data;
    }

    if (memcmp(ctx->buffer + ctx->offset, PIC("DIDL"), 4) != 0) {
        // magic bytes do not match
        return parser_unexpected_tx_version;
    }
    ctx->offset += 4;
    return parser_ok;
}

const char *IDLTypeToString(IDLTypes_e t) {
    switch (t) {
        case Null:
            return "Null";
        case Bool:
            return "Bool";
        case Nat:
            return "Nat";
        case Int:
            return "Int";
////
        case Nat8:
            return "Nat8";
        case Nat16:
            return "Nat16";
        case Nat32:
            return "Nat32";
        case Nat64:
            return "Nat64";
////
        case Int8:
            return "Int8";
        case Int16:
            return "Int16";
        case Int32:
            return "Int32";
        case Int64:
            return "Int64";
////
        case Float32:
            return "Float32";
        case Float64:
            return "Float64";
        case Text:
            return "Text";
        case Reserved:
            return "Reserved";
        case Empty:
            return "Empty";
        case Opt:
            return "Opt";
        case Vector:
            return "Vector";
        case Record:
            return "Record";
        case Variant:
            return "Variant";
        case Func:
            return "Func";
        case Service:
            return "Service";
        case Principal:
            return "Principal";
        default:
            return "?";
    }
}

const char *CustomTypeToString(uint64_t t) {
#ifdef CANDID_TESTING
    switch (t) {
        case 4895187:
            return "4895187";
        case 5097222:
            return "5097222";
        default:
            return "?";
    }
#else
    return "?";
#endif
}

static parser_error_t readCandidLEB128(parser_context_t *ctx, uint64_t *v) {
    uint16_t consumed;
    CHECK_PARSER_ERR(decompressLEB128(ctx->buffer + ctx->offset, ctx->bufferLen - ctx->offset, v, &consumed))
    ctx->offset += consumed;
    return parser_ok;
}

static parser_error_t readCandidSLEB128(parser_context_t *ctx, int64_t *v) {
    uint16_t consumed;
    CHECK_PARSER_ERR(decompressSLEB128(ctx->buffer + ctx->offset, ctx->bufferLen - ctx->offset, v, &consumed))
    ctx->offset += consumed;
    return parser_ok;
}

static parser_error_t readCandidByte(parser_context_t *ctx, uint8_t *v) {
    if (ctx->offset < ctx->bufferLen) {
        *v = *(ctx->buffer + ctx->offset);
        ctx->offset++;
        return parser_ok;
    }
    return parser_no_data;
}

static parser_error_t readCandidBytes(parser_context_t *ctx, uint8_t *buff, uint8_t buffLen) {
    if (ctx->bufferLen - ctx->offset < buffLen) {
        return parser_unexpected_buffer_end;
    }
    MEMCPY(buff, (ctx->buffer + ctx->offset), buffLen);
    ctx->offset += buffLen;
    return parser_ok;
}

static parser_error_t readCandidNat(parser_context_t *ctx, uint64_t *v) {
    CHECK_PARSER_ERR(readCandidLEB128(ctx, v))
    return parser_ok;
}

static parser_error_t readCandidNat32(parser_context_t *ctx, uint32_t *v) {
    // need to compose it because ledger cannot deference misaligned values
    uint8_t b;
    *v = 0;

    for (uint8_t i = 0; i < 32; i += 8) {
        CHECK_PARSER_ERR(readCandidByte(ctx, &b))
        *v += (uint32_t) b << i;
    }
    return parser_ok;
}

static parser_error_t readCandidNat64(parser_context_t *ctx, uint64_t *v) {
    // need to compose it because ledger cannot deference misaligned values
    uint8_t b;
    *v = 0;

    for (uint8_t i = 0; i < 64; i += 8) {
        CHECK_PARSER_ERR(readCandidByte(ctx, &b))
        *v += (uint64_t) b << i;
    }
    return parser_ok;
}

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

static parser_error_t readCandidText(parser_context_t *ctx, sizedBuffer_t *v) {
    CHECK_PARSER_ERR(readCandidLEB128(ctx, &v->len))
    if (ctx->bufferLen - ctx->offset < v->len) {
        return parser_unexpected_buffer_end;
    }
    v->p = ctx->buffer + ctx->offset;
    ctx->offset += v->len;
    return parser_ok;
}

static parser_error_t readCandidType(parser_context_t *ctx, int64_t *t) {
    CHECK_PARSER_ERR(readCandidSLEB128(ctx, t))

    if (*t < -24) {
        return parser_value_out_of_range;
    }

    if (*t > (int64_t) ctx->tx_obj->candid_typetableSize) {
        return parser_value_out_of_range;
    }

    return parser_ok;
}

static parser_error_t readCandidWhichVariant(parser_context_t *ctx, uint64_t *t) {
    CHECK_PARSER_ERR(readCandidLEB128(ctx, t))
    return parser_ok;
}

static parser_error_t readAndCheckRootType(parser_context_t *ctx) {
    int64_t tmpType = -1;
    CHECK_PARSER_ERR(readCandidType(ctx, &tmpType))
    if (tmpType < 0 || (uint64_t) tmpType >= ctx->tx_obj->candid_typetableSize) {
        return parser_unexpected_type;
    }

    ctx->tx_obj->candid_rootType = (uint64_t) tmpType;

    return parser_ok;
}

static parser_error_t readCandidTypeTable_Opt(parser_context_t *ctx) {
    int64_t t;
    CHECK_PARSER_ERR(readCandidType(ctx, &t))
#if CANDID_TESTING
    if (t < 0) {
        ZEMU_LOGF(50, "          [opt    ] %s", IDLTypeToString(t))
    } else {
        ZEMU_LOGF(50, "          [opt    ] %03lld", t)
    }
#endif
    return parser_ok;
}

static parser_error_t readCandidTypeTable_VectorItem(parser_context_t *ctx) {
    int64_t t;
    CHECK_PARSER_ERR(readCandidType(ctx, &t))
#if CANDID_TESTING
    if (t < 0) {
        ZEMU_LOGF(50, "          [item   ] %s", IDLTypeToString(t))
    } else {
        ZEMU_LOGF(50, "          [item   ] %03lld", t)
    }
#endif
    return parser_ok;
}

static parser_error_t readCandidRecordLength(candid_transaction_t *txn) {
    if (txn == NULL) {
        return parser_unexpected_error;
    }
    if (txn->txn_type != Record) {
        return parser_unexpected_type;
    }
    CHECK_PARSER_ERR(readCandidLEB128(&txn->ctx, &txn->txn_length))
    return parser_ok;
}

static parser_error_t readCandidInnerElement(candid_transaction_t *txn, candid_element_t *element) {
    if (txn == NULL || element == NULL) {
        return parser_unexpected_error;
    }

    if (element->variant_index >= txn->txn_length) {
        return parser_unexpected_value;
    }

    uint16_t start_offset = txn->ctx.offset;
    uint64_t prevHash = 0;
    bool_t prevHashInitialized = 0;
    int64_t t;

    for (uint64_t i = 0; i <= element->variant_index; i++) {
        uint64_t hash;
        CHECK_PARSER_ERR(readCandidLEB128(&txn->ctx, &hash))

        if (prevHashInitialized && hash <= prevHash) {
            return parser_value_out_of_range;
        }
        prevHash = hash;
        prevHashInitialized = 1;

        CHECK_PARSER_ERR(readCandidType(&txn->ctx, &t))
#if CANDID_TESTING
        if (t < 0) {
            ZEMU_LOGF(100, "          [idx %lld] %016lld %s -> %s", i, hash, CustomTypeToString(hash),
                      IDLTypeToString(t))
        } else {
            ZEMU_LOGF(100, "          [idx %lld] %016lld %s -> %03lld", i, hash, CustomTypeToString(hash), t)
        }
#endif
        element->field_hash = hash;
        element->implementation = t;
    }

    txn->ctx.offset = start_offset;
    return parser_ok;
}

static parser_error_t readCandidTypeTable_Variant(parser_context_t *ctx) {
    uint64_t objectLength;
    CHECK_PARSER_ERR(readCandidLEB128(ctx, &objectLength))

    uint64_t prevHash = 0;
    bool_t prevHashInitialized = 0;
    int64_t t;

    for (uint64_t i = 0; i < objectLength; i++) {
        uint64_t hash;
        CHECK_PARSER_ERR(readCandidLEB128(ctx, &hash))

        if (prevHashInitialized && hash <= prevHash) {
            return parser_value_out_of_range;
        }
        prevHash = hash;
        prevHashInitialized = 1;

        CHECK_PARSER_ERR(readCandidType(ctx, &t))
#if CANDID_TESTING
        if (t < 0) {
            ZEMU_LOGF(100, "          [idx %lld] %016lld %s -> %s", i, hash, CustomTypeToString(hash),
                      IDLTypeToString(t))
        } else {
            ZEMU_LOGF(100, "          [idx %lld] %016lld %s -> %03lld", i, hash, CustomTypeToString(hash), t)
        }
#endif
    }

    return parser_ok;
}

static parser_error_t readCandidTypeTable_Item(parser_context_t *ctx, const int64_t *type, __Z_UNUSED uint64_t typeIdx) {
    switch (*type) {
        case Opt: {
            zemu_log_stack("readCandidTypeTable::Opt");
            CHECK_PARSER_ERR(readCandidTypeTable_Opt(ctx))
#if CANDID_TESTING
            ZEMU_LOGF(50, "[%03llu/%03llu] [opt    ]",
                      typeIdx,
                      ctx->tx_obj->candid_typetableSize - 1)
#endif
            break;
        }
        case Vector: {
            zemu_log_stack("readCandidTypeTable::Vector");
            CHECK_PARSER_ERR(readCandidTypeTable_VectorItem(ctx))
#if CANDID_TESTING
            ZEMU_LOGF(50, "[%03llu/%03llu] [vector ]",
                      typeIdx,
                      ctx->tx_obj->candid_typetableSize - 1)
#endif
            break;
        }

            ///////
        case Record: {
            zemu_log_stack("readCandidTypeTable::Record");
            CHECK_PARSER_ERR(readCandidTypeTable_Variant(ctx))
#if CANDID_TESTING
            ZEMU_LOGF(50, "[%03llu/%03llu] [record ]",
                      typeIdx,
                      ctx->tx_obj->candid_typetableSize - 1)
#endif
            break;
        }
        case Variant: {
            zemu_log_stack("readCandidTypeTable::Variant");
            CHECK_PARSER_ERR(readCandidTypeTable_Variant(ctx))
#if CANDID_TESTING
            ZEMU_LOGF(50, "[%03llu/%03llu] [variant]",
                      typeIdx,
                      ctx->tx_obj->candid_typetableSize - 1)
#endif
            break;
        }

        case Func:
        case Service:
        default:
            return parser_unexpected_type;
    }

    return parser_ok;
}

static parser_error_t readCandidOptional(candid_transaction_t *txn) {
    if (txn == NULL) {
        return parser_unexpected_error;
    }
    if (txn->txn_type != Opt) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(readCandidType(&txn->ctx, &txn->element.implementation))
    return parser_ok;
}

static parser_error_t getCandidTypeFromTable(candid_transaction_t *txn, uint64_t table_index) {
    if (txn == NULL) {
        return parser_unexpected_error;
    }

    if (table_index >= txn->ctx.tx_obj->candid_typetableSize) {
        return parser_value_out_of_range;
    }

    int64_t type = 0;

    // Move pointer to types table
    txn->ctx.offset = txn->types_entry_point;
    for (uint64_t itemIdx = 0; itemIdx <= table_index; itemIdx++) {
        CHECK_PARSER_ERR(readCandidType(&txn->ctx, &type))
        txn->txn_type = type;

        if (itemIdx < table_index) {
            CHECK_PARSER_ERR(readCandidTypeTable_Item(&txn->ctx, &type, itemIdx))
        }
    }
    return parser_ok;
}

static parser_error_t readCandidTypeTable(parser_context_t *ctx, candid_transaction_t *txn) {
    if (ctx == NULL || txn == NULL) {
        return parser_unexpected_error;
    }

    // Initialize rootType with an invalid value. It will be read later
    ctx->tx_obj->candid_rootType = MAX_TYPE_TABLE_SIZE;
    ctx->tx_obj->candid_typetableSize = 0;
    CHECK_PARSER_ERR(readCandidLEB128(ctx, &ctx->tx_obj->candid_typetableSize))

    if (ctx->tx_obj->candid_typetableSize >= MAX_TYPE_TABLE_SIZE) {
        return parser_value_out_of_range;
    }

    txn->types_entry_point = ctx->offset;
    int64_t type = 0;
    ZEMU_LOGF(50, "-------------------------------\n")
    for (uint64_t itemIdx = 0; itemIdx < ctx->tx_obj->candid_typetableSize; itemIdx++) {
        CHECK_PARSER_ERR(readCandidType(ctx, &type))
        txn->txn_type = (IDLTypes_e) type;
        CHECK_PARSER_ERR(readCandidTypeTable_Item(ctx, &type, itemIdx))
    }
    ZEMU_LOGF(50, "-------------------------------\n")

    return parser_ok;
}

static parser_error_t readCandidHeader(parser_context_t *ctx, candid_transaction_t *txn) {
    // Check DIDL magic bytes
    CHECK_PARSER_ERR(checkCandidMAGIC(ctx))
    // Read type table
    CHECK_PARSER_ERR(readCandidTypeTable(ctx, txn))
    // Read number of arguments
    uint64_t argsLen;
    CHECK_PARSER_ERR(readCandidNat(ctx, &argsLen))
    if (argsLen != 1) {
        return parser_value_out_of_range;
    }
    return parser_ok;
}

#define CREATE_CTX(__CTX, __TX, __INPUT, __INPUT_SIZE) \
    parser_context_t __CTX; \
    ctx.buffer = __INPUT; \
    ctx.bufferLen = __INPUT_SIZE; \
    ctx.offset = 0; \
    ctx.tx_obj = __TX;


static parser_error_t getHash(candid_transaction_t *txn, const uint8_t variant, uint64_t *hash) {
    if (txn == NULL || hash == NULL) {
        return parser_unexpected_error;
    }
    *hash = 0;
    // Get option type implementation
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, txn->element.implementation))

    int64_t type = 0;
    CHECK_PARSER_ERR(readCandidType(&txn->ctx, &type))
    CHECK_PARSER_ERR(getCandidTypeFromTable(txn, type))

    uint64_t variantLength = 0;
    CHECK_PARSER_ERR(readCandidLEB128(&txn->ctx, &variantLength))
    if (variant >= variantLength) {
        return parser_value_out_of_range;
    }

    // Move until requested variant
    for (uint64_t i = 0; i < variant; i++) {
        int64_t dummyType;
        uint64_t tmpHash = 0;
        CHECK_PARSER_ERR(readCandidLEB128(&txn->ctx, &tmpHash))
        CHECK_PARSER_ERR(readCandidType(&txn->ctx, &dummyType))
    }

    CHECK_PARSER_ERR(readCandidLEB128(&txn->ctx, hash))
    CHECK_PARSER_ERR(readCandidType(&txn->ctx, &txn->element.implementation))
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
    candid_ManageNeuron_t *val = &tx->tx_fields.call.data.candid_manageNeuron;

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))

    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    if (txn.txn_length != 3) {
        return parser_unexpected_value;
    }

    // Check sanity Id
    txn.element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != hash_id) {
        return parser_unexpected_type;
    }
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(&txn))

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    if (txn.txn_length != 1) {
        return parser_unexpected_value;
    }
    txn.element.variant_index = 0;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != hash_id || txn.element.implementation != Nat64) {
        return parser_unexpected_type;
    }
    // Read Id
    CHECK_PARSER_ERR(readCandidByte(&ctx, &val->has_id))
    if (val->has_id) {
        CHECK_PARSER_ERR(readCandidNat64(&ctx, &val->id.id))
    }

    // Check sanity Command
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))

    txn.element.variant_index = 1;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != hash_command) {
        return parser_unexpected_type;
    }
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(&txn))

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    if (txn.txn_type != Variant) {
        return parser_unexpected_type;
    }

    // Reset pointers and read Command
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    txn.element.variant_index = 1;
    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))

    CHECK_PARSER_ERR(readCandidByte(&ctx, &val->has_command))
    if (val->has_command) {
        CHECK_PARSER_ERR(readCandidNat(&ctx, &val->command.variant))
        CHECK_PARSER_ERR(getHash(&txn, val->command.variant, &val->command.hash))

        switch (val->command.hash) {
            case hash_command_Split: {
                // Check sanity Split
                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                CHECK_PARSER_ERR(readCandidRecordLength(&txn))
                if (txn.txn_length != 1) {
                    return parser_unexpected_value;
                }
                txn.element.variant_index = 0;
                CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
                if (txn.element.field_hash != hash_amount_e8s || txn.element.implementation != Nat64) {
                    return parser_unexpected_type;
                }

                // Read Split
                CHECK_PARSER_ERR(readCandidNat64(&ctx, &val->command.split.amount_e8s))
                break;
            }

            case hash_command_Merge: {
                // Check sanity Merge
                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                CHECK_PARSER_ERR(readCandidRecordLength(&txn))
                if (txn.txn_length != 1) {
                    return parser_unexpected_value;
                }
                txn.element.variant_index = 0;
                CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))

                if (txn.element.field_hash != hash_source_neuron_id) {
                    return parser_unexpected_type;
                }

                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                CHECK_PARSER_ERR(readCandidOptional(&txn))

                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                CHECK_PARSER_ERR(readCandidRecordLength(&txn))
                if (txn.txn_length != 1) {
                    return parser_unexpected_value;
                }
                CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))

                if (txn.element.field_hash != hash_id || txn.element.implementation != Nat64) {
                    return parser_unexpected_type;
                }

                // Read Merge
                CHECK_PARSER_ERR(readCandidByte(&ctx, &val->command.merge.has_source))
                if (!val->command.merge.has_source) {
                    // https://github.com/Zondax/ledger-icp/issues/149
                    // indicates that missing source should be rejected
                    return parser_unexpected_value;
                }
                CHECK_PARSER_ERR(readCandidNat64(&ctx, &val->command.merge.source.id))
                break;
            }

            case hash_command_Configure: {
                // Save this type
                const int64_t txn_element_implementation = txn.element.implementation;

                // Check sanity Configure
                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                CHECK_PARSER_ERR(readCandidRecordLength(&txn))
                if (txn.txn_length != 1) {
                    return parser_unexpected_value;
                }
                txn.element.variant_index = 0;
                CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
                if (txn.element.field_hash != hash_operation) {
                    return parser_unexpected_type;
                }

                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                CHECK_PARSER_ERR(readCandidOptional(&txn))

                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                if (txn.txn_type != Variant) {
                    return parser_unexpected_type;
                }

                // Read Configure / Operation
                CHECK_PARSER_ERR(readCandidByte(&ctx, &val->command.configure.has_operation))
                if (!val->command.configure.has_operation) {
                    return parser_unexpected_value;
                }
                candid_Operation_t *operation = &val->command.configure.operation;
                CHECK_PARSER_ERR(readCandidWhichVariant(&ctx, &operation->which))

                // Restore saved type
                txn.element.implementation = txn_element_implementation;
                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                CHECK_PARSER_ERR(readCandidRecordLength(&txn))
                if (txn.txn_length > 1) {
                    return parser_unexpected_number_items;
                }

                txn.element.variant_index = 0;
                CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
                CHECK_PARSER_ERR(getHash(&txn, operation->which, &operation->hash))

                switch (operation->hash) {
                    case hash_operation_SetDissolvedTimestamp: {
                        // Check sanity SetDissolvedTimestamp
                        CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                        CHECK_PARSER_ERR(readCandidRecordLength(&txn))
                        if (txn.txn_length > 1) {
                            return parser_unexpected_number_items;
                        }

                        txn.element.variant_index = 0;
                        CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
                        if (txn.element.field_hash != hash_dissolve_timestamp_seconds || txn.element.implementation != Nat64) {
                            return parser_unexpected_type;
                        }

                        // Read SetDissolvedTimestamp
                        CHECK_PARSER_ERR(readCandidNat64(&ctx,
                                                         &operation->setDissolveTimestamp.dissolve_timestamp_seconds))

                        if (operation->setDissolveTimestamp.dissolve_timestamp_seconds >= 4102444800) {
                            return parser_value_out_of_range;
                        }

                        break;
                    }
                    case hash_operation_LeaveCommunityFund: {
                        // Check sanity LeaveCommunityFund
                        CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                        CHECK_PARSER_ERR(readCandidRecordLength(&txn))
                        if (txn.txn_length != 0) {
                            return parser_unexpected_number_items;
                        }
                        // Empty record
                        break;
                    }
                    case hash_operation_ChangeAutoStakeMaturity:
                        CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                        CHECK_PARSER_ERR(readCandidRecordLength(&txn))
                        if (txn.txn_length != 1) {
                            return parser_unexpected_number_items;
                        }
                        txn.element.variant_index = 0;
                        CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
                        if (txn.element.field_hash != hash_setting_auto_stake_maturity
                            || txn.element.implementation != Bool) {
                            return parser_unexpected_type;
                        }
                        // let's read
                        CHECK_PARSER_ERR(readCandidByte(
                                             &ctx,
                                             &operation->autoStakeMaturity.requested_setting_for_auto_stake_maturity))
                        break;
                    default:
                        ZEMU_LOGF(100, "Unimplemented operation | Hash: %llu\n", operation->hash)
                        return parser_unexpected_value;
                }
                break;
            }
            case hash_command_Spawn: {
                // Check sanity
                const int64_t spawnRoot = txn.element.implementation;
                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                CHECK_PARSER_ERR(readCandidRecordLength(&txn))
                if (txn.txn_length != 3) {
                    return parser_unexpected_value;
                }

                txn.element.variant_index = 0;
                CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
                if (txn.element.field_hash != hash_percentage_to_spawn) {
                    return parser_unexpected_type;
                }
                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                CHECK_PARSER_ERR(readCandidOptional(&txn))
                if (txn.element.implementation != Nat32) {
                    return parser_unexpected_type;
                }

                // reset txn
                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, spawnRoot))
                CHECK_PARSER_ERR(readCandidRecordLength(&txn))

                txn.element.variant_index = 1;
                CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
                if (txn.element.field_hash != hash_new_controller) {
                    return parser_unexpected_type;
                }
                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                CHECK_PARSER_ERR(readCandidOptional(&txn))
                if (txn.element.implementation != Principal) {
                    return parser_unexpected_type;
                }

                // reset txn
                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, spawnRoot))
                CHECK_PARSER_ERR(readCandidRecordLength(&txn))

                txn.element.variant_index = 2;
                CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
                if (txn.element.field_hash != hash_nonce) {
                    return parser_unexpected_type;
                }
                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                CHECK_PARSER_ERR(readCandidOptional(&txn))
                if (txn.element.implementation != Nat64) {
                    return parser_unexpected_type;
                }

                // now let's read
                // Percentage to spawn
                CHECK_PARSER_ERR(readCandidByte(&ctx, &val->command.spawn.has_percentage_to_spawn))
                if (val->command.spawn.has_percentage_to_spawn) {
                    CHECK_PARSER_ERR(readCandidNat32(&ctx, &val->command.spawn.percentage_to_spawn))
                    // Sanity check
                    if (val->command.spawn.percentage_to_spawn == 0 || val->command.spawn.percentage_to_spawn > 100) {
                        return parser_value_out_of_range;
                    }
                }

                // Controller
                CHECK_PARSER_ERR(readCandidByte(&ctx, &val->command.spawn.has_controller))
                if (val->command.spawn.has_controller) {
                    uint8_t has_principal = 0;
                    uint8_t principalSize = 0;
                    CHECK_PARSER_ERR(readCandidByte(&ctx, &has_principal))
                    if(has_principal) {
                        CHECK_PARSER_ERR(readCandidByte(&ctx, &principalSize))
                        CHECK_PARSER_ERR(readCandidBytes(&ctx, val->command.spawn.new_controller, principalSize))
                    }
                }

                // Nonce
                CHECK_PARSER_ERR(readCandidByte(&ctx, &val->command.spawn.has_nonce))
                if (val->command.spawn.has_nonce) {
                    CHECK_PARSER_ERR(readCandidNat64(&ctx, &val->command.spawn.nonce))
                }

                break;
            }
            case hash_command_StakeMaturity:
                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                CHECK_PARSER_ERR(readCandidRecordLength(&txn))
                if (txn.txn_length != 1) {
                    return parser_unexpected_value;
                }

                txn.element.variant_index = 0;
                CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
                if (txn.element.field_hash != hash_percentage_to_stake) {
                    return parser_unexpected_type;
                }
                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                CHECK_PARSER_ERR(readCandidOptional(&txn))
                if (txn.element.implementation != Nat32) {
                    return parser_unexpected_type;
                }

                // now let's read
                CHECK_PARSER_ERR(readCandidByte(&ctx, &val->command.stake.has_percentage_to_stake))
                if (val->command.spawn.has_percentage_to_spawn) {
                    CHECK_PARSER_ERR(readCandidNat32(&ctx, &val->command.stake.percentage_to_stake))
                    // Sanity check
                    if (val->command.stake.percentage_to_stake == 0 || val->command.stake.percentage_to_stake > 100) {
                        return parser_value_out_of_range;
                    }
                }
                break;

            default:
                ZEMU_LOGF(100, "Unimplemented command | Hash: %llu\n", val->command.hash)
                return parser_unexpected_type;
        }
    }

    // Check sanity Neuron id or subaccount
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    txn.element.variant_index = 2;

    CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))
    if (txn.element.field_hash != hash_neuron_id_or_subaccount) {
        return parser_unexpected_type;
    }

    const int64_t savedElementImplementation = txn.element.implementation;

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    CHECK_PARSER_ERR(readCandidOptional(&txn))
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
    if (txn.txn_type != Variant) {
        return parser_unexpected_type;
    }

    // Read neuron id or subaccount
    CHECK_PARSER_ERR(readCandidByte(&ctx, &val->has_neuron_id_or_subaccount))
    if (val->has_neuron_id_or_subaccount) {
        CHECK_PARSER_ERR(readCandidWhichVariant(&ctx, &val->neuron_id_or_subaccount.which))

        txn.element.implementation = savedElementImplementation;
        uint64_t neuron_id_or_subaccount_hash = 0;
        CHECK_PARSER_ERR(getHash(&txn, val->neuron_id_or_subaccount.which, &neuron_id_or_subaccount_hash))

        switch (neuron_id_or_subaccount_hash) {
            case hash_subaccount: {
                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                if (txn.txn_type != Vector) {
                    return parser_unexpected_type;
                }

                // Read subaccount
                CHECK_PARSER_ERR(readCandidText(&ctx, &val->neuron_id_or_subaccount.subaccount))
                break;
            }
            case hash_neuron_id: {
                CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, txn.element.implementation))
                CHECK_PARSER_ERR(readCandidRecordLength(&txn))
                if (txn.txn_length != 1) {
                    return parser_unexpected_value;
                }

                // Read neuron id
                CHECK_PARSER_ERR(readCandidNat64(&ctx, &val->neuron_id_or_subaccount.neuronId.id))
                break;
            }
            default:
                return parser_value_out_of_range;
        }

    }

    if (ctx.bufferLen - ctx.offset > 0) {
        return parser_unexpected_characters;
    }

    return parser_ok;
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
