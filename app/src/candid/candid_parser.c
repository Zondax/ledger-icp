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
#define APP_TESTING 1
#define CANDID_TESTING 1

#include "candid_parser.h"
#include "leb128.h"

// Good reference:  https://github.com/dfinity/agent-js/tree/main/packages/candid
// https://github.com/dfinity/candid/blob/master/spec/Candid.md#deserialisation

parser_error_t checkCandidMAGIC(parser_context_t *ctx) {
    // Check DIDL magic bytes
    if (ctx->bufferLen < 4) {
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
    return "?"
#endif
}

parser_error_t readCandidLEB128(parser_context_t *ctx, uint64_t *v) {
    uint16_t consumed;
    CHECK_PARSER_ERR(decompressLEB128(ctx->buffer + ctx->offset, ctx->bufferLen - ctx->offset, v, &consumed))
    ctx->offset += consumed;
    return parser_ok;
}

parser_error_t readCandidSLEB128(parser_context_t *ctx, int64_t *v) {
    uint16_t consumed;
    CHECK_PARSER_ERR(decompressSLEB128(ctx->buffer + ctx->offset, ctx->bufferLen - ctx->offset, v, &consumed))
    ctx->offset += consumed;
    return parser_ok;
}

parser_error_t readCandidByte(parser_context_t *ctx, uint8_t *v) {
    if (ctx->offset < ctx->bufferLen) {
        *v = *(ctx->buffer + ctx->offset);
        ctx->offset++;
        return parser_ok;
    }
    return parser_no_data;
}

parser_error_t readCandidInt(parser_context_t *ctx, int64_t *v) {
    CHECK_PARSER_ERR(readCandidSLEB128(ctx, v))
    return parser_ok;
}

parser_error_t readCandidNat(parser_context_t *ctx, uint64_t *v) {
    CHECK_PARSER_ERR(readCandidLEB128(ctx, v))
    return parser_ok;
}

parser_error_t readCandidNat64(parser_context_t *ctx, uint64_t *v) {
    // need to compose it because ledger cannot deference misaligned values
    uint8_t b;
    *v = 0;

    for (uint64_t i = 0; i < 64; i += 8) {
        CHECK_PARSER_ERR(readCandidByte(ctx, &b))
        *v += (uint64_t) b << i;
    }
    return parser_ok;
}

parser_error_t readCandidText(parser_context_t *ctx, sizedBuffer_t *v) {
    CHECK_PARSER_ERR(readCandidLEB128(ctx, &v->len))
    if (ctx->bufferLen - ctx->offset < v->len) {
        return parser_unexpected_buffer_end;
    }
    v->p = ctx->buffer + ctx->offset;
    ctx->offset += v->len;
    return parser_ok;
}

parser_error_t readCandidType(parser_context_t *ctx, int64_t *t) {
    CHECK_PARSER_ERR(readCandidSLEB128(ctx, t))

    if (*t < -24) {
        return parser_value_out_of_range;
    }

    if (*t > ctx->tx_obj->candid_state.typetableSize) {
        return parser_value_out_of_range;
    }

    return parser_ok;
}

parser_error_t readCandidWhichVariant(parser_context_t *ctx, uint64_t *t) {
    CHECK_PARSER_ERR(readCandidLEB128(ctx, t))
    return parser_ok;
}

parser_error_t readAndCheckType(parser_context_t *ctx, int64_t expected_type) {
    int64_t t;
    CHECK_PARSER_ERR(readCandidType(ctx, &t))
    if (t != expected_type) {
        return parser_unexpected_type;
    }
    return parser_ok;
}

parser_error_t readCandidTypeTable_Opt(parser_context_t *ctx) {
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

parser_error_t readCandidTypeTable_VectorItem(parser_context_t *ctx) {
    int64_t t;
    CHECK_PARSER_ERR(readCandidType(ctx, &t))
#if CANDID_TESTING
    if (t < 0) {
        ZEMU_LOGF(50, "          [item   ] %s", IDLTypeToString(t))
    } else {
        ZEMU_LOGF(50, "          [item   ] %03ld", t)
    }
#endif
    return parser_ok;
}

parser_error_t readCandidTypeTable_Variant(parser_context_t *ctx) {
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
            ZEMU_LOGF(100, "          [idx %ld] %016ld %s -> %s", i, hash, CustomTypeToString(hash),
                      IDLTypeToString(t))
        } else {
            ZEMU_LOGF(100, "          [idx %ld] %016ld %s -> %03ld", i, hash, CustomTypeToString(hash), t)
        }
#endif
    }

    return parser_ok;
}

parser_error_t readCandidTypeTable(parser_context_t *ctx) {
    uint64_t typeTableLen;
    CHECK_PARSER_ERR(readCandidLEB128(ctx, &typeTableLen))

    if (typeTableLen >= 16384) {
        return parser_value_out_of_range;
    }

    ctx->tx_obj->candid_state.typetableSize = typeTableLen;
    ctx->tx_obj->candid_state.typetableCurrent = 0;

    zemu_log_stack("readCandidTypeTable::loop");

    for (uint64_t item = 0; item < typeTableLen; item++) {
        int64_t ty;
        CHECK_PARSER_ERR(readCandidType(ctx, &ty))
        zemu_log_stack("readCandidTypeTable::read type");

        switch (ty) {
            case Opt: {
                zemu_log_stack("readCandidTypeTable::Opt");
                CHECK_PARSER_ERR(readCandidTypeTable_Opt(ctx))
#if CANDID_TESTING
                ZEMU_LOGF(50, "[%03d/%03d] [opt    ]",
                          ctx->tx_obj->candid_state.typetableCurrent,
                          ctx->tx_obj->candid_state.typetableSize - 1)
#endif
                break;
            }
            case Vector: {
                zemu_log_stack("readCandidTypeTable::Vector");
                CHECK_PARSER_ERR(readCandidTypeTable_VectorItem(ctx))
#if CANDID_TESTING
                ZEMU_LOGF(50, "[%03d/%03d] [vector ]",
                          ctx->tx_obj->candid_state.typetableCurrent,
                          ctx->tx_obj->candid_state.typetableSize - 1)
#endif
                break;
            }

                ///////
            case Record: {
                zemu_log_stack("readCandidTypeTable::Record");
                CHECK_PARSER_ERR(readCandidTypeTable_Variant(ctx))
#if CANDID_TESTING
                ZEMU_LOGF(50, "[%03d/%03d] [record ]",
                          ctx->tx_obj->candid_state.typetableCurrent,
                          ctx->tx_obj->candid_state.typetableSize - 1)
#endif
                break;
            }
            case Variant: {
                zemu_log_stack("readCandidTypeTable::Variant");
                CHECK_PARSER_ERR(readCandidTypeTable_Variant(ctx))
#if CANDID_TESTING
                ZEMU_LOGF(50, "[%03d/%03d] [variant]",
                          ctx->tx_obj->candid_state.typetableCurrent,
                          ctx->tx_obj->candid_state.typetableSize - 1)
#endif
                break;
            }

            case Func:
            case Service:
            default:
                return parser_unexpected_type;
        }

        ctx->tx_obj->candid_state.typetableCurrent++;
    }


    return parser_ok;
}

parser_error_t readCandidManageNeuron(parser_tx_t *tx, const uint8_t *input, uint16_t inputSize) {
    parser_context_t ctx;

    // initialize context
    ctx.buffer = input;
    ctx.bufferLen = inputSize;
    ctx.offset = 0;
    ctx.tx_obj = tx;

    // Check DIDL magic bytes
    CHECK_PARSER_ERR(checkCandidMAGIC(&ctx))

    // Read type table
    CHECK_PARSER_ERR(readCandidTypeTable(&ctx))

    // Read number of arguments
    uint64_t argsLen;
    CHECK_PARSER_ERR(readCandidNat(&ctx, &argsLen))
    if (argsLen != 1) {
        return parser_value_out_of_range;
    }

    candid_ManageNeuron_t *val = &tx->tx_fields.call.data.candid_manageNeuron;

    CHECK_PARSER_ERR(readAndCheckType(&ctx, 65))

    CHECK_PARSER_ERR(readCandidByte(&ctx, &val->has_id))
    if (val->has_id) {
        CHECK_PARSER_ERR(readCandidNat64(&ctx, &val->id.id))
    }

    CHECK_PARSER_ERR(readCandidByte(&ctx, &val->has_command))
    if (val->has_command) {
        CHECK_PARSER_ERR(readCandidNat(&ctx, &val->command.variant))

        switch (val->command.variant) {
            case command_Split: CHECK_PARSER_ERR(readCandidNat64(&ctx, &val->command.split.amount_e8s))
                break;
            case command_Merge: {
                CHECK_PARSER_ERR(readCandidByte(&ctx, &val->command.merge.has_source))
                if (!val->command.merge.has_source) {
                    // https://github.com/Zondax/ledger-icp/issues/149
                    // indicates that missing source should be rejected
                    return parser_unexpected_value;
                }
                CHECK_PARSER_ERR(readCandidNat64(&ctx, &val->command.merge.source.id))
                break;
            }
            case command_Configure: {
                CHECK_PARSER_ERR(readCandidByte(&ctx, &val->command.configure.has_operation))
                if (!val->command.configure.has_operation) {
                    return parser_unexpected_value;
                }
                CHECK_PARSER_ERR(readCandidWhichVariant(&ctx, &val->command.configure.operation.which))
                switch (val->command.configure.operation.which) {
                    case operation_SetDissolvedTimestamp:
                        break;
                    default:
                        return parser_unexpected_value;
                }

            }
            default:
                return parser_unexpected_type;
        }
    }

    CHECK_PARSER_ERR(readCandidByte(&ctx, &val->has_neuron_id_or_subaccount))
    if (val->has_neuron_id_or_subaccount) {
        CHECK_PARSER_ERR(readCandidWhichVariant(&ctx, &val->neuron_id_or_subaccount.which))

        switch (val->neuron_id_or_subaccount.which) {
            case 0:
                //CHECK_PARSER_ERR(readCandidText(&ctx, &val->neuron_id_or_subaccount.subaccount))
                break;
            case 1: CHECK_PARSER_ERR(readCandidNat64(&ctx, &val->neuron_id_or_subaccount.neuronId.id))
                break;
            default:
                return parser_value_out_of_range;
        }

    }

    return parser_ok;
}

parser_error_t readCandidUpdateNodeProvider(parser_tx_t *tx, const uint8_t *input, uint16_t inputSize) {
    parser_context_t ctx;

    // initialize context
    ctx.buffer = input;
    ctx.bufferLen = inputSize;
    ctx.offset = 0;
    ctx.tx_obj = tx;

    // Check DIDL magic bytes
    CHECK_PARSER_ERR(checkCandidMAGIC(&ctx))

    // Read type table
    CHECK_PARSER_ERR(readCandidTypeTable(&ctx))

    // Read number of arguments
    uint64_t argsLen;
    CHECK_PARSER_ERR(readCandidLEB128(&ctx, &argsLen))

    if (argsLen != 1) {
        return parser_value_out_of_range;
    }

    CHECK_PARSER_ERR(readAndCheckType(&ctx, 3))

    candid_UpdateNodeProvider_t *val = &tx->tx_fields.call.data.candid_updateNodeProvider;

    CHECK_PARSER_ERR(readCandidByte(&ctx, &val->has_reward_account))
    if (!val->has_reward_account) {
        return parser_unexpected_value;
    }

    CHECK_PARSER_ERR(readCandidText(&ctx, &val->account_identifier))
    if (val->account_identifier.len != 32) {
        return parser_unexpected_number_items;
    }

    return parser_ok;
}
