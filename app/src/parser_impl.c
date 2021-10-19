/*******************************************************************************
*  (c) 2019 Zondax GmbH
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

#include <zxmacros.h>
#include "parser_impl.h"
#include "parser_txdef.h"
#include "cbor.h"
#include "app_mode.h"
#include "pb_decode.h"
#include "protobuf/dfinity.pb.h"
#include "protobuf/governance.pb.h"

parser_tx_t parser_tx_obj;

__Z_INLINE parser_error_t parser_mapCborError(CborError err);

#define CHECK_CBOR_MAP_ERR(CALL) { \
    CborError err = CALL;  \
    if (err!=CborNoError) return parser_mapCborError(err);}

#define CHECK_CBOR_TYPE(TYPE, EXPECTED) {if ( (TYPE)!= (EXPECTED) ) return parser_unexpected_type;}

#define INIT_CBOR_PARSER(c, it)  \
    CborParser parser;           \
    CHECK_CBOR_MAP_ERR(cbor_parser_init((c)->buffer + (c)->offset, (c)->bufferLen - (c)->offset, 0, &parser, &it))

parser_error_t parser_init_context(parser_context_t *ctx,
                                   const uint8_t *buffer,
                                   uint16_t bufferSize) {
    ctx->offset = 0;
    ctx->buffer = NULL;
    ctx->bufferLen = 0;

    if (bufferSize == 0 || buffer == NULL) {
        // Not available, use defaults
        return parser_init_context_empty;
    }

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;
    return parser_ok;
}

parser_error_t parser_init(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
    CHECK_PARSER_ERR(parser_init_context(ctx, buffer, bufferSize))
    return parser_ok;
}

__Z_INLINE parser_error_t parser_mapCborError(CborError err) {
    switch (err) {
        case CborErrorUnexpectedEOF:
            return parser_cbor_unexpected_EOF;
        case CborErrorMapNotSorted:
            return parser_cbor_not_canonical;
        case CborNoError:
            return parser_ok;
        case CborErrorOutOfMemory: {
            return parser_value_out_of_range;
        }
        default:
            return parser_cbor_unexpected;
    }
}

const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        // General errors
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_init_context_empty:
            return "Initialized empty context";
        case parser_display_idx_out_of_range:
            return "display_idx_out_of_range";
        case parser_display_page_out_of_range:
            return "display_page_out_of_range";
        case parser_unexepected_error:
            return "Unexepected internal error";
            // cbor
        case parser_cbor_unexpected:
            return "unexpected CBOR error";
        case parser_cbor_not_canonical:
            return "CBOR was not in canonical order";
        case parser_cbor_unexpected_EOF:
            return "Unexpected CBOR EOF";
            // Coin specific
        case parser_unexpected_tx_version:
            return "tx version is not supported";
        case parser_unexpected_type:
            return "Unexpected data type";
        case parser_unexpected_method:
            return "Unexpected method";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_unexpected_value:
            return "Unexpected value";
        case parser_unexpected_number_items:
            return "Unexpected number of items";
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_invalid_address:
            return "Invalid address format";
            /////////// Context specific
        case parser_context_mismatch:
            return "context prefix is invalid";
        case parser_context_unexpected_size:
            return "context unexpected size";
        case parser_context_invalid_chars:
            return "context invalid chars";
            // Required fields error
        case parser_required_nonce:
            return "Required field nonce";
        case parser_required_method:
            return "Required field method";
        default:
            return "Unrecognized error code";
    }
}

// envelope (TAG 55799)
//    content [map]
//        request_type [text]
//        read_state / query [blob]
//        nonce [blob] (optional)
//        ingress_expiry [nat]
//        sender [principal]
//        canister_id [principal]
//        method_name [text]
//        arg [blob]
//    sender_pubkey [blob]
//    sender_sig [blob]

#define READ_INT64(MAP, FIELDNAME, V_OUTPUT) {                     \
    CborValue it;                                                                           \
    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(MAP, FIELDNAME, &it));                     \
    CHECK_CBOR_MAP_ERR(cbor_value_get_raw_integer(&it, &V_OUTPUT)); \
}

#define READ_STRING(MAP, FIELDNAME, V_OUTPUT) {                                             \
    size_t stringLen = 0;                                                                   \
    CborValue it;                                                                           \
    MEMZERO(&(V_OUTPUT).data, sizeof((V_OUTPUT).data));                                     \
    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(MAP, FIELDNAME, &it));                     \
    PARSER_ASSERT_OR_ERROR(cbor_value_is_byte_string(&it) || cbor_value_is_text_string(&it), parser_context_mismatch); \
    CHECK_CBOR_MAP_ERR(cbor_value_get_string_length(&it, &stringLen));                      \
    PARSER_ASSERT_OR_ERROR(stringLen < sizeof((V_OUTPUT).data), parser_context_unexpected_size)   \
    (V_OUTPUT).len = stringLen; \
    CHECK_CBOR_MAP_ERR(_cbor_value_copy_string(&it, (V_OUTPUT).data, &(V_OUTPUT).len, NULL)); \
}

parser_error_t try_read_nonce(CborValue *content_map, parser_tx_t *v){
    size_t stringLen = 0;
    CborValue it;

    size_t *dataLen = &v->tx_fields.call.nonce.len;

    MEMZERO(&v->tx_fields.call.nonce.data, sizeof(v->tx_fields.call.nonce.data));
    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(content_map, "nonce", &it))
    if(!cbor_value_is_valid(&it)){
        v->tx_fields.call.has_nonce = false;
        return parser_ok;
    }
    PARSER_ASSERT_OR_ERROR(cbor_value_is_byte_string(&it) || cbor_value_is_text_string(&it), parser_context_mismatch);
    CHECK_CBOR_MAP_ERR(cbor_value_get_string_length(&it, &stringLen));
    PARSER_ASSERT_OR_ERROR(stringLen < sizeof(v->tx_fields.call.nonce.data), parser_context_unexpected_size)
    *dataLen = stringLen;
    CHECK_CBOR_MAP_ERR(_cbor_value_copy_string(&it, v->tx_fields.call.nonce.data, dataLen, NULL));
    v->tx_fields.call.has_nonce = true;
    return parser_ok;
}

parser_error_t parsePaths(CborValue *content_map, state_read_t *stateRead) {
    CborValue it;                                                                           \
    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(content_map, "paths", &it));
    PARSER_ASSERT_OR_ERROR(cbor_value_is_container(&it), parser_unexpected_type);

    size_t pathsLen = 0;
    CHECK_CBOR_MAP_ERR(cbor_value_get_array_length(&it, &pathsLen))
    if (pathsLen != 1) {
        return parser_value_out_of_range;
    }

    CborValue content_paths;
    CHECK_CBOR_MAP_ERR(cbor_value_enter_container(&it, &content_paths))

    size_t arrayLen = 0;
    CHECK_CBOR_MAP_ERR(cbor_value_get_array_length(&content_paths, &arrayLen));

    if (arrayLen <= 0 || arrayLen > PATH_MAX_ARRAY) {
        return parser_value_out_of_range;
    }
    stateRead->paths.arrayLen = arrayLen;

    CHECK_CBOR_MAP_ERR(cbor_value_enter_container(&content_paths, &it));

    size_t stringLen = 0;

    for (size_t index = 0; index < arrayLen; index++) {
        PARSER_ASSERT_OR_ERROR(cbor_value_is_byte_string(&it), parser_context_mismatch)
        CHECK_CBOR_MAP_ERR(cbor_value_get_string_length(&it, &stringLen))
        PARSER_ASSERT_OR_ERROR(stringLen < sizeof(stateRead->paths.paths[index].data), parser_context_unexpected_size)
        stateRead->paths.paths[index].len = sizeof(stateRead->paths.paths[index].data);
        CHECK_CBOR_MAP_ERR(
                _cbor_value_copy_string(&it, stateRead->paths.paths[index].data, &stateRead->paths.paths[index].len,
                                        NULL))
        CHECK_CBOR_MAP_ERR(cbor_value_advance(&it));
    }

    if (strcmp((char *) stateRead->paths.paths[0].data, "request_status") != 0) {
        return parser_context_mismatch;
    }

    while (!cbor_value_at_end(&it)) {
        CHECK_CBOR_MAP_ERR(cbor_value_advance(&it));
    }
    CHECK_CBOR_MAP_ERR(cbor_value_leave_container(&content_paths, &it))

    return parser_ok;
}

#define GEN_PARSER_PB(OBJ) parser_error_t _parser_pb_ ## OBJ(parser_tx_t *v, uint8_t *buffer, size_t bufferLen) \
{                                                                                           \
    OBJ request = OBJ ##_init_zero;                                                         \
    pb_istream_t stream = pb_istream_from_buffer(buffer, bufferLen);                        \
    CHECK_APP_CANARY()                                                                      \
    const bool status = pb_decode(&stream, OBJ ##_fields, &request);                        \
    if (!status) { return parser_unexepected_error; }                                       \
    MEMCPY(&v->tx_fields.call.pb_fields.OBJ, &request, sizeof(OBJ));                        \
    CHECK_APP_CANARY()                                                                      \
    return parser_ok;                                                                       \
}                                                                                           \

GEN_PARSER_PB(SendRequest)
GEN_PARSER_PB(ic_nns_governance_pb_v1_ManageNeuron)
GEN_PARSER_PB(ListNeurons)

parser_error_t getManageNeuronType(parser_tx_t *v){
    pb_size_t command = v->tx_fields.call.pb_fields.ic_nns_governance_pb_v1_ManageNeuron.which_command;
    manageNeuron_e *mn_type = &v->tx_fields.call.manage_neuron_type;
    switch(command){
        case 2: {
            pb_size_t operation = v->tx_fields.call.pb_fields.ic_nns_governance_pb_v1_ManageNeuron.command.configure.which_operation;
            if(1 <= operation && operation <= 6){
                *mn_type = (manageNeuron_e)operation;
                return parser_ok;
            }else{
                return parser_unexpected_type;
            }
        }

        case 3: {
            *mn_type = Disburse;
            return parser_ok;
        }

        case 4: {
            *mn_type = Spawn;
            return parser_ok;
        }

        case 13: {
            *mn_type = MergeMaturity;
            return parser_ok;
        }

        default: {
            return parser_unexpected_type;
        }
    }
}

parser_error_t readProtobuf(parser_tx_t *v, uint8_t *buffer, size_t bufferLen) {
    char *method = v->tx_fields.call.method_name.data;
    if (strcmp(method, "send_pb") == 0 || v->tx_fields.call.special_transfer_type == neuron_stake_transaction) {
        v->tx_fields.call.pbtype = pb_sendrequest;
        return _parser_pb_SendRequest(v, buffer, bufferLen);
    }

    if(strcmp(method, "manage_neuron_pb") == 0) {
        v->tx_fields.call.pbtype = pb_manageneuron;
        CHECK_PARSER_ERR(_parser_pb_ic_nns_governance_pb_v1_ManageNeuron(v, buffer, bufferLen))
        return getManageNeuronType(v);
    }

    if(strcmp(method, "list_neurons_pb") == 0) {
        v->tx_fields.call.pbtype = pb_listneurons;
        return _parser_pb_ListNeurons(v, buffer, bufferLen);
    }


    return parser_unexpected_type;
}

parser_error_t readContent(CborValue *content_map, parser_tx_t *v) {
    CborValue content_it;

    PARSER_ASSERT_OR_ERROR(cbor_value_is_container(content_map), parser_unexpected_type)
    CHECK_CBOR_MAP_ERR(cbor_value_enter_container(content_map, &content_it))
    CHECK_CBOR_TYPE(cbor_value_get_type(content_map), CborMapType)

    // Check request type
    READ_STRING(content_map, "request_type", v->request_type)
    size_t mapsize = 0;

    // Skip fields until the end
    size_t fieldCount = 0;
    while (!cbor_value_at_end(&content_it)) {
        CHECK_CBOR_MAP_ERR(cbor_value_advance(&content_it));
        fieldCount++;
    }

    if (strcmp(v->request_type.data, "call") == 0) {
        if (fieldCount != 6*2 && fieldCount != 7*2) {
            return parser_context_unexpected_size;
        }

        v->txtype = call;
        // READ CALL
        call_t *fields = &v->tx_fields.call;
        READ_STRING(content_map, "sender", fields->sender)
        READ_STRING(content_map, "canister_id", fields->canister_id)

        CHECK_PARSER_ERR(try_read_nonce(content_map, v));

        READ_STRING(content_map, "method_name", fields->method_name)
        READ_INT64(content_map, "ingress_expiry", fields->ingress_expiry)
        READ_STRING(content_map, "arg", fields->arg)
        CHECK_PARSER_ERR(readProtobuf(v, fields->arg.data, fields->arg.len));

    } else if (strcmp(v->request_type.data, "read_state") == 0) {
        state_read_t *fields = &v->tx_fields.stateRead;

        CHECK_CBOR_MAP_ERR(cbor_value_get_map_length(content_map, &mapsize))
        PARSER_ASSERT_OR_ERROR(mapsize == 4, parser_context_unexpected_size)
        v->txtype = state_transaction_read;
        READ_STRING(content_map, "sender", fields->sender)
        READ_INT64(content_map, "ingress_expiry", fields->ingress_expiry)
        CHECK_PARSER_ERR(parsePaths(content_map, fields))

    } else if (strcmp(v->request_type.data, "query") == 0) {
        return parser_unexpected_method;
    } else {
        return parser_unexpected_value;
    }

    // Exit envelope
    CHECK_CBOR_MAP_ERR(cbor_value_leave_container(content_map, &content_it))

    return parser_ok;
}

parser_error_t _readEnvelope(const parser_context_t *c, parser_tx_t *v) {
    zemu_log_stack("read envelope");
    CborValue it;
    INIT_CBOR_PARSER(c, it)
    PARSER_ASSERT_OR_ERROR(!cbor_value_at_end(&it), parser_unexpected_buffer_end)

    // Verify tag
    CHECK_CBOR_TYPE(cbor_value_get_type(&it), CborTagType)
    CborTag tag;
    CHECK_CBOR_MAP_ERR(cbor_value_get_tag(&it, &tag))
    if (tag != 55799) {
        return parser_unexpected_value;
    }
    cbor_value_advance(&it);

    {
        // Enter envelope
        PARSER_ASSERT_OR_ERROR(cbor_value_is_container(&it), parser_unexpected_type)
        PARSER_ASSERT_OR_ERROR(cbor_value_is_map(&it), parser_unexpected_type)

        // check envelope size
        size_t mapLen = 0;
        CHECK_CBOR_MAP_ERR(cbor_value_get_map_length(&it, &mapLen))
        if (mapLen != 3 && mapLen != 1) {
            return parser_unexpected_value;
        }
        CborValue envelope;
        CHECK_CBOR_MAP_ERR(cbor_value_enter_container(&it, &envelope))

        {
            // Enter content
            CborValue content_item;
            CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(&it, "content", &content_item))
            PARSER_ASSERT_OR_ERROR(cbor_value_is_container(&content_item), parser_unexpected_type)
            CHECK_PARSER_ERR(readContent(&content_item, v))
        }

        // Skip fields until the end
        while (!cbor_value_at_end(&envelope)) {
            CHECK_CBOR_MAP_ERR(cbor_value_advance(&envelope));
        }

        // Exit envelope
        CHECK_CBOR_MAP_ERR(cbor_value_leave_container(&it, &envelope))
        // End of buffer does not match end of parsed data
        PARSER_ASSERT_OR_ERROR(it.ptr == c->buffer + c->bufferLen, parser_cbor_unexpected_EOF)
    }

    return parser_ok;
}

#define CHECK_METHOD_WITH_CANISTER(CANISTER_ID){                           \
        if (strcmp(canister_textual, (CANISTER_ID)) != 0) {                     \
            zemu_log_stack("invalid canister");                                 \
            return parser_unexpected_value;                                     \
        } else {                                                                \
            return parser_ok;                                                   \
        }                                                                       \
}

parser_error_t checkPossibleCanisters(const parser_tx_t *v, char *canister_textual){
    switch(v->tx_fields.call.pbtype) {
        case pb_sendrequest : {
            CHECK_METHOD_WITH_CANISTER("ryjl3tyaaaaaaaaaaabacai")
        }

        case pb_listneurons :
        case pb_manageneuron : {
            CHECK_METHOD_WITH_CANISTER("rrkahfqaaaaaaaaaaaaqcai")
        }

        default: {
            return parser_unexpected_type;
        }
    }
}

parser_error_t _validateTx(const parser_context_t *c, const parser_tx_t *v) {
    UNUSED(c);
    const uint8_t *sender = NULL;

    switch (v->txtype) {
        case call: {
            zemu_log_stack("Call type");
            if (strcmp(v->request_type.data, "call") != 0) {
                zemu_log_stack("call not found");
                return parser_unexpected_value;
            }

            if (v->tx_fields.call.pbtype == pb_manageneuron){
                ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.pb_fields.ic_nns_governance_pb_v1_ManageNeuron;
                PARSER_ASSERT_OR_ERROR(fields->has_id ^ (fields->neuron_id_or_subaccount.neuron_id.id != 0), parser_unexepected_error);
            }

            const uint8_t *canisterId = v->tx_fields.call.canister_id.data;
            char canister_textual[50];
            uint16_t outLen = sizeof(canister_textual);
            MEMZERO(canister_textual, outLen);

            PARSER_ASSERT_OR_ERROR(
                    crypto_principalToTextual(canisterId,
                                              v->tx_fields.call.canister_id.len,
                                              canister_textual,
                                              &outLen) == zxerr_ok, parser_unexepected_error)
            CHECK_PARSER_ERR(checkPossibleCanisters(v, (char *) canister_textual))

            sender = v->tx_fields.call.sender.data;
            break;
        }
        case state_transaction_read: {
            zemu_log_stack("state_transaction_read");
            if (strcmp(v->request_type.data, "read_state") != 0) {
                return parser_unexpected_value;
            }

            sender = v->tx_fields.stateRead.sender.data;
            break;
        }
        default: {
            zemu_log_stack("unsupported tx");
            return parser_unexpected_method;
        }
    }

#if defined(TARGET_NANOS) || defined(TARGET_NANOX)
    uint8_t publicKey[SECP256K1_PK_LEN];
    uint8_t principalBytes[DFINITY_PRINCIPAL_LEN];

    MEMZERO(publicKey, sizeof(publicKey));
    MEMZERO(principalBytes, sizeof(principalBytes));

    PARSER_ASSERT_OR_ERROR(crypto_extractPublicKey(hdPath, publicKey, sizeof(publicKey)) == zxerr_ok,
                           parser_unexepected_error)

    PARSER_ASSERT_OR_ERROR(crypto_computePrincipal(publicKey, principalBytes) == zxerr_ok, parser_unexepected_error)

    if (memcmp(sender, principalBytes, DFINITY_PRINCIPAL_LEN) != 0) {
        return parser_unexpected_value;
    }

#endif

    bool is_stake_tx = parser_tx_obj.tx_fields.call.special_transfer_type == neuron_stake_transaction;
    if(is_stake_tx){
        uint8_t to_hash[32];
        PARSER_ASSERT_OR_ERROR(zxerr_ok == crypto_principalToStakeAccount(sender, DFINITY_PRINCIPAL_LEN,
                                                                          v->tx_fields.call.pb_fields.SendRequest.memo.memo,
                                                                          to_hash,sizeof(to_hash)), parser_unexepected_error);

        const uint8_t *to = v->tx_fields.call.pb_fields.SendRequest.to.hash;

        if(memcmp(to_hash, to, 32) != 0){
            zemu_log_stack("wrong data");
            return parser_invalid_address;
        }
    }
    return parser_ok;
}

uint8_t _getNumItems(const parser_context_t *c, const parser_tx_t *v) {
    UNUSED(c);
    switch (v->txtype) {
        case call: {
            switch(v->tx_fields.call.pbtype) {
                case pb_sendrequest: {
                    const bool is_stake_tx = v->tx_fields.call.special_transfer_type == neuron_stake_transaction;

                    if (is_stake_tx) {
                        return app_mode_expert() ? 7 : 5;
                    }

                    return app_mode_expert() ? 8 : 6;
                }

                case pb_listneurons : {
                    return 1;
                }

                case pb_manageneuron : {
                    switch(v->tx_fields.call.manage_neuron_type){
                        case StopDissolving :
                        case StartDissolving : {
                            return 2;
                        }
                        case Spawn :
                        case RemoveHotKey :
                        case AddHotKey :
                        case MergeMaturity :
                        case IncreaseDissolveDelay : {
                            return 3;
                        }

                        case Disburse : {
                            return 4;
                        }

                        default: {
                            return 0;
                        }
                    }
                }
                default :{
                    return 0;
                }
            }
        }
        case state_transaction_read : {
            // based on https://github.com/Zondax/ledger-dfinity/issues/48
            if (!app_mode_expert()) {
                return 1;               // only check status
            }
            return 3;
        }
        default : {
            return 0;
        }
    }

}
