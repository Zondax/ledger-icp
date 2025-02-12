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
#include "candid/candid_types.h"
#include "crypto.h"
#include "parser_impl.h"
#include "parser_txdef.h"
#include "cbor.h"
#include "app_mode.h"
#include "pb_decode.h"
#include "protobuf/dfinity.pb.h"
#include "protobuf/governance.pb.h"
#include "candid_parser.h"

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
            return "Display index out of range";
        case parser_display_page_out_of_range:
            return "Display page out of range";
        case parser_unexpected_error:
            return "Unexpected internal error";
        case parser_not_implemented:
            return "Feature not implemented";
        // cbor
        case parser_cbor_unexpected:
            return "Unexpected CBOR error";
        case parser_cbor_not_canonical:
            return "CBOR was not in canonical order";
        case parser_cbor_unexpected_EOF:
            return "Unexpected CBOR EOF";
        // Coin specific
        case parser_unexpected_tx_version:
            return "TX version is not supported";
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
        // Context specific
        case parser_context_mismatch:
            return "Context prefix is invalid";
        case parser_context_unexpected_size:
            return "Context unexpected size";
        case parser_context_invalid_chars:
            return "Context invalid chars";
        case parser_context_unknown_prefix:
            return "Unknown context prefix";
        // Required fields error
        case parser_required_nonce:
            return "Required field nonce";
        case parser_required_method:
            return "Required field method";
        // Special codes
        case parser_type_not_found:
            return "Type not found";
        case parser_invalid_label:
            return "Invalid label";
        case parser_invalid_delegation:
            return "Invalid delegation";
        case parser_invalid_certificate:
            return "Invalid certificate";
        case parser_invalid_tree:
            return "Invalid tree";
        case parser_minicbor_error:
            return "MiniCBOR error";
        case parser_recursion_limit_reached:
            return "Recursion limit reached";
        // New errors added from Rust
        case parser_invalid_tag:
            return "Invalid tag";
        case parser_invalid_msg_metadata:
            return "Invalid message metadata";
        case parser_invalid_consent_msg:
            return "Invalid consent message";
        case parser_invalid_utf8:
            return "Invalid UTF-8";
        case parser_invalid_error_response:
            return "Invalid error response";
        case parser_invalid_response_type:
            return "Invalid response type";
        case parser_invalid_call_request:
            return "Invalid call request";
        case parser_invalid_consent_msg_request:
            return "Invalid consent message request";
        case parser_invalid_canister_id:
            return "Invalid canister ID";
        case parser_invalid_language:
            return "Invalid language";
        case parser_too_many_types:
            return "Too many types";
        case parser_too_many_fields:
            return "Too many fields";
        case parser_field_not_found:
            return "Field not found";
        case parser_leb128_overflow:
            return "LEB128 overflow";
        case parser_invalid_time:
            return "Invalid time";
        case parser_invalid_visibility:
            return "Invalid neuron visibility";
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

#define READ_STRING_PTR_SIZE(MAP, FIELDNAME, V_OUTPUT_PTR, V_OUTPUT_SIZE) {                  \
    CborValue it;                                                                           \
    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(MAP, FIELDNAME, &it));                     \
    PARSER_ASSERT_OR_ERROR(cbor_value_is_byte_string(&it) || cbor_value_is_text_string(&it), parser_context_mismatch); \
    CHECK_CBOR_MAP_ERR(get_string_chunk(&it, (const void **)&V_OUTPUT_PTR, &V_OUTPUT_SIZE));\
}

parser_error_t try_read_nonce(CborValue *content_map, parser_tx_t *v) {
    size_t stringLen = 0;
    CborValue it;

    size_t *dataLen = &v->tx_fields.call.nonce.len;

    MEMZERO(&v->tx_fields.call.nonce.data, sizeof(v->tx_fields.call.nonce.data));
    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(content_map, "nonce", &it))
    if (!cbor_value_is_valid(&it)) {
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

    if (arrayLen == 0 || arrayLen > PATH_MAX_ARRAY) {
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
    if (!status) { return parser_unexpected_error; }                                       \
    MEMCPY(&v->tx_fields.call.data.OBJ, &request, sizeof(OBJ));                        \
    CHECK_APP_CANARY()                                                                      \
    return parser_ok;                                                                       \
}                                                                                           \


GEN_PARSER_PB(SendRequest)

GEN_PARSER_PB(ic_nns_governance_pb_v1_ManageNeuron)

GEN_PARSER_PB(ListNeurons)

parser_error_t getManageNeuronType(const parser_tx_t *v, manageNeuron_e *mn_type) {
    switch (v->tx_fields.call.method_type) {
        case pb_manageneuron: {
            pb_size_t command = v->tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron.which_command;

            switch (command) {
                case Configure: {
                    pb_size_t operation = v->tx_fields.call
                            .data.ic_nns_governance_pb_v1_ManageNeuron
                            .command.configure.which_operation;

                    if (1 <= operation && operation <= 7 && operation != 6) {
                        *mn_type = (manageNeuron_e) (2000 + operation);
                        return parser_ok;
                    }

                    return parser_unexpected_type;
                }

                case Disburse:
                case Spawn:
                case Follow:
                case RegisterVote:
                    *mn_type = command;
                    return parser_ok;

                default: {
                    return parser_unexpected_type;
                }
            }
        }
        case candid_manageneuron: {

            if (!v->tx_fields.call.data.candid_manageNeuron.has_command) {
                return parser_unexpected_value;
            }

            const candid_Command_t *command = &v->tx_fields.call.data.candid_manageNeuron.command;
            const bool isSNS = v->tx_fields.call.is_sns;
            switch (command->hash) {
                case hash_command_Spawn:
                    *mn_type = SpawnCandid;
                    return parser_ok;
                case hash_command_StakeMaturity:
                    *mn_type = isSNS ? SNS_StakeMaturity : StakeMaturityCandid;
                    return parser_ok;
                case hash_command_Split:
                    *mn_type = Split;
                    return parser_ok;
                case hash_command_Merge:
                    *mn_type = Merge;
                    return parser_ok;
                case hash_command_RegisterVote:
                    *mn_type = RegisterVoteCandid;
                    return parser_ok;
                case hash_command_Follow:
                    *mn_type = FollowCandid;
                    return parser_ok;
                case hash_command_RefreshVotingPower:
                    *mn_type = NNS_RefreshVotingPower;
                    return parser_ok;
                case hash_command_Configure: {
                    if (!command->configure.has_operation) {
                        return parser_unexpected_value;
                    }
                    switch (command->configure.operation.hash) {
                        case hash_operation_SetDissolvedTimestamp:
                            *mn_type = isSNS ? SNS_Configure_SetDissolveDelay : Configure_SetDissolvedTimestamp;
                            break;
                        case hash_operation_LeaveNeuronsFund:
                            *mn_type = Configure_LeaveNeuronsFundCandid;
                            break;
                        case hash_operation_ChangeAutoStakeMaturity:
                            *mn_type = Configure_ChangeAutoStakeMaturity;
                            break;
                        case hash_operation_IncreaseDissolveDelay:
                            *mn_type = Configure_IncreaseDissolveDelayCandid;
                            break;
                        case hash_operation_StartDissolving:
                            *mn_type = isSNS ? SNS_Configure_StartDissolving : Configure_StartDissolvingCandid;
                            break;
                        case hash_operation_StopDissolving:
                            *mn_type = isSNS ? SNS_Configure_StopDissolving : Configure_StopDissolvingCandid;
                            break;
                        case hash_operation_JoinNeuronsFund:
                            *mn_type = Configure_JoinNeuronsFundCandid;
                            break;
                        case hash_operation_AddHotkey:
                            *mn_type = Configure_AddHotkeyCandid;
                            break;
                        case hash_operation_RemoveHotkey:
                            *mn_type = Configure_RemoveHotkeyCandid;
                            break;
                        case hash_operation_SetVisibility:
                            *mn_type = Configure_SetVisibility;
                            break;
                        default:
                            ZEMU_LOGF(50, "Unknow operation hash: 0x%08X%08X\n",
                                (uint32_t)(command->configure.operation.hash >> 32),
                                (uint32_t)(command->configure.operation.hash & 0xFFFFFFFF)
                            );
                            return parser_unexpected_value;
                    }
                    return parser_ok;
                }
                case sns_hash_command_AddNeuronPermissions:
                    *mn_type = SNS_AddNeuronPermissions;
                    return parser_ok;
                case sns_hash_command_RemoveNeuronPermissions:
                    *mn_type = SNS_RemoveNeuronPermissions;
                    return parser_ok;
                case sns_hash_command_Disburse:
                    *mn_type = isSNS ? SNS_Disburse : DisburseCandid;
                    return parser_ok;

                default:
                    break;
            }
            break;
        }
        default:
            break;
    }

    return parser_unexpected_type;
}

parser_error_t readPayload(parser_tx_t *v, uint8_t *buffer, size_t bufferLen) {
    char *method = v->tx_fields.call.method_name.data;
    manageNeuron_e mn_type;

    v->tx_fields.call.is_sns = 0; // we'll set this var later if is sns

    // Depending on the method, we may try to read protobuf or candid

    if (strcmp(method, "send_pb") == 0) {
        v->tx_fields.call.method_type = pb_sendrequest;
        return _parser_pb_SendRequest(v, buffer, bufferLen);
    }

    if (strcmp(method, "manage_neuron_pb") == 0) {
        v->tx_fields.call.method_type = pb_manageneuron;
        CHECK_PARSER_ERR(_parser_pb_ic_nns_governance_pb_v1_ManageNeuron(v, buffer, bufferLen))
        return getManageNeuronType(v, &mn_type);
    }

    if (strcmp(method, "list_neurons_pb") == 0) {
        v->tx_fields.call.method_type = pb_listneurons;
        return _parser_pb_ListNeurons(v, buffer, bufferLen);
    }

    if (strcmp(method, "claim_neurons") == 0) {
        if (130 <= bufferLen && bufferLen <= 150) {
            v->tx_fields.call.method_type = pb_claimneurons;
            return parser_ok;
        }
    }

    // Candid NNS + SNS
    if (strcmp(method, "manage_neuron") == 0) {
        v->tx_fields.call.method_type = candid_manageneuron;
        CHECK_PARSER_ERR(readCandidManageNeuron(v, buffer, bufferLen))
        return parser_ok;
    }

    if (strcmp(method, "update_node_provider") == 0) {
        CHECK_PARSER_ERR(readCandidUpdateNodeProvider(v, buffer, bufferLen))
        v->tx_fields.call.method_type = candid_updatenodeprovider;
        return parser_ok;
    }

    if (strcmp(method, "list_neurons") == 0) {
        CHECK_PARSER_ERR(readCandidListNeurons(v, buffer, bufferLen))
        v->tx_fields.call.method_type = candid_listneurons;
        return parser_ok;
    }

    if (strcmp(method, "icrc1_transfer") == 0) {
        v->tx_fields.call.method_type = candid_icrc_transfer;
        CHECK_PARSER_ERR(readCandidICRCTransfer(v, buffer, bufferLen))
        return parser_ok;
    }

    if (strcmp(method, "transfer") == 0) {
        v->tx_fields.call.method_type = candid_transfer;
        CHECK_PARSER_ERR(readCandidTransfer(v, buffer, bufferLen))
        return parser_ok;
    }

    return parser_unexpected_type;
}

static bool isCandidTransaction(parser_tx_t *v) {
    char *method = v->tx_fields.call.method_name.data;
    if (strcmp(method, "manage_neuron") == 0) {
        return true;
    }

    if (strcmp(method, "update_node_provider") == 0) {
        return true;
    }

    if (strcmp(method, "list_neurons") == 0) {
        return true;
    }

    if (strcmp(method, "icrc1_transfer") == 0) {
        return true;
    }

    if (strcmp(method, "transfer") == 0) {
        return true;
    }

    return false;
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
        if (fieldCount != 6 * 2 && fieldCount != 7 * 2) {
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

        if (isCandidTransaction(v)) {
            READ_STRING_PTR_SIZE(content_map, "arg", fields->method_args.dataPtr, fields->method_args.len)
            if (fields->method_args.dataPtr == NULL) {
                return parser_no_data;
            }
            CHECK_PARSER_ERR(readPayload(v, fields->method_args.dataPtr, fields->method_args.len))
        } else {
            READ_STRING(content_map, "arg", fields->method_args)
            CHECK_PARSER_ERR(readPayload(v, fields->method_args.data, fields->method_args.len))
            fields->method_args.dataPtr = fields->method_args.data;
        }

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

parser_error_t readEnvelope(const parser_context_t *c, parser_tx_t *v) {
    zemu_log_stack("read envelope");
    CborValue it;
    CHECK_APP_CANARY()
    INIT_CBOR_PARSER(c, it)
    CHECK_APP_CANARY()
    PARSER_ASSERT_OR_ERROR(!cbor_value_at_end(&it), parser_unexpected_buffer_end)
    // Verify tag
    CHECK_CBOR_TYPE(cbor_value_get_type(&it), CborTagType)
    CborTag tag;
    CHECK_CBOR_MAP_ERR(cbor_value_get_tag(&it, &tag))
    if (tag != 55799) {
        zemu_log_stack("wrong tag");
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

#define CHECK_METHOD_WITH_CANISTER(CANISTER_ID){                         \
        if (strcmp(canister_textual, (CANISTER_ID)) != 0) {              \
            zemu_log_stack("invalid canister");                          \
            return parser_unexpected_value;                              \
        }                                                                \
        return parser_ok;                                                \
}

parser_error_t checkPossibleCanisters(const parser_tx_t *v, char *canister_textual) {
    switch (v->tx_fields.call.method_type) {
        case candid_transfer:
        case pb_sendrequest : {
            CHECK_METHOD_WITH_CANISTER("ryjl3tyaaaaaaaaaaabacai")
        }

        case pb_listneurons :
        case pb_manageneuron :
        case candid_updatenodeprovider:
        case candid_listneurons:
        case candid_manageneuron: {
            if (v->tx_fields.call.is_sns) return parser_ok; // sns has dynamic canister id
            CHECK_METHOD_WITH_CANISTER("rrkahfqaaaaaaaaaaaaqcai")
        }

        case pb_claimneurons : {
            CHECK_METHOD_WITH_CANISTER("renrkeyaaaaaaaaaaadacai")
        }

        case candid_icrc_transfer: {
            return parser_ok;
        }

        default: {
            return parser_unexpected_type;
        }
    }
}

parser_error_t _validateTx(__Z_UNUSED const parser_context_t *c, const parser_tx_t *v) {
    const uint8_t *sender = NULL;

    switch (v->txtype) {
        case call: {
            zemu_log_stack("Call type");
            if (strcmp(v->request_type.data, "call") != 0) {
                zemu_log_stack("call not found");
                return parser_unexpected_value;
            }

            if (v->special_transfer_type == invalid) {
                zemu_log_stack("invalid transfer type");
                return parser_unexpected_value;
            }

            if (v->tx_fields.call.method_type == pb_manageneuron) {
                const ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;
                PARSER_ASSERT_OR_ERROR(fields->has_id ^ (fields->neuron_id_or_subaccount.neuron_id.id != 0),
                                       parser_unexpected_error);
            }

            const uint8_t *canisterId = v->tx_fields.call.canister_id.data;
            char canister_textual[50];
            uint16_t outLen = sizeof(canister_textual);
            MEMZERO(canister_textual, outLen);

            PARSER_ASSERT_OR_ERROR(
                    crypto_principalToTextual(canisterId,
                                              v->tx_fields.call.canister_id.len,
                                              canister_textual,
                                              &outLen) == zxerr_ok, parser_unexpected_error)
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


#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX)
    if (v->txtype != call || v->tx_fields.call.method_type != candid_icrc_transfer) {
        uint8_t publicKey[SECP256K1_PK_LEN];
        uint8_t principalBytes[DFINITY_PRINCIPAL_LEN];

        MEMZERO(publicKey, sizeof(publicKey));
        MEMZERO(principalBytes, sizeof(principalBytes));

        PARSER_ASSERT_OR_ERROR(crypto_extractPublicKey(publicKey, sizeof(publicKey)) == zxerr_ok,
                            parser_unexpected_error)

        PARSER_ASSERT_OR_ERROR(crypto_computePrincipal(publicKey, principalBytes) == zxerr_ok, parser_unexpected_error)

        if (memcmp(sender, principalBytes, DFINITY_PRINCIPAL_LEN) != 0) {
            return parser_unexpected_value;
        }
    }
#endif

    if (v->txtype == call && parser_tx_obj.special_transfer_type == neuron_stake_transaction) {
        uint8_t to_hash[32] = {0};
        if (v->tx_fields.call.method_type == candid_icrc_transfer) {
            const icrc_transfer_t *fields = &v->tx_fields.call.data.icrcTransfer;
            if (fields->icp_canister == 0 || fields->account.has_owner == 0 ||
                fields->account.has_subaccount == 0 ||
                fields->account.subaccount.len != DFINITY_SUBACCOUNT_LEN ||
                fields->has_memo == 0 || fields->memo.len == 0) {
                return parser_invalid_address;
            }
            // stands for rrkah-fqaaa-aaaaa-aaaaq-cai principal
            uint8_t governanceCanister[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01};
            if (fields->account.owner.len != sizeof(governanceCanister) ||
                memcmp(governanceCanister, fields->account.owner.ptr, 10) != 0) {
                zemu_log_stack("wrong principal");
                return parser_invalid_address;
            }
            PARSER_ASSERT_OR_ERROR(
                zxerr_ok == crypto_computeStakeSubaccount(sender, v->tx_fields.call.sender.len,
                                                          fields->memo.p, fields->memo.len,
                                                          to_hash, sizeof(to_hash)),
                parser_unexpected_error);
            if (memcmp(to_hash, fields->account.subaccount.p, DFINITY_SUBACCOUNT_LEN) != 0) {
                zemu_log_stack("wrong data");
                return parser_invalid_address;
            }
        } else {
            const bool is_candid = v->tx_fields.call.method_type == candid_transfer;
            uint64_t memo = is_candid ? v->tx_fields.call.data.candid_transfer.memo
                                      : v->tx_fields.call.data.SendRequest.memo.memo;
            const uint8_t *to = is_candid ? v->tx_fields.call.data.candid_transfer.to
                                          : v->tx_fields.call.data.SendRequest.to.hash;
            PARSER_ASSERT_OR_ERROR(
                zxerr_ok == crypto_principalToStakeAccount(sender, DFINITY_PRINCIPAL_LEN,
                                                           memo, to_hash, sizeof(to_hash)),
                parser_unexpected_error);
            if (memcmp(to_hash, to, DFINITY_ADDR_LEN) != 0) {
                zemu_log_stack("wrong data");
                return parser_invalid_address;
            }
        }
    }
    return parser_ok;
}

uint8_t getNumItemsManageNeurons(__Z_UNUSED const parser_context_t *c, const parser_tx_t *v) {
    manageNeuron_e mn_type;
    if (getManageNeuronType(v, &mn_type) != parser_ok) {
        return 0;
    }

    switch (mn_type) {
        case Configure_StopDissolving :
        case Configure_JoinNeuronsFund :
        case Configure_LeaveNeuronsFund :
        case Configure_JoinNeuronsFundCandid:
        case Configure_LeaveNeuronsFundCandid:
        case Configure_StartDissolving : {
            return 2;
        }
        case Spawn :
        case Split:
        case Merge:
        case Configure_RemoveHotKey :
        case Configure_AddHotKey :
        case Configure_RemoveHotkeyCandid:
        case Configure_AddHotkeyCandid:
        case Configure_IncreaseDissolveDelay:
        case Configure_IncreaseDissolveDelayCandid:
        case Configure_ChangeAutoStakeMaturity:
        case Configure_SetDissolvedTimestamp: {
            return 3;
        }
        case Configure_SetVisibility:
            // items: title, neuron_id
            return 2;
        case SNS_Configure_SetDissolveDelay:
        case RegisterVote :
        case RegisterVoteCandid:
        case DisburseCandid:
        case Disburse : {
            return 4;
        }
        case SpawnCandid: {
            // 2 fields + opt(percentage_to_spawn) + controller (opt or self) + opt(nonce)
            return 3
            + (v->tx_fields.call.data.candid_manageNeuron.command.spawn.has_percentage_to_spawn ? 1 : 0)
            + (v->tx_fields.call.data.candid_manageNeuron.command.spawn.has_nonce ? 1 : 0);
        }
        case Configure_StartDissolvingCandid:
        case Configure_StopDissolvingCandid:
            return 2;
        case StakeMaturityCandid:
            // 2 fields + opt(percentage_to_stake)
            return 2
            + (v->tx_fields.call.data.candid_manageNeuron.command.stake.has_percentage_to_stake ? 1 : 0);

        case Follow : {
            pb_size_t follow_count = v->tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron.command.follow.followees_count;
            return follow_count > 0 ? 3 + follow_count : 4;
        }
        case FollowCandid: {
            uint8_t followees_count = v->tx_fields.call.data.candid_manageNeuron.command.follow.followees_size;
            return followees_count > 0 ? 3 + followees_count : 4;
        }

        case SNS_Configure_StartDissolving:
        case SNS_Configure_StopDissolving:
            return 3;

        case SNS_AddNeuronPermissions:
        case SNS_RemoveNeuronPermissions: {
            if (v->tx_fields.call.data.sns_manageNeuron.command.neuronPermissions.has_permissionList) {
                return 4 + v->tx_fields.call.data.sns_manageNeuron.command.neuronPermissions.permissionList.list_size;
            }
            return 5;
        }

        case SNS_Disburse:
            return 5;

        case SNS_StakeMaturity:
            return 3 + (v->tx_fields.call.data.sns_manageNeuron.command.stake.has_percentage_to_stake ? 1 : 0);
        case NNS_RefreshVotingPower:
            return 2;

        default:
            break;
    }
    return 0;
}

uint8_t _getNumItems(__Z_UNUSED const parser_context_t *c, const parser_tx_t *v) {
    switch (v->txtype) {
        case call: {
            switch (v->tx_fields.call.method_type) {
                case candid_transfer:
                case pb_sendrequest: {
                    const bool is_stake_tx = v->special_transfer_type == neuron_stake_transaction;

                    uint8_t itemCount = 6;

                    if (is_stake_tx) itemCount--;
                    if (app_mode_expert()) itemCount += 2;

                    return itemCount;
                }

                case pb_claimneurons :
                case pb_listneurons : {
                    return 1;
                }

                case candid_updatenodeprovider: {
                    return 2;
                }

                case pb_manageneuron :
                case candid_manageneuron: {
                    return getNumItemsManageNeurons(c, v);
                }
                case candid_listneurons:
                    return 1 + v->tx_fields.call.data.candid_listNeurons.neuron_ids_size;
                case candid_icrc_transfer: {
                    const call_t *call = &v->tx_fields.call;
                    const bool icp_canisterId = call->data.icrcTransfer.icp_canister;
                    const bool is_stake_tx = parser_tx_obj.special_transfer_type == neuron_stake_transaction;

                    // Canister ID will be display only when different to ICP
                    // Fee will be display if available or default if Canister ID is ICP
                    // To account is only shown if tx is not stake
                    return 4 + (icp_canisterId ? 0 : 1) + ((call->data.icrcTransfer.has_fee || icp_canisterId) ? 1 : 0) + (is_stake_tx ? 0 : 1);
                }

                default:
                    break;
            }
        }
        case state_transaction_read : {
            // based on https://github.com/Zondax/ledger-dfinity/issues/48
            if (!app_mode_expert()) {
                return 1;               // only check status
            }
            return 3;
        }
        default:
            break;
    }

    return 0;
}
