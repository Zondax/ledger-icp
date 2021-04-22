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

parser_tx_t parser_tx_obj;

__Z_INLINE parser_error_t parser_mapCborError(CborError err);

#define CHECK_CBOR_MAP_ERR(CALL) { \
    CborError err = CALL;  \
    if (err!=CborNoError) return parser_mapCborError(err);}

#define PARSER_ASSERT_OR_ERROR(CALL, ERROR) if (!(CALL)) return ERROR;

#define CHECK_CBOR_TYPE(type, expected) {if (type!=expected) return parser_unexpected_type;}

#define INIT_CBOR_PARSER(c, it)  \
    CborParser parser;           \
    CHECK_CBOR_MAP_ERR(cbor_parser_init(c->buffer + c->offset, c->bufferLen - c->offset, 0, &parser, &it))

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


parser_error_t _readTransactionStateRead(const parser_context_t *c, parser_tx_t *v) {
    CborValue it;
    INIT_CBOR_PARSER(c, it)
    PARSER_ASSERT_OR_ERROR(!cbor_value_at_end(&it), parser_unexpected_buffer_end)
    cbor_value_advance(&it);

    PARSER_ASSERT_OR_ERROR(cbor_value_is_container(&it), parser_unexpected_type)
    CborValue contents;
    CborValue value;
    CHECK_CBOR_MAP_ERR(cbor_value_enter_container(&it, &contents));

    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(&it, "content", &value));

    PARSER_ASSERT_OR_ERROR(cbor_value_is_container(&value), parser_unexpected_type);
    CHECK_CBOR_MAP_ERR(cbor_value_enter_container(&value, &contents));

    size_t mapLen = 0;
    CHECK_CBOR_MAP_ERR(cbor_value_get_map_length(&value, &mapLen));

    PARSER_ASSERT_OR_ERROR(mapLen == NUM_MAP_TYPE1, parser_context_unexpected_size);
    size_t stringLen = 0;
    MEMZERO(&v->sender.data, sizeof(v->sender.data));
    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(&value, "sender", &contents));
    CHECK_CBOR_MAP_ERR(cbor_value_get_string_length(&contents, &stringLen))
    PARSER_ASSERT_OR_ERROR(stringLen <= SENDER_MAX_LEN, parser_context_unexpected_size)
    CHECK_CBOR_MAP_ERR(_cbor_value_copy_string(&contents, v->sender.data, &v->sender.len, NULL));

    MEMZERO(&v->request_type.data, sizeof(v->request_type.data));
    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(&value, "request_type", &contents));
    CHECK_CBOR_MAP_ERR(cbor_value_get_string_length(&contents, &stringLen))
    PARSER_ASSERT_OR_ERROR(stringLen <= REQUEST_MAX_LEN, parser_context_unexpected_size)
    CHECK_CBOR_MAP_ERR(_cbor_value_copy_string(&contents, v->request_type.data, &v->request_type.len, NULL));

    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(&value, "ingress_expiry", &contents));
    v->ingress_expiry = _cbor_value_decode_int64_internal(&contents);

    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(&value, "paths", &contents));
    PARSER_ASSERT_OR_ERROR(cbor_value_is_container(&contents), parser_unexpected_type);

    CborValue subvalue;
    CHECK_CBOR_MAP_ERR(cbor_value_enter_container(&contents, &subvalue))

    size_t arrayLen = 0;
    CHECK_CBOR_MAP_ERR(cbor_value_get_array_length(&subvalue, &arrayLen));

    if (arrayLen <= 0 || arrayLen > PATH_MAX_ARRAY) {
        return parser_value_out_of_range;
    }
    v->paths.arrayLen = arrayLen;

    CHECK_CBOR_MAP_ERR(cbor_value_enter_container(&subvalue, &contents));

    uint8_t index = 0;
    do {
        CHECK_CBOR_MAP_ERR(cbor_value_get_string_length(&contents, &stringLen))
        PARSER_ASSERT_OR_ERROR(stringLen <= PATH_MAX_LEN, parser_context_unexpected_size)
        CHECK_CBOR_MAP_ERR(
                _cbor_value_copy_string(&contents, v->paths.paths[index].data, &v->paths.paths[index].len, NULL));
        CHECK_CBOR_MAP_ERR(cbor_value_advance(&contents));
        index++;
    } while (index < arrayLen);

    return parser_ok;
}

parser_error_t read_protobuf(uint8_t *buffer, size_t bufferLen) {
    bool status;

    zemu_log_stack("protobuf");
    CHECK_APP_CANARY()
    /* Allocate space for the decoded message. */
    SendRequest request = SendRequest_init_zero;
    CHECK_APP_CANARY()
    zemu_log_stack("protobuf before stream");

    /* Create a stream that reads from the buffer. */
    pb_istream_t stream = pb_istream_from_buffer(buffer, bufferLen);
    CHECK_APP_CANARY()
    zemu_log_stack("protobuf before decode");

    /* Now we are ready to decode the message. */
    status = pb_decode(&stream, SendRequest_fields, &request);

    zemu_log_stack("protobuf after decode");

    CHECK_APP_CANARY()
    /* Check for errors... */
    if (!status) {
        return parser_unexepected_error;
    }

    return parser_ok;
}

parser_error_t _readTokenTransfer(const parser_context_t *c, parser_tx_t *v) {
    CborValue it;
    INIT_CBOR_PARSER(c, it)
    PARSER_ASSERT_OR_ERROR(!cbor_value_at_end(&it), parser_unexpected_buffer_end)
    cbor_value_advance(&it);

    PARSER_ASSERT_OR_ERROR(cbor_value_is_container(&it), parser_unexpected_type)
    CborValue contents;
    CborValue value;
    CHECK_CBOR_MAP_ERR(cbor_value_enter_container(&it, &contents));

    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(&it, "content", &value));

    PARSER_ASSERT_OR_ERROR(cbor_value_is_container(&value), parser_unexpected_type);
    CHECK_CBOR_MAP_ERR(cbor_value_enter_container(&value, &contents));

    size_t mapLen = 0;
    CHECK_CBOR_MAP_ERR(cbor_value_get_map_length(&value, &mapLen));

    PARSER_ASSERT_OR_ERROR(mapLen == NUM_MAP_TYPE0, parser_context_unexpected_size);

    size_t stringLen = 0;
    MEMZERO(&v->canister_id.data, sizeof(v->canister_id.data));
    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(&value, "canister_id", &contents));
    CHECK_CBOR_MAP_ERR(cbor_value_get_string_length(&contents, &stringLen))
    PARSER_ASSERT_OR_ERROR(stringLen <= CANISTER_MAX_LEN, parser_context_unexpected_size)
    CHECK_CBOR_MAP_ERR(_cbor_value_copy_string(&contents, v->canister_id.data, &v->canister_id.len, NULL));

    MEMZERO(&v->sender.data, sizeof(v->sender.data));
    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(&value, "sender", &contents));
    CHECK_CBOR_MAP_ERR(cbor_value_get_string_length(&contents, &stringLen))
    PARSER_ASSERT_OR_ERROR(stringLen <= SENDER_MAX_LEN, parser_context_unexpected_size)
    CHECK_CBOR_MAP_ERR(_cbor_value_copy_string(&contents, v->sender.data, &v->sender.len, NULL));

    MEMZERO(&v->request_type.data, sizeof(v->request_type.data));
    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(&value, "request_type", &contents));
    CHECK_CBOR_MAP_ERR(cbor_value_get_string_length(&contents, &stringLen))
    PARSER_ASSERT_OR_ERROR(stringLen <= REQUEST_MAX_LEN, parser_context_unexpected_size)
    CHECK_CBOR_MAP_ERR(_cbor_value_copy_string(&contents, v->request_type.data, &v->request_type.len, NULL));

    MEMZERO(&v->nonce.data, sizeof(v->nonce.data));
    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(&value, "nonce", &contents));
    CHECK_CBOR_MAP_ERR(cbor_value_get_string_length(&contents, &stringLen))
    PARSER_ASSERT_OR_ERROR(stringLen <= NONCE_MAX_LEN, parser_context_unexpected_size)
    CHECK_CBOR_MAP_ERR(_cbor_value_copy_string(&contents, v->nonce.data, &v->nonce.len, NULL));

    MEMZERO(&v->method_name.data, sizeof(v->method_name.data));
    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(&value, "method_name", &contents));
    CHECK_CBOR_MAP_ERR(cbor_value_get_string_length(&contents, &stringLen))
    PARSER_ASSERT_OR_ERROR(stringLen <= METHOD_MAX_LEN, parser_context_unexpected_size)
    CHECK_CBOR_MAP_ERR(_cbor_value_copy_string(&contents, v->method_name.data, &v->method_name.len, NULL));

    MEMZERO(&v->arg.data, sizeof(v->arg.data));
    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(&value, "arg", &contents));
    CHECK_CBOR_MAP_ERR(cbor_value_get_string_length(&contents, &stringLen))
    PARSER_ASSERT_OR_ERROR(stringLen <= ARG_MAX_LEN, parser_context_unexpected_size)
    CHECK_CBOR_MAP_ERR(_cbor_value_copy_string(&contents, v->arg.data, &v->arg.len, NULL));

    CHECK_PARSER_ERR(read_protobuf(v->arg.data, v->arg.len));

    CHECK_CBOR_MAP_ERR(cbor_value_map_find_value(&value, "ingress_expiry", &contents));
    v->ingress_expiry = _cbor_value_decode_int64_internal(&contents);

    return parser_ok;
}

parser_error_t _validateTx(const parser_context_t *c, const parser_tx_t *v) {
    // Note: This is place holder for transaction level checks that the project may require before accepting
    // the parsed values. the parser already validates input
    // This function is called by parser_validate, where additional checks are made (formatting, UI/UX, etc.(
    return parser_ok;
}

uint8_t _getNumItems(const parser_context_t *c, const parser_tx_t *v) {
    uint8_t itemCount = 0;
    switch (v->txtype) {
        case 0x00 : {
            itemCount = 7;
            break;
        }
        case 0x01 : {
            itemCount = 3 + v->paths.arrayLen;
            break;
        }
        default : {
            break;
        }
    }

    return itemCount;
}
