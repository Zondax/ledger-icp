/*******************************************************************************
*   (c) 2019 Zondax GmbH
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

#include <stdio.h>
#include <zxmacros.h>
#include <app_mode.h>
#include "candid_parser.h"
#include "parser_impl.h"
#include "parser.h"
#include "coin.h"
#include "parser_txdef.h"
#include "crypto.h"
#include "formatting.h"
#include "zxformat.h"
#include "timeutils.h"
#include "parser_print_candid.h"
#include "parser_print_helper.h"
#include "parser_print_protobuf.h"
#if defined(BLS_SIGNATURE)
#include "rslib.h"
#endif



#if defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX) || defined(TARGET_FLEX)
// For some reason NanoX requires this function
void __assert_fail(__Z_UNUSED const char * assertion, __Z_UNUSED const char * file, __Z_UNUSED unsigned int line, __Z_UNUSED const char * function){
    while(1) {};
}
#endif

#define GEN_DEC_READFIX_UNSIGNED(BITS) parser_error_t _readUInt ## BITS(parser_context_t *ctx, uint ## BITS ##_t *value) \
{                                                                                           \
    if (value == NULL)  return parser_no_data;                                              \
    *value = 0u;                                                                            \
    for(uint8_t i=0u; i < (BITS##u>>3u); i++, ctx->offset++) {                              \
        if (ctx->offset >= ctx->bufferLen) return parser_unexpected_buffer_end;             \
        *value += (uint ## BITS ##_t) *(ctx->buffer + ctx->offset) << (8u*i);               \
    }                                                                                       \
    return parser_ok;                                                                       \
}

GEN_DEC_READFIX_UNSIGNED(8)

GEN_DEC_READFIX_UNSIGNED(16)

GEN_DEC_READFIX_UNSIGNED(32)

GEN_DEC_READFIX_UNSIGNED(64)

parser_error_t parser_parse_combined(parser_context_t *ctx, const uint8_t *data, size_t dataLen) {
    if (dataLen < 1) {
        return parser_no_data;
    }
    zemu_log_stack("parser parse combined");
    //if combined_tx:
    //split data in two transactions
    //should start with checking status
    //add one more check in validate
    //define txtype
    const uint8_t *start_state_read_data = data;
    CHECK_PARSER_ERR(parser_init(ctx, start_state_read_data, dataLen))
    uint32_t dataLen_state_read = 0;
    CHECK_PARSER_ERR(_readUInt32(ctx, &dataLen_state_read))
    PARSER_ASSERT_OR_ERROR(4 + dataLen_state_read < dataLen, parser_value_out_of_range)
    ctx->bufferLen = 4 + dataLen_state_read;

    CHECK_PARSER_ERR(readEnvelope(ctx, &parser_tx_obj))
    PARSER_ASSERT_OR_ERROR(parser_tx_obj.txtype == state_transaction_read, parser_unexpected_type)
    CHECK_PARSER_ERR(_validateTx(ctx, &parser_tx_obj))
    uint8_t state_hash[32];
    MEMZERO(state_hash, sizeof(state_hash));
    PARSER_ASSERT_OR_ERROR(zxerr_ok == crypto_getDigest(state_hash, state_transaction_read), parser_unexpected_error)

    uint8_t request_id_stateread[32];
    MEMZERO(request_id_stateread, 32);
    PARSER_ASSERT_OR_ERROR(32 == parser_tx_obj.tx_fields.stateRead.paths.paths[1].len, parser_unexpected_error)

    MEMCPY(request_id_stateread, parser_tx_obj.tx_fields.stateRead.paths.paths[1].data, 32);

    data += 4 + dataLen_state_read;
    const uint8_t *start_request_data = data;
    CHECK_PARSER_ERR(parser_init(ctx, start_request_data, dataLen - 4 - dataLen_state_read))
    uint32_t dataLen_request = 0;
    CHECK_PARSER_ERR(_readUInt32(ctx, &dataLen_request))

    PARSER_ASSERT_OR_ERROR(dataLen == dataLen_request + dataLen_state_read + 8, parser_value_out_of_range)
    ctx->bufferLen = 4 + dataLen_request;

    CHECK_PARSER_ERR(readEnvelope(ctx, &parser_tx_obj))
    PARSER_ASSERT_OR_ERROR(parser_tx_obj.txtype == call, parser_unexpected_type)
    CHECK_PARSER_ERR(_validateTx(ctx, &parser_tx_obj))

    uint8_t request_hash[32];
    MEMZERO(request_hash, sizeof(request_hash));
    PARSER_ASSERT_OR_ERROR(zxerr_ok == crypto_getDigest(request_hash, call), parser_unexpected_error)

#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX) || defined(TARGET_FLEX)
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    PARSER_ASSERT_OR_ERROR(memcmp(request_hash, request_id_stateread, 32) == 0, parser_context_invalid_chars)
    MEMCPY(G_io_apdu_buffer, request_hash, 32);
    MEMCPY(G_io_apdu_buffer + 32, state_hash, 32);
#endif

    return parser_ok;
}

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen) {
    if (dataLen < 1) {
        return parser_no_data;
    }
    zemu_log_stack("parser parse");
    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen))
    return readEnvelope(ctx, &parser_tx_obj);
}

parser_error_t parser_validate(const parser_context_t *ctx) {
    zemu_log("parser_validate\n");
    CHECK_PARSER_ERR(_validateTx(ctx, &parser_tx_obj))
    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))

    char tmpKey[70] = {0};
    char tmpVal[180] = {0}; // up to 180 in stax

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_PARSER_ERR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }

    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    *num_items = _getNumItems(ctx, &parser_tx_obj);
    PARSER_ASSERT_OR_ERROR(*num_items > 0, parser_unexpected_number_items)
    return parser_ok;
}

static parser_error_t parser_getItemTransactionStateRead(const parser_context_t *ctx,
                                                  uint8_t displayIdx,
                                                  char *outKey, uint16_t outKeyLen,
                                                  char *outVal, uint16_t outValLen,
                                                  uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");
    *pageCount = 1;

    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    if (displayIdx >= numItems) {
        return parser_no_data;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Check status");
        return parser_ok;
    }

    if (app_mode_expert()) {
        const state_read_t *fields = &parser_tx_obj.tx_fields.stateRead;

        if (displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Sender ");
            return print_principal(fields->sender.data, (uint16_t) fields->sender.len, outVal, outValLen, pageIdx, pageCount);
        }

        displayIdx -= 2;

        if (displayIdx >= fields->paths.arrayLen) {
            return parser_no_data;
        }

        snprintf(outKey, outKeyLen, "Request ID ");
        return page_hexstring_with_delimiters(fields->paths.paths[1].data, fields->paths.paths[1].len,
                                              outVal, outValLen, pageIdx, pageCount);
    }

    return parser_ok;
}

parser_error_t parser_getItem(const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    switch (parser_tx_obj.txtype) {
        case call: {
            switch (parser_tx_obj.tx_fields.call.method_type) {
                case pb_sendrequest:
                case pb_manageneuron:
                case pb_listneurons:
                case pb_claimneurons: {
                    return parser_getItemProtobuf(displayIdx,
                                                  outKey, outKeyLen,
                                                  outVal, outValLen,
                                                  pageIdx, pageCount);
                }

                case candid_manageneuron:
                case candid_listneurons:
                case candid_updatenodeprovider:
                case candid_transfer:
                case candid_icrc_transfer: {
                    return parser_getItemCandid(ctx, displayIdx,
                                                outKey, outKeyLen,
                                                outVal, outValLen,
                                                pageIdx, pageCount);
                }

                default :
                    break;
            }
            break;
        }
        case state_transaction_read: {
            return parser_getItemTransactionStateRead(ctx, displayIdx,
                                                      outKey, outKeyLen,
                                                      outVal, outValLen,
                                                      pageIdx, pageCount);
        }
        default :
            break;
    }

    return parser_unexpected_type;
}

#if defined(BLS_SIGNATURE)
uint8_t parsed_obj_buffer[CERT_OBJ_MAX_SIZE];

parser_error_t parser_certNumItems(uint8_t *num_items) {
    CHECK_PARSER_ERR(rs_getNumItems(num_items));
    PARSER_ASSERT_OR_ERROR(*num_items > 0, parser_unexpected_number_items)
    return parser_ok;
}

parser_error_t parser_certGetItem(uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {

    *pageCount = 1;
    return rs_getItem(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
}
#endif
