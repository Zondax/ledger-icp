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
#include "parser_impl.h"
#include "parser.h"
#include "coin.h"
#include "parser_txdef.h"
#include "crypto.h"

#if defined(TARGET_NANOX)
// For some reason NanoX requires this function
void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function){
    while(1) {};
}
#endif

parser_error_t zeroize_parser_tx(parser_tx_t *v) {
    for (int i = 0; i < PATH_MAX_ARRAY; i++) {
        MEMZERO(v->paths.paths[i].data, PATH_MAX_LEN);
    }
    return parser_ok;
}

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen) {
    if (dataLen < 1) {
        return parser_no_data;
    }

    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen))
    CHECK_PARSER_ERR(zeroize_parser_tx(&parser_tx_obj));
    return _readEnvelope(ctx, &parser_tx_obj);
}

parser_error_t parser_validate(const parser_context_t *ctx) {
    CHECK_PARSER_ERR(_validateTx(ctx, &parser_tx_obj))

    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems));

    char tmpKey[40];
    char tmpVal[40];

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_PARSER_ERR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }

    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    *num_items = _getNumItems(ctx, &parser_tx_obj);
    return parser_ok;
}

parser_error_t parser_getItemTransactionStateRead(const parser_context_t *ctx,
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

    char buffer[100];
    MEMZERO(buffer, sizeof(buffer));

    if (displayIdx < 0 || displayIdx >= numItems) {
        return parser_no_data;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "request_type");
        snprintf(outVal, outValLen, "%s", parser_tx_obj.request_type.data);
        return parser_ok;
    }
    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "ingress_expiry");
        fpuint64_to_str(buffer, sizeof(buffer), parser_tx_obj.ingress_expiry, 0);
        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "sender");
        uint16_t outLen = 0;
        uint8_t tmpbuffer[100];
        crypto_addrToTextual((uint8_t *) parser_tx_obj.sender.data, parser_tx_obj.sender.len, tmpbuffer, &outLen);
        addr_to_textual(buffer, sizeof(buffer), (const char *) tmpbuffer, outLen);
        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }

    displayIdx -= 3;
    if (displayIdx < 0 || displayIdx >= parser_tx_obj.paths.arrayLen) {
        return parser_no_data;
    }
    snprintf(outKey, outKeyLen, "Path %d", displayIdx + 1);
    array_to_hexstr(buffer, sizeof(buffer), parser_tx_obj.paths.paths[displayIdx].data,
                    parser_tx_obj.paths.paths[displayIdx].len);
    pageString(outVal, outValLen, (char *) buffer, pageIdx, pageCount);
    return parser_ok;


}

parser_error_t parser_getItemTokenTransfer(const parser_context_t *ctx,
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

    char buffer[300];
    MEMZERO(buffer, sizeof(buffer));

    if (displayIdx < 0 || displayIdx >= numItems) {
        return parser_no_data;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "request_type");
        snprintf(outVal, outValLen, "%s", parser_tx_obj.request_type.data);
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "nonce");
        array_to_hexstr(buffer, sizeof(buffer), parser_tx_obj.nonce.data, parser_tx_obj.nonce.len);
        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "ingress_expiry");
        fpuint64_to_str(buffer, sizeof(buffer), parser_tx_obj.ingress_expiry, 0);
        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "sender");
        uint16_t outLen = 0;
        uint8_t tmpbuffer[100];
        crypto_addrToTextual((uint8_t *) parser_tx_obj.sender.data, parser_tx_obj.sender.len, tmpbuffer, &outLen);
        addr_to_textual(buffer, sizeof(buffer), (const char *) tmpbuffer, outLen);
        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 4) {
        snprintf(outKey, outKeyLen, "canister_id");
        uint16_t outLen = 0;
        uint8_t tmpbuffer[100];
        crypto_addrToTextual((uint8_t *) parser_tx_obj.canister_id.data, parser_tx_obj.canister_id.len, tmpbuffer,
                             &outLen);
        addr_to_textual(buffer, sizeof(buffer), (const char *) tmpbuffer, outLen);
        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 5) {
        snprintf(outKey, outKeyLen, "method_name");
        snprintf(outVal, outValLen, "%s", parser_tx_obj.method_name.data);
        return parser_ok;
    }

    if (displayIdx == 6) {
        snprintf(outKey, outKeyLen, "arg (bytes)");
        array_to_hexstr(buffer, sizeof(buffer), parser_tx_obj.arg.data, parser_tx_obj.arg.len);
        pageString(outVal, outValLen, buffer, pageIdx, pageCount);

        return parser_ok;
    }
    return parser_ok;
}

parser_error_t parser_getItem(const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {
    switch (parser_tx_obj.txtype) {
        case 0x00: {
            return parser_getItemTokenTransfer(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                               pageCount);
        }
        case 0x01: {
            return parser_getItemTransactionStateRead(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                      pageCount);

        }
        default : {
            return parser_unexepected_error;
        }
    }
}
