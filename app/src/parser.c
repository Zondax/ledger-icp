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
    MEMZERO(v, sizeof(v));
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

#define DISPLAY_U64(KEYNAME, VALUE) { \
    char buffer[100];                                           \
    MEMZERO(buffer, sizeof(buffer));                                  \
    snprintf(outKey, outKeyLen, KEYNAME);  \
    fpuint64_to_str(buffer, sizeof(buffer), VALUE, 0); \
    pageString(outVal, outValLen, buffer, pageIdx, pageCount); \
    return parser_ok;                                          \
}

#define DISPLAY_ICP(KEYNAME, VALUE) { \
    char buffer[100];                                           \
    MEMZERO(buffer, sizeof(buffer));                                  \
    snprintf(outKey, outKeyLen, KEYNAME);  \
    fpuint64_to_str(buffer, sizeof(buffer), VALUE, 8);          \
    number_inplace_trimming(buffer);                           \
    pageString(outVal, outValLen, buffer, pageIdx, pageCount); \
    return parser_ok;                                          \
}

#define DISPLAY_SHORTSTRING(KEYNAME, VALUE) { \
    snprintf(outKey, outKeyLen, KEYNAME);                       \
    snprintf(outVal, outValLen, "%s", VALUE); \
    return parser_ok;                                              \
}

#define DISPLAY_BYTES(KEYNAME, VALUE) { \
    char buffer[100];                                           \
    MEMZERO(buffer, sizeof(buffer));                              \
    snprintf(outKey, outKeyLen, KEYNAME);                       \
    array_to_hexstr(buffer, sizeof(buffer), (VALUE).data, (VALUE).len); \
    pageString(outVal, outValLen, buffer, pageIdx, pageCount);  \
    return parser_ok;                            \
}

#define DISPLAY_TEXTUAL(KEYNAME, VALUE) { \
    char buffer[100];                                           \
    MEMZERO(buffer, sizeof(buffer));                                      \
    snprintf(outKey, outKeyLen, KEYNAME); \
    uint16_t outLen = 0;          \
    uint8_t tmpbuffer[100];        \
    crypto_principalToTextual((uint8_t *)(VALUE).data, (VALUE).len, tmpbuffer, &outLen);  \
    addr_to_textual(buffer, sizeof(buffer), (const char *)tmpbuffer, outLen);   \
    pageString(outVal, outValLen, buffer, pageIdx, pageCount);  \
    return parser_ok;                            \
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

    if (displayIdx < 0 || displayIdx >= numItems) {
        return parser_no_data;
    }

    if (!app_mode_expert()) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Check status");
    } else {
        state_read_t *fields = &parser_tx_obj.tx_fields.stateRead;

        if (displayIdx == 0) {
            DISPLAY_SHORTSTRING("Transaction type", "Check status")
        }

        if (displayIdx == 1) {
            DISPLAY_TEXTUAL("Sender", fields->sender)
        }

        displayIdx -= 2;
        if (displayIdx < 0 || displayIdx >= fields->paths.arrayLen) {
            return parser_no_data;
        }
        char buffer[100];
        MEMZERO(buffer, sizeof(buffer));
        snprintf(outKey, outKeyLen, "Request ID %d", displayIdx + 1);
        array_to_hexstr(buffer, sizeof(buffer), fields->paths.paths[displayIdx].data,
                        fields->paths.paths[displayIdx].len);
        pageString(outVal, outValLen, (char *) buffer, pageIdx, pageCount);
    }

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

    call_t *fields = &parser_tx_obj.tx_fields.call;

    if (displayIdx < 0 || displayIdx >= numItems) {
        return parser_no_data;
    }

    if (!app_mode_expert()) {
        if (displayIdx == 0) {
            DISPLAY_SHORTSTRING("Transaction type", "Send ICP")
        }

        if (displayIdx == 1) {
            DISPLAY_TEXTUAL("From account", fields->sender)             // FIXME:
        }

        if (displayIdx == 2) {
            char buffer[100];
            MEMZERO(buffer, sizeof(buffer));
            snprintf(outKey, outKeyLen, "To account");
            array_to_hexstr(buffer, sizeof(buffer), (uint8_t *) fields->pb_fields.sendrequest.to.hash, 32);
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            return parser_ok;
        }

        if (displayIdx == 3) {
            DISPLAY_ICP("Payment (ICP)", fields->pb_fields.sendrequest.payment.receiver_gets.e8s)
        }

        if (displayIdx == 4) {
            DISPLAY_ICP("Maximum Fee (ICP)", fields->pb_fields.sendrequest.max_fee.e8s)
        }

        if (displayIdx == 5) {
            DISPLAY_U64("Memo", fields->pb_fields.sendrequest.memo.memo)
        }
    } else {
        if (displayIdx == 3) {
            DISPLAY_TEXTUAL("sender", fields->sender)
        }

        if (displayIdx == 4) {
            DISPLAY_TEXTUAL("canister_id", fields->canister_id)
        }

        if (displayIdx == 5) {
            DISPLAY_SHORTSTRING("method_name", fields->method_name.data)
        }

        if (displayIdx == 9) {
            char buffer[100];
            MEMZERO(buffer, sizeof(buffer));
            snprintf(outKey, outKeyLen, "Subaccount");
            if (fields->pb_fields.sendrequest.has_from_subaccount) {
                array_to_hexstr(buffer, sizeof(buffer), fields->pb_fields.sendrequest.from_subaccount.sub_account, 32);
                pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            } else {
                snprintf(outVal, outValLen, "Not set");
            }
            return parser_ok;
        }
    }

    return parser_ok;
}

parser_error_t parser_getItem(const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {
    switch (parser_tx_obj.txtype) {
        case token_transfer: {
            return parser_getItemTokenTransfer(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                               pageCount);
        }
        case state_transaction_read: {
            return parser_getItemTransactionStateRead(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                      pageCount);
        }
        default : {
            return parser_unexepected_error;
        }
    }
}
