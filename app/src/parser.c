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
    MEMZERO(v, sizeof(parser_tx_t));
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
    fpuint64_to_str(buffer, sizeof(buffer), VALUE, 0, NULL); \
    pageString(outVal, outValLen, buffer, pageIdx, pageCount); \
    return parser_ok;                                          \
}

parser_error_t parser_displayICP(const char *key,
                                 uint64_t value,
                                 char *outKey, uint16_t outKeyLen,
                                 char *outVal, uint16_t outValLen,
                                 uint8_t pageIdx, uint8_t *pageCount) {
    // FIXME: https://github.com/Zondax/ledger-dfinity/issues/46
// - thousand separator comma: ,
// - fractional at least 2 digits
    char buffer[100];                                           \
    MEMZERO(buffer, sizeof(buffer));                                  \
    snprintf(outKey, outKeyLen, "%s", key);  \
    fpuint64_to_str(buffer, sizeof(buffer), value, 8, NULL);          \
    number_inplace_trimming(buffer);                           \
    pageString(outVal, outValLen, buffer, pageIdx, pageCount); \
    return parser_ok;                                          \

    return parser_ok;
}

#define DISPLAY_SHORTSTRING(KEYNAME, VALUE) { \
    snprintf(outKey, outKeyLen, KEYNAME);                       \
    snprintf(outVal, outValLen, "%s", VALUE); \
    return parser_ok;                                              \
}

// FIXME: 3 groups of 5 and split
#define DISPLAY_TEXTUAL(KEYNAME, VALUE) { \
    uint8_t buffer[100];                                           \
    MEMZERO(buffer, sizeof(buffer));                                      \
    snprintf(outKey, outKeyLen, KEYNAME); \
    uint16_t outLen = 0;          \
    char tmpbuffer[100];        \
    crypto_principalToTextual((char *)(VALUE).data, (VALUE).len, (char *) tmpbuffer, &outLen);  \
    addr_to_textual(buffer, sizeof(buffer), (const char *)tmpbuffer, outLen);   \
    if (outValLen < 37) { return parser_unexpected_buffer_end; } \
    outValLen = 37; \
    pageString(outVal, outValLen, buffer, pageIdx, pageCount);  \
    return parser_ok;                            \
}

// FIXME: 32 hex characters on each line
#define DISPLAY_ACCOUNTBYTES(PRINCIPAL, SUBACCOUNT) { \
    char buffer[100];                                                           \
    MEMZERO(buffer, sizeof(buffer));                                            \
    uint8_t address[32];                                                        \
    MEMZERO(address, sizeof(address));                                           \
    zxerr_t err = crypto_principalToSubaccount(PRINCIPAL, 29, SUBACCOUNT, 32,   \
                                           address, sizeof(address));           \
    if (err != zxerr_ok){                                                       \
        return parser_unexepected_error;                                        \
    }                                                                           \
    array_to_hexstr(buffer, sizeof(buffer), (uint8_t *) address, 32);           \
    pageString(outVal, outValLen, buffer, pageIdx, pageCount);                  \
    return parser_ok;                                                           \
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
        // FIXME: path filtering
        if (displayIdx < 0 || displayIdx >= fields->paths.arrayLen) {
            return parser_no_data;
        }
        char buffer[100];
        MEMZERO(buffer, sizeof(buffer));
        uint8_t requeststatus = fields->has_requeststatus_path ? 1 : 0;

        snprintf(outKey, outKeyLen, "Request ID");
        array_to_hexstr(buffer, sizeof(buffer), fields->paths.paths[displayIdx+requeststatus].data,
                        fields->paths.paths[displayIdx+requeststatus].len);
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
            snprintf(outKey, outKeyLen, "From account");
            DISPLAY_ACCOUNTBYTES(fields->sender.data, fields->pb_fields.sendrequest.from_subaccount.sub_account)
        }

        if (displayIdx == 2) {
            // FIXME: 4 lines of 16 char each
            char buffer[100];
            MEMZERO(buffer, sizeof(buffer));
            snprintf(outKey, outKeyLen, "To account");
            array_to_hexstr(buffer, sizeof(buffer), (uint8_t *) fields->pb_fields.sendrequest.to.hash, 32);
            if (outValLen < 33) {
                return parser_unexpected_buffer_end;
            }

            outValLen = 33;
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            return parser_ok;
        }

        if (displayIdx == 3) {
            return parser_displayICP("Payment (ICP)",
                                     fields->pb_fields.sendrequest.payment.receiver_gets.e8s,
                                     outKey, outKeyLen,
                                     outVal, outValLen,
                                     pageIdx, pageCount);
        }

        if (displayIdx == 4) {
            return parser_displayICP("Maximum fee (ICP)",
                                     fields->pb_fields.sendrequest.max_fee.e8s,
                                     outKey, outKeyLen,
                                     outVal, outValLen,
                                     pageIdx, pageCount);
        }

        if (displayIdx == 5) {
            DISPLAY_U64("Memo", fields->pb_fields.sendrequest.memo.memo)
        }
    } else {
        if (displayIdx == 0) {
            DISPLAY_SHORTSTRING("Transaction type", "Send ICP")
        }

        if (displayIdx == 1) {
            DISPLAY_TEXTUAL("Sender", fields->sender)
        }

        if (displayIdx == 2) {
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

        if (displayIdx == 3) {
            snprintf(outKey, outKeyLen, "From account");
            DISPLAY_ACCOUNTBYTES(fields->sender.data, fields->pb_fields.sendrequest.from_subaccount.sub_account)
        }

        if (displayIdx == 4) {
            char buffer[100];
            MEMZERO(buffer, sizeof(buffer));
            snprintf(outKey, outKeyLen, "To account");
            array_to_hexstr(buffer, sizeof(buffer), (uint8_t *) fields->pb_fields.sendrequest.to.hash, 32);
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            return parser_ok;
        }

        if (displayIdx == 5) {
            return parser_displayICP("Payment (ICP)",
                                     fields->pb_fields.sendrequest.payment.receiver_gets.e8s,
                                     outKey, outKeyLen,
                                     outVal, outValLen,
                                     pageIdx, pageCount);
        }

        if (displayIdx == 6) {
            return parser_displayICP("Maximum fee (ICP)",
                                     fields->pb_fields.sendrequest.max_fee.e8s,
                                     outKey, outKeyLen,
                                     outVal, outValLen,
                                     pageIdx, pageCount);
        }

        if (displayIdx == 7) {
            DISPLAY_U64("Memo", fields->pb_fields.sendrequest.memo.memo)
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
