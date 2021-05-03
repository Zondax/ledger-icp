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
#include "formatting.h"

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

__Z_INLINE parser_error_t print_u64(uint64_t value,
                                    char *outVal, uint16_t outValLen,
                                    uint8_t pageIdx, uint8_t *pageCount) {
    char buffer[100];
    MEMZERO(buffer, sizeof(buffer));
    fpuint64_to_str(buffer, sizeof(buffer), value, 0);
    pageString(outVal, outValLen, buffer, pageIdx, pageCount);
    return parser_ok;

}

__Z_INLINE parser_error_t print_ICP(uint64_t value,
                                    char *outVal, uint16_t outValLen,
                                    uint8_t pageIdx, uint8_t *pageCount) {
    char buffer[200];
    MEMZERO(buffer, sizeof(buffer));

    zxerr_t err = formatICP(buffer, sizeof(buffer), value);
    if (err != zxerr_ok) {
        return parser_unexepected_error;
    }

    pageString(outVal, outValLen, buffer, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t print_textual(sender_t *sender,
                                        char *outVal, uint16_t outValLen,
                                        uint8_t pageIdx, uint8_t *pageCount) {
    char tmpBuffer[100];
    uint16_t outLen = sizeof(tmpBuffer);
    zxerr_t err = crypto_principalToTextual((const uint8_t *) sender->data, sender->len, (char *) tmpBuffer,
                                            &outLen);
    if (err != zxerr_ok) {
        return parser_unexepected_error;
    }

    char buffer[100];
    MEMZERO(buffer, sizeof(buffer));
    err = addr_to_textual(buffer, sizeof(buffer), (const char *) tmpBuffer, outLen);   \
    if (err != zxerr_ok) {
        return parser_unexepected_error;
    }

    if (outValLen < 37) { return parser_unexpected_buffer_end; }
    outValLen = 37;

    pageString(outVal, outValLen, buffer, pageIdx, pageCount);

#if defined(TARGET_NANOS) || defined(TARGET_NANOX)
    // Remove trailing dashes
    if (outVal[17] == '-') outVal[17] = ' ';
    if (outVal[35] == '-') outVal[35] = ' ';
#endif

    return parser_ok;
}

__Z_INLINE parser_error_t print_accountBytes(sender_t sender,
                                             SendRequest *sendrequest,
                                             char *outVal, uint16_t outValLen,
                                             uint8_t pageIdx, uint8_t *pageCount) {
    uint8_t address[32];
    MEMZERO(address, sizeof(address));

    zxerr_t err = crypto_principalToSubaccount(sender.data, sender.len,
                                               sendrequest->from_subaccount.sub_account, 32,
                                               address, sizeof(address));
    if (err != zxerr_ok) {
        return parser_unexepected_error;
    }

    char buffer[80];
    MEMZERO(buffer, sizeof(buffer));
    array_to_hexstr(buffer, sizeof(buffer), (uint8_t *) address, 32);

#if defined(TARGET_NANOS) || defined(TARGET_NANOX)
    // insert spaces to force alignment
    inplace_insert_char(buffer, sizeof(buffer), 8, ' ');
    inplace_insert_char(buffer, sizeof(buffer), 17, ' ');
    inplace_insert_char(buffer, sizeof(buffer), 26, ' ');
    inplace_insert_char(buffer, sizeof(buffer), 35, ' ');
    inplace_insert_char(buffer, sizeof(buffer), 44, ' ');
    inplace_insert_char(buffer, sizeof(buffer), 53, ' ');
    inplace_insert_char(buffer, sizeof(buffer), 62, ' ');
#endif

    pageString(outVal, outValLen, buffer, pageIdx, pageCount);

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

    if (displayIdx < 0 || displayIdx >= numItems) {
        return parser_no_data;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Check status");
        return parser_ok;
    }

    if (app_mode_expert()) {
        state_read_t *fields = &parser_tx_obj.tx_fields.stateRead;

        if (displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Sender");
            return print_textual(&fields->sender, outVal, outValLen, pageIdx, pageCount);
        }

        displayIdx -= 2;

        if (displayIdx < 0 || displayIdx >= fields->paths.arrayLen) {
            return parser_no_data;
        }

        char buffer[100];
        MEMZERO(buffer, sizeof(buffer));
        snprintf(outKey, outKeyLen, "Request ID");
        array_to_hexstr(buffer, sizeof(buffer), fields->paths.paths[1].data,
                        fields->paths.paths[1].len);
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
            snprintf(outKey, outKeyLen, "Transaction type");
            snprintf(outVal, outValLen, "Send ICP");
        }

        if (displayIdx == 1) {
            snprintf(outKey, outKeyLen, "FromAccount");
            return print_accountBytes(fields->sender, &fields->pb_fields.sendrequest,
                                      outVal, outValLen,
                                      pageIdx, pageCount);
        }

        if (displayIdx == 2) {
            snprintf(outKey, outKeyLen, "To account");

            // FIXME: 4 lines of 16 char each
            char buffer[100];
            MEMZERO(buffer, sizeof(buffer));
            array_to_hexstr(buffer, sizeof(buffer), (uint8_t *) fields->pb_fields.sendrequest.to.hash, 32);
            if (outValLen < 33) {
                return parser_unexpected_buffer_end;
            }

            outValLen = 33;
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            return parser_ok;
        }

        if (displayIdx == 3) {
            snprintf(outKey, outKeyLen, "Payment (ICP)");
            return print_ICP(fields->pb_fields.sendrequest.payment.receiver_gets.e8s,
                             outVal, outValLen,
                             pageIdx, pageCount);
        }

        if (displayIdx == 4) {
            snprintf(outKey, outKeyLen, "Maximum fee (ICP)");
            return print_ICP(fields->pb_fields.sendrequest.max_fee.e8s,
                             outVal, outValLen,
                             pageIdx, pageCount);
        }

        if (displayIdx == 5) {
            snprintf(outKey, outKeyLen, "Memo");
            return print_u64(fields->pb_fields.sendrequest.memo.memo, outVal, outValLen, pageIdx, pageCount);
        }
    } else {
        if (displayIdx == 0) {
            snprintf(outKey, outKeyLen, "Transaction type");
            snprintf(outVal, outValLen, "Send ICP");
        }

        if (displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Sender");
            return print_textual(&fields->sender, outVal, outValLen, pageIdx, pageCount);
        }

        if (displayIdx == 2) {
            snprintf(outKey, outKeyLen, "Subaccount");
            snprintf(outVal, outValLen, "Not set");

            if (fields->pb_fields.sendrequest.has_from_subaccount) {
                char buffer[100];
                MEMZERO(buffer, sizeof(buffer));
                array_to_hexstr(buffer, sizeof(buffer), fields->pb_fields.sendrequest.from_subaccount.sub_account,
                                32);
                pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            }

            return parser_ok;
        }

        if (displayIdx == 3) {
            snprintf(outKey, outKeyLen, "FromAccount");
            return print_accountBytes(fields->sender, &fields->pb_fields.sendrequest,
                                      outVal, outValLen,
                                      pageIdx, pageCount);
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
            snprintf(outKey, outKeyLen, "Payment (ICP)");
            return print_ICP(fields->pb_fields.sendrequest.payment.receiver_gets.e8s,
                             outVal, outValLen,
                             pageIdx, pageCount);
        }

        if (displayIdx == 6) {
            snprintf(outKey, outKeyLen, "Maximum fee (ICP)");
            return print_ICP(fields->pb_fields.sendrequest.max_fee.e8s,
                             outVal, outValLen,
                             pageIdx, pageCount);
        }

        if (displayIdx == 7) {
            snprintf(outKey, outKeyLen, "Memo");
            return print_u64(fields->pb_fields.sendrequest.memo.memo, outVal, outValLen, pageIdx, pageCount);
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
            return parser_getItemTokenTransfer(ctx, displayIdx,
                                               outKey, outKeyLen,
                                               outVal, outValLen,
                                               pageIdx, pageCount);
        }
        case state_transaction_read: {
            return parser_getItemTransactionStateRead(ctx, displayIdx,
                                                      outKey, outKeyLen,
                                                      outVal, outValLen,
                                                      pageIdx, pageCount);
        }
        default : {
            return parser_unexepected_error;
        }
    }
}
