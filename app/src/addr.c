/*******************************************************************************
*   (c) 2020 Zondax GmbH
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
#include "coin.h"
#include "parser_print_helper.h"
#include "zxerror.h"
#include "zxmacros.h"
#include "app_mode.h"
#include "crypto.h"
#include "actions.h"
#include "formatting.h"
#include "zxformat.h"
#include "rslib.h"

zxerr_t addr_getNumItems(uint8_t *num_items) {
    zemu_log_stack("addr_getNumItems");
    *num_items = 2;
    if (app_mode_expert()) {
        *num_items = 3;
    }
    return zxerr_ok;
}

uint8_t counter = 0;

zxerr_t addr_getItem(int8_t displayIdx,
                     char *outKey, uint16_t outKeyLen,
                     char *outVal, uint16_t outValLen,
                     uint8_t pageIdx, uint8_t *pageCount) {
    // Assuming the signature is 48 bytes long based on the provided values
    uint8_t s[48] = {
        139, 118, 54, 85, 203, 37, 178, 69, 140, 15, 123, 156, 250, 54, 205, 107,
        22, 254, 170, 98, 234, 151, 252, 248, 245, 75, 211, 209, 237, 75, 135, 119,
        53, 244, 174, 38, 241, 127, 34, 154, 2, 92, 174, 10, 73, 110, 128, 24
    };

    // Assuming the public key is 96 bytes long based on the provided values
    uint8_t pub[96] = {
        136, 241, 121, 119, 242, 65, 192, 110, 129, 119, 65, 77, 158, 13, 150, 144,
        28, 235, 33, 208, 173, 221, 78, 19, 60, 123, 224, 65, 6, 100, 121, 203,
        211, 101, 20, 169, 44, 125, 233, 145, 41, 91, 200, 233, 176, 158, 87, 101,
        14, 124, 251, 239, 197, 63, 193, 29, 63, 169, 173, 27, 106, 244, 66, 35,
        18, 131, 154, 12, 85, 56, 162, 240, 100, 125, 155, 115, 241, 135, 95, 223,
        191, 44, 141, 140, 9, 202, 43, 152, 228, 117, 44, 46, 126, 194, 128, 157
    };

    // Assuming the message is 11 bytes long based on the provided values
    uint8_t message[11] = {
        104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100
    };

    CHECK_APP_CANARY();

    char buffer[50] = {0};
    snprintf(buffer, sizeof(buffer), "addr_getItem %d/%d", displayIdx, pageIdx);
    zemu_log_stack(buffer);
    if (action_addrResponseLen < VIEW_PRINCIPAL_OFFSET_TEXT || IO_APDU_BUFFER_SIZE < action_addrResponseLen) {
        return zxerr_buffer_too_small;
    }

    parser_error_t err = parser_unexpected_error;
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Address ");
            if (counter == 0 && verify_bls_sign(s, message, 11, pub) == 1) {
                zemu_log_stack("\n OK!!***\n");
            } else {
                zemu_log_stack("\nERR!!***\n");
            }
            counter += 1;
            err = page_hexstring_with_delimiters(G_io_apdu_buffer + VIEW_ADDRESS_OFFSET_TEXT, DFINITY_SUBACCOUNT_LEN,
                                                 outVal, outValLen, pageIdx, pageCount);
            if (err != parser_ok) {
                return zxerr_unknown;
            }
            CHECK_APP_CANARY();
            return zxerr_ok;

        case 1:
            snprintf(outKey, outKeyLen, "Principal ");
            err = page_textual_with_delimiters((const char*)G_io_apdu_buffer + VIEW_PRINCIPAL_OFFSET_TEXT,
                                               action_addrResponseLen - VIEW_PRINCIPAL_OFFSET_TEXT,
                                               outVal, outValLen, pageIdx, pageCount);
            if (err != parser_ok) {
                return zxerr_unknown;
            }
            return zxerr_ok;

        case 2: {
            if (!app_mode_expert()) {
                return zxerr_no_data;
            }

            snprintf(outKey, outKeyLen, "Path");
            bip32_to_str(buffer, sizeof(buffer), hdPath, HDPATH_LEN_DEFAULT);
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            return zxerr_ok;
        }
        default:
            return zxerr_no_data;
    }
}
