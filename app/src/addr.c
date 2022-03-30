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
#include "zxerror.h"
#include "zxmacros.h"
#include "app_mode.h"
#include "crypto.h"
#include "actions.h"
#include "formatting.h"
#include "zxformat.h"

zxerr_t addr_getNumItems(uint8_t *num_items) {
    zemu_log_stack("addr_getNumItems");
    *num_items = 2;
    if (app_mode_expert()) {
        *num_items = 3;
    }
    return zxerr_ok;
}

zxerr_t addr_getItem(int8_t displayIdx,
                     char *outKey, uint16_t outKeyLen,
                     char *outVal, uint16_t outValLen,
                     uint8_t pageIdx, uint8_t *pageCount) {
    char buffer[300];
    snprintf(buffer, sizeof(buffer), "addr_getItem %d/%d", displayIdx, pageIdx);
    zemu_log_stack(buffer);
    if(action_addrResponseLen < VIEW_PRINCIPAL_OFFSET_TEXT || IO_APDU_BUFFER_SIZE < action_addrResponseLen){
        return zxerr_buffer_too_small;
    }
    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Principal ");
            CHECK_ZXERR(addr_to_textual(buffer, sizeof(buffer),
                                        (const char *) G_io_apdu_buffer + VIEW_PRINCIPAL_OFFSET_TEXT,
                                        action_addrResponseLen - VIEW_PRINCIPAL_OFFSET_TEXT));

            // Remove trailing dashes
            if (buffer[17] == '-') buffer[17] = ' ';
            if (buffer[35] == '-') buffer[35] = ' ';
            if (buffer[53] == '-') buffer[53] = ' ';

            pageString(outVal, outValLen, buffer, pageIdx, pageCount);

            return zxerr_ok;

        case 1:
            snprintf(outKey, outKeyLen, "Address ");
            MEMZERO(buffer, sizeof(buffer));
            array_to_hexstr(buffer, sizeof(buffer), G_io_apdu_buffer + VIEW_ADDRESS_OFFSET_TEXT,
                            DFINITY_SUBACCOUNT_LEN);

            #if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2)
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
