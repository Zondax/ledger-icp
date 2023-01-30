/*******************************************************************************
*   (c) 2018 - 2023 Zondax AG
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
#include "parser_print_helper.h"
#include "formatting.h"
#include "zxformat.h"
#include "base32.h"

#define CRC_LENGTH  4
#define SUBACCOUNT_EXTRA_BYTE 0x7F

parser_error_t print_u64(uint64_t value,
                        char *outVal, uint16_t outValLen,
                        uint8_t pageIdx, uint8_t *pageCount) {
    char buffer[100];
    MEMZERO(buffer, sizeof(buffer));
    fpuint64_to_str(buffer, sizeof(buffer), value, 0);
    pageString(outVal, outValLen, buffer, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t print_ICP(uint64_t value,
                         char *outVal, uint16_t outValLen,
                         uint8_t pageIdx, uint8_t *pageCount) {
    char buffer[200] = {0};
    zxerr_t err = formatICP(buffer, sizeof(buffer), value);
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    pageString(outVal, outValLen, buffer, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t print_textual(uint8_t *data, uint16_t len,
                             char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount) {
    char tmpBuffer[100] = {0};
    uint16_t outLen = sizeof(tmpBuffer);
    zxerr_t err = crypto_principalToTextual((const uint8_t *) data, len, (char *) tmpBuffer,
                                            &outLen);
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    char buffer[100];
    MEMZERO(buffer, sizeof(buffer));
    err = addr_to_textual(buffer, sizeof(buffer), (const char *) tmpBuffer, outLen);   \
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    // Remove trailing dashes
    if (buffer[17] == '-') buffer[17] = ' ';
    if (buffer[35] == '-') buffer[35] = ' ';
    if (buffer[53] == '-') buffer[53] = ' ';

    pageString(outVal, outValLen, buffer, pageIdx, pageCount);

    return parser_ok;
}

parser_error_t print_principal(uint8_t *data, uint16_t len,
                             char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount) {

    const uint8_t MAX_CHARS_PER_LINE = 38;
    if (data == NULL || outVal == NULL || pageCount == NULL || outValLen < MAX_CHARS_PER_LINE) {
        return parser_unexpected_error;
    }
    char tmpBuffer[100] = {0};
    uint16_t outLen = sizeof(tmpBuffer);
    zxerr_t err = crypto_principalToTextual((const uint8_t *) data, len, (char *) tmpBuffer,
                                            &outLen);
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    char buffer[100] = {0};
    err = addr_to_textual(buffer, sizeof(buffer), (const char *) tmpBuffer, outLen);
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    // Alignment logic
    if (buffer[17] == '-') buffer[17] = ' ';
    if (buffer[53] == '-') buffer[53] = ' ';
    // Remove one buffer[35] ('-' character)
    MEMMOVE(buffer+35, buffer+36, sizeof(buffer) - 36);

    inplace_insert_char(buffer, sizeof(buffer), 18, ':');
    inplace_insert_char(buffer, sizeof(buffer), 19, ' ');

    inplace_insert_char(buffer, sizeof(buffer), 55, ':');
    inplace_insert_char(buffer, sizeof(buffer), 56, ' ');

    pageString(outVal, MAX_CHARS_PER_LINE, buffer, pageIdx, pageCount);

    return parser_ok;
}

parser_error_t print_canisterId(uint8_t *data, uint16_t len,
                             char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount) {
    char tmpBuffer[100] = {0};
    uint16_t outLen = sizeof(tmpBuffer);
    zxerr_t err = crypto_principalToTextual((const uint8_t *) data, len, (char *) tmpBuffer,
                                            &outLen);
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    char buffer[100] = {0};
    err = addr_to_textual(buffer, sizeof(buffer), (const char *) tmpBuffer, outLen);   \
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    // Remove trailing dashes
    if (buffer[17] == '-') buffer[17] = ' ';
    if (buffer[35] == '-') buffer[35] = ' ';
    if (buffer[53] == '-') buffer[53] = ' ';

    inplace_insert_char(buffer, sizeof(buffer), 18, ':');
    inplace_insert_char(buffer, sizeof(buffer), 19, ' ');

    pageString(outVal, outValLen, buffer, pageIdx, pageCount);

    return parser_ok;
}

zxerr_t print_hexstring(char *out, uint16_t outLen, const uint8_t *data, uint16_t dataLen) {
    MEMZERO(out, outLen);
    const uint32_t writtenBytes = array_to_hexstr(out, outLen, data, dataLen);
    if (writtenBytes != dataLen * 2) {
        return zxerr_out_of_bounds;
    }

    // insert spaces to force alignment
    CHECK_ZXERR(inplace_insert_char(out, outLen, 8, ' '))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 17, ' '))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 26, ' '))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 35, ' '))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 44, ' '))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 53, ' '))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 62, ' '))

    return zxerr_ok;
}


parser_error_t subaccount_hexstring(const uint8_t *subaccount, const uint16_t subaccountLen,
                                    uint8_t *output, const uint16_t outputLen, uint8_t *pageCount) {

    if (subaccount == NULL || output == NULL || pageCount == NULL) {
        return parser_unexpected_error;
    }

    const uint8_t chunksRem = (subaccountLen % 3) ? 1 : 0;
    const uint16_t chunks = subaccountLen / 3 + chunksRem;

    const uint8_t pageRem = (chunks % 3) ? 1 : 0;
    const uint16_t pages = chunks / 3 + pageRem;
    if (pages > 255) {
        return parser_unexpected_value;
    }
    *pageCount = (uint8_t) pages;

    const char delimiter[] = " : ";

    if (outputLen < 6 * chunks + (*pageCount * 2 * sizeof(delimiter))) {
        return parser_unexpected_buffer_end;
    }

    // Take 3 bytes, convert them to hexstr, add delimiter = " : " and then repeat until the end
    // 3 chunks per page and do not add delimiter on the last one from each page
    uint8_t delimiterCount = 0;
    for (uint16_t i = 0; i < subaccountLen; i+= 3) {
        const uint8_t bytesToProcess = (subaccountLen - i) >= 3 ? 3 : (subaccountLen - i);
        for (uint8_t j = 0; j < bytesToProcess; j++) {
            snprintf((char*) output, 3, "%02x", *subaccount);
            subaccount++;
            output += 2;
        }

        // Reset delimiterCount if needed
        delimiterCount = (i%9 == 0) ? 0 : delimiterCount;

        if (bytesToProcess == 3 && delimiterCount < 2) {
            snprintf((char*) output, sizeof(delimiter), delimiter);
            output += 3;
            delimiterCount++;
        }
    }

    return parser_ok;
}

static parser_error_t page_with_delimiters(char *input, uint16_t inputLen, char *output, uint16_t outputLen, uint8_t pageIdx, uint8_t *pageCount) {
    const uint8_t CHARS_PER_PAGE = 30;
    const uint8_t CHARS_PER_CHUNK = 5;
    const uint8_t CHUNKS_PER_PAGE = 6;

    *pageCount = inputLen / CHARS_PER_PAGE + (inputLen % CHARS_PER_PAGE ? 1 : 0);
    if (pageIdx >= *pageCount) {
        return parser_display_idx_out_of_range;
    }

    input += pageIdx * CHARS_PER_PAGE;
    for (uint8_t idx = 0; idx < CHUNKS_PER_PAGE; idx++) {
        if (idx == 3) {
            snprintf(output, 4, " : ");
            output += 3;
        }

        const bool endOfInput = strlen(input) < 6;
        const bool skipDash = (idx == 2 || idx == 5);

        if (skipDash || endOfInput) {
            snprintf(output, CHARS_PER_CHUNK + 1, "%.*s", CHARS_PER_CHUNK, input);
        } else {
            snprintf(output, CHARS_PER_CHUNK + 2, "%.*s-", CHARS_PER_CHUNK, input);
        }

        if (endOfInput) break;

        input += CHARS_PER_CHUNK;
        output += CHARS_PER_CHUNK + (skipDash ? 0 : 1);
    }

    return parser_ok;
}

parser_error_t print_principal_with_subaccount(const uint8_t *sender, uint16_t senderLen,
                                               const uint8_t *fromSubaccount, uint16_t fromSubaccountLen,
                                               char *outVal, uint16_t outValLen,
                                               uint8_t pageIdx, uint8_t *pageCount) {

    if (sender == NULL || senderLen != DFINITY_PRINCIPAL_LEN || (fromSubaccount != NULL && fromSubaccountLen != DFINITY_SUBACCOUNT_LEN)) {
        return parser_unexpected_error;
    }

    //[ CRC | sender | shrink(fromSubaccount) | bytes(shrink(fromSubaccount)) | EXTRA_BYTE(0x7F) ]
    uint8_t tmpArray[CRC_LENGTH + DFINITY_PRINCIPAL_LEN + DFINITY_SUBACCOUNT_LEN + 2] = {0};

    MEMCPY(tmpArray + CRC_LENGTH, sender, senderLen);

    int8_t shrinkBytes = 0;
    if (fromSubaccount != NULL) {
        for (shrinkBytes = fromSubaccountLen - 1; shrinkBytes >= 0; shrinkBytes--) {
            if (*(fromSubaccount + shrinkBytes)) {
                break; // find the first non zero byte
            }
        }
        shrinkBytes++;

        if (shrinkBytes > 0) {
            MEMCPY(tmpArray + CRC_LENGTH + DFINITY_PRINCIPAL_LEN, fromSubaccount, shrinkBytes);
            // Add fromSubaccount length after shrinked and EXTRA_BYTE
            tmpArray[CRC_LENGTH + DFINITY_PRINCIPAL_LEN + shrinkBytes] = shrinkBytes;
            tmpArray[CRC_LENGTH + DFINITY_PRINCIPAL_LEN + shrinkBytes + 1] = SUBACCOUNT_EXTRA_BYTE;
        }
    }


    const uint8_t tmpArrayLen = shrinkBytes
                                ? (CRC_LENGTH + DFINITY_PRINCIPAL_LEN + shrinkBytes + 2)
                                : (CRC_LENGTH + DFINITY_PRINCIPAL_LEN);

    char buffer[110] = {0};
    uint16_t bufferSize = sizeof(buffer);
    crypto_toTextual(tmpArray, tmpArrayLen, buffer, &bufferSize);

    return page_with_delimiters(buffer, bufferSize, outVal, outValLen, pageIdx, pageCount);
}
