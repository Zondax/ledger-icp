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

// 365.25 * 24*60*60 = 31557600
#define ICP_YEAR_IN_SECONDS ((uint64_t)31557600)

parser_error_t page_principal_with_delimiters(const char *input, const uint16_t inputLen, char *output, const uint16_t outputLen, const uint8_t pageIdx, uint8_t *pageCount) {
#if defined(TARGET_STAX)
    const uint8_t LINES_PER_PAGE = 7;
#elif defined(TARGET_NANOS2) || defined(TARGET_NANOX)
    const uint8_t LINES_PER_PAGE = 3;
#else
    const uint8_t LINES_PER_PAGE = 2;
#endif

    const uint8_t CHARS_PER_CHUNK = 5;
    const uint8_t CHARS_PER_PAGE = 15 * LINES_PER_PAGE;
    const uint8_t CHUNKS_PER_PAGE = 3 * LINES_PER_PAGE;

    if (outputLen < 35) {
        return parser_unexpected_buffer_end;
    }

    const size_t inputStrLen = strnlen(input, inputLen); // not including null terminator
    *pageCount = (uint8_t) (inputStrLen / CHARS_PER_PAGE) + ((inputStrLen % CHARS_PER_PAGE) ? 1 : 0);
    if (pageIdx >= *pageCount) {
        return parser_display_idx_out_of_range;
    }

    input += pageIdx * CHARS_PER_PAGE;
    for (uint8_t idx = 0; idx < CHUNKS_PER_PAGE; idx++) {
        if (idx % 3 == 0 && idx != 0) {
#ifdef TARGET_STAX
            snprintf(output, 2, "\n");
#else
            snprintf(output, 2, " ");
#endif
            output += 1;
        }

        const size_t remainingChars = inputStrLen - (pageIdx * CHARS_PER_PAGE) - (idx * CHARS_PER_CHUNK);
        const bool endOfInput = remainingChars <= 5; // strnlen does not count null terminator
        const bool skipDash = (idx % 3 == 2);

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

parser_error_t print_subaccount_hex(const uint8_t *input, const uint64_t inputLen,
                                    char *output, const uint16_t outputLen,
                                    const uint8_t pageIdx, uint8_t *pageCount) {
#if defined(TARGET_STAX)
    const uint8_t LINES_PER_PAGE = 7;
#elif defined(TARGET_NANOS2) || defined(TARGET_NANOX)
    const uint8_t LINES_PER_PAGE = 3;
#else
    const uint8_t LINES_PER_PAGE = 2;
#endif

    const uint8_t CHARS_PER_CHUNK = 8;
    const uint8_t CHARS_PER_PAGE = 16 * LINES_PER_PAGE;
    const uint8_t CHUNKS_PER_PAGE = 2 * LINES_PER_PAGE;

    if (outputLen < 35) {
        return parser_unexpected_buffer_end;
    }

    char tmpBuf[100] = {0};
    uint16_t tmpBufLen = sizeof(tmpBuf);
    const uint16_t inputStrLen = 2 * (uint16_t)inputLen; // 2 chars per byte without null terminator
    if (tmpBufLen < inputStrLen + 1) { // with null terminator
        return parser_unexpected_buffer_end;
    }
    array_to_hexstr(tmpBuf, tmpBufLen, input, (uint8_t)inputLen);

    *pageCount = (uint8_t) (inputStrLen / CHARS_PER_PAGE) + ((inputStrLen % CHARS_PER_PAGE) ? 1 : 0);
    if (pageIdx >= *pageCount) {
        return parser_display_idx_out_of_range;
    }

    uint16_t tmpBufIdx = pageIdx * CHARS_PER_PAGE;
    for (uint8_t idx = 0; idx < CHUNKS_PER_PAGE; idx++, tmpBufIdx += CHARS_PER_CHUNK) {
        if (idx % 2 == 0 && idx != 0) {
#ifdef TARGET_STAX
            snprintf(output, 2, "\n");
#else
            snprintf(output, 2, " ");
#endif
            output += 1;
        }

        const uint16_t remainingChars = inputStrLen - (pageIdx * CHARS_PER_PAGE) - (idx * CHARS_PER_CHUNK);
        const bool endOfInput = remainingChars <= 8; // without null terminator
        const bool skipSpace = (idx % 2 == 1);

        if (skipSpace || endOfInput) {
            snprintf(output, CHARS_PER_CHUNK + 1, "%.*s", CHARS_PER_CHUNK, &tmpBuf[tmpBufIdx]);
        } else {
            snprintf(output, CHARS_PER_CHUNK + 2, "%.*s ", CHARS_PER_CHUNK, &tmpBuf[tmpBufIdx]);
        }

        if (endOfInput) break;

        output += CHARS_PER_CHUNK + (skipSpace ? 0 : 1);
    }

    return parser_ok;
}

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

parser_error_t print_textual(const uint8_t *data, uint16_t len,
                             char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount) {
    char tmpBuffer[100] = {0};
    uint16_t outLen = sizeof(tmpBuffer);
    zxerr_t err = crypto_principalToTextual(data, len, (char *) tmpBuffer, &outLen);
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    return page_principal_with_delimiters(tmpBuffer, outLen, outVal, outValLen, pageIdx, pageCount);
}

zxerr_t print_hexstring(char *out, uint16_t outLen, const uint8_t *data, uint16_t dataLen) {
    MEMZERO(out, outLen);
    if (dataLen > 255) return zxerr_out_of_bounds;

    const uint32_t writtenBytes = array_to_hexstr(out, outLen, data, (uint8_t) dataLen);
    if (writtenBytes != dataLen * 2) {
        return zxerr_out_of_bounds;
    }

    #if defined(TARGET_STAX)
        const char separator = 0x0A; //new line
    #else
        const char separator = 0x20; //space
    #endif

    // insert spaces to force alignment
    CHECK_ZXERR(inplace_insert_char(out, outLen, 8, ' '))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 17, separator))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 26, ' '))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 35, separator))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 44, ' '))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 53, separator))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 62, ' '))

    return zxerr_ok;
}

parser_error_t print_principal_with_subaccount(const uint8_t *sender, uint16_t senderLen,
                                               const uint8_t *fromSubaccount, uint16_t fromSubaccountLen,
                                               char *outVal, uint16_t outValLen,
                                               uint8_t pageIdx, uint8_t *pageCount) {

    if (sender == NULL || senderLen != DFINITY_PRINCIPAL_LEN || (fromSubaccount != NULL && fromSubaccountLen != DFINITY_SUBACCOUNT_LEN)) {
        return parser_unexpected_error;
    }

    // [ CRC | sender | shrink(fromSubaccount) | bytes(shrink(fromSubaccount)) | EXTRA_BYTE(0x7F) ]
    uint8_t tmpArray[CRC_LENGTH + DFINITY_PRINCIPAL_LEN + DFINITY_SUBACCOUNT_LEN + 2] = {0};

    MEMCPY(tmpArray + CRC_LENGTH, sender, senderLen);

    int shrinkBytes = 0;
    if (fromSubaccount != NULL) {
        for (shrinkBytes = fromSubaccountLen - 1; shrinkBytes >= 0; shrinkBytes--) {
            if (*(fromSubaccount + shrinkBytes)) {
                break; // find the first non zero byte
            }
        }
        shrinkBytes++;

        if (shrinkBytes > 0) {
            if (shrinkBytes > DFINITY_SUBACCOUNT_LEN) return parser_unexpected_value;
            MEMCPY(tmpArray + CRC_LENGTH + DFINITY_PRINCIPAL_LEN, fromSubaccount, shrinkBytes);
            // Add fromSubaccount length after shrinked and EXTRA_BYTE
            tmpArray[CRC_LENGTH + DFINITY_PRINCIPAL_LEN + shrinkBytes] = (uint8_t) shrinkBytes;
            tmpArray[CRC_LENGTH + DFINITY_PRINCIPAL_LEN + shrinkBytes + 1] = SUBACCOUNT_EXTRA_BYTE;
        }
    }


    const uint8_t tmpArrayLen = shrinkBytes
                                ? (CRC_LENGTH + DFINITY_PRINCIPAL_LEN + (uint8_t) shrinkBytes + 2)
                                : (CRC_LENGTH + DFINITY_PRINCIPAL_LEN);

    char buffer[120] = {0};
    uint16_t bufferSize = sizeof(buffer);
    crypto_toTextual(tmpArray, tmpArrayLen, buffer, &bufferSize);

    return page_principal_with_delimiters(buffer, sizeof(buffer), outVal, outValLen, pageIdx, pageCount);
}

parser_error_t parser_printDelay(uint64_t value, char *buffer, uint16_t bufferSize) {
    MEMZERO(buffer, bufferSize);
    uint16_t index = 0;
    uint64_t years = value / ICP_YEAR_IN_SECONDS;
    if (years >= 1) {
        index += fpuint64_to_str(buffer, bufferSize, years, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end)
        MEMCPY(buffer + index, (char *) "y", 1);
        index += 1;
    }
    value %= ICP_YEAR_IN_SECONDS;

    uint64_t days = value / (uint64_t) (60 * 60 * 24);
    if (days > 0) {
        if (index > 0) {
            PARSER_ASSERT_OR_ERROR(index + 2 < bufferSize, parser_unexpected_buffer_end)
            MEMCPY(buffer + index, (char *) ", ", 2);
            index += 2;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, days, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end)
        MEMCPY(buffer + index, (char *) "d", 1);
        index += 1;
    }
    value %= (uint64_t) (60 * 60 * 24);

    uint64_t hours = value / (uint64_t) (60 * 60);
    if (hours > 0) {
        if (index > 0) {
            PARSER_ASSERT_OR_ERROR(index + 2 < bufferSize, parser_unexpected_buffer_end)
            MEMCPY(buffer + index, (char *) ", ", 2);
            index += 2;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, hours, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end)
        MEMCPY(buffer + index, (char *) "h", 1);
        index += 1;
    }
    value %= (uint64_t) (60 * 60);

    uint64_t minutes = value / (uint64_t) (60);
    if (minutes > 0) {
        if (index > 0) {
            PARSER_ASSERT_OR_ERROR(index + 2 < bufferSize, parser_unexpected_buffer_end)
            MEMCPY(buffer + index, (char *) ", ", 2);
            index += 2;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, minutes, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end)
        MEMCPY(buffer + index, (char *) "m", 1);
        index += 1;
    }
    value %= (uint64_t) (60);

    uint64_t seconds = value;
    if (seconds > 0) {
        if (index > 0) {
            PARSER_ASSERT_OR_ERROR(index + 2 < bufferSize, parser_unexpected_buffer_end)
            MEMCPY(buffer + index, (char *) ", ", 2);
            index += 2;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, seconds, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end)
        MEMCPY(buffer + index, (char *) "s", 1);
        index += 1;
    }

    buffer[index] = 0;
    return parser_ok;
}
