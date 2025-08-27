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

#include "base32.h"
#include "formatting.h"
#include "zxformat.h"

// 365.25 * 24*60*60 = 31557600
#define ICP_MINUTE_IN_SECONDS (uint64_t)(60)
#define ICP_HOUR_IN_SECONDS (uint64_t)(ICP_MINUTE_IN_SECONDS * 60)
#define ICP_DAY_IN_SECONDS (uint64_t)(ICP_HOUR_IN_SECONDS * 24)
#define ICP_YEAR_IN_SECONDS (uint64_t)(ICP_DAY_IN_SECONDS * 365.25)
#define MAX_OUTPUT_LEN 35

#if defined(TARGET_STAX) || defined(TARGET_FLEX)
#include "view_internal.h"
const uint8_t LINES_PER_PAGE = MAX_LINES_PER_PAGE_REVIEW;
static const char SEPARATOR = 0x0a;  // newline
#elif defined(TARGET_NANOS2) || defined(TARGET_NANOX)
const uint8_t LINES_PER_PAGE = 3;
static const char SEPARATOR = 0x20;  // space
#else
const uint8_t LINES_PER_PAGE = 2;
static const char SEPARATOR = 0x20;  // space
#endif

parser_error_t format_principal_with_delimiters(const char *input, const uint16_t inputLen, char *output,
                                                const uint16_t outputLen) {
    const uint8_t CHARS_PER_CHUNK = 5;

    if (outputLen < MAX_OUTPUT_LEN) {
        return parser_unexpected_buffer_end;
    }

    const size_t inputStrLen = strnlen(input, inputLen);
    size_t outPos = 0;  // Track position in output buffer explicitly

    for (size_t idx = 0; idx * CHARS_PER_CHUNK < inputStrLen; idx++) {
        // Add separator between groups of 3 chunks
        if (idx % 3 == 0 && idx != 0) {
            output[outPos++] = '-';  // Using SEPARATOR or '-' directly
        }

        // Copy the chunk
        size_t inPos = idx * CHARS_PER_CHUNK;
        for (int i = 0; i < CHARS_PER_CHUNK && inPos + i < inputStrLen; i++) {
            output[outPos++] = input[inPos + i];
        }

        // Add dash unless it's the last chunk or after every 3rd chunk
        const bool isLastChunk = ((idx + 1) * CHARS_PER_CHUNK >= inputStrLen);
        const bool skipDash = (idx % 3 == 2);
        if (!skipDash && !isLastChunk) {
            output[outPos++] = '-';
        }
    }

    output[outPos] = '\0';
    return parser_ok;
}

parser_error_t page_textual_with_delimiters(const char *input, const uint16_t inputLen, char *output,
                                            const uint16_t outputLen, const uint8_t pageIdx, uint8_t *pageCount) {
    const uint8_t CHARS_PER_CHUNK = 5;
    const uint8_t CHARS_PER_PAGE = 15 * LINES_PER_PAGE;
    const uint8_t CHUNKS_PER_PAGE = 3 * LINES_PER_PAGE;

    if (outputLen < MAX_OUTPUT_LEN) {
        return parser_unexpected_buffer_end;
    }

    const size_t inputStrLen = strnlen(input, inputLen);  // not including null terminator
    *pageCount = (uint8_t)(inputStrLen / CHARS_PER_PAGE) + ((inputStrLen % CHARS_PER_PAGE) ? 1 : 0);
    if (pageIdx >= *pageCount) {
        return parser_display_idx_out_of_range;
    }

    char *output_start = output;
    input += pageIdx * CHARS_PER_PAGE;
    for (uint8_t idx = 0; idx < CHUNKS_PER_PAGE; idx++) {
        if (idx % 3 == 0 && idx != 0) {
            size_t remaining_output = outputLen - (output - output_start);
            if (remaining_output < 2) {
                return parser_unexpected_buffer_end;
            }
            snprintf(output, remaining_output, "%c", SEPARATOR);
            output += 1;
        }

        const size_t remainingChars = inputStrLen - (pageIdx * CHARS_PER_PAGE) - (idx * CHARS_PER_CHUNK);
        const bool endOfInput = remainingChars <= 5;  // strnlen does not count null terminator
        const bool skipDash = (idx % 3 == 2);

        size_t remaining_output = outputLen - (output - output_start);
        if (skipDash || endOfInput) {
            if (remaining_output < CHARS_PER_CHUNK + 1) {
                return parser_unexpected_buffer_end;
            }
            snprintf(output, remaining_output, "%.*s", CHARS_PER_CHUNK, input);
        } else {
            if (remaining_output < CHARS_PER_CHUNK + 2) {
                return parser_unexpected_buffer_end;
            }
            snprintf(output, remaining_output, "%.*s-", CHARS_PER_CHUNK, input);
        }

        if (endOfInput) {
            break;
        }

        input += CHARS_PER_CHUNK;
        output += CHARS_PER_CHUNK + (skipDash ? 0 : 1);
    }

    return parser_ok;
}

parser_error_t page_hexstring_with_delimiters(const uint8_t *input, const uint64_t inputLen, char *output,
                                              const uint16_t outputLen, const uint8_t pageIdx, uint8_t *pageCount) {
    const uint8_t CHARS_PER_CHUNK = 8;
    const uint8_t CHARS_PER_PAGE = 16 * LINES_PER_PAGE;
    const uint8_t CHUNKS_PER_PAGE = 2 * LINES_PER_PAGE;

    if (outputLen < MAX_OUTPUT_LEN) {
        return parser_unexpected_buffer_end;
    }

    char buffer[PRINT_BUFFER_SMALL_LEN] = {0};
    uint16_t bufferLen = sizeof(buffer);
    const uint16_t inputStrLen = 2 * (uint16_t)inputLen;  // 2 chars per byte without null terminator
    if (bufferLen < inputStrLen + 1) {                    // with null terminator
        return parser_unexpected_buffer_end;
    }
    if (inputLen > UINT16_MAX) {
        return parser_unexpected_value;
    }
    array_to_hexstr(buffer, bufferLen, input, (uint16_t)inputLen);

    *pageCount = (uint8_t)(inputStrLen / CHARS_PER_PAGE) + ((inputStrLen % CHARS_PER_PAGE) ? 1 : 0);
    if (pageIdx >= *pageCount) {
        return parser_display_idx_out_of_range;
    }

    char *output_start = output;
    uint16_t bufferIdx = pageIdx * CHARS_PER_PAGE;
    for (uint8_t idx = 0; idx < CHUNKS_PER_PAGE; idx++, bufferIdx += CHARS_PER_CHUNK) {
        if (idx % 2 == 0 && idx != 0) {
            size_t remaining_output = outputLen - (output - output_start);
            if (remaining_output < 2) {
                return parser_unexpected_buffer_end;
            }
            snprintf(output, remaining_output, "%c", SEPARATOR);
            output += 1;
        }

        const uint16_t remainingChars = inputStrLen - (pageIdx * CHARS_PER_PAGE) - (idx * CHARS_PER_CHUNK);
        const bool endOfInput = remainingChars <= 8;  // without null terminator
        const bool skipSpace = (idx % 2 == 1);

        size_t remaining_output = outputLen - (output - output_start);
        if (skipSpace || endOfInput) {
            if (remaining_output < CHARS_PER_CHUNK + 1) {
                return parser_unexpected_buffer_end;
            }
            snprintf(output, remaining_output, "%.*s", CHARS_PER_CHUNK, &buffer[bufferIdx]);
        } else {
            if (remaining_output < CHARS_PER_CHUNK + 2) {
                return parser_unexpected_buffer_end;
            }
            snprintf(output, remaining_output, "%.*s ", CHARS_PER_CHUNK, &buffer[bufferIdx]);
        }

        if (endOfInput) {
            break;
        }

        output += CHARS_PER_CHUNK + (skipSpace ? 0 : 1);
    }

    return parser_ok;
}

parser_error_t page_principal_with_subaccount(const uint8_t *sender, uint16_t senderLen, const uint8_t *fromSubaccount,
                                              uint16_t fromSubaccountLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                              uint8_t *pageCount) {
    if (sender == NULL || senderLen > DFINITY_PRINCIPAL_LEN ||
        (fromSubaccount != NULL && fromSubaccountLen != DFINITY_SUBACCOUNT_LEN)) {
        return parser_unexpected_error;
    }

    uint8_t initialSubaccZerosLen = DFINITY_SUBACCOUNT_LEN;
    if (fromSubaccount != NULL) {
        // we checked that length is exactly DFINITY_SUBACCOUNT_LEN right above
        for (uint8_t i = 0; i < DFINITY_SUBACCOUNT_LEN; i++) {
            if (*(fromSubaccount + i)) {
                initialSubaccZerosLen = i;
                break;  // find the first non zero byte
            }
        }
    }

    if (fromSubaccount == NULL || initialSubaccZerosLen == fromSubaccountLen) {  // this is both not having subaccount or
                                                                                 // empty subaccount
        return print_principal(sender, senderLen, outVal, outValLen, pageIdx, pageCount);
    }

    const uint8_t *subaccTrim = fromSubaccount + initialSubaccZerosLen;
    const uint16_t subaccTrimLen = fromSubaccountLen - initialSubaccZerosLen;

    // from here assume that we have subaccount with certain length
    char text[150] = {0};  // total text will be at max 144 chars
    char *text_ptr = text;

    // print principal
    uint16_t principalLen = sizeof(text);
    zxerr_t err = zxerr_unknown;

    err = crypto_principalToTextual(sender, senderLen, text_ptr, &principalLen);

    // maximum length without separators is 53
    if (err != zxerr_ok || principalLen > 53) {
        return parser_unexpected_error;
    }

    // every 5 chars there's a separator, and last block has no separator after it
    const uint8_t principalTextLen = (uint8_t)(principalLen + principalLen / 5 - (principalLen % 5 ? 0 : 1));

    for (uint8_t i = 5; i < principalTextLen; i += 6) {
        // two blocks separated with dash, 3rd with SEPARATOR
        if ((i + 1) % 18 == 0) {
            err = inplace_insert_char(text_ptr, sizeof(text), i,
                                      SEPARATOR);  // line break
        } else {
            err = inplace_insert_char(text_ptr, sizeof(text), i, '-');
        }
        if (err != zxerr_ok) {
            return parser_unexpected_error;
        }
    }

    // we are sure it's going to be up to 63 (53 + 10)
    principalLen = (uint16_t)strnlen(text, sizeof(text));
    if (principalLen > 63) {
        return parser_unexpected_value;
    }

    *(text_ptr + principalLen) = '-';
    text_ptr += principalLen + 1;

    // calculate crc32 checksum
    uint8_t crc_array[4] = {0};
    char crc_text[10] = {0};
    uint8_t tmpArray[DFINITY_PRINCIPAL_LEN + DFINITY_SUBACCOUNT_LEN + 1] = {0};
    MEMCPY(tmpArray, sender, senderLen);

    // crc is computed with full subaccount with all zeros at the beginning
    MEMCPY(tmpArray + senderLen, fromSubaccount, fromSubaccountLen);
    uint32_t crc = 0;

    crc32_small(tmpArray, senderLen + fromSubaccountLen, &crc);
    crc_array[0] = (uint8_t)((crc & 0xFF000000) >> 24);
    crc_array[1] = (uint8_t)((crc & 0x00FF0000) >> 16);
    crc_array[2] = (uint8_t)((crc & 0x0000FF00) >> 8);
    crc_array[3] = (uint8_t)((crc & 0x000000FF) >> 0);

    uint8_t crcLen = (uint8_t)base32_encode(crc_array, 4, crc_text, sizeof(crc_text));
    if (crcLen == 0) {
        return parser_unexpected_error;
    }

    // print checksum
    MEMCPY(text_ptr, crc_text, crcLen);
    *(text_ptr + crcLen) = SEPARATOR;
    text_ptr += crcLen + 1;

#if !defined(TARGET_STAX) && !defined(TARGET_FLEX)  // needed if crc32 length is < 7
    for (uint8_t i = crcLen; i < 7; i++) {
        *text_ptr = ' ';
        text_ptr++;
    }
#endif
    crcLen = 8;  // also counting separator

    *text_ptr = '.';
    text_ptr++;

    uint16_t bytesToShow = subaccTrimLen;
    if (subaccTrimLen > DFINITY_SUBACCOUNT_MAX_BYTES_TO_TEXTUAL) {
        bytesToShow = DFINITY_SUBACCOUNT_MAX_BYTES_TO_TEXTUAL;
    }

    array_to_hexstr(text_ptr, (uint16_t)sizeof(text) - principalLen - crcLen, subaccTrim, bytesToShow);

    const uint8_t subaccountTextLen = 2 * bytesToShow + bytesToShow / 4 - 1 + (bytesToShow % 4 ? 1 : 0);

    const uint8_t FIRST_BLOCK = 7;
    const uint8_t OTHER_BLOCKS = 8;

    if (subaccountTextLen >= FIRST_BLOCK) {
        for (uint8_t i = 0, pos = FIRST_BLOCK; i < 3 && pos < subaccountTextLen; i++) {
            err = inplace_insert_char(text_ptr, sizeof(text), pos, ' ');
            if (err != zxerr_ok) {
                return parser_unexpected_error;
            }
            // +1 for the space we just inserted
            pos += OTHER_BLOCKS + 1;
        }
    }

    uint8_t finalStrLen = (uint8_t)strnlen(text, sizeof(text));
    // [principal (<=64 chars) | crc32 (8 chars) | subaccount (<=71 chars) + 1
    // ('.')]
    if (finalStrLen > 144) {
        return parser_unexpected_error;
    }

    // now let's print
    // we have blocks of 18 chars per line
    const uint8_t CHARS_PER_PAGE = 18 * LINES_PER_PAGE;
    *pageCount = finalStrLen / CHARS_PER_PAGE + (finalStrLen % CHARS_PER_PAGE ? 1 : 0);
    const char *textToPrint = text + pageIdx * CHARS_PER_PAGE;

    // we don't want to print last separator for each page
    if (CHARS_PER_PAGE > outValLen) {
        return parser_unexpected_error;
    }
    snprintf(outVal, CHARS_PER_PAGE, "%.*s", CHARS_PER_PAGE - 1, textToPrint);

    return parser_ok;
}

parser_error_t print_u64(uint64_t value, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    char buffer[PRINT_NUMBER_BUFFER_LEN] = {0};
    fpuint64_to_str(buffer, sizeof(buffer), value, 0);
    pageString(outVal, outValLen, buffer, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t print_ICP(uint64_t value, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    char buffer[PRINT_BUFFER_MEDIUM_LEN] = {0};
    zxerr_t err = formatICP(buffer, sizeof(buffer), value);
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    pageString(outVal, outValLen, buffer, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t print_Amount(uint64_t value, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount,
                            uint8_t decimals) {
    char buffer[PRINT_BUFFER_MEDIUM_LEN] = {0};
    zxerr_t err = formatValue(buffer, sizeof(buffer), value, decimals);
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    pageString(outVal, outValLen, buffer, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t print_principal(const uint8_t *data, uint16_t len, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                               uint8_t *pageCount) {
    char buffer[PRINT_BUFFER_SMALL_LEN] = {0};
    uint16_t outLen = sizeof(buffer);
    zxerr_t err = crypto_principalToTextual(data, len, (char *)buffer, &outLen);
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    return page_textual_with_delimiters(buffer, outLen, outVal, outValLen, pageIdx, pageCount);
}

parser_error_t parser_printDelay(uint64_t value, char *buffer, uint16_t bufferSize) {
    MEMZERO(buffer, bufferSize);
    uint16_t index = 0;
    uint64_t years = value / ICP_YEAR_IN_SECONDS;
    if (years >= 1) {
        index += fpuint64_to_str(buffer, bufferSize, years, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end)
        MEMCPY(buffer + index, (char *)"y", 1);
        index += 1;
    }
    value %= ICP_YEAR_IN_SECONDS;

    uint64_t days = value / ICP_DAY_IN_SECONDS;
    if (days > 0) {
        if (index > 0) {
            PARSER_ASSERT_OR_ERROR(index + 2 < bufferSize, parser_unexpected_buffer_end)
            MEMCPY(buffer + index, (char *)", ", 2);
            index += 2;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, days, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end)
        MEMCPY(buffer + index, (char *)"d", 1);
        index += 1;
    }
    value %= ICP_DAY_IN_SECONDS;

    uint64_t hours = value / ICP_HOUR_IN_SECONDS;
    if (hours > 0) {
        if (index > 0) {
            PARSER_ASSERT_OR_ERROR(index + 2 < bufferSize, parser_unexpected_buffer_end)
            MEMCPY(buffer + index, (char *)", ", 2);
            index += 2;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, hours, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end)
        MEMCPY(buffer + index, (char *)"h", 1);
        index += 1;
    }
    value %= (uint64_t)(60 * 60);

    uint64_t minutes = value / (uint64_t)(60);
    if (minutes > 0) {
        if (index > 0) {
            PARSER_ASSERT_OR_ERROR(index + 2 < bufferSize, parser_unexpected_buffer_end)
            MEMCPY(buffer + index, (char *)", ", 2);
            index += 2;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, minutes, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end)
        MEMCPY(buffer + index, (char *)"m", 1);
        index += 1;
    }
    value %= (uint64_t)(60);

    uint64_t seconds = value;
    if (seconds > 0) {
        if (index > 0) {
            PARSER_ASSERT_OR_ERROR(index + 2 < bufferSize, parser_unexpected_buffer_end)
            MEMCPY(buffer + index, (char *)", ", 2);
            index += 2;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, seconds, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end)
        MEMCPY(buffer + index, (char *)"s", 1);
        index += 1;
    }

    buffer[index] = 0;
    return parser_ok;
}

parser_error_t format_principal(const uint8_t *data, uint16_t len, char *outVal, uint16_t outValLen) {
    if (outValLen < MAX_OUTPUT_LEN) {
        return parser_unexpected_buffer_end;
    }

    // First convert to textual representation
    char buffer[PRINT_BUFFER_SMALL_LEN] = {'\0'};
    uint16_t outLen = sizeof(buffer);
    zxerr_t err = crypto_principalToTextual(data, len, buffer, &outLen);
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    // Remove any newlines that might have been added
    char *newline = strchr(buffer, '\n');
    if (newline != NULL) {
        *newline = '\0';
        outLen = (uint16_t)(newline - buffer);
    }

    // Now format with delimiters
    return format_principal_with_delimiters(buffer, outLen, outVal, outValLen);
}
