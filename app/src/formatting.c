/*******************************************************************************
*   (c) 2021 Zondax GmbH
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
#include "formatting.h"
#include "zxformat.h"

zxerr_t inplace_insert_char(char *s, uint16_t sMaxLen, uint16_t pos, char separator) {
    const size_t len = strlen(s);
    if (len >= sMaxLen) {
        return zxerr_buffer_too_small;
    }

    if (pos > len) {
        return zxerr_out_of_bounds;
    }

    MEMMOVE(s + pos + 1, s + pos, len - pos + 1);  // len-pos+1 because we copy zero terminator
    s[pos] = separator;

    return zxerr_ok;
}

zxerr_t number_inplace_thousands(char *s, uint16_t sMaxLen, char separator) {
    const size_t len = strlen(s);
    if (len > sMaxLen) {
        return zxerr_encoding_failed;
    }

    // find decimal point
    int32_t dec_point = -1;
    for (uint32_t i = 0; i < len && dec_point < 0; i++) {
        if (s[i] == '.') {
            dec_point = i;
        }
    }

    if (dec_point < 0) {
        dec_point = (uint16_t) len;
    }

    if (dec_point < 4) {
        return zxerr_ok;
    }

    const uint8_t numSep = (dec_point - 1) / 3;

    if (len + numSep >= sMaxLen) {
        return zxerr_buffer_too_small;
    }

    size_t pos = dec_point;

    while (pos > 3) {
        pos -= 3;
        CHECK_ZXERR(inplace_insert_char(s, sMaxLen, pos, separator));
    }

    return zxerr_ok;
}

zxerr_t formatICP(char *out, uint16_t outLen, uint64_t value) {
    MEMZERO(out, outLen);

    fpuint64_to_str(out, outLen, value, COIN_AMOUNT_DECIMAL_PLACES);
    number_inplace_trimming(out, COIN_AMOUNT_DECIMAL_NON_TRIMMED_PLACES);
    CHECK_ZXERR(number_inplace_thousands(out, outLen, COIN_AMOUNT_THOUSAND_SEPARATOR));

    return zxerr_ok;
}
