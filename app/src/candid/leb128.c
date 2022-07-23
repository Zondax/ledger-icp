/*******************************************************************************
*   (c) 2022 Zondax AG
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

#include "leb128.h"

parser_error_t decompressLEB128(const uint8_t *input, uint16_t inputSize, uint64_t *v, uint16_t *bytesConsumed) {
    unsigned int i = 0;

    *bytesConsumed= 0;
    *v = 0;
    uint16_t shift = 0;
    while (i < 10u && i < inputSize) {
        uint64_t b = input[i] & 0x7fu;

        if (shift >= 63 && b > 1) {
            // This will overflow uint64_t
            break;
        }

        *v |= b << shift;

        if (!(input[i] & 0x80u)) {
            *bytesConsumed = i + 1;
            return parser_ok;
        }

        shift += 7;
        i++;
    }

    // exit because of overflowing outputSize
    *v = 0;
    return parser_unexpected_error;
}

parser_error_t decompressSLEB128(const uint8_t *input, uint16_t inputSize, int64_t *v, uint16_t *bytesConsumed) {
    unsigned int i = 0;

    *bytesConsumed= 0;
    *v = 0;
    uint16_t shift = 0;

    while (i < 10u && i < inputSize) {
        int64_t b = input[i] & 0x7fu;

        if (shift >= 63 && b > 1) {
            // This will overflow uint64_t
            break;
        }

        *v |= b << shift;
        shift += 7;

        if ((input[i] & 0x80u) == 0) {

            if (shift < inputSize * 8) {
                if (input[i] & 0x40) {
                    *v |= -(1 << shift);
                }
            }

            *bytesConsumed = i + 1;
            return parser_ok;
        }

        i++;
    }

    // exit because of overflowing outputSize
    *v = 0;
    return parser_unexpected_error;
}
