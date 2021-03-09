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

#include "gtest/gtest.h"

#include <string>
#include <hexutils.h>
#include <zxmacros.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

uint32_t crc32_for_byte(uint8_t rbyte) {
    uint32_t r = (uint32_t)(rbyte) & (uint32_t)0x000000FF;
    for(int j = 0; j < 8; ++j)
        r = (r & 1? 0: (uint32_t)0xEDB88320L) ^ r >> 1;
    return r ^ (uint32_t)0xFF000000L;
}

void crc32_small(const void *data, size_t n_bytes, uint32_t* crc) {
    for(size_t i = 0; i < n_bytes; ++i) {
        uint8_t index = ((uint8_t) * crc ^ ((uint8_t *) data)[i]);
        uint32_t crcbyte = crc32_for_byte(index);
        *crc = crcbyte ^ *crc >> 8;
    }
}

namespace {
    TEST(AddressToStringTests, CRC32) {
        uint8_t inBuffer[100];
        const char *tmp = "a275407a1070096ee5d8bd00d711a4c7904ca28fbbe592dc68d77d4d02";
        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        uint32_t crc = 0;
        crc32_small(inBuffer, 29, &crc);
        EXPECT_EQ(crc, 768128161);
    }

}