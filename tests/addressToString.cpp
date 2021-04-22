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
#include "crypto.h"

#include <stdint.h>

namespace {
    TEST(SubaccountTests, AddressesTest) {
        uint8_t inBuffer[1000];
        uint8_t principal[29];
        const char *tmp = "C2D8180272D6EA9B84B3E4FA72CDF714058912BFF8E6365EF55638A102";
        parseHexString(principal, sizeof(principal), tmp);

        uint8_t subaccount[32];
        MEMZERO(subaccount,sizeof(subaccount));

        uint8_t address[32];
        MEMZERO(address,sizeof(address));

        zxerr_t err = crypto_principalToSubaccount(principal, sizeof(principal), subaccount, sizeof(subaccount), address, sizeof(address));

        EXPECT_EQ(err, zxerr_ok);

        const char *tmp2 = "53d20dbdcf47908822c97fc36875eca3f4df19d55cb7693f78d3392a0835d9c1";
        parseHexString(inBuffer, sizeof(inBuffer), tmp2);
        for (int i = 0; i < 32; i++) {
            EXPECT_EQ(inBuffer[i], address[i]);
        }
    }

    TEST(AddressToStringTests, CRC32) {
        uint8_t inBuffer[100];
        const char *tmp = "a275407a1070096ee5d8bd00d711a4c7904ca28fbbe592dc68d77d4d02";
        parseHexString(inBuffer, sizeof(inBuffer), tmp);

        uint32_t crc = 0;
        crc32_small(inBuffer, 29, &crc);
        EXPECT_EQ(crc, 768128161);
    }

    TEST(AddressToStringTests, AddrToText) {
        uint8_t inBuffer[100];
        const char *tmp = "047060f720298ffa0f48d9606abdb013bc82f4ff269f9adc3e7226391af3fad8b30fd6a30deb81d5b4f9e142971085d0ae15b8e222d85af1e17438e630d09b7ef4";
        parseHexString(inBuffer, sizeof(inBuffer), tmp);

        uint8_t addr[29];

        crypto_computeAddress(inBuffer, addr);

        const char *tmp2 = "b93ea0acd43afb38c85f3d9998cc8aa118a3916339e51401b460234402";
        parseHexString(inBuffer, sizeof(inBuffer), tmp2);
        for (int i = 0; i < 29; i++) {
            EXPECT_EQ(inBuffer[i], addr[i]);
        }

        MEMZERO(inBuffer, 100);
        uint16_t len = 0;
        crypto_principalToTextual(addr, sizeof(addr), inBuffer, &len);
        EXPECT_STREQ((const char *) inBuffer, "di6pv55zh2qkzvb27m4mqxz5tgmmzcvbdcrzcyzz4ukadndaencae");
    }

}
