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
#include <cstring>
#include <cstdint>

zxerr_t crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    const char *tmp = "0410d34980a51af89d3331ad5fa80fe30d8868ad87526460b3b3e15596ee58e812422987d8589ba61098264df5bb9c2d3ff6fe061746b4b31a44ec26636632b835";
    parseHexString(pubKey, pubKeyLen, tmp);

    return zxerr_ok;
}

namespace {
    TEST(SubaccountTests, AddressesTest) {
        uint8_t inBuffer[1000];
        uint8_t principal[29];
        const char *principals[3] = {
                "C2D8180272D6EA9B84B3E4FA72CDF714058912BFF8E6365EF55638A102",
                "45717A3A0E68FCEEF546AC77BAC551754B48DBB1FCCFA180673030B602",
                "7BDD7F75EEA6FCF58001E0DFB7D718B9E8F2C3B01E1CCEC9AB305AAD02",
        };

        const char *accounts[3] = {
                "53d20dbdcf47908822c97fc36875eca3f4df19d55cb7693f78d3392a0835d9c1",
                "62cea813fc49dcdbd187bd35200f2876bee1ec34c109823dde326bcb4c63936b",
                "382ab02556066a4bf76fbec8c9ac9c6b512869b72dc6159a930cb56e7b90d0e5",
        };

        uint8_t subaccount[32];
        uint8_t address[32];

        for (int i = 0; i < 3; i++) {
            parseHexString(principal, sizeof(principal), principals[i]);
            MEMZERO(subaccount, sizeof(subaccount));
            MEMZERO(address, sizeof(address));

            zxerr_t err = crypto_principalToSubaccount(principal, sizeof(principal), subaccount, sizeof(subaccount),
                                                       address, sizeof(address));
            EXPECT_EQ(err, zxerr_ok);

            parseHexString(inBuffer, sizeof(inBuffer), accounts[i]);
            for (int i = 0; i < 32; i++) {
                EXPECT_EQ(inBuffer[i], address[i]);
            }

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

        crypto_computePrincipal(inBuffer, addr);

        const char *tmp2 = "b93ea0acd43afb38c85f3d9998cc8aa118a3916339e51401b460234402";
        parseHexString(inBuffer, sizeof(inBuffer), tmp2);
        for (int i = 0; i < 29; i++) {
            EXPECT_EQ(inBuffer[i], addr[i]);
        }

        char addressText[100];
        uint16_t len = sizeof(addressText);
        MEMZERO(addressText, 100);
        EXPECT_EQ(crypto_principalToTextual(addr, sizeof(addr), addressText, &len), zxerr_ok);
        EXPECT_STREQ((const char *) addressText, "di6pv55zh2qkzvb27m4mqxz5tgmmzcvbdcrzcyzz4ukadndaencae");
    }

    TEST(AddressToStringTests, AddrToTextSplitting1) {
        const char *testInput = "di6pv55zh2qkzvb27m4mqxz5tgmmzcvbdcrzcyzz4ukadndaencae";
        char outBuffer[200];

        addr_to_textual(outBuffer, sizeof(outBuffer), testInput, strlen(testInput));
        EXPECT_STREQ((const char *) outBuffer, "di6pv-55zh2-qkzvb-27m4m-qxz5t-gmmzc-vbdcr-zcyzz-4ukad-ndaen-cae");
    }

    zxerr_t addr_getblock(const char *inS, uint16_t inLen, uint8_t index, char *outS, uint8_t outChunkLen) {
        MEMZERO(outS, outChunkLen);
        const uint16_t offset = index * outChunkLen;

        if (inLen < offset) {
            return zxerr_buffer_too_small;
        }

        const uint16_t size = inLen - offset < outChunkLen ? inLen - offset : outChunkLen;

        MEMCPY((void *) outS, (const void *) (inS + offset), size);
        return zxerr_ok;
    }

    TEST(AddressToStringTests, AddrToTextSplitting2) {
        const char *testInput = "di6pv55zh2qkzvb27m4mqxz5tgmmzcvbdcrzcyzz4ukadndaencae";
        char outBuffer[200];
        MEMZERO(outBuffer,sizeof(outBuffer));

        addr_getblock(testInput, strlen(testInput), 1, outBuffer, 5);
        printf("%s\n", outBuffer);
        EXPECT_STREQ((const char *) outBuffer, "55zh2");

        addr_getblock(testInput, strlen(testInput), 0, outBuffer, 5);
        printf("%s\n", outBuffer);
        EXPECT_STREQ((const char *) outBuffer, "di6pv");

        addr_getblock(testInput, strlen(testInput), 10, outBuffer, 5);
        printf("%s\n", outBuffer);
        EXPECT_STREQ((const char *) outBuffer, "cae");
    }

    TEST(AddressToStringTests, StakeAccount) {
        uint8_t inBuffer[100];
        const char *tmp = "EF9E5D18E3B90E0B388A988441C39E95F006C85CA2D5D9023C30D30A02";
        size_t len = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        char addressText[100];
        uint16_t lenT = sizeof(addressText);
        MEMZERO(addressText, 100);
        EXPECT_EQ(crypto_principalToTextual(inBuffer, 29, addressText, &lenT), zxerr_ok);
        EXPECT_STREQ((const char *) addressText, "fzy62xpptzorry5zbyftrcuyqra4hhuv6admqxfc2xmqepbq2mfae");

        uint8_t memo[8] = {0x00, 0xf4, 0x1d, 0x14, 0x5f, 0xfe, 0x95, 0x7f};

        uint8_t address[32];
        zxerr_t err = crypto_principalToStakeAccount(inBuffer, len, memo, address, sizeof(address));

        char outBuffer[300];
        array_to_hexstr(outBuffer, sizeof(outBuffer),address, 32);
        printf("%s\n", outBuffer);
        EXPECT_EQ(err, zxerr_ok);
    }
}
