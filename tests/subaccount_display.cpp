/*******************************************************************************
 *   (c) 2018 - 2024 Zondax AG
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

#include <hexutils.h>
#include <zxformat.h>

#include <algorithm>
#include <string>

#include "coin.h"
#include "gtest/gtest.h"
#include "parser_print_helper.h"

namespace {
// Same value buffer the device UI hands to the parser, so the paging here
// matches what a user actually sees.
constexpr uint16_t VALUE_LEN = 37;

// Concatenate every page of an account so the assertions below are about the
// whole rendered identifier rather than whichever page it happens to land on.
std::string renderAccount(const uint8_t *principal, const uint8_t *subaccount) {
    std::string rendered;
    char page[VALUE_LEN];
    uint8_t pageCount = 1;

    for (uint8_t pageIdx = 0; pageIdx < pageCount; pageIdx++) {
        memset(page, 0, sizeof(page));
        const parser_error_t err = page_principal_with_subaccount(
            principal, DFINITY_PRINCIPAL_LEN, subaccount, DFINITY_SUBACCOUNT_LEN, page, VALUE_LEN, pageIdx, &pageCount);
        EXPECT_EQ(err, parser_ok) << "page " << static_cast<int>(pageIdx);
        if (err != parser_ok) {
            break;
        }
        rendered += page;
    }

    return rendered;
}

// Drop the spacing the renderer inserts so hex can be matched directly.
std::string strippedHex(std::string rendered) {
    rendered.erase(std::remove(rendered.begin(), rendered.end(), ' '), rendered.end());
    return rendered;
}

std::string toHex(const uint8_t *subaccount) {
    char hex[2 * DFINITY_SUBACCOUNT_LEN + 1] = {0};
    array_to_hexstr(hex, sizeof(hex), subaccount, DFINITY_SUBACCOUNT_LEN);
    return std::string(hex);
}

TEST(SubaccountDisplay, TrailingBytesAppearInTheHex) {
    uint8_t principal[DFINITY_PRINCIPAL_LEN] = {0};
    parseHexString(principal, sizeof(principal), "C2D8180272D6EA9B84B3E4FA72CDF714058912BFF8E6365EF55638A102");

    // Two accounts that agree on the first 16 bytes of the subaccount and
    // differ only at byte 20. Truncating the display to 16 bytes left the two
    // hex renderings identical, so a substituted destination differed from the
    // intended one only in the checksum - and CRC32 is cheap to collide.
    uint8_t subaccountA[DFINITY_SUBACCOUNT_LEN];
    memset(subaccountA, 0xAB, sizeof(subaccountA));
    uint8_t subaccountB[DFINITY_SUBACCOUNT_LEN];
    memcpy(subaccountB, subaccountA, sizeof(subaccountB));
    subaccountB[20] ^= 0xFF;

    const std::string hexA = strippedHex(renderAccount(principal, subaccountA));
    const std::string hexB = strippedHex(renderAccount(principal, subaccountB));

    EXPECT_NE(hexA.find(toHex(subaccountA)), std::string::npos);
    EXPECT_EQ(hexA.find(toHex(subaccountB)), std::string::npos);
    EXPECT_NE(hexB.find(toHex(subaccountB)), std::string::npos);
}

TEST(SubaccountDisplay, EverySubaccountByteIsRendered) {
    uint8_t principal[DFINITY_PRINCIPAL_LEN] = {0};
    parseHexString(principal, sizeof(principal), "C2D8180272D6EA9B84B3E4FA72CDF714058912BFF8E6365EF55638A102");

    uint8_t subaccount[DFINITY_SUBACCOUNT_LEN];
    for (uint8_t i = 0; i < sizeof(subaccount); i++) {
        // Distinct, non-zero bytes so none of them is dropped as a leading zero
        // and each one is identifiable in the hex output.
        subaccount[i] = static_cast<uint8_t>(0x10 + i);
    }

    const std::string rendered = strippedHex(renderAccount(principal, subaccount));

    EXPECT_NE(rendered.find(toHex(subaccount)), std::string::npos) << "full subaccount missing from rendering: " << rendered;
}
}  // namespace
