/*******************************************************************************
 *   (c) 2026 Zondax AG
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
#include <zxmacros.h>

#include <string>
#include <vector>

#include "coin.h"
#include "gtest/gtest.h"
#include "parser_print_helper.h"

namespace {

// A real principal, and a subaccount whose significant bytes run past the
// point the display used to stop at.
const char *PRINCIPAL_HEX = "29794883d3efb57cc835619ba5961941d7a11ac192735943b2c886e902";
const char *SUBACCOUNT_HEX = "d7e851652cd032ba5ed76b17f626aa47829f06e5235a0d580e96d3727729ea24";

// The same first 16 bytes, different after -- and chosen so the CRC32 shown
// beside the account agrees as well. CRC32 is affine, so given any prefix the
// last four bytes can be solved to hit a target checksum. Under a display that
// stopped at 16 bytes these two accounts were indistinguishable on screen,
// checksum included, while signing different destinations.
const char *SUBACCOUNT_CRC_COLLISION_HEX = "d7e851652cd032ba5ed76b17f626aa47deadbeefdeadbeefdeadbeef9c741bce";

// Render every page of an account and join them, the way the review shows it.
std::string renderAccount(const uint8_t *principal, uint16_t principalLen, const uint8_t *subaccount,
                          uint16_t subaccountLen) {
    char outVal[40] = {0};
    uint8_t pageCount = 0;
    std::string all;

    parser_error_t err = page_principal_with_subaccount(principal, principalLen, subaccount, subaccountLen, outVal,
                                                        sizeof(outVal), 0, &pageCount);
    EXPECT_EQ(err, parser_ok);
    EXPECT_GT(pageCount, 0);
    all += outVal;

    for (uint8_t page = 1; page < pageCount; page++) {
        memset(outVal, 0, sizeof(outVal));
        uint8_t ignored = 0;
        err = page_principal_with_subaccount(principal, principalLen, subaccount, subaccountLen, outVal, sizeof(outVal),
                                             page, &ignored);
        EXPECT_EQ(err, parser_ok);
        all += outVal;
    }

    return all;
}

// The property the display owes a signer: two accounts that are not the same
// must not read the same on screen. The renderer used to stop after 16 of the
// 32 subaccount bytes with no marker, so any pair differing only past that
// point produced identical text -- and the checksum shown alongside is a CRC32,
// which is affine and can be made to agree as well.
TEST(SubaccountDisplay, AccountsDifferingPastByte16RenderDifferently) {
    uint8_t principal[DFINITY_PRINCIPAL_LEN] = {0};
    ASSERT_EQ(parseHexString(principal, sizeof(principal), PRINCIPAL_HEX), DFINITY_PRINCIPAL_LEN);

    uint8_t subA[DFINITY_SUBACCOUNT_LEN] = {0};
    ASSERT_EQ(parseHexString(subA, sizeof(subA), SUBACCOUNT_HEX), DFINITY_SUBACCOUNT_LEN);

    // Not merely a different byte: this one also forces the CRC32 to match, so
    // the checksum cannot be what distinguishes them either.
    uint8_t subB[DFINITY_SUBACCOUNT_LEN] = {0};
    ASSERT_EQ(parseHexString(subB, sizeof(subB), SUBACCOUNT_CRC_COLLISION_HEX), DFINITY_SUBACCOUNT_LEN);

    ASSERT_EQ(memcmp(subA, subB, 16), 0) << "the two subaccounts must agree over the first 16 bytes";
    ASSERT_NE(memcmp(subA, subB, DFINITY_SUBACCOUNT_LEN), 0);

    const std::string renderedA = renderAccount(principal, sizeof(principal), subA, sizeof(subA));
    const std::string renderedB = renderAccount(principal, sizeof(principal), subB, sizeof(subB));

    EXPECT_NE(renderedA, renderedB) << "accounts differing past byte 16 rendered identically:\n"
                                    << "  A: " << renderedA << "\n  B: " << renderedB;
}

// Every significant byte of the subaccount must appear, so the value the user
// approves is the value that gets signed.
TEST(SubaccountDisplay, WholeSubaccountIsRendered) {
    uint8_t principal[DFINITY_PRINCIPAL_LEN] = {0};
    ASSERT_EQ(parseHexString(principal, sizeof(principal), PRINCIPAL_HEX), DFINITY_PRINCIPAL_LEN);

    uint8_t subaccount[DFINITY_SUBACCOUNT_LEN] = {0};
    ASSERT_EQ(parseHexString(subaccount, sizeof(subaccount), SUBACCOUNT_HEX), DFINITY_SUBACCOUNT_LEN);

    std::string rendered = renderAccount(principal, sizeof(principal), subaccount, sizeof(subaccount));

    // Drop the separators the formatter inserts for readability.
    std::string compact;
    for (char c : rendered) {
        if (c != ' ' && c != '.' && c != '-') {
            compact += c;
        }
    }

    std::string expectedHex(SUBACCOUNT_HEX);
    EXPECT_NE(compact.find(expectedHex), std::string::npos)
        << "the full subaccount is not present in the rendered account:\n  " << rendered;
}

}  // namespace
