/*******************************************************************************
 *   (c) 2019 Zondax AG
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

#include <cstdint>
#include <vector>

#include "candid/leb128.h"
#include "crypto.h"
#include "gtest/gtest.h"

namespace {

typedef struct {
    uint64_t value;
    std::vector<uint8_t> expected;
    std::string name;
} LEB128TestCase;

class LEB128Encode : public ::testing::TestWithParam<LEB128TestCase> {};

// Encodings taken from the LEB128 definition the IC uses for ingress_expiry.
INSTANTIATE_TEST_SUITE_P(
    Values, LEB128Encode,
    ::testing::Values(
        // Zero is a single 0x00 byte, not an empty encoding.
        LEB128TestCase{0, {0x00}, "zero"}, LEB128TestCase{1, {0x01}, "one"},
        // Largest single-byte value, and the first that needs a continuation.
        LEB128TestCase{127, {0x7f}, "max_single_byte"}, LEB128TestCase{128, {0x80, 0x01}, "min_two_bytes"},
        LEB128TestCase{624485, {0xe5, 0x8e, 0x26}, "spec_example"},
        LEB128TestCase{UINT64_MAX, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, "u64_max"}),
    [](const ::testing::TestParamInfo<LEB128TestCase> &info) { return info.param.name; });

TEST_P(LEB128Encode, matchesExpectedBytes) {
    const auto &tc = GetParam();

    uint8_t buffer[16] = {0};
    uint16_t outLen = 0;

    ASSERT_EQ(compressLEB128(tc.value, sizeof(buffer), buffer, &outLen), zxerr_ok);
    ASSERT_EQ(outLen, tc.expected.size());
    EXPECT_EQ(std::vector<uint8_t>(buffer, buffer + outLen), tc.expected);
}

TEST_P(LEB128Encode, roundTripsThroughDecompress) {
    const auto &tc = GetParam();

    uint8_t buffer[16] = {0};
    uint16_t outLen = 0;
    ASSERT_EQ(compressLEB128(tc.value, sizeof(buffer), buffer, &outLen), zxerr_ok);

    uint64_t decoded = 0;
    uint16_t consumed = 0;
    ASSERT_EQ(decompressLEB128(buffer, outLen, &decoded, &consumed), parser_ok);
    EXPECT_EQ(decoded, tc.value);
    EXPECT_EQ(consumed, outLen);
}

TEST(LEB128Encode, zeroNeedsOneByteOfRoom) {
    uint8_t buffer[1] = {0xAA};
    uint16_t outLen = 0;

    // Zero still has to be written, so a zero-sized output is too small.
    EXPECT_EQ(compressLEB128(0, 0, buffer, &outLen), zxerr_buffer_too_small);

    ASSERT_EQ(compressLEB128(0, sizeof(buffer), buffer, &outLen), zxerr_ok);
    EXPECT_EQ(outLen, 1);
    EXPECT_EQ(buffer[0], 0x00);
}

TEST(LEB128Encode, rejectsUndersizedBuffer) {
    uint8_t buffer[2] = {0};
    uint16_t outLen = 0;

    // 128 needs two bytes; one is not enough.
    EXPECT_EQ(compressLEB128(128, 1, buffer, &outLen), zxerr_buffer_too_small);
    EXPECT_EQ(compressLEB128(UINT64_MAX, sizeof(buffer), buffer, &outLen), zxerr_buffer_too_small);
}

}  // namespace
