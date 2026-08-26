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

#include <parser_common.h>

#include <vector>

#include "candid/candid_helper.h"
#include "gtest/gtest.h"

namespace {

// Minimal LEB128 encoder, so the tests state the wire form directly.
std::vector<uint8_t> leb128(uint64_t value) {
    std::vector<uint8_t> out;
    do {
        uint8_t byte = value & 0x7Fu;
        value >>= 7;
        if (value) {
            byte |= 0x80u;
        }
        out.push_back(byte);
    } while (value);
    return out;
}

// A Candid vec's element count is LEB128, so counts from 128 up take more than
// one byte. Reading only the first byte both mis-read the count and left the
// parser one byte behind the encoder, so the elements were then walked from the
// wrong offset while the replica read the payload correctly.
TEST(CandidVecLength, DecodesMultiByteLengths) {
    struct {
        uint64_t value;
        size_t encodedLen;
    } cases[] = {
        {0, 1}, {1, 1}, {127, 1}, {128, 2}, {200, 2}, {255, 2},
    };

    for (const auto &c : cases) {
        auto encoded = leb128(c.value);
        ASSERT_EQ(encoded.size(), c.encodedLen) << "value " << c.value;

        // A trailing sentinel: if the reader consumes the wrong number of
        // bytes, the offset lands somewhere other than the end.
        encoded.push_back(0xAA);

        parser_context_t ctx = {};
        ctx.buffer = encoded.data();
        ctx.bufferLen = (uint16_t)encoded.size();
        ctx.offset = 0;

        uint8_t out = 0;
        ASSERT_EQ(readCandidVecLength(&ctx, &out), parser_ok) << "value " << c.value;
        EXPECT_EQ(out, c.value) << "value " << c.value;
        EXPECT_EQ(ctx.offset, c.encodedLen) << "offset must land past the whole length, value " << c.value;
        EXPECT_EQ(ctx.buffer[ctx.offset], 0xAA) << "next byte must be the element data, value " << c.value;
    }
}

// A count that will not fit the field it is stored in is refused rather than
// truncated: a transaction whose elements cannot all be counted cannot be
// displayed honestly either.
TEST(CandidVecLength, RejectsLengthsThatDoNotFit) {
    for (uint64_t value : {(uint64_t)256, (uint64_t)1000, (uint64_t)70000}) {
        auto encoded = leb128(value);

        parser_context_t ctx = {};
        ctx.buffer = encoded.data();
        ctx.bufferLen = (uint16_t)encoded.size();
        ctx.offset = 0;

        uint8_t out = 0;
        EXPECT_EQ(readCandidVecLength(&ctx, &out), parser_value_out_of_range) << "value " << value;
    }
}

TEST(CandidVecLength, RejectsTruncatedLength) {
    // A continuation bit with nothing following it.
    std::vector<uint8_t> encoded = {0x80};

    parser_context_t ctx = {};
    ctx.buffer = encoded.data();
    ctx.bufferLen = (uint16_t)encoded.size();
    ctx.offset = 0;

    uint8_t out = 0;
    EXPECT_NE(readCandidVecLength(&ctx, &out), parser_ok);
}

}  // namespace
