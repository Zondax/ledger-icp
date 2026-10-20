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
#include <parser.h>

#include <array>
#include <cstring>
#include <functional>
#include <vector>

#include "candid/candid_helper.h"
#include "common.h"
#include "gtest/gtest.h"
#include "parser_impl.h"

namespace {

class NeuronSelectorRegressions : public ::testing::Test {
   protected:
    parser_context_t ctx{};
    std::array<uint8_t, 10000> buffer{};

    void SetUp() override {
        const auto cases = GetJsonTestCases("disburse-nns-neuron-maturity.json");
        ASSERT_FALSE(cases.empty());

        std::memset(&parser_tx_obj, 0, sizeof(parser_tx_obj));
        const auto buffer_len = parseHexString(buffer.data(), buffer.size(), cases.front().blob.c_str());
        ASSERT_EQ(parser_parse(&ctx, buffer.data(), buffer_len), parser_ok);
        parser_tx_obj.special_transfer_type = normal_transaction;
        ASSERT_EQ(parser_validate(&ctx), parser_ok);
    }
};

TEST_F(NeuronSelectorRegressions, DisplaysTheAlternateNeuronSelector) {
    constexpr uint64_t alternate_neuron_id = 424242424242ULL;
    auto &fields = parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    fields.has_id = 0;
    fields.id.id = 0;
    fields.has_neuron_id_or_subaccount = 1;
    fields.neuron_id_or_subaccount.which = 1;
    fields.neuron_id_or_subaccount.neuronId.id = alternate_neuron_id;

    ASSERT_EQ(parser_validate(&ctx), parser_ok);

    char key[40] = {0};
    char value[40] = {0};
    uint8_t page_count = 0;
    ASSERT_EQ(parser_getItem(&ctx, 1, key, sizeof(key), value, sizeof(value), 0, &page_count), parser_ok);
    EXPECT_STREQ(key, "Neuron ID");
    EXPECT_STREQ(value, "424242424242");
}

TEST_F(NeuronSelectorRegressions, RejectsTwoNeuronSelectors) {
    auto &fields = parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    ASSERT_TRUE(fields.has_id);
    fields.has_neuron_id_or_subaccount = 1;
    fields.neuron_id_or_subaccount.which = 1;
    fields.neuron_id_or_subaccount.neuronId.id = fields.id.id + 1;

    EXPECT_EQ(parser_validate(&ctx), parser_unexpected_error);
}

// Candid vec lengths are LEB128. They were read as a single byte, so a length
// of 128 or more took its first byte alone and parsed the rest as elements.
TEST(CandidVecLength, ReadsTheWholeLeb128Length) {
    const struct {
        std::vector<uint8_t> bytes;
        parser_error_t err;
        uint8_t len;
        uint16_t consumed;
    } cases[] = {
        {{0x00}, parser_ok, 0, 1},
        {{0x05}, parser_ok, 5, 1},
        {{0x7F}, parser_ok, 127, 1},
        {{0x80, 0x01}, parser_ok, 128, 2},
        {{0xFD, 0x01}, parser_ok, 253, 2},
        {{0xFF, 0x01}, parser_ok, 255, 2},
        // Longer lists are refused rather than wrapped into a uint8_t count.
        {{0x80, 0x02}, parser_value_out_of_range, 0, 0},
        {{0xFF, 0xFF, 0x03}, parser_value_out_of_range, 0, 0},
    };

    for (const auto &c : cases) {
        parser_context_t ctx{};
        ctx.buffer = c.bytes.data();
        ctx.bufferLen = static_cast<uint16_t>(c.bytes.size());

        uint8_t len = 0xAA;
        ASSERT_EQ(readCandidVecLength(&ctx, &len), c.err);
        if (c.err == parser_ok) {
            EXPECT_EQ(len, c.len);
            EXPECT_EQ(ctx.offset, c.consumed);
        }
    }

    // A length cut off mid-way is not a length.
    const uint8_t truncated[] = {0x80};
    parser_context_t ctx{};
    ctx.buffer = truncated;
    ctx.bufferLen = sizeof(truncated);
    uint8_t len = 0;
    EXPECT_NE(readCandidVecLength(&ctx, &len), parser_ok);
}

// The item counts built from those lengths were summed in uint8_t. A long
// enough list wrapped the count to a small number, and the review ended before
// the items past the wrap - for an SNS permission grant, the grantee - were
// ever shown, while the device still signed the whole request.
class ItemCountRegressions : public ::testing::Test {
   protected:
    parser_context_t ctx{};
    std::array<uint8_t, 10000> buffer{};

    // Parse the first case in `file` that `matches` and that validates.
    bool LoadFirst(const char *file, const std::function<bool()> &matches) {
        for (const auto &tc : GetJsonTestCases(file)) {
            std::memset(&parser_tx_obj, 0, sizeof(parser_tx_obj));
            const auto len = parseHexString(buffer.data(), buffer.size(), tc.blob.c_str());
            if (parser_parse(&ctx, buffer.data(), len) != parser_ok) {
                continue;
            }
            parser_tx_obj.special_transfer_type = normal_transaction;
            if (matches() && parser_validate(&ctx) == parser_ok) {
                return true;
            }
        }
        return false;
    }

    static bool IsManageNeuron(manageNeuron_e expected) {
        manageNeuron_e type;
        return getManageNeuronType(&parser_tx_obj, &type) == parser_ok && type == expected;
    }

    void ExpectCountRefused() {
        uint8_t num_items = 0;
        EXPECT_EQ(parser_getNumItems(&ctx, &num_items), parser_unexpected_number_items);
        EXPECT_EQ(parser_validate(&ctx), parser_unexpected_number_items);
    }
};

TEST_F(ItemCountRegressions, SnsPermissionListLongerThanTheReviewIsRefused) {
    ASSERT_TRUE(LoadFirst("sns_add_neuron_permission.json", [] {
        return IsManageNeuron(SNS_AddNeuronPermissions) &&
               parser_tx_obj.tx_fields.call.data.sns_manageNeuron.command.neuronPermissions.has_permissionList;
    }));

    // 4 + 253 used to come out as 1: only the transaction type was shown.
    auto &list = parser_tx_obj.tx_fields.call.data.sns_manageNeuron.command.neuronPermissions.permissionList;
    for (const uint8_t size : {252, 253, 255}) {
        SCOPED_TRACE(size);
        list.list_size = size;
        ExpectCountRefused();
    }
}

TEST_F(ItemCountRegressions, CandidFolloweeListLongerThanTheReviewIsRefused) {
    ASSERT_TRUE(LoadFirst("phase2.json", [] {
        return IsManageNeuron(FollowCandid) &&
               parser_tx_obj.tx_fields.call.data.candid_manageNeuron.command.follow.followees_size > 0;
    }));

    auto &follow = parser_tx_obj.tx_fields.call.data.candid_manageNeuron.command.follow;
    for (const uint8_t size : {253, 255}) {
        SCOPED_TRACE(size);
        follow.followees_size = size;
        ExpectCountRefused();
    }
}

TEST_F(ItemCountRegressions, CandidNeuronIdListLongerThanTheReviewIsRefused) {
    ASSERT_TRUE(LoadFirst("phase2.json", [] {
        return parser_tx_obj.txtype == call && parser_tx_obj.tx_fields.call.method_type == candid_listneurons;
    }));

    parser_tx_obj.tx_fields.call.data.candid_listNeurons.neuron_ids_size = 255;
    ExpectCountRefused();
}

}  // namespace
