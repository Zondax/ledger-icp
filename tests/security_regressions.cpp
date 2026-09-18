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

}  // namespace
