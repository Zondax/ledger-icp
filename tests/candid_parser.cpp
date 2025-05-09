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

#include "candid_parser.h"

#include <hexutils.h>
#include <parser_common.h>
#include <parser_impl.h>

#include <algorithm>

#include "candid/leb128.h"
#include "gtest/gtest.h"

namespace {
typedef struct {
    std::string input;
    uint64_t expected;
    int16_t consumed;
} testcase_leb128_t;

typedef struct {
    std::string input;
    __int128 expected;
    int16_t consumed;
} testcase_sleb128_t;

class CandidLEB128Tests : public ::testing::TestWithParam<testcase_leb128_t> {};

class CandidSLEB128Tests : public ::testing::TestWithParam<testcase_sleb128_t> {};

INSTANTIATE_TEST_SUITE_P(CompactPrintTestcases, CandidLEB128Tests,
                         ::testing::ValuesIn({
                             testcase_leb128_t{"00", 0, 1},
                             testcase_leb128_t{"07", 7, 1},
                             testcase_leb128_t{"7F", 127, 1},
                             testcase_leb128_t{"c09a0c", 200000, 3},
                             testcase_leb128_t{"E58E26", 624485, 3},
                             testcase_leb128_t{"80897A", 2000000, 3},
                             testcase_leb128_t{"808098F4E9B5CA6A", 60000000000000000, 8},
                         }));

INSTANTIATE_TEST_SUITE_P(CompactPrintTestcases, CandidSLEB128Tests,
                         ::testing::ValuesIn({
                             testcase_sleb128_t{"00", 0, 1},
                             testcase_sleb128_t{"2A", 42, 1},
                             testcase_sleb128_t{"7F", -1, 1},
                             testcase_sleb128_t{"C0BB78", -123456, 3},
                             testcase_sleb128_t{"8089FA00", 2000000, 4},
                             testcase_sleb128_t{"808098F4E9B5CAEA00", 60000000000000000, 9},
                             testcase_sleb128_t{"FFFFFFFF40", -16911433729, 5},
                             testcase_sleb128_t{"8080808080808080807F", -9223372036854775808U, 10},
                         }));

TEST_P(CandidLEB128Tests, basicLEB128) {
    parser_tx_obj.special_transfer_type = normal_transaction;
    uint8_t inBuffer[1000];

    auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), GetParam().input.c_str());

    uint64_t v;
    uint16_t consumed;
    auto err = decompressLEB128(inBuffer, inBufferLen, &v, &consumed);
    EXPECT_EQ(err, parser_ok);

    EXPECT_EQ(v, GetParam().expected);
    EXPECT_EQ(consumed, GetParam().consumed);
}

TEST_P(CandidSLEB128Tests, basicSLEB128) {
    parser_tx_obj.special_transfer_type = normal_transaction;
    uint8_t inBuffer[1000];

    auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), GetParam().input.c_str());

    int64_t v;
    uint16_t consumed;
    auto err = decompressSLEB128(inBuffer, inBufferLen, &v, &consumed);
    EXPECT_EQ(err, parser_ok);

    EXPECT_EQ(v, (int64_t)GetParam().expected);
    EXPECT_EQ(consumed, GetParam().consumed);
}

TEST(CandidBLOBs, basicBlobManageNeuron) {
    uint8_t inBuffer[1000];

    // based on
    // https://github.com/aviate-labs/candid-go/blob/b8b641a7ea00fed75c96a513d764c03c0dcca370/candid_test.go#L63
    auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer),
                                      "4449444c426c01dbb701786e006e686e786c02dbe2be950902ef9999fe09036c01b9ef93"
                                      "8008786d006c02afa3bda10175c2cee0d80c066c006c029cb1fa2502ba89e5c204786b03"
                                      "9ef5cc0f089992ccd00109dae1c99903786e0a6c01d7ab010b6c01f6b0989a08026c018e"
                                      "ddc3a60d026c018dc3b2b303796c01c88ecad50a786b0796a7f7150df381d4ab020eb09b"
                                      "9ba40708d0fb87af070890f29afe070fe4ac938d0c08c3a2f6c90e106e116c01a7888282"
                                      "0a126c02ea99cff20475b2b8d4960b016c01c38fbbd10b016c05f5bbe3900178d2bbf0d9"
                                      "017eb9ef93800878dbe2be950902ef9999fe09786c04efd6e4027198abec810118b6f798"
                                      "b2013ea696a48708716e716c02cbe4fdc70471fc91f4f805186e196c02dbb70101bac7a7"
                                      "fa0d1a6c01b99d9da50b796d7b6c01cedfa0a8041d6e1e6c01e0a9b302786e206c02a9dd"
                                      "f49b071fd8a38ca80d216b0b9b9cd0a40104bab5f1a40105918bacf10207fc9fc683050c"
                                      "c6b3bb9106138db2d592091498a5d0c7091591b2fab80a16e0f8fffd0b1789b8b3b30e1c"
                                      "a3f3c0ad0f226e236b02cd8e8eb9041dcebee1d308006e256c03dbb70101cbe2b58b0824"
                                      "f1bb8b880d266c02e4d7bee905758effd6e90e1d6c02dbb701029df1afe7071f6e296c01"
                                      "f5bbe39001786c01a9ddf49b071f6b02fdf59aec0b2be3b586ff0c2c6e2d6c03ce9ca6ce"
                                      "012af382ccb3072eb9ef938008786c01c2cee0d80c066c02007501306d316c0184aead33"
                                      "326d2f6c01a4ccf7dd0a346c089eb493cf0378befa8dd40479be8fe6e30478ce89be9706"
                                      "7886f998bc0978c5cae3d40a7893a190e00c78f5e1d0e70d786d686c018594e2c50b376b"
                                      "02bf80e42b29c6a6e4b90a296e396c01f0a2cabb0b3a6c0196bdb4e904716b0a93a7e09d"
                                      "021bd881c9c40327d69ce79d0a2882ffcfaa0c2fe3c3c5990e33b1a5aea10e35f5d9d7a5"
                                      "0e36fad5ddf40e38db9cebf70e3bd6f4c7ff0f3c6e3d6b0b9b9cd0a40104bab5f1a40105"
                                      "918bacf10207fc9fc683050cc6b3bb9106138db2d592091498a5d0c7091591b2fab80a16"
                                      "e0f8fffd0b1789b8b3b30e1ca3f3c0ad0f226e3f6c03dbb70101cbe2b58b08c000f1bb8b"
                                      "880d2601c1000001017b0000000000000001017b00000000000000");

    //        TYPE 65
    //        type ManageNeuron = record {
    //                id : opt NeuronId;
    //                command : opt Command;
    //                neuron_id_or_subaccount : opt NeuronIdOrSubaccount;
    //        };
    //
    //        type NeuronId = record { id : nat64 };
    //
    //        type Command = variant {
    //                Spawn : Spawn;
    //                Split : Split;
    //                Follow : Follow;
    //                ClaimOrRefresh : ClaimOrRefresh;
    //                Configure : Configure;
    //                RegisterVote : RegisterVote;
    //                Merge : Merge;
    //                DisburseToNeuron : DisburseToNeuron;
    //                MakeProposal : Proposal;
    //                MergeMaturity : MergeMaturity;
    //                Disburse : Disburse;
    //        };
    //        type Split = record { amount_e8s : nat64 };
    //
    //
    //        type NeuronIdOrSubaccount = variant {
    //                Subaccount : vec nat8;
    //                NeuronId : NeuronId;
    //        };
    //
    //     Expected
    //        "0 | Transaction type : Split Neuron",
    //        "1 | Neuron ID : 123",
    //        "2 | Amount : 0.00000123 ICP"

    parser_tx_t tx;
    auto err = readCandidManageNeuron(&tx, inBuffer, inBufferLen);
    EXPECT_EQ(err, parser_ok);
}
}  // namespace
