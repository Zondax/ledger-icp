/*******************************************************************************
 *   (c) 2019-2021 Zondax GmbH
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
#include "common.h"

#include <app_mode.h>
#include <fmt/core.h>
#include <hexutils.h>
#include <json/json.h>
#include <parser.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "gmock/gmock.h"
#include "parser_impl.h"

std::vector<std::string> dumpUI(parser_context_t *ctx, uint16_t maxKeyLen, uint16_t maxValueLen) {
    auto answer = std::vector<std::string>();

    uint8_t numItems;
    parser_error_t err = parser_getNumItems(ctx, &numItems);
    if (err != parser_ok) {
        return answer;
    }

    for (uint16_t idx = 0; idx < numItems; idx++) {
        char keyBuffer[1000];
        char valueBuffer[1000];
        uint8_t pageIdx = 0;
        uint8_t pageCount = 1;

        while (pageIdx < pageCount) {
            std::stringstream ss;

            err = parser_getItem(ctx, (uint8_t)idx, keyBuffer, maxKeyLen, valueBuffer, maxValueLen, pageIdx, &pageCount);

            ss << fmt::format("{} | {}", idx, keyBuffer);
            if (pageCount > 1) {
                ss << fmt::format("[{}/{}]", pageIdx + 1, pageCount);
            }
            ss << " : ";

            if (err == parser_ok) {
                // Model multiple lines
                ss << fmt::format("{}", valueBuffer);
            } else {
                ss << parser_getErrorDescription(err);
            }

            auto output = ss.str();
            if (output.back() == ' ') {
                output = output.substr(0, output.size() - 1);
            }

            answer.push_back(output);

            pageIdx++;
        }
    }

    return answer;
}

std::string CleanTestname(std::string s) {
    s.erase(remove_if(s.begin(), s.end(),
                      [](char v) -> bool {
                          return v == ':' || v == ' ' || v == '/' || v == '-' || v == '.' || v == '_' || v == '#';
                      }),
            s.end());
    return s;
}

std::vector<testcase_t> GetJsonTestCases(const std::string &jsonFile) {
    auto answer = std::vector<testcase_t>();

    Json::CharReaderBuilder builder;
    Json::Value obj;

    std::string fullPathJsonFile = std::string(TESTVECTORS_DIR) + jsonFile;

    std::ifstream inFile(fullPathJsonFile);
    if (!inFile.is_open()) {
        return answer;
    }

    // Retrieve all test cases
    JSONCPP_STRING errs;
    Json::parseFromStream(builder, inFile, &obj, &errs);
    std::cout << "Number of testcases: " << obj.size() << std::endl;

    for (auto &i : obj) {
        auto outputs = std::vector<std::string>();
        for (const auto &s : i["output"]) {
            outputs.push_back(s.asString());
        }

        auto outputs_expert = std::vector<std::string>();
        for (const auto &s : i["output_expert"]) {
            outputs_expert.push_back(s.asString());
        }

        bool valid = true;
        if (i.isMember("valid")) {
            valid = i["valid"].asBool();
        }

        auto name = CleanTestname(i["name"].asString());

        answer.push_back(testcase_t{i["index"].asUInt64(), name, i["blob"].asString(), valid, outputs, outputs_expert});
    }

    return answer;
}

void check_testcase(const testcase_t &tc, bool expert_mode) {
    app_mode_set_expert(expert_mode);

    parser_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    memset(&parser_tx_obj, 0, sizeof(parser_tx_obj));
    parser_error_t err, err_val;

    uint8_t buffer[10000];
    uint16_t bufferLen = parseHexString(buffer, sizeof(buffer), tc.blob.c_str());

    err = parser_parse(&ctx, buffer, bufferLen);
    parser_tx_obj.special_transfer_type = normal_transaction;
    err_val = parser_validate(&ctx);

    if (tc.valid) {
        ASSERT_EQ(err, parser_ok) << parser_getErrorDescription(err);
    } else {
        if (err == parser_ok) {
            ASSERT_NE(err_val, parser_ok) << parser_getErrorDescription(err_val);
        } else {
            ASSERT_NE(err, parser_ok) << parser_getErrorDescription(err);
        }
        return;
    }
    ASSERT_EQ(err_val, parser_ok) << parser_getErrorDescription(err);

    auto output = dumpUI(&ctx, 40, 37);

    std::cout << std::endl;
    for (const auto &i : output) {
        std::cout << i << std::endl;
    }
    std::cout << std::endl << std::endl;

    std::vector<std::string> expected = app_mode_expert() && !tc.expected_expert.empty() ? tc.expected_expert : tc.expected;
    EXPECT_EQ(output.size(), expected.size());
    for (size_t i = 0; i < expected.size(); i++) {
        if (i < output.size()) {
            EXPECT_THAT(output[i], testing::Eq(expected[i]));
        }
    }
}
