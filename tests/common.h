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
#pragma once

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "parser_common.h"

typedef struct {
    uint64_t index;
    std::string name;
    std::string blob;
    bool valid;
    std::vector<std::string> expected;
    std::vector<std::string> expected_expert;
} testcase_t;

class JsonTests_Base : public ::testing::TestWithParam<testcase_t> {
   public:
    struct PrintToStringParamName {
        template <class ParamType>
        std::string operator()(const testing::TestParamInfo<ParamType> &info) const {
            auto p = static_cast<testcase_t>(info.param);
            std::stringstream ss;
            ss << p.index << "_" << p.name;
            return ss.str();
        }
    };
};

#define EXPECT_EQ_STR(_STR1, _STR2, _errorMessage)                                                                     \
    {                                                                                                                  \
        if (_STR1 != nullptr & _STR2 != nullptr)                                                                       \
            EXPECT_TRUE(!strcmp(_STR1, _STR2)) << _errorMessage << ", expected: " << _STR2 << ", received: " << _STR1; \
        else                                                                                                           \
            FAIL() << "One of the strings is null";                                                                    \
    }

std::vector<std::string> dumpUI(parser_context_t *ctx, uint16_t maxKeyLen, uint16_t maxValueLen);

std::vector<testcase_t> GetJsonTestCases(const std::string &jsonFile);

void check_testcase(const testcase_t &tc, bool expert_mode);
