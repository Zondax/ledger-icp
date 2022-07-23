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

#include "gmock/gmock.h"
#include "common.h"

using ::testing::TestWithParam;

class JsonTests_Phase1 : public JsonTests_Base {};
class JsonTests_Phase2 : public JsonTests_Base {};

INSTANTIATE_TEST_SUITE_P (
        Phase1,
        JsonTests_Phase1,
        ::testing::ValuesIn(GetJsonTestCases("manual.json")),
        JsonTests_Phase1::PrintToStringParamName()
);

// Parametric test using current runtime:
TEST_P(JsonTests_Phase1, Normal) { check_testcase(GetParam(), false); }

TEST_P(JsonTests_Phase1, Expert) { check_testcase(GetParam(), true); }

////////////////////
////////////////////
////////////////////

INSTANTIATE_TEST_SUITE_P (
        Phase2,
        JsonTests_Phase2,
        ::testing::ValuesIn(GetJsonTestCases("phase2.json")),
        JsonTests_Phase2::PrintToStringParamName()
);

//// Parametric test using current runtime:
TEST_P(JsonTests_Phase2, Normal) { check_testcase(GetParam(), false); }

TEST_P(JsonTests_Phase2, Expert) { check_testcase(GetParam(), true); }
