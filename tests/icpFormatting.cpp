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

#include <fmt/core.h>

#include "formatting.h"
#include "gtest/gtest.h"

namespace {
TEST(ICPFormatting, Simple) {
    char buffer[100];
    uint64_t input = 1000;

    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "0.00001");

    input = 10000;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "0.0001");

    input = 100000;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "0.001");

    input = 1000000;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "0.01");

    input = 10000000;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "0.10");

    input = 100000000;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "1.00");

    input = 1000000000;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "10.00");

    input = 10000000000;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "100.00");

    input = 100000000000;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "1'000.00");

    input = 1000000000000;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "10'000.00");

    input = 10000000000000;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "100'000.00");

    input = 100000000000000;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "1'000'000.00");

    input = 1000000000000000;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "10'000'000.00");

    input = 10000000001;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "100.00000001");

    input = 1000000001;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "10.00000001");

    input = 100000001;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "1.00000001");

    input = 10000001;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "0.10000001");

    input = 1000001;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "0.01000001");

    input = 100001;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "0.00100001");

    input = 10001;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "0.00010001");

    input = 1001;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "0.00001001");

    input = 101;
    formatICP(buffer, sizeof(buffer), input);
    EXPECT_STREQ(buffer, "0.00000101");

    input = 11;
    EXPECT_EQ(formatICP(buffer, sizeof(buffer), input), zxerr_ok);
    EXPECT_STREQ(buffer, "0.00000011");
}

TEST(ICPFormatting, FormatWithSeparators) {
    char buffer[100];
    uint64_t input;

    input = 100000000000;
    EXPECT_EQ(formatICP(buffer, sizeof(buffer), input), zxerr_ok);
    EXPECT_STREQ(buffer, "1'000.00");

    input = 100000000;
    EXPECT_EQ(formatICP(buffer, sizeof(buffer), input), zxerr_ok);
    EXPECT_STREQ(buffer, "1.00");

    input = 1000000000;
    EXPECT_EQ(formatICP(buffer, sizeof(buffer), input), zxerr_ok);
    EXPECT_STREQ(buffer, "10.00");

    input = 10000000000;
    EXPECT_EQ(formatICP(buffer, sizeof(buffer), input), zxerr_ok);
    EXPECT_STREQ(buffer, "100.00");

    input = 1000000000000;
    EXPECT_EQ(formatICP(buffer, sizeof(buffer), input), zxerr_ok);
    EXPECT_STREQ(buffer, "10'000.00");

    input = 10000000000000;
    EXPECT_EQ(formatICP(buffer, sizeof(buffer), input), zxerr_ok);
    EXPECT_STREQ(buffer, "100'000.00");

    input = 100000000000000;
    EXPECT_EQ(formatICP(buffer, sizeof(buffer), input), zxerr_ok);
    EXPECT_STREQ(buffer, "1'000'000.00");
}

TEST(ICPFormatting, insertChar) {
    char buffer[100];
    uint64_t input;

    snprintf(buffer, sizeof(buffer), "abcdef0123456789");
    buffer[6] = 0;
    EXPECT_EQ(inplace_insert_char(buffer, sizeof(buffer), 2, 'X'), zxerr_ok);
    EXPECT_STREQ(buffer, "abXcdef");

    snprintf(buffer, sizeof(buffer), "abcdef0123456789");
    buffer[2] = 0;
    EXPECT_EQ(inplace_insert_char(buffer, sizeof(buffer), 2, 'X'), zxerr_ok);
    EXPECT_STREQ(buffer, "abX");

    snprintf(buffer, sizeof(buffer), "abcdef0123456789");
    buffer[2] = 0;
    EXPECT_EQ(inplace_insert_char(buffer, sizeof(buffer), 2, 'X'), zxerr_ok);
    EXPECT_STREQ(buffer, "abX");
}

TEST(ICPFormatting, thousandSeparator) {
    char buffer[100];

    snprintf(buffer, sizeof(buffer), "1");
    EXPECT_EQ(number_inplace_thousands(buffer, sizeof(buffer), '\''), zxerr_ok);
    EXPECT_STREQ(buffer, "1");

    snprintf(buffer, sizeof(buffer), "10");
    EXPECT_EQ(number_inplace_thousands(buffer, sizeof(buffer), '\''), zxerr_ok);
    EXPECT_STREQ(buffer, "10");

    snprintf(buffer, sizeof(buffer), "100");
    EXPECT_EQ(number_inplace_thousands(buffer, sizeof(buffer), '\''), zxerr_ok);
    EXPECT_STREQ(buffer, "100");

    snprintf(buffer, sizeof(buffer), "1000");
    EXPECT_EQ(number_inplace_thousands(buffer, sizeof(buffer), '\''), zxerr_ok);
    EXPECT_STREQ(buffer, "1'000");

    snprintf(buffer, sizeof(buffer), "1000000");
    EXPECT_EQ(number_inplace_thousands(buffer, sizeof(buffer), '\''), zxerr_ok);
    EXPECT_STREQ(buffer, "1'000'000");

    snprintf(buffer, sizeof(buffer), "1000000000");
    EXPECT_EQ(number_inplace_thousands(buffer, sizeof(buffer), '\''), zxerr_ok);
    EXPECT_STREQ(buffer, "1'000'000'000");
}
}  // namespace
