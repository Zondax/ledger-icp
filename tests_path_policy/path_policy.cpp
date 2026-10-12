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

#include <gtest/gtest.h>

#include <array>
#include <cstring>

#include "path.h"

uint8_t G_io_apdu_buffer[260] = {0};
uint32_t hdPath[HDPATH_LEN_DEFAULT] = {0};

namespace {

bool expert_mode = false;

void load_path(const std::array<uint32_t, HDPATH_LEN_DEFAULT> &path) {
    std::memcpy(G_io_apdu_buffer, path.data(), sizeof(path));
}

void extract(const std::array<uint32_t, HDPATH_LEN_DEFAULT> &path, bool expert) {
    expert_mode = expert;
    load_path(path);
    extractHDPath(sizeof(path), 0);
}

const std::array<uint32_t, HDPATH_LEN_DEFAULT> default_path = {
    HDPATH_0_DEFAULT, HDPATH_1_DEFAULT, HDPATH_2_DEFAULT, HDPATH_3_DEFAULT, HDPATH_4_DEFAULT,
};

TEST(PathPolicy, RejectsWrongHardeningEvenInExpertMode) {
    auto unhardened_account = default_path;
    unhardened_account[2] = 0;
    EXPECT_THROW(extract(unhardened_account, false), PathPolicyError);
    EXPECT_THROW(extract(unhardened_account, true), PathPolicyError);

    auto hardened_address = default_path;
    hardened_address[4] = 0x80000000u;
    EXPECT_THROW(extract(hardened_address, false), PathPolicyError);
    EXPECT_THROW(extract(hardened_address, true), PathPolicyError);
}

TEST(PathPolicy, LimitsCustomIndexesToExpertMode) {
    auto custom_account = default_path;
    custom_account[2] = 0x80000100u;
    EXPECT_THROW(extract(custom_account, false), PathPolicyError);
    EXPECT_NO_THROW(extract(custom_account, true));

    auto custom_change = default_path;
    custom_change[3] = 1;
    EXPECT_THROW(extract(custom_change, false), PathPolicyError);
    EXPECT_NO_THROW(extract(custom_change, true));
}

}  // namespace

extern "C" bool app_mode_expert() { return expert_mode; }
