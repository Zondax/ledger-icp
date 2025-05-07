/*******************************************************************************
 *  (c) 2018-2021 Zondax AG
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

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CLA 0x11u

#define INS_SIGN_COMBINED 0x03u
#define INS_CONSENT_REQUEST 0x04u
#define INS_CANISTER_CALL_TX 0x05u
#define INS_CERTIFICATE_AND_SIGN 0x06u
#define INS_SUPPORTED_TOKENS_LEN 0x07u
#define INS_TOKEN_AT_IDX 0x08u

#define HDPATH_LEN_DEFAULT 5u

#define HDPATH_0_DEFAULT (0x80000000u | 0x2cu)
#define HDPATH_1_DEFAULT (0x80000000u | 0xdfu)
#define HDPATH_2_DEFAULT (0x80000000u | 0u)
#define HDPATH_3_DEFAULT (0u)
#define HDPATH_4_DEFAULT (0u)

#define HDPATH_0_TESTNET (0x80000000u | 0x2cu)
#define HDPATH_1_TESTNET (0x80000000u | 0xdfu)

#define HDPATH_RESTRICTED_MASK 0xFFFFFF00u

#define SECP256K1_PK_LEN 65u
#define DFINITY_ADDR_LEN 32u
#define DFINITY_SUBACCOUNT_LEN 32u
#define DFINITY_PRINCIPAL_LEN 29u
#define DFINITY_TEXTUAL_SIZE 100u
// From an account we just display the first 16 bytes:
// including the '.' prefix
// 2 | From account [3/3] : .d7e8516 52cd032b a5ed76b1 7f626aa4"
#define DFINITY_SUBACCOUNT_MAX_BYTES_TO_TEXTUAL 16u

#define MAX_CHARS_PER_VALUE_LINE 18u

typedef enum {
    addr_secp256k1 = 0,
} address_kind_e;

#define COIN_SECRET_REQUIRED_CLICKS 0
#define COIN_AMOUNT_DECIMAL_PLACES 8
#define COIN_AMOUNT_DECIMAL_NON_TRIMMED_PLACES 2
#define COIN_AMOUNT_THOUSAND_SEPARATOR '\''

#define VIEW_ADDRESS_OFFSET_SECP256K1 (SECP256K1_PK_LEN)
#define VIEW_PRINCIPAL_OFFSET_TEXT (SECP256K1_PK_LEN + DFINITY_PRINCIPAL_LEN + DFINITY_SUBACCOUNT_LEN)
#define VIEW_ADDRESS_OFFSET_TEXT (SECP256K1_PK_LEN + DFINITY_PRINCIPAL_LEN)
#define COIN_SUPPORTED_TX_VERSION 0

#if defined(TARGET_STAX) || defined(TARGET_FLEX)
#define MENU_MAIN_APP_LINE1 "Internet Computer"
#define MENU_MAIN_APP_LINE2 "ICP"
#define CUSTOM_ADDRESS_TEXT "Verify Internet\nComputer address"
#else
#define MENU_MAIN_APP_LINE1 "Internet"
#define MENU_MAIN_APP_LINE2 "Computer"
#endif

#define MENU_MAIN_APP_LINE2_SECRET "???"
#define APPVERSION_LINE1 "Version"
#define APPVERSION_LINE2 "v" APPVERSION

#ifdef __cplusplus
}
#endif
