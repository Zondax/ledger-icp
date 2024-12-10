/*******************************************************************************
*  (c) 2019 Zondax GmbH
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

#include "parser_common.h"
#include "token_info.h"
#include "crypto.h"
#include "parser_print_helper.h"

// Static definition of all tokens
static const token_info_t TOKEN_REGISTRY[] = {
    {
        //              ryjl3-tyaaa-aaaaa-aaaba-cai
        .canister_id = "ryjl3-tyaaa-aaaaa-aaaba-cai",
        .token_symbol = "ICP",
        .decimals = 8
    },
    {
        .canister_id = "ss2fx-dyaaa-aaaar-qacoq-cai",
        .token_symbol = "ckETH",
        .decimals = 18
    },
    {
        .canister_id = "pe5t5-diaaa-aaaar-qahwa-cai",
        .token_symbol = "ckEURC",
        .decimals = 6
    },
    {
        .canister_id = "ilzky-ayaaa-aaaar-qahha-cai",
        .token_symbol = "ckUNI",
        .decimals = 18
    },
    {
        .canister_id = "bptq2-faaaa-aaaar-qagxq-cai",
        .token_symbol = "ckWBTC",
        .decimals = 8
    },
    {
        .canister_id = "g4tto-rqaaa-aaaar-qageq-cai",
        .token_symbol = "ckLINK",
        .decimals = 18
    },
    {
        .canister_id = "nza5v-qaaaa-aaaar-qahzq-cai",
        .token_symbol = "ckXAUT",
        .decimals = 6
    },
    {
        .canister_id = "etik7-oiaaa-aaaar-qagia-cai",
        .token_symbol = "ckPEPE",
        .decimals = 18
    },
    {
        .canister_id = "j2tuh-yqaaa-aaaar-qahcq-cai",
        .token_symbol = "ckWSTETH",
        .decimals = 18
    },
    {
        .canister_id = "fxffn-xiaaa-aaaar-qagoa-cai",
        .token_symbol = "ckSHIB",
        .decimals = 18
    },
    {
        .canister_id = "xevnm-gaaaa-aaaar-qafnq-cai",
        .token_symbol = "ckUSDC",
        .decimals = 6
    },
    {
        .canister_id = "cngnf-vqaaa-aaaar-qag4q-cai",
        .token_symbol = "ckUSDT",
        .decimals = 6
    },
    {
        .canister_id = "ebo5g-cyaaa-aaaar-qagla-cai",
        .token_symbol = "ckOCT",
        .decimals = 18
    },
    {
        .canister_id = "yfumr-cyaaa-aaaar-qaela-cai",
        .token_symbol = "ckSepoliaUSDC",
        .decimals = 6
    },
    {
        .canister_id = "hw4ru-taaaa-aaaar-qagdq-cai",
        .token_symbol = "ckSepoliaPEPE",
        .decimals = 18
    },
    {
        .canister_id = "r52mc-qaaaa-aaaar-qafzq-cai",
        .token_symbol = "ckSepoliaLINK",
        .decimals = 18
    },
    {
        .canister_id = "zfcdd-tqaaa-aaaaq-aaaga-cai",
        .token_symbol = "DKP",
        .decimals = 8
    },
    {
        .canister_id = "2ouva-viaaa-aaaaq-aaamq-cai",
        .token_symbol = "CHAT",
        .decimals = 8
    },
    {
        .canister_id = "73mez-iiaaa-aaaaq-aaasq-cai",
        .token_symbol = "KINIC",
        .decimals = 8
    },
    {
        .canister_id = "6rdgd-kyaaa-aaaaq-aaavq-cai",
        .token_symbol = "DOLR",
        .decimals = 8
    },
    {
        .canister_id = "4c4fd-caaaa-aaaaq-aaa3a-cai",
        .token_symbol = "GHOST",
        .decimals = 8
    },
    {
        .canister_id = "xsi2v-cyaaa-aaaaq-aabfq-cai",
        .token_symbol = "DCD",
        .decimals = 8
    },
    {
        .canister_id = "vtrom-gqaaa-aaaaq-aabia-cai",
        .token_symbol = "BOOM",
        .decimals = 8
    },
    {
        .canister_id = "uf2wh-taaaa-aaaaq-aabna-cai",
        .token_symbol = "CTZ",
        .decimals = 8
    },
    {
        .canister_id = "rffwt-piaaa-aaaaq-aabqq-cai",
        .token_symbol = "SEER",
        .decimals = 8
    },
    {
        .canister_id = "rxdbk-dyaaa-aaaaq-aabtq-cai",
        .token_symbol = "NUA",
        .decimals = 8
    },
    {
        .canister_id = "qbizb-wiaaa-aaaaq-aabwq-cai",
        .token_symbol = "SONIC",
        .decimals = 8
    },
    {
        .canister_id = "tyyy3-4aaaa-aaaaq-aab7a-cai",
        .token_symbol = "GLDGov",
        .decimals = 8
    },
    {
        .canister_id = "emww2-4yaaa-aaaaq-aacbq-cai",
        .token_symbol = "TRAX",
        .decimals = 8
    },
    {
        .canister_id = "f54if-eqaaa-aaaaq-aacea-cai",
        .token_symbol = "NTN",
        .decimals = 8
    },
    {
        .canister_id = "hvgxa-wqaaa-aaaaq-aacia-cai",
        .token_symbol = "SNEED",
        .decimals = 8
    },
    {
        .canister_id = "hhaaz-2aaaa-aaaaq-aacla-cai",
        .token_symbol = "ICL",
        .decimals = 8
    },
    {
        .canister_id = "gemj7-oyaaa-aaaaq-aacnq-cai",
        .token_symbol = "ELNA",
        .decimals = 8
    },
    {
        .canister_id = "ddsp7-7iaaa-aaaaq-aacqq-cai",
        .token_symbol = "FPL",
        .decimals = 8
    },
    {
        .canister_id = "druyg-tyaaa-aaaaq-aactq-cai",
        .token_symbol = "PANDA",
        .decimals = 8
    },
    {
        .canister_id = "ca6gz-lqaaa-aaaaq-aacwa-cai",
        .token_symbol = "ICS",
        .decimals = 8
    },
    {
        .canister_id = "atbfz-diaaa-aaaaq-aacyq-cai",
        .token_symbol = "YUKU",
        .decimals = 8
    },
    {
        .canister_id = "bliq2-niaaa-aaaaq-aac4q-cai",
        .token_symbol = "EST",
        .decimals = 8
    },
    {
        .canister_id = "k45jy-aiaaa-aaaaq-aadcq-cai",
        .token_symbol = "MOTOKO",
        .decimals = 8
    },
    {
        .canister_id = "lrtnw-paaaa-aaaaq-aadfa-cai",
        .token_symbol = "CONF",
        .decimals = 8
    },
    {
        .canister_id = "lkwrt-vyaaa-aaaaq-aadhq-cai",
        .token_symbol = "OGY",
        .decimals = 8
    },
    {
        .canister_id = "jcmow-hyaaa-aaaaq-aadlq-cai",
        .token_symbol = "WTN",
        .decimals = 8
    },
    {
        .canister_id = "itgqj-7qaaa-aaaaq-aadoa-cai",
        .token_symbol = "CTS",
        .decimals = 8
    },
    {
        .canister_id = "np5km-uyaaa-aaaaq-aadrq-cai",
        .token_symbol = "DOGMI",
        .decimals = 8
    },
    {
        .canister_id = "m6xut-mqaaa-aaaaq-aadua-cai",
        .token_symbol = "ICVC",
        .decimals = 8
    }
};

#define TOKEN_REGISTRY_SIZE (sizeof(TOKEN_REGISTRY) / sizeof(TOKEN_REGISTRY[0]))


// Function to get decimals for a canister ID
const token_info_t *get_token(const uint8_t* canister_id, size_t len) {
    zemu_log_stack("get_token\n");
    if (canister_id == NULL) {
        return NULL;
    }

    char canister[100] = {'\0'};

    uint8_t pageCount = 0;
    if (format_principal(canister_id, len, canister, 99) != parser_ok) {
        return NULL;
    }

    zemu_log("\nlooking for->\n");
    zemu_log(canister);

    // Now look up in registry
    const token_info_t *token = NULL;
    for (size_t i = 0; i < TOKEN_REGISTRY_SIZE; i++) {
        zemu_log("with: ");
        zemu_log(TOKEN_REGISTRY[i].canister_id);
        zemu_log("\n");


        if (strcmp(canister, TOKEN_REGISTRY[i].canister_id) == 0) {
            zemu_log_stack("Found\n");
            token = (const token_info_t *)&TOKEN_REGISTRY[i];
            return token;
        }
    }

    return NULL;
}
