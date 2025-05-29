/*******************************************************************************
 *  (c) 2019 Zondax AG
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

#include "token_info.h"

#include "crypto.h"
#include "parser_common.h"
#include "parser_print_helper.h"

#define CANISTER_TEXTUAL_BUFFER_SIZE 100

// Static definition of all tokens
static const token_info_t TOKEN_REGISTRY[] = {
    {.canister_id = "ryjl3-tyaaa-aaaaa-aaaba-cai", .token_symbol = "ICP", .decimals = 8},
    {.canister_id = "mxzaz-hqaaa-aaaar-qaada-cai", .token_symbol = "ckBTC", .decimals = 8},
    {.canister_id = "ss2fx-dyaaa-aaaar-qacoq-cai", .token_symbol = "ckETH", .decimals = 18},
    {.canister_id = "pe5t5-diaaa-aaaar-qahwa-cai", .token_symbol = "ckEURC", .decimals = 6},
    {.canister_id = "ilzky-ayaaa-aaaar-qahha-cai", .token_symbol = "ckUNI", .decimals = 18},
    {.canister_id = "bptq2-faaaa-aaaar-qagxq-cai", .token_symbol = "ckWBTC", .decimals = 8},
    {.canister_id = "g4tto-rqaaa-aaaar-qageq-cai", .token_symbol = "ckLINK", .decimals = 18},
    {.canister_id = "nza5v-qaaaa-aaaar-qahzq-cai", .token_symbol = "ckXAUT", .decimals = 6},
    {.canister_id = "etik7-oiaaa-aaaar-qagia-cai", .token_symbol = "ckPEPE", .decimals = 18},
    {.canister_id = "j2tuh-yqaaa-aaaar-qahcq-cai", .token_symbol = "ckWSTETH", .decimals = 18},
    {.canister_id = "fxffn-xiaaa-aaaar-qagoa-cai", .token_symbol = "ckSHIB", .decimals = 18},
    {.canister_id = "xevnm-gaaaa-aaaar-qafnq-cai", .token_symbol = "ckUSDC", .decimals = 6},
    {.canister_id = "cngnf-vqaaa-aaaar-qag4q-cai", .token_symbol = "ckUSDT", .decimals = 6},
    {.canister_id = "ebo5g-cyaaa-aaaar-qagla-cai", .token_symbol = "ckOCT", .decimals = 18},
    {.canister_id = "yfumr-cyaaa-aaaar-qaela-cai", .token_symbol = "ckSepoliaUSDC", .decimals = 6},
    {.canister_id = "hw4ru-taaaa-aaaar-qagdq-cai", .token_symbol = "ckSepoliaPEPE", .decimals = 18},
    {.canister_id = "r52mc-qaaaa-aaaar-qafzq-cai", .token_symbol = "ckSepoliaLINK", .decimals = 18},
    {.canister_id = "zfcdd-tqaaa-aaaaq-aaaga-cai", .token_symbol = "DKP", .decimals = 8},
    {.canister_id = "2ouva-viaaa-aaaaq-aaamq-cai", .token_symbol = "CHAT", .decimals = 8},
    {.canister_id = "7ajy4-sqaaa-aaaaq-aaaqa-cai", .token_symbol = "SOC", .decimals = 8},
    {.canister_id = "73mez-iiaaa-aaaaq-aaasq-cai", .token_symbol = "KINIC", .decimals = 8},
    {.canister_id = "6rdgd-kyaaa-aaaaq-aaavq-cai", .token_symbol = "DOLR", .decimals = 8},
    {.canister_id = "4q2s2-oqaaa-aaaaq-aaaya-cai", .token_symbol = "GHOST", .decimals = 8},
    {.canister_id = "4c4fd-caaaa-aaaaq-aaa3a-cai", .token_symbol = "GHOST", .decimals = 8},
    {.canister_id = "5bqmf-wyaaa-aaaaq-aaa5q-cai", .token_symbol = "CAT", .decimals = 8},
    {.canister_id = "wedc6-xiaaa-aaaaq-aabaq-cai", .token_symbol = "EMC", .decimals = 8},
    {.canister_id = "wrett-waaaa-aaaaq-aabda-cai", .token_symbol = "MOD", .decimals = 8},
    {.canister_id = "xsi2v-cyaaa-aaaaq-aabfq-cai", .token_symbol = "DCD", .decimals = 8},
    {.canister_id = "vtrom-gqaaa-aaaaq-aabia-cai", .token_symbol = "BOOM", .decimals = 8},
    {.canister_id = "viusj-4iaaa-aaaaq-aabkq-cai", .token_symbol = "SEER", .decimals = 8},
    {.canister_id = "uf2wh-taaaa-aaaaq-aabna-cai", .token_symbol = "CTZ", .decimals = 8},
    {.canister_id = "rffwt-piaaa-aaaaq-aabqq-cai", .token_symbol = "SEER", .decimals = 8},
    {.canister_id = "rxdbk-dyaaa-aaaaq-aabtq-cai", .token_symbol = "NUA", .decimals = 8},
    {.canister_id = "qbizb-wiaaa-aaaaq-aabwq-cai", .token_symbol = "SONIC", .decimals = 8},
    {.canister_id = "sotaq-jqaaa-aaaaq-aab2a-cai", .token_symbol = "QRO", .decimals = 8},
    {.canister_id = "tn7jw-5iaaa-aaaaq-aab4q-cai", .token_symbol = "TRAX", .decimals = 8},
    {.canister_id = "tyyy3-4aaaa-aaaaq-aab7a-cai", .token_symbol = "GOLDAO", .decimals = 8},
    {.canister_id = "emww2-4yaaa-aaaaq-aacbq-cai", .token_symbol = "TRAX", .decimals = 8},
    {.canister_id = "f54if-eqaaa-aaaaq-aacea-cai", .token_symbol = "NTN", .decimals = 8},
    {.canister_id = "hvgxa-wqaaa-aaaaq-aacia-cai", .token_symbol = "SNEED", .decimals = 8},
    {.canister_id = "hhaaz-2aaaa-aaaaq-aacla-cai", .token_symbol = "ICL", .decimals = 8},
    {.canister_id = "gemj7-oyaaa-aaaaq-aacnq-cai", .token_symbol = "ELNA", .decimals = 8},
    {.canister_id = "ddsp7-7iaaa-aaaaq-aacqq-cai", .token_symbol = "ICFC", .decimals = 8},
    {.canister_id = "druyg-tyaaa-aaaaq-aactq-cai", .token_symbol = "PANDA", .decimals = 8},
    {.canister_id = "ca6gz-lqaaa-aaaaq-aacwa-cai", .token_symbol = "ICS", .decimals = 8},
    {.canister_id = "atbfz-diaaa-aaaaq-aacyq-cai", .token_symbol = "YUKU", .decimals = 8},
    {.canister_id = "bliq2-niaaa-aaaaq-aac4q-cai", .token_symbol = "EST", .decimals = 8},
    {.canister_id = "bzohd-byaaa-aaaaq-aac7q-cai", .token_symbol = "MORA", .decimals = 8},
    {.canister_id = "k45jy-aiaaa-aaaaq-aadcq-cai", .token_symbol = "MOTOKO", .decimals = 8},
    {.canister_id = "lrtnw-paaaa-aaaaq-aadfa-cai", .token_symbol = "CONF", .decimals = 8},
    {.canister_id = "lkwrt-vyaaa-aaaaq-aadhq-cai", .token_symbol = "OGY", .decimals = 8},
    {.canister_id = "jcmow-hyaaa-aaaaq-aadlq-cai", .token_symbol = "WTN", .decimals = 8},
    {.canister_id = "itgqj-7qaaa-aaaaq-aadoa-cai", .token_symbol = "CTS", .decimals = 8},
    {.canister_id = "np5km-uyaaa-aaaaq-aadrq-cai", .token_symbol = "DOGMI", .decimals = 8},
    {.canister_id = "m6xut-mqaaa-aaaaq-aadua-cai", .token_symbol = "ICVC", .decimals = 8},
    {.canister_id = "mmrdk-aaaaa-aaaaq-aadxa-cai", .token_symbol = "JUNOBUILD", .decimals = 8},
    {.canister_id = "o7oak-iyaaa-aaaaq-aadzq-cai", .token_symbol = "KONG", .decimals = 8},
    {.canister_id = "p3dpy-ryaaa-aaaaq-aad7q-cai", .token_symbol = "ICTO", .decimals = 8},
    {.canister_id = "p7vqo-eyaaa-aaaaq-aaeca-cai", .token_symbol = "CANI", .decimals = 8},
    {.canister_id = "o4zzi-qaaaa-aaaaq-aaeeq-cai", .token_symbol = "WELL", .decimals = 8},
    {.canister_id = "oj6if-riaaa-aaaaq-aaeha-cai", .token_symbol = "ALICE", .decimals = 8},
    {.canister_id = "mih44-vaaaa-aaaaq-aaekq-cai", .token_symbol = "NFIDW", .decimals = 8},
    {.canister_id = "nfjys-2iaaa-aaaaq-aaena-cai", .token_symbol = "FUEL", .decimals = 8},
    {.canister_id = "ifwyg-gaaaa-aaaaq-aaeqq-cai", .token_symbol = "ICE", .decimals = 8},
    {.canister_id = "ixqp7-kqaaa-aaaaq-aaetq-cai", .token_symbol = "DAO", .decimals = 8},
    {.canister_id = "jg2ra-syaaa-aaaaq-aaewa-cai", .token_symbol = "CECIL", .decimals = 8},
    {.canister_id = "lvfsa-2aaaa-aaaaq-aaeyq-cai", .token_symbol = "ICX", .decimals = 8},
    {.token_symbol = "nICP", .decimals = 8, .canister_id = "buwm7-7yaaa-aaaar-qagva-cai"},
};

static const size_t NUM_TOKENS = sizeof(TOKEN_REGISTRY) / sizeof(token_info_t);

#define TOKEN_REGISTRY_SIZE (sizeof(TOKEN_REGISTRY) / sizeof(TOKEN_REGISTRY[0]))

// Function to remove hyphens and spaces from a string
void remove_hyphens(char *str) {
    char *src = str;
    char *dst = str;

    while (*src) {
        if (*src != '-' && *src != ' ') {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0';
}

bool compare_canister_ids(const char *id1, const char *id2) {
    if (id1 == NULL || id2 == NULL) {
        return false;
    }

    size_t i = 0;
    size_t j = 0;

    size_t count = 0;

    while (id1[i] != '\0' && id2[j] != '\0' && count < CANISTER_ID_STR_MAX_LEN) {
        // Skip hyphens and spaces in first ID
        while ((id1[i] == '-' || id1[i] == ' ') && count < CANISTER_ID_STR_MAX_LEN) {
            i++;
        }

        // Skip hyphens and spaces in second ID
        while ((id2[j] == '-' || id2[j] == ' ') && count < CANISTER_ID_STR_MAX_LEN) {
            j++;
        }

        if (id1[i] == '\0' || id2[j] == '\0') {
            break;
        }

        if (id1[i] != id2[j]) {
            return false;
        }

        i++;
        j++;
        count++;
    }

    while ((id1[i] == '-' || id1[i] == ' ') && count < CANISTER_ID_STR_MAX_LEN) {
        i++;
        count++;
    }
    while ((id2[j] == '-' || id2[j] == ' ') && count < CANISTER_ID_STR_MAX_LEN) {
        j++;
        count++;
    }

    // Both strings should be at their end
    bool equal = (id1[i] == '\0' && id2[j] == '\0');
    return equal;
}

// Function to get decimals for a canister ID
const token_info_t *get_token(const uint8_t *canister_id, size_t len) {
    if (canister_id == NULL || len > CANISTER_MAX_LEN) {
        return NULL;
    }

    char canister[CANISTER_TEXTUAL_BUFFER_SIZE] = {0};
    char canister_no_hyphens[CANISTER_TEXTUAL_BUFFER_SIZE] = {0};
    uint16_t textual_len = sizeof(canister_no_hyphens) - 1;  // Reserve space for null terminator

    // Convert binary principal to textual representation
    if (crypto_principalToTextual(canister_id, (uint16_t)len, canister_no_hyphens, &textual_len) != zxerr_ok) {
        return NULL;
    }

    // Format with delimiters - use the actual textual length, not the binary length
    if (format_principal_with_delimiters(canister_no_hyphens, textual_len, canister, sizeof(canister)) != parser_ok) {
        return NULL;
    }

    // Now look up in registry
    for (size_t i = 0; i < TOKEN_REGISTRY_SIZE; i++) {
        const char *id = TOKEN_REGISTRY[i].canister_id;
        if (compare_canister_ids(canister, id)) {
            return (const token_info_t *)&TOKEN_REGISTRY[i];
        }
    }

    return NULL;
}

// Number of tokens that fit into the APDU buffer
uint8_t token_registry_size(void) { return NUM_TOKENS; }

uint16_t get_token_i(size_t index, uint8_t *out, uint16_t out_len) {
    if ((index >= NUM_TOKENS) || out == NULL) {
        return 0;
    }
    const token_info_t *token = &TOKEN_REGISTRY[index];

    uint8_t canister_len = strlen(token->canister_id);
    uint8_t symbol_len = strlen(token->token_symbol);

    // Calculate exact size needed for this specific token
    uint16_t token_size = 1 + canister_len + 1 + symbol_len + sizeof(token->decimals);

    if (out_len < token_size) {
        return 0;
    }

    uint16_t offset = 0;

    // Write canister id length and data
    out[offset] = canister_len;
    offset += 1;
    MEMCPY(out + offset, token->canister_id, canister_len);
    offset += canister_len;

    out[offset] = symbol_len;
    offset += 1;
    MEMCPY(out + offset, token->token_symbol, symbol_len);
    offset += symbol_len;

    // Write decimals
    MEMCPY(out + offset, &token->decimals, sizeof(token->decimals));
    offset += sizeof(token->decimals);

    return offset;
}
