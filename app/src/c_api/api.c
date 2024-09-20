/*******************************************************************************
 *   (c) 2018 -2024 Zondax AG
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
#if defined(BLS_SIGNATURE)
#include "crypto.h"
#include "coin.h"

int8_t c_fill_principal(uint8_t *output, uint16_t output_len, uint16_t *response_len) {
    answer_t answer = {0};
    uint16_t addr_len = 0;

    if (output_len < DFINITY_PRINCIPAL_LEN){
        *response_len = 0;
        return -1;
    }
    zxerr_t err = crypto_fillAddress((uint8_t*)&answer, sizeof(answer), &addr_len);
    if (err != zxerr_ok) {
        *response_len = 0;
        return -1;
    }

    MEMCPY(output, answer.principalBytes, DFINITY_PRINCIPAL_LEN);

    *response_len = DFINITY_PRINCIPAL_LEN;

    return 0;
}
#endif
