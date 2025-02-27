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
#pragma once

#include "parser_txdef.h"

#ifdef __cplusplus
extern "C" {
#endif

const token_info_t *get_token(const uint8_t *canister_id, uint8_t len);
uint8_t token_registry_size(void);
uint16_t get_token_i(size_t index, uint8_t *out, uint16_t out_len);

#ifdef __cplusplus
}
#endif
