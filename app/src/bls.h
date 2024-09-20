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
#pragma once

#include "zxerror.h"
#include "rslib.h"

#ifdef __cplusplus
extern "C" {
#endif

zxerr_t bls_saveConsentRequest(void);
zxerr_t bls_saveCanisterCall(void);
zxerr_t bls_saveRootKey(uint8_t *root_key);
zxerr_t bls_verify();
uint8_t *bls_root_key();
void reset_bls_state();
#ifdef __cplusplus
}
#endif
#endif
