/*******************************************************************************
*   (c) 2021 Zondax GmbH
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
#include "stdint.h"
#include "parser.h"

#ifdef __cplusplus
extern "C" {
#endif

zxerr_t inplace_insert_char(char *s, uint16_t sMaxLen, uint16_t pos, char separator);

zxerr_t number_inplace_thousands(char *s, uint16_t sMaxLen, char separator);

zxerr_t formatICP(char *out, uint16_t outLen, uint64_t value);

#ifdef __cplusplus
}
#endif