/*******************************************************************************
*   (c) 2022 Zondax AG
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

#ifdef __cplusplus
extern "C" {
#endif

#include <zxmacros.h>
#include <zxerror.h>
#include "parser_common.h"

parser_error_t decompressLEB128(const uint8_t *input, uint16_t inputSize, uint64_t *v, uint16_t *bytesConsumed);

parser_error_t decompressSLEB128(const uint8_t *input, uint16_t inputSize, int64_t *v, uint16_t *bytesConsumed);

#ifdef __cplusplus
}
#endif
