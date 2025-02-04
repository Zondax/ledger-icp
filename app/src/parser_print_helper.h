/*******************************************************************************
*   (c) 2018 - 2023 Zondax AG
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
#include "candid_types.h"
#include "parser_common.h"
#include "parser_impl.h"

parser_error_t print_u64(uint64_t value, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);
parser_error_t print_ICP(uint64_t value, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);
parser_error_t print_Amount(uint64_t value, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount, uint8_t decimals);
parser_error_t print_principal(const uint8_t *data, uint16_t len, char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount);
parser_error_t parser_printDelay(uint64_t value, char *buffer, uint16_t bufferSize);

parser_error_t page_hexstring_with_delimiters(const uint8_t *input, const uint64_t inputLen,
                                              char *output, const uint16_t outputLen,
                                              const uint8_t pageIdx, uint8_t *pageCount);
parser_error_t page_principal_with_subaccount(const uint8_t *sender, uint16_t senderLen,
                                              const uint8_t *fromSubaccount, uint16_t fromSubaccountLen,
                                              char *outVal, uint16_t outValLen,
                                              uint8_t pageIdx, uint8_t *pageCount);

parser_error_t page_textual_with_delimiters(const char *input, const uint16_t inputLen, char *output, const uint16_t outputLen, const uint8_t pageIdx, uint8_t *pageCount);

parser_error_t format_principal_with_delimiters(const char *input, const uint16_t inputLen,
                                              char *output, const uint16_t outputLen);

parser_error_t format_principal(const uint8_t *data, uint16_t len,
                              char *outVal, uint16_t outValLen);

#ifdef __cplusplus
}
#endif
