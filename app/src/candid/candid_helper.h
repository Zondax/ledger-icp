/*******************************************************************************
 *   (c) 2018 - 2023s Zondax AG
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

#include <zxerror.h>
#include <zxmacros.h>

#include "candid_types.h"
#include "parser_common.h"

typedef struct {
    uint64_t variant_index;
    uint64_t field_hash;
    int64_t implementation;
} candid_element_t;

typedef struct {
    uint16_t types_entry_point;
    parser_context_t ctx;
    int64_t txn_type;
    uint64_t txn_length;
    candid_element_t element;
} candid_transaction_t;

parser_error_t readCandidLEB128(parser_context_t *ctx, uint64_t *v);
parser_error_t readCandidSLEB128(parser_context_t *ctx, int64_t *v);

parser_error_t readCandidHeader(parser_context_t *ctx, candid_transaction_t *txn);
parser_error_t readAndCheckRootType(parser_context_t *ctx);

parser_error_t readCandidNat(parser_context_t *ctx, uint64_t *v);
parser_error_t readCandidNat32(parser_context_t *ctx, uint32_t *v);
parser_error_t readCandidNat64(parser_context_t *ctx, uint64_t *v);

parser_error_t readCandidInt32(parser_context_t *ctx, int32_t *v);

parser_error_t readCandidRecordLength(candid_transaction_t *txn);
parser_error_t readCandidByte(parser_context_t *ctx, uint8_t *v);
parser_error_t readCandidBytes(parser_context_t *ctx, uint8_t *buff, uint8_t buffLen);

parser_error_t readCandidOptional(candid_transaction_t *txn);
parser_error_t readCandidText(parser_context_t *ctx, sizedBuffer_t *v);

parser_error_t readCandidInnerElement(candid_transaction_t *txn, candid_element_t *element);

parser_error_t readCandidType(parser_context_t *ctx, int64_t *t);
parser_error_t readCandidTypeTable_Item(parser_context_t *ctx, const int64_t *type, __Z_UNUSED uint64_t typeIdx);

parser_error_t getCandidTypeFromTable(candid_transaction_t *txn, uint64_t table_index);
parser_error_t getHash(candid_transaction_t *txn, const uint8_t variant, uint64_t *hash);

#ifdef __cplusplus
}
#endif
