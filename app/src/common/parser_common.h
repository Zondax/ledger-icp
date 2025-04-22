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

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "parser_txdef.h"

#define CHECK_PARSER_ERR(__CALL)              \
    {                                         \
        parser_error_t __err = __CALL;        \
        CHECK_APP_CANARY()                    \
        if (__err != parser_ok) return __err; \
    }

typedef enum {
    // Generic errors
    parser_ok = 0,
    parser_no_data,
    parser_init_context_empty,
    parser_display_idx_out_of_range,
    parser_display_page_out_of_range,
    parser_unexpected_error,
    parser_not_implemented,
    // Cbor
    parser_cbor_unexpected,
    parser_cbor_unexpected_EOF,
    parser_cbor_not_canonical,
    // Coin specific
    parser_unexpected_tx_version,
    parser_unexpected_type,
    parser_unexpected_method,
    parser_unexpected_buffer_end,
    parser_unexpected_value,
    parser_unexpected_number_items,
    parser_unexpected_characters,
    parser_unexpected_field,
    parser_value_out_of_range,
    parser_invalid_address,
    // Context related errors
    parser_context_mismatch,
    parser_context_unexpected_size,
    parser_context_invalid_chars,
    parser_context_unknown_prefix,
    // Required fields
    parser_required_nonce,
    parser_required_method,
    // Special codes
    parser_type_not_found,
    parser_invalid_label,
    parser_invalid_delegation,
    parser_invalid_certificate,
    parser_invalid_tree,
    parser_minicbor_error,
    parser_recursion_limit_reached,
    // New errors added from Rust
    parser_invalid_tag,
    parser_invalid_msg_metadata,
    parser_invalid_consent_msg,
    parser_invalid_utf8,
    parser_invalid_error_response,
    parser_invalid_response_type,
    parser_invalid_call_request,
    parser_invalid_consent_msg_request,
    parser_invalid_canister_id,
    parser_invalid_language,
    parser_too_many_types,
    parser_too_many_fields,
    parser_field_not_found,
    parser_leb128_overflow,
    parser_invalid_time,
    parser_invalid_visibility,
} parser_error_t;

typedef struct {
    const uint8_t *buffer;
    uint16_t bufferLen;
    uint16_t offset;
    parser_tx_t *tx_obj;
} parser_context_t;

#ifdef __cplusplus
}
#endif
