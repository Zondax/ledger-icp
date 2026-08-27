/*******************************************************************************
 *   (c) 2019 Zondax AG
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

#include "parser.h"

#include <app_mode.h>
#include <stdio.h>
#include <zxmacros.h>

#include "candid_parser.h"
#include "coin.h"
#include "crypto.h"
#include "formatting.h"
#include "parser_impl.h"
#include "parser_print_candid.h"
#include "parser_print_helper.h"
#include "parser_print_protobuf.h"
#include "parser_txdef.h"
#include "timeutils.h"
#include "zxformat.h"
#if defined(BLS_SIGNATURE)
#include "rslib.h"
#endif

#if defined(LEDGER_SPECIFIC)
// For some reason NanoX requires this function
void __assert_fail(__Z_UNUSED const char *assertion, __Z_UNUSED const char *file, __Z_UNUSED unsigned int line,
                   __Z_UNUSED const char *function) {
    while (1) {
    };
}

// Digests for the combined sign flow, captured while parsing and consumed when
// the user approves. Kept out of G_io_apdu_buffer on purpose: the SDK copies
// every incoming APDU into that buffer before handleApdu gets to reject it, so
// nothing stored there survives an async review intact.
static uint8_t combined_request_hash[32];
static uint8_t combined_state_hash[32];
static bool combined_digests_ready = false;

bool parser_combinedDigestsReady() { return combined_digests_ready; }

const uint8_t *parser_getCombinedRequestHash() { return combined_request_hash; }

const uint8_t *parser_getCombinedStateHash() { return combined_state_hash; }

void parser_clearCombinedDigests() {
    combined_digests_ready = false;
    MEMZERO(combined_request_hash, sizeof(combined_request_hash));
    MEMZERO(combined_state_hash, sizeof(combined_state_hash));
}
#endif

#define GEN_DEC_READFIX_UNSIGNED(BITS)                                              \
    parser_error_t _readUInt##BITS(parser_context_t *ctx, uint##BITS##_t *value) {  \
        if (value == NULL) return parser_no_data;                                   \
        *value = 0u;                                                                \
        for (uint8_t i = 0u; i < (BITS##u >> 3u); i++, ctx->offset++) {             \
            if (ctx->offset >= ctx->bufferLen) return parser_unexpected_buffer_end; \
            *value += (uint##BITS##_t) * (ctx->buffer + ctx->offset) << (8u * i);   \
        }                                                                           \
        return parser_ok;                                                           \
    }

GEN_DEC_READFIX_UNSIGNED(8)

GEN_DEC_READFIX_UNSIGNED(16)

GEN_DEC_READFIX_UNSIGNED(32)

GEN_DEC_READFIX_UNSIGNED(64)

parser_error_t parser_parse_combined(parser_context_t *ctx, const uint8_t *data, size_t dataLen) {
    if (dataLen < 1) {
        return parser_no_data;
    }
    zemu_log_stack("parser parse combined");
    // if combined_tx:
    // split data in two transactions
    // should start with checking status
    // add one more check in validate
    // define txtype
    const uint8_t *start_state_read_data = data;
    CHECK_PARSER_ERR(parser_init(ctx, start_state_read_data, dataLen))
    uint32_t dataLen_state_read = 0;
    CHECK_PARSER_ERR(_readUInt32(ctx, &dataLen_state_read))
    // Overflow-safe form of `4 + dataLen_state_read < dataLen`. Also reserves 4
    // bytes for the trailing request length prefix and 4+ bytes of request
    // body so the second parse below has something to read.
    PARSER_ASSERT_OR_ERROR(dataLen >= 8, parser_value_out_of_range)
    PARSER_ASSERT_OR_ERROR(dataLen_state_read < (size_t)(dataLen - 8), parser_value_out_of_range)
    ctx->bufferLen = 4 + dataLen_state_read;

    CHECK_PARSER_ERR(readEnvelope(ctx, &parser_tx_obj))
    PARSER_ASSERT_OR_ERROR(parser_tx_obj.txtype == state_transaction_read, parser_unexpected_type)
    CHECK_PARSER_ERR(_validateTx(ctx, &parser_tx_obj))
    uint8_t state_hash[32];
    MEMZERO(state_hash, sizeof(state_hash));
    PARSER_ASSERT_OR_ERROR(zxerr_ok == crypto_getDigest(state_hash, state_transaction_read), parser_unexpected_error)

    uint8_t request_id_stateread[32];
    MEMZERO(request_id_stateread, 32);
    PARSER_ASSERT_OR_ERROR(32 == parser_tx_obj.tx_fields.stateRead.paths.paths[1].len, parser_unexpected_error)

    MEMCPY(request_id_stateread, parser_tx_obj.tx_fields.stateRead.paths.paths[1].data, 32);

    data += 4 + dataLen_state_read;
    const uint8_t *start_request_data = data;
    CHECK_PARSER_ERR(parser_init(ctx, start_request_data, dataLen - 4 - dataLen_state_read))
    uint32_t dataLen_request = 0;
    CHECK_PARSER_ERR(_readUInt32(ctx, &dataLen_request))

    // Overflow-safe form of `dataLen == dataLen_request + dataLen_state_read + 8`.
    // `dataLen_state_read + 8 <= dataLen` is already established above, so
    // `dataLen - 8 - dataLen_state_read` cannot underflow.
    PARSER_ASSERT_OR_ERROR(dataLen_request == (size_t)(dataLen - 8 - dataLen_state_read), parser_value_out_of_range)
    ctx->bufferLen = 4 + dataLen_request;

    CHECK_PARSER_ERR(readEnvelope(ctx, &parser_tx_obj))
    PARSER_ASSERT_OR_ERROR(parser_tx_obj.txtype == call, parser_unexpected_type)
    CHECK_PARSER_ERR(_validateTx(ctx, &parser_tx_obj))

    uint8_t request_hash[32];
    MEMZERO(request_hash, sizeof(request_hash));
    PARSER_ASSERT_OR_ERROR(zxerr_ok == crypto_getDigest(request_hash, call), parser_unexpected_error)

#if defined(LEDGER_SPECIFIC)
    parser_clearCombinedDigests();
    PARSER_ASSERT_OR_ERROR(memcmp(request_hash, request_id_stateread, 32) == 0, parser_context_invalid_chars)
    MEMCPY(combined_request_hash, request_hash, 32);
    MEMCPY(combined_state_hash, state_hash, 32);
    combined_digests_ready = true;
#endif

    return parser_ok;
}

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen) {
    if (dataLen < 1) {
        return parser_no_data;
    }
    zemu_log_stack("parser parse");
    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen))
    return readEnvelope(ctx, &parser_tx_obj);
}

parser_error_t parser_validate(const parser_context_t *ctx) {
    zemu_log("parser_validate\n");
    CHECK_PARSER_ERR(_validateTx(ctx, &parser_tx_obj))
    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))

    char tmpKey[70] = {0};
    char tmpVal[180] = {0};  // up to 180 in stax

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_PARSER_ERR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }

    return parser_ok;
}

// ingress_expiry is nanoseconds since the Unix epoch; decodeTime takes seconds.
#define NANOSECONDS_PER_SECOND 1000000000ULL

static parser_error_t print_utc_time(uint64_t time_ns, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                                     uint8_t *pageCount) {
    timedata_t td = {0};
    if (decodeTime(&td, time_ns / NANOSECONDS_PER_SECOND) != zxerr_ok) {
        return parser_unexpected_value;
    }

    // decodeTime bounds every field, so the result is always 23 characters,
    // but the compiler only knows the fields are ints and sizes the worst case
    // at 30. Give it the room it thinks it needs rather than carrying a
    // truncation warning on every build.
    char buffer[36] = {0};
    snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d UTC", td.tm_year, td.tm_mon, td.tm_day, td.tm_hour,
             td.tm_min, td.tm_sec);

    pageString(outVal, outValLen, buffer, pageIdx, pageCount);
    return parser_ok;
}

// Both envelope types carry an ingress_expiry, and it is hashed into the
// request id for both.
static bool tx_has_ingress_expiry(void) {
    return parser_tx_obj.txtype == call || parser_tx_obj.txtype == state_transaction_read;
}

// Transfers carry a creation time that the receiving ledger deduplicates on.
// Leaving it out is legal and removes the dedup window entirely, so the same
// signed request can then be submitted more than once; it is signed either
// way, which is reason enough not to leave it off the screen.
static bool tx_created_at(bool *isSet, uint64_t *value_ns) {
    if (parser_tx_obj.txtype != call) {
        return false;
    }

    const call_t *fields = &parser_tx_obj.tx_fields.call;
    switch (fields->method_type) {
        case pb_sendrequest:
            *isSet = fields->data.SendRequest.has_created_at_time;
            *value_ns = fields->data.SendRequest.created_at_time.timestamp_nanos;
            return true;
        case candid_transfer:
            *isSet = fields->data.candid_transfer.has_timestamp;
            *value_ns = fields->data.candid_transfer.timestamp;
            return true;
        case candid_icrc_transfer:
            *isSet = fields->data.icrcTransfer.has_created_at_time;
            *value_ns = fields->data.icrcTransfer.created_at_time;
            return true;
        case candid_icrc2_approve:
            *isSet = fields->data.icrc2_approve.has_created_at_time;
            *value_ns = fields->data.icrc2_approve.created_at_time;
            return true;
        default:
            return false;
    }
}

static bool tx_has_created_at(void) {
    bool isSet = false;
    uint64_t value_ns = 0;
    return tx_created_at(&isSet, &value_ns);
}

static parser_error_t parser_getItemCreatedAt(char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                              uint8_t pageIdx, uint8_t *pageCount) {
    bool isSet = false;
    uint64_t value_ns = 0;
    if (!tx_created_at(&isSet, &value_ns)) {
        return parser_unexpected_type;
    }

    snprintf(outKey, outKeyLen, "Created at");
    if (!isSet) {
        snprintf(outVal, outValLen, "Not set");
        return parser_ok;
    }

    return print_utc_time(value_ns, outVal, outValLen, pageIdx, pageCount);
}

// ingress_expiry is signed but was never shown. It fixes how long a signed
// request stays submittable, so a host that sets it hours out can hold the
// approved transaction back and choose when it lands. The device has no clock
// and cannot judge the value on its own; rendering it as an absolute time is
// what lets the user notice a window that is not the customary few minutes.
static parser_error_t parser_getItemIngressExpiry(char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                  uint8_t pageIdx, uint8_t *pageCount) {
    uint64_t expiry_ns = 0;
    switch (parser_tx_obj.txtype) {
        case call:
            expiry_ns = parser_tx_obj.tx_fields.call.ingress_expiry;
            break;
        case state_transaction_read:
            expiry_ns = parser_tx_obj.tx_fields.stateRead.ingress_expiry;
            break;
        default:
            return parser_unexpected_type;
    }

    snprintf(outKey, outKeyLen, "Valid until");
    return print_utc_time(expiry_ns, outVal, outValLen, pageIdx, pageCount);
}

// Any path other than 0'/0/0 is named on screen, in both modes - accounts
// 1'-255' and indices 1-255 are reachable without expert mode, and expert mode
// lifts the range cap on top of that. Nothing used to say which account was
// signing. Only the device knows the requested path; off-device builds have no
// derivation to report.
static bool tx_has_custom_path(void) {
#if defined(LEDGER_SPECIFIC)
    return hdPath[2] != HDPATH_2_DEFAULT || hdPath[3] != HDPATH_3_DEFAULT || hdPath[4] != HDPATH_4_DEFAULT;
#else
    return false;
#endif
}

static parser_error_t parser_getItemSigningPath(char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                uint8_t pageIdx, uint8_t *pageCount) {
    char buffer[PRINT_BUFFER_SMALL_LEN] = {0};
    bip32_to_str(buffer, sizeof(buffer), hdPath, HDPATH_LEN_DEFAULT);

    snprintf(outKey, outKeyLen, "Signing account");
    pageString(outVal, outValLen, buffer, pageIdx, pageCount);
    return parser_ok;
}

// Rows appended after whatever the method-specific renderer produces, in the
// order listed here; each is present only when it applies.
typedef enum {
    tail_created_at = 0,
    tail_signing_path,
    tail_ingress_expiry,
    tail_item_count,
} tail_item_e;

static bool tx_has_tail_item(tail_item_e item) {
    switch (item) {
        case tail_created_at:
            return tx_has_created_at();
        case tail_signing_path:
            return tx_has_custom_path();
        case tail_ingress_expiry:
            return tx_has_ingress_expiry();
        default:
            return false;
    }
}

static uint8_t tx_tail_items(void) {
    uint8_t count = 0;
    for (tail_item_e item = 0; item < tail_item_count; item++) {
        if (tx_has_tail_item(item)) {
            count++;
        }
    }
    return count;
}

static parser_error_t parser_getItemTail(uint8_t tailIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                         uint8_t pageIdx, uint8_t *pageCount) {
    uint8_t seen = 0;
    for (tail_item_e item = 0; item < tail_item_count; item++) {
        if (!tx_has_tail_item(item)) {
            continue;
        }
        if (seen == tailIdx) {
            switch (item) {
                case tail_created_at:
                    return parser_getItemCreatedAt(outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
                case tail_signing_path:
                    return parser_getItemSigningPath(outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
                case tail_ingress_expiry:
                    return parser_getItemIngressExpiry(outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
                default:
                    return parser_no_data;
            }
        }
        seen++;
    }
    return parser_no_data;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    zemu_log_stack("parser_getNumItems");
    const uint8_t items = _getNumItems(ctx, &parser_tx_obj);
    PARSER_ASSERT_OR_ERROR(items > 0, parser_unexpected_number_items)

    const uint16_t total = (uint16_t)items + tx_tail_items();
    PARSER_ASSERT_OR_ERROR(total <= UINT8_MAX, parser_unexpected_number_items)

    *num_items = (uint8_t)total;
    return parser_ok;
}

static parser_error_t parser_getItemTransactionStateRead(const parser_context_t *ctx, uint8_t displayIdx, char *outKey,
                                                         uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                                         uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");
    *pageCount = 1;

    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    if (displayIdx >= numItems) {
        return parser_no_data;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Check status");
        return parser_ok;
    }

    const state_read_t *fields = &parser_tx_obj.tx_fields.stateRead;

    if (app_mode_expert()) {
        if (displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Sender ");
            return print_principal(fields->sender.data, (uint16_t)fields->sender.len, outVal, outValLen, pageIdx, pageCount);
        }
        displayIdx--;
    }

    if (displayIdx == 1) {
        // paths is ["request_status", <request id>], enforced at parse time.
        snprintf(outKey, outKeyLen, "Request ID ");
        return page_hexstring_with_delimiters(fields->paths.paths[1].data, fields->paths.paths[1].len, outVal, outValLen,
                                              pageIdx, pageCount);
    }

    return parser_no_data;
}

parser_error_t parser_getItem(const parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    // The tail rows come from the envelope, or from fields every transfer
    // carries, so they are rendered here rather than being threaded through
    // each of the per-method item functions.
    const uint8_t tail = tx_tail_items();
    if (tail > 0) {
        uint8_t numItems = 0;
        CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))
        if (displayIdx + tail >= numItems) {
            const uint8_t tailIdx = (uint8_t)(displayIdx - (numItems - tail));
            MEMZERO(outKey, outKeyLen);
            MEMZERO(outVal, outValLen);
            return parser_getItemTail(tailIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
    }

    switch (parser_tx_obj.txtype) {
        case call: {
            switch (parser_tx_obj.tx_fields.call.method_type) {
                case pb_sendrequest:
                case pb_manageneuron:
                case pb_listneurons:
                case pb_claimneurons: {
                    return parser_getItemProtobuf(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
                }

                case candid_manageneuron:
                case candid_listneurons:
                case candid_updatenodeprovider:
                case candid_transfer:
                case candid_icrc_transfer:
                case candid_icrc2_approve: {
                    return parser_getItemCandid(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
                }

                default:
                    break;
            }
            break;
        }
        case state_transaction_read: {
            return parser_getItemTransactionStateRead(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx,
                                                      pageCount);
        }
        default:
            break;
    }

    return parser_unexpected_type;
}

#if defined(BLS_SIGNATURE)
uint8_t parsed_obj_buffer[CERT_OBJ_MAX_SIZE];

parser_error_t parser_certNumItems(uint8_t *num_items) {
    CHECK_PARSER_ERR(rs_getNumItems(num_items));
    PARSER_ASSERT_OR_ERROR(*num_items > 0, parser_unexpected_number_items)
    return parser_ok;
}

parser_error_t parser_certGetItem(uint8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    return rs_getItem(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
}

parser_error_t parser_getIntent(char *outIntent, uint16_t intentLen) {
    if (outIntent == NULL || intentLen == 0) {
        return parser_no_data;
    }
    return rs_get_intent(outIntent, intentLen);
}
#endif
