/*******************************************************************************
*   (c) 2019 Zondax GmbH
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

#include <stdio.h>
#include <zxmacros.h>
#include <app_mode.h>
#include "candid_parser.h"
#include "parser_impl.h"
#include "parser.h"
#include "coin.h"
#include "parser_txdef.h"
#include "crypto.h"
#include "formatting.h"
#include "zxformat.h"
#include "timeutils.h"

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
// For some reason NanoX requires this function
void __assert_fail(__Z_UNUSED const char * assertion, __Z_UNUSED const char * file, __Z_UNUSED unsigned int line, __Z_UNUSED const char * function){
    while(1) {};
}
#endif

#define GEN_DEC_READFIX_UNSIGNED(BITS) parser_error_t _readUInt ## BITS(parser_context_t *ctx, uint ## BITS ##_t *value) \
{                                                                                           \
    if (value == NULL)  return parser_no_data;                                              \
    *value = 0u;                                                                            \
    for(uint8_t i=0u; i < (BITS##u>>3u); i++, ctx->offset++) {                              \
        if (ctx->offset >= ctx->bufferLen) return parser_unexpected_buffer_end;             \
        *value += (uint ## BITS ##_t) *(ctx->buffer + ctx->offset) << (8u*i);               \
    }                                                                                       \
    return parser_ok;                                                                       \
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
    //if combined_tx:
    //split data in two transactions
    //should start with checking status
    //add one more check in validate
    //define txtype
    const uint8_t *start_state_read_data = data;
    CHECK_PARSER_ERR(parser_init(ctx, start_state_read_data, dataLen))
    uint32_t dataLen_state_read = 0;
    CHECK_PARSER_ERR(_readUInt32(ctx, &dataLen_state_read))
    PARSER_ASSERT_OR_ERROR(4 + dataLen_state_read < dataLen, parser_value_out_of_range)
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

    PARSER_ASSERT_OR_ERROR(dataLen == dataLen_request + dataLen_state_read + 8, parser_value_out_of_range)
    ctx->bufferLen = 4 + dataLen_request;

    CHECK_PARSER_ERR(readEnvelope(ctx, &parser_tx_obj))
    PARSER_ASSERT_OR_ERROR(parser_tx_obj.txtype == call, parser_unexpected_type)
    CHECK_PARSER_ERR(_validateTx(ctx, &parser_tx_obj))

    uint8_t request_hash[32];
    MEMZERO(request_hash, sizeof(request_hash));
    PARSER_ASSERT_OR_ERROR(zxerr_ok == crypto_getDigest(request_hash, call), parser_unexpected_error)

#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2)
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    PARSER_ASSERT_OR_ERROR(memcmp(request_hash, request_id_stateread, 32) == 0, parser_context_invalid_chars)
    MEMCPY(G_io_apdu_buffer, request_hash, 32);
    MEMCPY(G_io_apdu_buffer + 32, state_hash, 32);
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
    CHECK_PARSER_ERR(_validateTx(ctx, &parser_tx_obj))
    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))

    char tmpKey[100];
    char tmpVal[100];

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_PARSER_ERR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }

    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    *num_items = _getNumItems(ctx, &parser_tx_obj);
    PARSER_ASSERT_OR_ERROR(*num_items > 0, parser_unexpected_number_items)
    return parser_ok;
}

__Z_INLINE parser_error_t print_u64(uint64_t value,
                                    char *outVal, uint16_t outValLen,
                                    uint8_t pageIdx, uint8_t *pageCount) {
    char buffer[100];
    MEMZERO(buffer, sizeof(buffer));
    fpuint64_to_str(buffer, sizeof(buffer), value, 0);
    pageString(outVal, outValLen, buffer, pageIdx, pageCount);
    return parser_ok;

}

__Z_INLINE parser_error_t print_ICP(uint64_t value,
                                    char *outVal, uint16_t outValLen,
                                    uint8_t pageIdx, uint8_t *pageCount) {
    char buffer[200];
    MEMZERO(buffer, sizeof(buffer));

    zxerr_t err = formatICP(buffer, sizeof(buffer), value);
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    pageString(outVal, outValLen, buffer, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t print_textual(uint8_t *data, uint16_t len,
                                        char *outVal, uint16_t outValLen,
                                        uint8_t pageIdx, uint8_t *pageCount) {
    char tmpBuffer[100];
    uint16_t outLen = sizeof(tmpBuffer);
    zxerr_t err = crypto_principalToTextual((const uint8_t *) data, len, (char *) tmpBuffer,
                                            &outLen);
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    char buffer[100];
    MEMZERO(buffer, sizeof(buffer));
    err = addr_to_textual(buffer, sizeof(buffer), (const char *) tmpBuffer, outLen);   \
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    // Remove trailing dashes
    if (buffer[17] == '-') buffer[17] = ' ';
    if (buffer[35] == '-') buffer[35] = ' ';
    if (buffer[53] == '-') buffer[53] = ' ';

    pageString(outVal, outValLen, buffer, pageIdx, pageCount);

    return parser_ok;
}

__Z_INLINE zxerr_t print_hexstring(char *out, uint16_t outLen, const uint8_t *data, uint16_t dataLen) {
    MEMZERO(out, outLen);
    const uint32_t writtenBytes = array_to_hexstr(out, outLen, data, dataLen);
    if (writtenBytes != dataLen * 2) {
        return zxerr_out_of_bounds;
    }

    // insert spaces to force alignment
    CHECK_ZXERR(inplace_insert_char(out, outLen, 8, ' '))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 17, ' '))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 26, ' '))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 35, ' '))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 44, ' '))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 53, ' '))
    CHECK_ZXERR(inplace_insert_char(out, outLen, 62, ' '))

    return zxerr_ok;
}

__Z_INLINE parser_error_t print_accountBytes(sender_t sender,
                                             SendRequest *sendrequest,
                                             char *outVal, uint16_t outValLen,
                                             uint8_t pageIdx, uint8_t *pageCount) {
    uint8_t address[32];
    MEMZERO(address, sizeof(address));

    zxerr_t err = crypto_principalToSubaccount(sender.data, sender.len,
                                               sendrequest->from_subaccount.sub_account, 32,
                                               address, sizeof(address));
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    char buffer[80];
    err = print_hexstring(buffer, sizeof(buffer), (uint8_t *) address, 32);
    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }

    pageString(outVal, outValLen, buffer, pageIdx, pageCount);

    return parser_ok;
}

// 365.25 * 24*60*60 = 31557600
#define ICP_YEAR_IN_SECONDS ((uint64_t)31557600)

parser_error_t parser_printDelay(uint64_t value, char *buffer, uint16_t bufferSize) {
    MEMZERO(buffer, bufferSize);
    uint16_t index = 0;
    uint64_t years = value / ICP_YEAR_IN_SECONDS;
    if (years >= 1) {
        index += fpuint64_to_str(buffer, bufferSize, years, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end)
        MEMCPY(buffer + index, (char *) "y", 1);
        index += 1;
    }
    value %= ICP_YEAR_IN_SECONDS;

    uint64_t days = value / (uint64_t) (60 * 60 * 24);
    if (days > 0) {
        if (index > 0) {
            PARSER_ASSERT_OR_ERROR(index + 2 < bufferSize, parser_unexpected_buffer_end)
            MEMCPY(buffer + index, (char *) ", ", 2);
            index += 2;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, days, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end)
        MEMCPY(buffer + index, (char *) "d", 1);
        index += 1;
    }
    value %= (uint64_t) (60 * 60 * 24);

    uint64_t hours = value / (uint64_t) (60 * 60);
    if (hours > 0) {
        if (index > 0) {
            PARSER_ASSERT_OR_ERROR(index + 2 < bufferSize, parser_unexpected_buffer_end)
            MEMCPY(buffer + index, (char *) ", ", 2);
            index += 2;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, hours, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end)
        MEMCPY(buffer + index, (char *) "h", 1);
        index += 1;
    }
    value %= (uint64_t) (60 * 60);

    uint64_t minutes = value / (uint64_t) (60);
    if (minutes > 0) {
        if (index > 0) {
            PARSER_ASSERT_OR_ERROR(index + 2 < bufferSize, parser_unexpected_buffer_end)
            MEMCPY(buffer + index, (char *) ", ", 2);
            index += 2;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, minutes, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end)
        MEMCPY(buffer + index, (char *) "m", 1);
        index += 1;
    }
    value %= (uint64_t) (60);

    uint64_t seconds = value;
    if (seconds > 0) {
        if (index > 0) {
            PARSER_ASSERT_OR_ERROR(index + 2 < bufferSize, parser_unexpected_buffer_end)
            MEMCPY(buffer + index, (char *) ", ", 2);
            index += 2;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, seconds, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end)
        MEMCPY(buffer + index, (char *) "s", 1);
        index += 1;
    }

    buffer[index] = 0;
    return parser_ok;
}

static parser_error_t parser_getItemTransactionStateRead(const parser_context_t *ctx,
                                                  uint8_t displayIdx,
                                                  char *outKey, uint16_t outKeyLen,
                                                  char *outVal, uint16_t outValLen,
                                                  uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");
    *pageCount = 1;

    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    if (displayIdx < 0 || displayIdx >= numItems) {
        return parser_no_data;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Check status");
        return parser_ok;
    }

    if (app_mode_expert()) {
        state_read_t *fields = &parser_tx_obj.tx_fields.stateRead;

        if (displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Sender ");
            return print_textual(fields->sender.data, fields->sender.len, outVal, outValLen, pageIdx, pageCount);
        }

        displayIdx -= 2;

        if (displayIdx < 0 || displayIdx >= fields->paths.arrayLen) {
            return parser_no_data;
        }

        snprintf(outKey, outKeyLen, "Request ID ");
        char buffer[100];
        zxerr_t err = print_hexstring(buffer, sizeof(buffer),
                                      fields->paths.paths[1].data,
                                      fields->paths.paths[1].len);
        if (err != zxerr_ok) {
            return parser_unexpected_error;
        }

        pageString(outVal, outValLen, (char *) buffer, pageIdx, pageCount);
    }

    return parser_ok;
}

static parser_error_t parser_getItemTokenTransfer(const parser_context_t *ctx,
                                                  uint8_t displayIdx,
                                                  char *outKey, uint16_t outKeyLen,
                                                  char *outVal, uint16_t outValLen,
                                                  uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");
    *pageCount = 1;

    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    call_t *fields = &parser_tx_obj.tx_fields.call;

    if (displayIdx < 0 || displayIdx >= numItems) {
        return parser_no_data;
    }

    const bool is_stake_tx = parser_tx_obj.special_transfer_type == neuron_stake_transaction;
    if (is_stake_tx) {
        return parser_unexpected_error;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Send ICP");
        return parser_ok;
    }

    if (app_mode_expert()) {
        if (displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Sender ");
            return print_textual(fields->sender.data, fields->sender.len, outVal, outValLen, pageIdx, pageCount);
        }

        if (displayIdx == 2) {
            snprintf(outKey, outKeyLen, "Subaccount ");
            snprintf(outVal, outValLen, "Not set");

            if (fields->data.SendRequest.has_from_subaccount) {
                char buffer[100];
                zxerr_t err = print_hexstring(buffer, sizeof(buffer),
                                              fields->data.SendRequest.from_subaccount.sub_account, 32);
                if (err != zxerr_ok) {
                    return parser_unexpected_error;
                }
                pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            }

            return parser_ok;
        }
        displayIdx -= 2;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "From account");
        return print_accountBytes(fields->sender, &fields->data.SendRequest,
                                  outVal, outValLen,
                                  pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        PARSER_ASSERT_OR_ERROR(fields->data.SendRequest.has_to, parser_unexpected_number_items)
        snprintf(outKey, outKeyLen, "To account ");

        char buffer[100];
        zxerr_t err = print_hexstring(buffer, sizeof(buffer), (uint8_t *) fields->data.SendRequest.to.hash, 32);
        if (err != zxerr_ok) {
            return parser_unexpected_error;
        }

        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Payment (ICP)");
        PARSER_ASSERT_OR_ERROR(fields->data.SendRequest.payment.has_receiver_gets, parser_unexpected_number_items)
        return print_ICP(fields->data.SendRequest.payment.receiver_gets.e8s,
                         outVal, outValLen,
                         pageIdx, pageCount);
    }

    if (displayIdx == 4) {
        snprintf(outKey, outKeyLen, "Maximum fee (ICP)");
        PARSER_ASSERT_OR_ERROR(fields->data.SendRequest.has_max_fee, parser_unexpected_number_items)
        return print_ICP(fields->data.SendRequest.max_fee.e8s,
                         outVal, outValLen,
                         pageIdx, pageCount);
    }

    if (displayIdx == 5) {
        snprintf(outKey, outKeyLen, "Memo");
        PARSER_ASSERT_OR_ERROR(fields->data.SendRequest.has_memo, parser_unexpected_number_items)
        return print_u64(fields->data.SendRequest.memo.memo, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemStakeNeuron(const parser_context_t *ctx,
                                                uint8_t displayIdx,
                                                char *outKey, uint16_t outKeyLen,
                                                char *outVal, uint16_t outValLen,
                                                uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");
    *pageCount = 1;

    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    call_t *fields = &parser_tx_obj.tx_fields.call;

    if (displayIdx < 0 || displayIdx >= numItems) {
        return parser_no_data;
    }

    const bool is_stake_tx = parser_tx_obj.special_transfer_type == neuron_stake_transaction;
    if (!is_stake_tx) {
        return parser_unexpected_error;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Stake Neuron");
        return parser_ok;
    }

    if (app_mode_expert()) {
        if (displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Sender ");
            return print_textual(fields->sender.data, fields->sender.len, outVal, outValLen, pageIdx, pageCount);
        }

        if (displayIdx == 2) {
            snprintf(outKey, outKeyLen, "Subaccount ");
            snprintf(outVal, outValLen, "Not set");

            if (fields->data.SendRequest.has_from_subaccount) {
                char buffer[100];
                zxerr_t err = print_hexstring(buffer, sizeof(buffer),
                                              fields->data.SendRequest.from_subaccount.sub_account, 32);
                if (err != zxerr_ok) {
                    return parser_unexpected_error;
                }
                pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            }

            return parser_ok;
        }
        displayIdx -= 2;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "From account");
        return print_accountBytes(fields->sender, &fields->data.SendRequest,
                                  outVal, outValLen,
                                  pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Payment (ICP)");
        PARSER_ASSERT_OR_ERROR(fields->data.SendRequest.payment.has_receiver_gets, parser_unexpected_number_items)
        return print_ICP(fields->data.SendRequest.payment.receiver_gets.e8s,
                         outVal, outValLen,
                         pageIdx, pageCount);
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Maximum fee (ICP)");
        PARSER_ASSERT_OR_ERROR(fields->data.SendRequest.has_max_fee, parser_unexpected_number_items)
        return print_ICP(fields->data.SendRequest.max_fee.e8s,
                         outVal, outValLen,
                         pageIdx, pageCount);
    }

    if (displayIdx == 4) {
        snprintf(outKey, outKeyLen, "Memo");
        PARSER_ASSERT_OR_ERROR(fields->data.SendRequest.has_memo, parser_unexpected_number_items)
        return print_u64(fields->data.SendRequest.memo.memo, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemStartStopDissolve(uint8_t displayIdx,
                                                      char *outKey, uint16_t outKeyLen,
                                                      char *outVal, uint16_t outValLen,
                                                      uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");

        manageNeuron_e mn_type;
        CHECK_PARSER_ERR(getManageNeuronType(&parser_tx_obj, &mn_type))

        if (mn_type == Configure_StartDissolving) {
            snprintf(outVal, outValLen, "Start Dissolve     Neuron");
        } else {
            snprintf(outVal, outValLen, "Stop Dissolve      Neuron");
        }
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        PARSER_ASSERT_OR_ERROR(!(fields->has_id && (fields->which_neuron_id_or_subaccount == 12 ||
                                                    fields->which_neuron_id_or_subaccount == 11)),
                               parser_unexpected_number_items)

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        } else if (fields->which_neuron_id_or_subaccount == 12) {
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        } else {
            //Only accept neuron_id
            return parser_unexpected_type;
        }
    }

    return parser_no_data;
}

static parser_error_t parser_getItemLeaveCommunityFund(uint8_t displayIdx,
                                                       char *outKey, uint16_t outKeyLen,
                                                       char *outVal, uint16_t outValLen,
                                                       uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    PARSER_ASSERT_OR_ERROR(fields->command.hash == hash_command_Configure, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.has_operation, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.hash == hash_operation_LeaveCommunityFund,
                           parser_unexpected_value)

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Leave Community Fund");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemSetDissolveTimestamp(uint8_t displayIdx,
                                                         char *outKey, uint16_t outKeyLen,
                                                         char *outVal, uint16_t outValLen,
                                                         uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    PARSER_ASSERT_OR_ERROR(fields->command.hash == hash_command_Configure, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.has_operation, parser_unexpected_value)
    PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.hash == hash_operation_SetDissolvedTimestamp,
                           parser_unexpected_value)

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Set Dissolve Delay");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Dissolve Time");
        uint64_t dissolve_timestamp_seconds = fields->command.configure.operation.setDissolveTimestamp.dissolve_timestamp_seconds;

        timedata_t td;
        zxerr_t zxerr = decodeTime(&td, dissolve_timestamp_seconds);
        if (zxerr != zxerr_ok) {
            return parser_unexpected_value;
        }

        char tmpBuffer[100];
        // YYYYmmdd HH:MM:SS
        snprintf(tmpBuffer, sizeof(tmpBuffer), "%04d-%02d-%02d %02d:%02d:%02d UTC",
                 td.tm_year, td.tm_mon, td.tm_day,
                 td.tm_hour, td.tm_min, td.tm_sec
        );

        pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemSpawn(uint8_t displayIdx,
                                          char *outKey, uint16_t outKeyLen,
                                          char *outVal, uint16_t outValLen,
                                          uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Spawn Neuron");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        PARSER_ASSERT_OR_ERROR(!(fields->has_id && (fields->which_neuron_id_or_subaccount == 12 ||
                                                    fields->which_neuron_id_or_subaccount == 11)),
                               parser_unexpected_number_items)

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->which_neuron_id_or_subaccount == 12) {
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Controller ");
        if (!fields->command.spawn.has_new_controller) {

            snprintf(outVal, outValLen, "Self");
            return parser_ok;
        }

        PARSER_ASSERT_OR_ERROR(fields->command.spawn.new_controller.serialized_id.size <= 29,
                               parser_value_out_of_range)

        return print_textual(fields->command.spawn.new_controller.serialized_id.bytes,
                             29,
                             outVal, outValLen,
                             pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemSpawnCandid(uint8_t displayIdx,
                                          char *outKey, uint16_t outKeyLen,
                                          char *outVal, uint16_t outValLen,
                                          uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;

    const uint8_t has_percentage_to_spawn = fields->command.spawn.has_percentage_to_spawn;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Spawn Neuron");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2 && has_percentage_to_spawn) {
        snprintf(outKey, outKeyLen, "Percentage to spawn");
        snprintf(outVal, outValLen, "%d", fields->command.spawn.percentage_to_spawn);
        return parser_ok;
    }

    if ((displayIdx == 2 && !has_percentage_to_spawn) ||
        (displayIdx == 3 && has_percentage_to_spawn)) {
        snprintf(outKey, outKeyLen, "Controller");
        if (!fields->command.spawn.has_controller) {

            snprintf(outVal, outValLen, "Self");
            return parser_ok;
        }

        //Paged fields need space ending
        snprintf(outKey, outKeyLen, "Controller ");
        return print_textual(fields->command.spawn.new_controller,
                             29,
                             outVal, outValLen,
                             pageIdx, pageCount);
    }

    if (fields->command.spawn.has_nonce &&
        ((displayIdx == 3 && !has_percentage_to_spawn) || displayIdx == 4)) {
        snprintf(outKey, outKeyLen, "Nonce");
        return print_u64(fields->command.spawn.nonce, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemSplit(uint8_t displayIdx,
                                          char *outKey, uint16_t outKeyLen,
                                          char *outVal, uint16_t outValLen,
                                          uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    PARSER_ASSERT_OR_ERROR(fields->command.hash == hash_command_Split, parser_unexpected_value)

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Split Neuron");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Amount (ICP)");
        return print_ICP(fields->command.split.amount_e8s, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemMerge(uint8_t displayIdx,
                                          char *outKey, uint16_t outKeyLen,
                                          char *outVal, uint16_t outValLen,
                                          uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    candid_ManageNeuron_t *fields = &parser_tx_obj.tx_fields.call.data.candid_manageNeuron;
    PARSER_ASSERT_OR_ERROR(fields->command.hash == hash_command_Merge, parser_unexpected_value)

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Merge Neuron");
        return parser_ok;
    }

    if (displayIdx == 1) {
        if (!fields->command.merge.has_source) {
            return parser_no_data;
        }

        snprintf(outKey, outKeyLen, "Neuron ID");
        return print_u64(fields->command.merge.source.id, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Into Neuron ID");

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->has_neuron_id_or_subaccount && fields->neuron_id_or_subaccount.which == 1) {
            return print_u64(fields->neuron_id_or_subaccount.neuronId.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemAddRemoveHotkey(uint8_t displayIdx,
                                                    char *outKey, uint16_t outKeyLen,
                                                    char *outVal, uint16_t outValLen,
                                                    uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");

        manageNeuron_e mn_type;
        CHECK_PARSER_ERR(getManageNeuronType(&parser_tx_obj, &mn_type))

        if (mn_type == Configure_AddHotKey) {
            snprintf(outVal, outValLen, "Add Hotkey");
        } else {
            snprintf(outVal, outValLen, "Remove Hotkey");
        }

        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        PARSER_ASSERT_OR_ERROR(!(fields->has_id && (fields->which_neuron_id_or_subaccount == 12 ||
                                                    fields->which_neuron_id_or_subaccount == 11)),
                               parser_unexpected_number_items)

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->which_neuron_id_or_subaccount == 12) {
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }


    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Principal ");
        manageNeuron_e mn_type;
        CHECK_PARSER_ERR(getManageNeuronType(&parser_tx_obj, &mn_type))

        if (mn_type == Configure_AddHotKey) {
            PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.add_hot_key.has_new_hot_key,
                                   parser_unexpected_number_items)
            PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.add_hot_key.new_hot_key.serialized_id.size <= 29,
                                   parser_value_out_of_range)
            return print_textual(fields->command.configure.operation.add_hot_key.new_hot_key.serialized_id.bytes, 29,
                                 outVal, outValLen, pageIdx, pageCount);
        }

        PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.remove_hot_key.has_hot_key_to_remove,
                               parser_unexpected_number_items)
        PARSER_ASSERT_OR_ERROR(
                fields->command.configure.operation.remove_hot_key.hot_key_to_remove.serialized_id.size <= 29,
                parser_value_out_of_range)

        return print_textual(
                fields->command.configure.operation.remove_hot_key.hot_key_to_remove.serialized_id.bytes, 29,
                outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemDisburse(uint8_t displayIdx,
                                             char *outKey, uint16_t outKeyLen,
                                             char *outVal, uint16_t outValLen,
                                             uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Disburse Neuron");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        PARSER_ASSERT_OR_ERROR(!(fields->has_id && (fields->which_neuron_id_or_subaccount == 12 ||
                                                    fields->which_neuron_id_or_subaccount == 11)),
                               parser_unexpected_number_items)
        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->which_neuron_id_or_subaccount == 12) {
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Disburse To ");

        if (!fields->command.disburse.has_to_account) {
            snprintf(outVal, outValLen, "Self");
            return parser_ok;
        }

        PARSER_ASSERT_OR_ERROR(fields->command.disburse.to_account.hash.size == 32, parser_context_unexpected_size)

        char buffer[80];
        zxerr_t err = print_hexstring(buffer, sizeof(buffer),
                                      (uint8_t *) fields->command.disburse.to_account.hash.bytes, 32);
        if (err != zxerr_ok) {
            return parser_unexpected_error;
        }

        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Amount (ICP)");

        if (!fields->command.disburse.has_amount) {
            snprintf(outVal, outValLen, "All");
            return parser_ok;
        }

        return print_ICP(fields->command.disburse.amount.e8s, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

static parser_error_t parser_getItemIncreaseNeuronTimer(uint8_t displayIdx,
                                                        char *outKey, uint16_t outKeyLen,
                                                        char *outVal, uint16_t outValLen,
                                                        uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Increase Dissolve  Delay");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        PARSER_ASSERT_OR_ERROR(!(fields->has_id && (fields->which_neuron_id_or_subaccount == 12 ||
                                                    fields->which_neuron_id_or_subaccount == 11)),
                               parser_unexpected_number_items)

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->which_neuron_id_or_subaccount == 12) {
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Additional Delay");

        if (fields->command.configure.operation.increase_dissolve_delay.additional_dissolve_delay_seconds == 0) {
            snprintf(outVal, outValLen, "0s");
            return parser_ok;
        }

        char buffer[100];
        MEMZERO(buffer, sizeof(buffer));
        uint64_t value = 0;
        MEMCPY(&value,
               &fields->command.configure.operation.increase_dissolve_delay.additional_dissolve_delay_seconds,
               4);

        CHECK_PARSER_ERR(parser_printDelay(value, buffer, sizeof(buffer)))
        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }
    return parser_no_data;
}

static parser_error_t parser_getItemMergeMaturity(uint8_t displayIdx,
                                                  char *outKey, uint16_t outKeyLen,
                                                  char *outVal, uint16_t outValLen,
                                                  uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Stake Maturity");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        PARSER_ASSERT_OR_ERROR(!(fields->has_id && (fields->which_neuron_id_or_subaccount == 12 ||
                                                    fields->which_neuron_id_or_subaccount == 11)),
                               parser_unexpected_number_items)

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->which_neuron_id_or_subaccount == 12) {
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Percentage");
        char buffer[100];
        MEMZERO(buffer, sizeof(buffer));
        uint64_t value = 0;
        MEMCPY(&value, &fields->command.merge_maturity.percentage_to_merge, 4);

        if (value > 100) {
            return parser_unexpected_value;
        }

        return print_u64(value, outVal, outValLen, pageIdx, pageCount);
    }
    return parser_no_data;
}

static parser_error_t parser_getItemJoinCommunityFund(uint8_t displayIdx,
                                                      char *outKey, uint16_t outKeyLen,
                                                      char *outVal, uint16_t outValLen,
                                                      uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Join Community     Fund");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        PARSER_ASSERT_OR_ERROR(!(fields->has_id && (fields->which_neuron_id_or_subaccount == 12 ||
                                                    fields->which_neuron_id_or_subaccount == 11)),
                               parser_unexpected_number_items)

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->which_neuron_id_or_subaccount == 12) {
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemRegisterVote(uint8_t displayIdx,
                                                 char *outKey, uint16_t outKeyLen,
                                                 char *outVal, uint16_t outValLen,
                                                 uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Register Vote");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        PARSER_ASSERT_OR_ERROR(!(fields->has_id && (fields->which_neuron_id_or_subaccount == 12 ||
                                                    fields->which_neuron_id_or_subaccount == 11)),
                               parser_unexpected_number_items)

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->which_neuron_id_or_subaccount == 12) {
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Proposal ID");
        char buffer[100];
        MEMZERO(buffer, sizeof(buffer));
        uint64_t value = 0;
        MEMCPY(&value, &fields->command.register_vote.proposal.id, 8);
        return print_u64(value, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Vote");
        ic_nns_governance_pb_v1_Vote v = fields->command.register_vote.vote;

        if (v == 0) {
            return parser_unexpected_value;
        }

        snprintf(outVal, outValLen, v == 1 ? "Yes" : "No");
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemFollow(uint8_t displayIdx,
                                           char *outKey, uint16_t outKeyLen,
                                           char *outVal, uint16_t outValLen,
                                           uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.data.ic_nns_governance_pb_v1_ManageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Follow");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        PARSER_ASSERT_OR_ERROR(!(fields->has_id && (fields->which_neuron_id_or_subaccount == 12 ||
                                                    fields->which_neuron_id_or_subaccount == 11)),
                               parser_unexpected_number_items)

        if (fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }

        if (fields->which_neuron_id_or_subaccount == 12) {
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }

        //Only accept neuron_id
        return parser_unexpected_type;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Topic");
        ic_nns_governance_pb_v1_Topic topic = fields->command.follow.topic;

        switch (topic) {
            case ic_nns_governance_pb_v1_Topic_TOPIC_UNSPECIFIED : {
                snprintf(outVal, outValLen, "Default");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_NEURON_MANAGEMENT : {
                snprintf(outVal, outValLen, "Neuron Management");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_EXCHANGE_RATE : {
                snprintf(outVal, outValLen, "Exchange Rate");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_NETWORK_ECONOMICS : {
                snprintf(outVal, outValLen, "Network Economics");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_GOVERNANCE : {
                snprintf(outVal, outValLen, "Governance");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_NODE_ADMIN : {
                snprintf(outVal, outValLen, "Node Admin");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_PARTICIPANT_MANAGEMENT : {
                snprintf(outVal, outValLen, "Participant Management");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_SUBNET_MANAGEMENT : {
                snprintf(outVal, outValLen, "Subnet Management");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_NETWORK_CANISTER_MANAGEMENT : {
                snprintf(outVal, outValLen, "Network Canister Management");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_KYC : {
                snprintf(outVal, outValLen, "KYC");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_NODE_PROVIDER_REWARDS : {
                snprintf(outVal, outValLen, "Node Provider Rewards");
                return parser_ok;
            }
            default: {
                return parser_unexpected_type;
            }
        }
    }

    uint8_t new_displayIdx = displayIdx - 3;
    pb_size_t follow_count = fields->command.follow.followees_count;

    if (follow_count > 99) {
        //check for number of chars, but the real limit is lower
        return parser_unexpected_number_items;
    }

    if (follow_count == 0) {
        if (new_displayIdx == 0) {
            snprintf(outKey, outKeyLen, "Followees");
            snprintf(outVal, outValLen, "None");
            return parser_ok;
        }

        return parser_unexpected_number_items;
    }

    if (new_displayIdx < follow_count) {
        uint64_t id = fields->command.follow.followees[new_displayIdx].id;
        new_displayIdx++; //higher by 1
        char buffer[100];
        MEMZERO(buffer, sizeof(buffer));
        uint16_t index = 0;
        MEMCPY(buffer, (char *) "Followees (", 11);
        index += 11;

        uint8_t tens = new_displayIdx / 10;
        if (tens > 0) {
            char ten = (char) ('0' + tens);
            MEMCPY(buffer + index, &ten, 1);
            index++;
        }

        uint8_t ones = new_displayIdx % 10;
        char one = (char) ('0' + ones);
        MEMCPY(buffer + index, &one, 1);
        index++;
        MEMCPY(buffer + index, ")", 1);
        snprintf(outKey, outKeyLen, "%s", buffer);
        return print_u64(id, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}


static parser_error_t parser_getItemClaimNeuron(uint8_t displayIdx,
                                                char *outKey, uint16_t outKeyLen,
                                                char *outVal, uint16_t outValLen) {
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Claim Neurons");
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemListNeurons(uint8_t displayIdx,
                                                char *outKey, uint16_t outKeyLen,
                                                char *outVal, uint16_t outValLen) {
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "List Own Neurons");
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemListNeuronsCandid(uint8_t displayIdx,
                                                      char *outKey, uint16_t outKeyLen,
                                                      char *outVal, uint16_t outValLen,
                                                      uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    candid_ListNeurons_t *fields = &parser_tx_obj.tx_fields.call.data.candid_listNeurons;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "List Own Neurons");
        return parser_ok;
    }
    if (displayIdx <= fields->neuron_ids_size) {
        snprintf(outKey, outKeyLen, "Neuron ID %d", displayIdx);
        uint64_t neuron_id = 0;
        CHECK_PARSER_ERR(getCandidNat64FromVec(fields->neuron_ids_ptr, &neuron_id, fields->neuron_ids_size, displayIdx - 1))
        return print_u64(neuron_id, outVal, outValLen, pageIdx, pageCount);
    }
    return parser_no_data;
}

static parser_error_t parser_getItemListUpdateNodeProvider(__Z_UNUSED const parser_context_t *_ctx,
                                                           uint8_t displayIdx,
                                                           char *outKey, uint16_t outKeyLen,
                                                           char *outVal, uint16_t outValLen,
                                                           uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    candid_UpdateNodeProvider_t *fields = &parser_tx_obj.tx_fields.call.data.candid_updateNodeProvider;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Set Node Provider : Reward Account");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Reward Account ");
        char buffer[100];
        zxerr_t err = print_hexstring(buffer, sizeof(buffer),
                                      fields->account_identifier.p,
                                      fields->account_identifier.len);
        if (err != zxerr_ok) {
            return parser_unexpected_error;
        }

        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }

    return parser_no_data;
}

static parser_error_t parser_getItemManageNeuron(const parser_context_t *ctx,
                                                 uint8_t displayIdx,
                                                 char *outKey, uint16_t outKeyLen,
                                                 char *outVal, uint16_t outValLen,
                                                 uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");
    *pageCount = 1;

    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    manageNeuron_e mn_type;
    CHECK_PARSER_ERR(getManageNeuronType(&parser_tx_obj, &mn_type))

    switch (mn_type) {
        case Configure_IncreaseDissolveDelay:
            return parser_getItemIncreaseNeuronTimer(displayIdx,
                                                     outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        case Configure_JoinCommunityFund :
            return parser_getItemJoinCommunityFund(displayIdx,
                                                   outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        case Configure_StopDissolving :
        case Configure_StartDissolving : {
            return parser_getItemStartStopDissolve(displayIdx,
                                                   outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }

        case Configure_LeaveCommunityFund: {
            return parser_getItemLeaveCommunityFund(displayIdx,
                                                      outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }

        case Configure_SetDissolvedTimestamp: {
            return parser_getItemSetDissolveTimestamp(displayIdx,
                                                      outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }

        case Spawn : {
            return parser_getItemSpawn(displayIdx,
                                       outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        case SpawnCandid: {
            return parser_getItemSpawnCandid(displayIdx,
                                        outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        case Split: {
            return parser_getItemSplit(displayIdx,
                                       outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        case Merge: {
            return parser_getItemMerge(displayIdx,
                                       outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }
        case Configure_RemoveHotKey:
        case Configure_AddHotKey:
            return parser_getItemAddRemoveHotkey(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case Disburse :
            return parser_getItemDisburse(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case MergeMaturity :
            return parser_getItemMergeMaturity(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case RegisterVote :
            return parser_getItemRegisterVote(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case Follow:
            return parser_getItemFollow(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        default:
            return parser_no_data;
    }
}

parser_error_t parser_getItem(const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    switch (parser_tx_obj.txtype) {
        case call: {
            switch (parser_tx_obj.tx_fields.call.method_type) {
                case pb_sendrequest : {
                    const bool is_stake_tx = parser_tx_obj.special_transfer_type == neuron_stake_transaction;

                    if (is_stake_tx) {
                        return parser_getItemStakeNeuron(ctx, displayIdx,
                                                         outKey, outKeyLen,
                                                         outVal, outValLen,
                                                         pageIdx, pageCount);
                    }

                    return parser_getItemTokenTransfer(ctx, displayIdx,
                                                       outKey, outKeyLen,
                                                       outVal, outValLen,
                                                       pageIdx, pageCount);
                }

                case pb_manageneuron :
                case candid_manageneuron: {
                    return parser_getItemManageNeuron(ctx, displayIdx,
                                                      outKey, outKeyLen,
                                                      outVal, outValLen,
                                                      pageIdx, pageCount);
                }

                case pb_listneurons : {
                    return parser_getItemListNeurons(displayIdx,
                                                     outKey, outKeyLen,
                                                     outVal, outValLen);
                }

                case pb_claimneurons : {
                    return parser_getItemClaimNeuron(displayIdx,
                                                     outKey, outKeyLen,
                                                     outVal, outValLen);
                }

                case candid_updatenodeprovider: {
                    return parser_getItemListUpdateNodeProvider(ctx, displayIdx,
                                                                outKey, outKeyLen,
                                                                outVal, outValLen,
                                                                pageIdx, pageCount);
                }

                case candid_listneurons: {
                    return parser_getItemListNeuronsCandid(displayIdx,
                                                           outKey, outKeyLen,
                                                           outVal, outValLen,
                                                           pageIdx, pageCount);
                }

                default :
                    break;
            }

        }
        case state_transaction_read: {
            return parser_getItemTransactionStateRead(ctx, displayIdx,
                                                      outKey, outKeyLen,
                                                      outVal, outValLen,
                                                      pageIdx, pageCount);
        }
        default :
            break;
    }

    return parser_unexpected_type;
}
