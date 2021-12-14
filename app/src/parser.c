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
#include "parser_impl.h"
#include "parser.h"
#include "coin.h"
#include "parser_txdef.h"
#include "crypto.h"
#include "formatting.h"

#if defined(TARGET_NANOX)
// For some reason NanoX requires this function
void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function){
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

GEN_DEC_READFIX_UNSIGNED(8);

GEN_DEC_READFIX_UNSIGNED(16);

GEN_DEC_READFIX_UNSIGNED(32);

GEN_DEC_READFIX_UNSIGNED(64);


parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen) {
    if (dataLen < 1) {
        return parser_no_data;
    }
    zemu_log_stack("parser parse");
    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen))
    return _readEnvelope(ctx, &parser_tx_obj);
}

parser_error_t parser_validate(const parser_context_t *ctx) {
    CHECK_PARSER_ERR(_validateTx(ctx, &parser_tx_obj))
    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems));

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
        return parser_unexepected_error;
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
        return parser_unexepected_error;
    }

    char buffer[100];
    MEMZERO(buffer, sizeof(buffer));
    err = addr_to_textual(buffer, sizeof(buffer), (const char *) tmpBuffer, outLen);   \
    if (err != zxerr_ok) {
        return parser_unexepected_error;
    }

    // Remove trailing dashes
    if (buffer[17] == '-') buffer[17] = ' ';
    if (buffer[35] == '-') buffer[35] = ' ';
    if (buffer[53] == '-') buffer[53] = ' ';

    pageString(outVal, outValLen, buffer, pageIdx, pageCount);

    return parser_ok;
}

__Z_INLINE zxerr_t print_hexstring(char *out, uint16_t outLen, uint8_t *data, uint16_t dataLen) {
    MEMZERO(out, outLen);
    const uint32_t writtenBytes = array_to_hexstr(out, outLen, data, dataLen);
    if (writtenBytes != dataLen*2) {
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
        return parser_unexepected_error;
    }

    char buffer[80];
    err = print_hexstring(buffer, sizeof(buffer), (uint8_t *) address, 32);
    if (err != zxerr_ok) {
        return parser_unexepected_error;
    }

    pageString(outVal, outValLen, buffer, pageIdx, pageCount);

    return parser_ok;
}

// 365.25 * 24*60*60 = 31557600
#define ICP_YEAR_IN_SECONDS ((uint64_t)31557600)

parser_error_t parser_printDelay(uint64_t value, char *buffer, uint16_t bufferSize){
    MEMZERO(buffer,bufferSize);
    uint16_t index = 0;
    uint64_t years = value / ICP_YEAR_IN_SECONDS;
    if(years >= 1){
        index += fpuint64_to_str(buffer, bufferSize, years, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end);
        MEMCPY(buffer + index, (char *)"y", 1);
        index += 1;
    }
    value %= ICP_YEAR_IN_SECONDS;

    uint64_t days = value / (uint64_t)(60*60*24);
    if(days > 0){
        if(index > 0) {
            PARSER_ASSERT_OR_ERROR(index + 2 < bufferSize, parser_unexpected_buffer_end);
            MEMCPY(buffer + index, (char *) ", ", 2);
            index += 2;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, days, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end);
        MEMCPY(buffer + index, (char *)"d", 1);
        index += 1;
    }
    value %= (uint64_t)(60*60*24);

    uint64_t hours = value / (uint64_t)(60*60);
    if(hours > 0){
        if(index > 0) {
            PARSER_ASSERT_OR_ERROR(index + 2 < bufferSize, parser_unexpected_buffer_end);
            MEMCPY(buffer + index, (char *) ", ", 2);
            index += 2;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, hours, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end);
        MEMCPY(buffer + index, (char *)"h", 1);
        index += 1;
    }
    value %= (uint64_t)(60*60);

    uint64_t minutes = value / (uint64_t)(60);
    if(minutes > 0){
        if(index > 0) {
            PARSER_ASSERT_OR_ERROR(index + 2 < bufferSize, parser_unexpected_buffer_end);
            MEMCPY(buffer + index, (char *) ", ", 2);
            index += 2;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, minutes, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end);
        MEMCPY(buffer + index, (char *)"m", 1);
        index += 1;
    }
    value %= (uint64_t)(60);

    uint64_t seconds = value;
    if(seconds > 0){
        if(index > 0) {
            PARSER_ASSERT_OR_ERROR(index + 2 < bufferSize, parser_unexpected_buffer_end);
            MEMCPY(buffer + index, (char *) ", ", 2);
            index += 2;
        }
        index += fpuint64_to_str(buffer + index, bufferSize - index, seconds, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end);
        MEMCPY(buffer + index, (char *)"s", 1);
        index += 1;
    }

    buffer[index] = 0;
    return parser_ok;
}

parser_error_t parser_getItemTransactionStateRead(const parser_context_t *ctx,
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
            return parser_unexepected_error;
        }

        pageString(outVal, outValLen, (char *) buffer, pageIdx, pageCount);
    }

    return parser_ok;
}

parser_error_t parser_getItemTokenTransfer(const parser_context_t *ctx,
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

    const bool is_stake_tx = parser_tx_obj.tx_fields.call.special_transfer_type == neuron_stake_transaction;
    if (is_stake_tx) {
        return parser_unexepected_error;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Send ICP");
        return parser_ok;
    }

    if(app_mode_expert()){
        if (displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Sender ");
            return print_textual(fields->sender.data, fields->sender.len, outVal, outValLen, pageIdx, pageCount);
        }

        if (displayIdx == 2) {
            snprintf(outKey, outKeyLen, "Subaccount ");
            snprintf(outVal, outValLen, "Not set");

            if (fields->pb_fields.SendRequest.has_from_subaccount) {
                char buffer[100];
                zxerr_t err = print_hexstring(buffer, sizeof(buffer), fields->pb_fields.SendRequest.from_subaccount.sub_account, 32);
                if (err != zxerr_ok) {
                    return parser_unexepected_error;
                }
                pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            }

            return parser_ok;
        }
        displayIdx -= 2;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "From account");
        return print_accountBytes(fields->sender, &fields->pb_fields.SendRequest,
                                  outVal, outValLen,
                                  pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        PARSER_ASSERT_OR_ERROR(fields->pb_fields.SendRequest.has_to, parser_unexpected_number_items)
        snprintf(outKey, outKeyLen, "To account ");

        char buffer[100];
        zxerr_t err = print_hexstring(buffer, sizeof(buffer), (uint8_t *) fields->pb_fields.SendRequest.to.hash, 32);
        if (err != zxerr_ok) {
            return parser_unexepected_error;
        }

        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Payment (ICP)");
        PARSER_ASSERT_OR_ERROR(fields->pb_fields.SendRequest.payment.has_receiver_gets, parser_unexpected_number_items)
        return print_ICP(fields->pb_fields.SendRequest.payment.receiver_gets.e8s,
                         outVal, outValLen,
                         pageIdx, pageCount);
    }

    if (displayIdx == 4) {
        snprintf(outKey, outKeyLen, "Maximum fee (ICP)");
        PARSER_ASSERT_OR_ERROR(fields->pb_fields.SendRequest.has_max_fee, parser_unexpected_number_items)
        return print_ICP(fields->pb_fields.SendRequest.max_fee.e8s,
                         outVal, outValLen,
                         pageIdx, pageCount);
    }

    if (displayIdx == 5) {
        snprintf(outKey, outKeyLen, "Memo");
        PARSER_ASSERT_OR_ERROR(fields->pb_fields.SendRequest.has_memo, parser_unexpected_number_items)
        return print_u64(fields->pb_fields.SendRequest.memo.memo, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

parser_error_t parser_getItemStakeNeuron(const parser_context_t *ctx,
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

    const bool is_stake_tx = parser_tx_obj.tx_fields.call.special_transfer_type == neuron_stake_transaction;
    if (!is_stake_tx) {
        return parser_unexepected_error;
    }

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Stake Neuron");
        return parser_ok;
    }

    if(app_mode_expert()){
        if (displayIdx == 1) {
            snprintf(outKey, outKeyLen, "Sender ");
            return print_textual(fields->sender.data, fields->sender.len, outVal, outValLen, pageIdx, pageCount);
        }

        if (displayIdx == 2) {
            snprintf(outKey, outKeyLen, "Subaccount ");
            snprintf(outVal, outValLen, "Not set");

            if (fields->pb_fields.SendRequest.has_from_subaccount) {
                char buffer[100];
                zxerr_t err = print_hexstring(buffer, sizeof(buffer), fields->pb_fields.SendRequest.from_subaccount.sub_account, 32);
                if (err != zxerr_ok) {
                    return parser_unexepected_error;
                }
                pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            }

            return parser_ok;
        }
        displayIdx -= 2;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "From account");
        return print_accountBytes(fields->sender, &fields->pb_fields.SendRequest,
                                  outVal, outValLen,
                                  pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Payment (ICP)");
        PARSER_ASSERT_OR_ERROR(fields->pb_fields.SendRequest.payment.has_receiver_gets, parser_unexpected_number_items)
        return print_ICP(fields->pb_fields.SendRequest.payment.receiver_gets.e8s,
                         outVal, outValLen,
                         pageIdx, pageCount);
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Maximum fee (ICP)");
        PARSER_ASSERT_OR_ERROR(fields->pb_fields.SendRequest.has_max_fee, parser_unexpected_number_items)
        return print_ICP(fields->pb_fields.SendRequest.max_fee.e8s,
                         outVal, outValLen,
                         pageIdx, pageCount);
    }

    if (displayIdx == 4) {
        snprintf(outKey, outKeyLen, "Memo");
        PARSER_ASSERT_OR_ERROR(fields->pb_fields.SendRequest.has_memo, parser_unexpected_number_items)
        return print_u64(fields->pb_fields.SendRequest.memo.memo, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

parser_error_t parser_getItemStartStopDissolve(uint8_t displayIdx,
                                             char *outKey, uint16_t outKeyLen,
                                             char *outVal, uint16_t outValLen,
                                             uint8_t pageIdx, uint8_t *pageCount) {

    ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.pb_fields.ic_nns_governance_pb_v1_ManageNeuron;
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        if (parser_tx_obj.tx_fields.call.manage_neuron_type == StartDissolving) {
            snprintf(outVal, outValLen, "Start Dissolve     Neuron");
        }else{
            snprintf(outVal, outValLen, "Stop Dissolve      Neuron");
        }
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        if(fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }else{
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }
    }

    return parser_no_data;
}

parser_error_t parser_getItemSpawn(uint8_t displayIdx,
                                             char *outKey, uint16_t outKeyLen,
                                             char *outVal, uint16_t outValLen,
                                             uint8_t pageIdx, uint8_t *pageCount) {

    ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.pb_fields.ic_nns_governance_pb_v1_ManageNeuron;
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Spawn Neuron");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        if(fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }else{
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Controller ");
        if(!fields->command.spawn.has_new_controller){

            snprintf(outVal, outValLen, "Self");
            return parser_ok;
        }

        PARSER_ASSERT_OR_ERROR(fields->command.spawn.new_controller.serialized_id.size == 29, parser_value_out_of_range);

        return print_textual(fields->command.spawn.new_controller.serialized_id.bytes, 29, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}


parser_error_t parser_getItemAddRemoveHotkey(uint8_t displayIdx,
                                                 char *outKey, uint16_t outKeyLen,
                                                 char *outVal, uint16_t outValLen,
                                                 uint8_t pageIdx, uint8_t *pageCount) {

    ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.pb_fields.ic_nns_governance_pb_v1_ManageNeuron;
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        if (parser_tx_obj.tx_fields.call.manage_neuron_type == AddHotKey) {
            snprintf(outVal, outValLen, "Add Hotkey");
        }else{
            snprintf(outVal, outValLen, "Remove Hotkey");
        }
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        if(fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }else{
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }
    }


    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Principal ");
        if (parser_tx_obj.tx_fields.call.manage_neuron_type == AddHotKey) {
            PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.add_hot_key.has_new_hot_key, parser_unexpected_number_items);
            PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.add_hot_key.new_hot_key.serialized_id.size == 29,
                                   parser_value_out_of_range);
            return print_textual(fields->command.configure.operation.add_hot_key.new_hot_key.serialized_id.bytes, 29,
                                 outVal, outValLen, pageIdx, pageCount);
        }else{
            PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.remove_hot_key.has_hot_key_to_remove, parser_unexpected_number_items);
            PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.remove_hot_key.hot_key_to_remove.serialized_id.size == 29,
                                   parser_value_out_of_range);
            return print_textual(fields->command.configure.operation.remove_hot_key.hot_key_to_remove.serialized_id.bytes, 29,
                                 outVal, outValLen, pageIdx, pageCount);
        }
    }

    return parser_no_data;
}

parser_error_t parser_getItemDisburse(uint8_t displayIdx,
                                                 char *outKey, uint16_t outKeyLen,
                                                 char *outVal, uint16_t outValLen,
                                                 uint8_t pageIdx, uint8_t *pageCount) {

    ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.pb_fields.ic_nns_governance_pb_v1_ManageNeuron;
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Disburse Neuron");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        if(fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }else{
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Disburse To ");
        if(!fields->command.disburse.has_to_account){
            snprintf(outVal, outValLen, "Self");
            return parser_ok;
        }
        char buffer[80];

        PARSER_ASSERT_OR_ERROR(fields->command.disburse.to_account.hash.size == 32, parser_context_unexpected_size);

        zxerr_t err = print_hexstring(buffer, sizeof(buffer), (uint8_t *)fields->command.disburse.to_account.hash.bytes, 32);
        if (err != zxerr_ok) {
            return parser_unexepected_error;
        }

        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Amount (ICP)");
        if(!fields->command.disburse.has_amount){
            snprintf(outVal, outValLen, "All");
            return parser_ok;
        }
        return print_ICP(fields->command.disburse.amount.e8s, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

parser_error_t parser_getItemIncreaseNeuronTimer(uint8_t displayIdx,
                                                  char *outKey, uint16_t outKeyLen,
                                                  char *outVal, uint16_t outValLen,
                                                  uint8_t pageIdx, uint8_t *pageCount) {

    ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.pb_fields.ic_nns_governance_pb_v1_ManageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Increase Dissolve  Delay");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        if(fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }else{
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Additional Delay");
        if(fields->command.configure.operation.increase_dissolve_delay.additional_dissolve_delay_seconds == 0){
            snprintf(outVal, outValLen, "0s");
            return parser_ok;
        }
        char buffer[100];
        MEMZERO(buffer,sizeof(buffer));
        uint64_t value = 0;
        MEMCPY(&value, &fields->command.configure.operation.increase_dissolve_delay.additional_dissolve_delay_seconds,4);
        CHECK_PARSER_ERR(parser_printDelay(value, buffer, sizeof(buffer)))
        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }
    return parser_no_data;
}

parser_error_t parser_getItemMergeMaturity(uint8_t displayIdx,
                                                 char *outKey, uint16_t outKeyLen,
                                                 char *outVal, uint16_t outValLen,
                                                 uint8_t pageIdx, uint8_t *pageCount) {

    ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.pb_fields.ic_nns_governance_pb_v1_ManageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Merge Maturity");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        if(fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }else{
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Percentage");
        char buffer[100];
        MEMZERO(buffer,sizeof(buffer));
        uint64_t value = 0;
        MEMCPY(&value, &fields->command.merge_maturity.percentage_to_merge,4);
        if (value > 100){
            return parser_unexpected_value;
        }
        return print_u64(value, outVal, outValLen, pageIdx, pageCount);
    }
    return parser_no_data;
}

parser_error_t parser_getItemRegisterVote(uint8_t displayIdx,
                                           char *outKey, uint16_t outKeyLen,
                                           char *outVal, uint16_t outValLen,
                                           uint8_t pageIdx, uint8_t *pageCount) {

    ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.pb_fields.ic_nns_governance_pb_v1_ManageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Register Vote");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        if(fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }else{
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Proposal ID");
        char buffer[100];
        MEMZERO(buffer,sizeof(buffer));
        uint64_t value = 0;
        MEMCPY(&value, &fields->command.register_vote.proposal.id,8);
        return print_u64(value, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Vote");
        ic_nns_governance_pb_v1_Vote v = fields->command.register_vote.vote;
        if (v == 0){
            return parser_unexpected_value;
        }else if(v == 1){
            snprintf(outVal, outValLen, "Yes");
        }else {
            snprintf(outVal, outValLen, "No");
        }
        return parser_ok;
    }
    return parser_no_data;
}

parser_error_t parser_getItemFollow(uint8_t displayIdx,
                                          char *outKey, uint16_t outKeyLen,
                                          char *outVal, uint16_t outValLen,
                                          uint8_t pageIdx, uint8_t *pageCount) {

    ic_nns_governance_pb_v1_ManageNeuron *fields = &parser_tx_obj.tx_fields.call.pb_fields.ic_nns_governance_pb_v1_ManageNeuron;

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Follow");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        if(fields->has_id) {
            return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
        }else{
            return print_u64(fields->neuron_id_or_subaccount.neuron_id.id, outVal, outValLen, pageIdx, pageCount);
        }
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Topic");
        ic_nns_governance_pb_v1_Topic topic = fields->command.follow.topic;
        switch (topic) {
            case ic_nns_governance_pb_v1_Topic_TOPIC_UNSPECIFIED : {
                snprintf(outVal, outValLen, "Default");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_NEURON_MANAGEMENT :{
                snprintf(outVal, outValLen, "Neuron Management");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_EXCHANGE_RATE :{
                snprintf(outVal, outValLen, "Exchange Rate");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_NETWORK_ECONOMICS :{
                snprintf(outVal, outValLen, "Network Economics");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_GOVERNANCE :{
                snprintf(outVal, outValLen, "Governance");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_NODE_ADMIN :{
                snprintf(outVal, outValLen, "Node Admin");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_PARTICIPANT_MANAGEMENT :{
                snprintf(outVal, outValLen, "Participant Management");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_SUBNET_MANAGEMENT :{
                snprintf(outVal, outValLen, "Subnet Management");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_NETWORK_CANISTER_MANAGEMENT :{
                snprintf(outVal, outValLen, "Network Canister Management");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_KYC :{
                snprintf(outVal, outValLen, "KYC");
                return parser_ok;
            }
            case ic_nns_governance_pb_v1_Topic_TOPIC_NODE_PROVIDER_REWARDS :{
                snprintf(outVal, outValLen, "Node Provider Rewards");
                return parser_ok;
            }
            default:{
                return parser_unexpected_type;
            }
        }
    }

    uint8_t new_displayIdx = displayIdx - 3;
    pb_size_t follow_count = fields->command.follow.followees_count;
    if (follow_count > 99){
        //check for number of chars, but the real limit is lower
        return parser_unexpected_number_items;
    }
    if (follow_count == 0){
        if(new_displayIdx == 0) {
            snprintf(outKey, outKeyLen, "Followees");
            snprintf(outVal, outValLen, "None");
            return parser_ok;
        }else{
            return parser_unexpected_number_items;
        }
    }
    if (new_displayIdx < follow_count){
        uint64_t id = fields->command.follow.followees[new_displayIdx].id;
        new_displayIdx ++; //higher by 1
        char buffer[100];
        MEMZERO(buffer,sizeof(buffer));
        uint16_t index = 0;
        MEMCPY(buffer, (char *)"Followees (", 11);
        index += 11;
        uint8_t tens = new_displayIdx / 10;
        if(tens > 0){
            char ten = (char) ('0' + tens);
            MEMCPY(buffer + index, &ten, 1);
            index ++;
        }
        uint8_t ones = new_displayIdx % 10;
        char one = (char) ('0' + ones);
        MEMCPY(buffer + index, &one, 1);
        index ++;
        MEMCPY(buffer + index, ")", 1);
        snprintf(outKey, outKeyLen, "%s",buffer);
        return print_u64(id,outVal, outValLen, pageIdx, pageCount);
    }
    return parser_no_data;
}


parser_error_t parser_getItemClaimNeuron(uint8_t displayIdx,
                                         char *outKey, uint16_t outKeyLen,
                                         char *outVal, uint16_t outValLen) {
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "Claim Neurons");
        return parser_ok;
    }
    return parser_no_data;
}

parser_error_t parser_getItemListNeurons(uint8_t displayIdx,
                                         char *outKey, uint16_t outKeyLen,
                                         char *outVal, uint16_t outValLen) {

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        snprintf(outVal, outValLen, "List Own Neurons");
        return parser_ok;
    }
    return parser_no_data;
}

parser_error_t parser_getItemManageNeuron(const parser_context_t *ctx,
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

    switch(parser_tx_obj.tx_fields.call.manage_neuron_type){
        case IncreaseDissolveDelay: return parser_getItemIncreaseNeuronTimer(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case StopDissolving :
        case StartDissolving : {
            return parser_getItemStartStopDissolve(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        }

        case Spawn : return parser_getItemSpawn(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case RemoveHotKey:
        case AddHotKey: return parser_getItemAddRemoveHotkey(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

        case Disburse : return parser_getItemDisburse(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        case MergeMaturity : return parser_getItemMergeMaturity(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        case RegisterVote : return parser_getItemRegisterVote(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        case Follow: return parser_getItemFollow(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
        default: return parser_no_data;
    }
}

parser_error_t parser_getItem(const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {
    switch (parser_tx_obj.txtype) {
        case call: {
            switch(parser_tx_obj.tx_fields.call.pbtype) {
                case pb_sendrequest : {
                    const bool is_stake_tx = parser_tx_obj.tx_fields.call.special_transfer_type == neuron_stake_transaction;

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

                case pb_manageneuron : {
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

                default : {
                    return parser_unexpected_type;
                }
            }

        }
        case state_transaction_read: {
            return parser_getItemTransactionStateRead(ctx, displayIdx,
                                                      outKey, outKeyLen,
                                                      outVal, outValLen,
                                                      pageIdx, pageCount);
        }
        default : {
            return parser_unexepected_error;
        }
    }
}
