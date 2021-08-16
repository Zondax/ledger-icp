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

parser_error_t parser_printDelay(uint64_t value, char *buffer, uint16_t bufferSize){
    MEMZERO(buffer,bufferSize);
    uint16_t index = 0;
    uint64_t years = value / (uint64_t)(365.25 * 24*60*60);
    if(years > 1){
        index += fpuint64_to_str(buffer, bufferSize, years, 0);
        PARSER_ASSERT_OR_ERROR(index + 1 < bufferSize, parser_unexpected_buffer_end);
        MEMCPY(buffer + index, (char *)"y", 1);
        index += 1;
    }
    value %= (uint64_t)(365.25 *60*60*24);

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

    bool is_stake_tx = parser_tx_obj.tx_fields.call.special_transfer_type == neuron_stake_transaction;
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Transaction type");
        if(is_stake_tx){
            snprintf(outVal, outValLen, "Stake Neuron");
        }else {
            snprintf(outVal, outValLen, "Send ICP");
        }
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
        return print_ICP(fields->pb_fields.SendRequest.payment.receiver_gets.e8s,
                         outVal, outValLen,
                         pageIdx, pageCount);
    }

    if (displayIdx == 4) {
        snprintf(outKey, outKeyLen, "Maximum fee (ICP)");
        return print_ICP(fields->pb_fields.SendRequest.max_fee.e8s,
                         outVal, outValLen,
                         pageIdx, pageCount);
    }

    if (displayIdx == 5) {
        snprintf(outKey, outKeyLen, "Memo");
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
        snprintf(outVal, outValLen, "Spawn");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "New Controller");

        PARSER_ASSERT_OR_ERROR(fields->command.spawn.new_controller.serialized_id.size == 29, parser_value_out_of_range);

        return print_textual(fields->command.configure.operation.add_hot_key.new_hot_key.serialized_id.bytes, 29, outVal, outValLen, pageIdx, pageCount);
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

        PARSER_ASSERT_OR_ERROR(fields->command.configure.operation.add_hot_key.new_hot_key.serialized_id.size == 29, parser_value_out_of_range);

        return print_textual(fields->command.configure.operation.add_hot_key.new_hot_key.serialized_id.bytes, 29, outVal, outValLen, pageIdx, pageCount);
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
        snprintf(outVal, outValLen, "Disburse");
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Neuron ID");
        return print_u64(fields->id.id, outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Account");
        char buffer[80];
        zxerr_t err = print_hexstring(buffer, sizeof(buffer), (uint8_t *)fields->command.disburse.to_account.hash.bytes, 32);
        if (err != zxerr_ok) {
            return parser_unexepected_error;
        }

        pageString(outVal, outValLen, buffer, pageIdx, pageCount);
        return parser_ok;
    }

    if (displayIdx == 3) {
        snprintf(outKey, outKeyLen, "Amount (ICP)");
        return print_u64(fields->command.disburse.amount.e8s, outVal, outValLen, pageIdx, pageCount);
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
