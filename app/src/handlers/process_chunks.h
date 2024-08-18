/*******************************************************************************
*   (c) 2018, 2019 Zondax GmbH
*   (c) 2016 Ledger
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
#include "app_main.h"

#include <string.h>
#include <os_io_seproxyhal.h>
#include <os.h>
#include <ux.h>

#include "app_mode.h"
#include "parser_impl.h"
#include "view.h"
#include "view_internal.h"
#include "actions.h"
#include "tx.h"
#include "addr.h"
#include "crypto.h"
#include "coin.h"
#include "zxmacros.h"
#include "bls.h"
#include "nvdata.h"

static bool tx_initialized = false;

__Z_INLINE bool process_chunk(volatile uint32_t *tx, uint32_t rx) {
    UNUSED(tx);
    const uint8_t payloadType = G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE];

    if (rx < OFFSET_DATA) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    if (G_io_apdu_buffer[OFFSET_P2] != 0 && G_io_apdu_buffer[OFFSET_P2] != 1) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    const bool is_stake_tx = parser_tx_obj.special_transfer_type == neuron_stake_transaction;

    uint32_t added;
    switch (payloadType) {
        case 0:
            tx_initialize();
            tx_reset();
            extractHDPath(rx, OFFSET_DATA);
            MEMZERO(&parser_tx_obj, sizeof(parser_tx_t));

            parser_tx_obj.special_transfer_type = normal_transaction;
            if (G_io_apdu_buffer[OFFSET_P2] == 1) {
                parser_tx_obj.special_transfer_type = neuron_stake_transaction;
            }

            tx_initialized = true;
            return false;
        case 1:
            if (is_stake_tx && G_io_apdu_buffer[OFFSET_P2] != 1) {
                THROW(APDU_CODE_DATA_INVALID);
            }
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            return false;
        case 2:
            if (is_stake_tx && G_io_apdu_buffer[OFFSET_P2] != 1) {
                THROW(APDU_CODE_DATA_INVALID);
            }
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }

            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            return true;

        default:
            break;
    }
    tx_initialized = false;
    THROW(APDU_CODE_INVALIDP1P2);
}

