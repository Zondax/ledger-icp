/*******************************************************************************
 *   (c) 2018, 2019 Zondax AG
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
#if defined(BLS_SIGNATURE)
#pragma once

#include <os.h>
#include <os_io_seproxyhal.h>
#include <stdint.h>
#include <string.h>
#include <ux.h>

#include "actions.h"
#include "addr.h"
#include "app_main.h"
#include "app_mode.h"
#include "bls.h"
#include "coin.h"
#include "crypto.h"
#include "nvdata.h"
#include "parser_impl.h"
#include "path.h"
#include "process_chunks.h"
#include "tx.h"
#include "view.h"
#include "view_internal.h"
#include "zxmacros.h"

__Z_INLINE void handleConsentRequest(__unused volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log_stack("handleConsentRequest");
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    CHECK_APP_CANARY()
    zxerr_t err = bls_saveConsentRequest();
    CHECK_APP_CANARY()

    if (err != zxerr_ok) {
        // Reset state and resources
        reset_bls_state();
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        THROW(APDU_CODE_DATA_INVALID);
    }
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleCanisterCall(__unused volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log_stack("handleCanisterCall");
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    CHECK_APP_CANARY()
    zxerr_t err = bls_saveCanisterCall();
    CHECK_APP_CANARY()

    if (err != zxerr_ok) {
        // Reset state and resources
        reset_bls_state();
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        THROW(APDU_CODE_DATA_INVALID);
    }
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleSignBls(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log_stack("handleSignBls");
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    if (!app_mode_blindsign()) {
        *flags |= IO_ASYNCH_REPLY;
        view_blindsign_error_show();
        THROW(APDU_CODE_DATA_INVALID);
    }

    // Parser Certificate and verify
    CHECK_APP_CANARY()
    zxerr_t err = tx_certVerify();
    CHECK_APP_CANARY()

    if (err != zxerr_ok) {
        // Reset state and resources
        reset_bls_state();
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        THROW(APDU_CODE_DATA_INVALID);
    }
    zemu_log_stack("cert_ok");

    CHECK_APP_CANARY()
    view_review_init(tx_certGetItem, tx_certNumItems, app_sign_bls);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}
#endif
