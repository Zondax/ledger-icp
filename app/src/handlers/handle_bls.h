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
#if defined(BLS_SIGNATURE)
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
#include "nvdata.h"
#include "bls.h"
#include <stdint.h>

__Z_INLINE void handleConsentRequest(__unused volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    CHECK_APP_CANARY()
    zxerr_t err = bls_saveConsentRequest();
    CHECK_APP_CANARY()

    if (err != zxerr_ok) {
        bls_nvm_reset();
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        THROW(APDU_CODE_DATA_INVALID);
    }
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleCanisterCall(__unused volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    CHECK_APP_CANARY()
    zxerr_t err = bls_saveCanisterCall();
    CHECK_APP_CANARY()

    if (err != zxerr_ok) {
        bls_nvm_reset();
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        THROW(APDU_CODE_DATA_INVALID);
    }
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleRootKey(__unused volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    CHECK_APP_CANARY()
    zxerr_t err = bls_saveRootKey();
    CHECK_APP_CANARY()

    if (err != zxerr_ok) {
        bls_nvm_reset();
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        THROW(APDU_CODE_DATA_INVALID);
    }
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleSignBls(__unused volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    // Parser Certificate and verify
    CHECK_APP_CANARY()
    zxerr_t err = bls_verify();

    CHECK_APP_CANARY()

    if (err != zxerr_ok) {
        bls_nvm_reset();
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        THROW(APDU_CODE_DATA_INVALID);
    }

    CHECK_APP_CANARY()

    // view_review_init(rs_getItem, rs_getNumItems, app_sign_bls);
    view_review_init(tx_certGetItem, tx_certNumItems, app_sign_bls);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;

    // Clear nvm data after signing and full certificate review
    bls_nvm_reset();

    THROW(APDU_CODE_OK);
}


#endif
