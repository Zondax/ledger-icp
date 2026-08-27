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

#pragma once
#include <os.h>
#include <os_io_seproxyhal.h>
#include <string.h>
#include <ux.h>

#include "actions.h"
#include "addr.h"
#include "app_main.h"
#include "app_mode.h"
#include "bls.h"
#include "coin.h"
#include "crypto.h"
#include "parser_impl.h"
#include "tx.h"
#include "view.h"
#include "view_internal.h"
#include "zxmacros.h"

__Z_INLINE void extractHDPath(uint32_t rx, uint32_t offset) {
    if ((rx - offset) < sizeof(uint32_t) * HDPATH_LEN_DEFAULT) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    MEMCPY(hdPath, G_io_apdu_buffer + offset, sizeof(uint32_t) * HDPATH_LEN_DEFAULT);

    const bool mainnet = hdPath[0] == HDPATH_0_DEFAULT && hdPath[1] == HDPATH_1_DEFAULT;

    const bool testnet = hdPath[0] == HDPATH_0_TESTNET && hdPath[1] == HDPATH_1_TESTNET;

    if (!mainnet && !testnet) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    // Hardening at the account and address-index levels is not negotiable in
    // either mode: the account must be hardened and the address index must
    // not be. Expert mode used to lift this along with the index range, so a
    // host could ask for an unhardened account or a hardened address index
    // and get a key derived from outside the scheme this app uses at all.
    // The change level is deliberately not constrained here.
    const bool hardening_ok = ((hdPath[2] & 0x80000000u) == 0x80000000u) && ((hdPath[4] & 0x80000000u) == 0x00000000u);

    if (!hardening_ok) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    // What expert mode is for: account and address numbers beyond 255, and a
    // non-zero change level. Those stay allowed. Note this predicate calls
    // 0'-255' "default", which is wider than the review screen does: any path
    // other than 0'/0/0 gets named on screen, in both modes, so the account
    // being signed under is no longer silent (tx_has_custom_path, parser.c).
    const bool is_default_path = ((hdPath[2] & HDPATH_RESTRICTED_MASK) == 0x80000000u) && (hdPath[3] == 0x00000000u) &&
                                 ((hdPath[4] & HDPATH_RESTRICTED_MASK) == 0x00000000u);

    if (!is_default_path && !app_mode_expert()) {
        THROW(APDU_CODE_DATA_INVALID);
    }
}
