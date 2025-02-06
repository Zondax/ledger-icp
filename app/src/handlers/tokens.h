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

#include <os.h>
#include <os_io_seproxyhal.h>
#include <string.h>
#include <ux.h>

#include "zxmacros.h"
#include <stdint.h>

#include "token_info.h"

__Z_INLINE void handleGetTokenIdx(__Z_UNUSED volatile uint32_t *flags,
                                  volatile uint32_t *tx,
                                  __Z_UNUSED uint32_t rx) {
  zemu_log_stack("handleGetTokenIdx\n");
  const uint8_t token_idx = G_io_apdu_buffer[OFFSET_P1];

  // Put data directly in the apdu buffer
  MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);

  // retrieve token at token_idx
  uint16_t len =
      get_token_i(token_idx, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2);

  *tx = len;

  THROW(APDU_CODE_OK);
}

__Z_INLINE void handleGetNumOfTokens(__Z_UNUSED volatile uint32_t *flags,
                                     volatile uint32_t *tx,
                                     __Z_UNUSED uint32_t rx) {

  zemu_log_stack("handleGetNumOfTokens\n");

  uint8_t num_tokens = token_registry_size();

  MEMCPY(G_io_apdu_buffer, &num_tokens, sizeof(uint8_t));

  *tx = sizeof(uint8_t);

  THROW(APDU_CODE_OK);
}
