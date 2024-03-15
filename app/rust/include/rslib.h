#pragma once

#include <stdint.h>
#include "parser_common.h"
#include "parser_txdef.h"

// Signature must be 48 bytes and key 96 bytes
uint16_t verify_bls_sign(const uint8_t *msg, uint16_t msg_len, const uint8_t *sk, uint8_t *sig);


