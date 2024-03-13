#pragma once

#include <stdint.h>
#include "parser_common.h"
#include "parser_txdef.h"


uint16_t bls_sign(const uint8_t *msg, uint16_t msg_len, const uint8_t *sk, uint8_t *sig);


