#pragma once

#include <stdint.h>
#include "parser_common.h"
#include "parser_txdef.h"

parser_error_t rs_getNumItems(const parser_context_t *ctx, uint8_t *num_items);

parser_error_t rs_getItem(const parser_context_t *ctx,
                              int8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outValue, uint16_t outValueLen,
                              uint8_t pageIdx, uint8_t *pageCount);


