#if defined(BLS_SIGNATURE)
#pragma once

#include <stdint.h>

#include "parser_common.h"
#include "parser_txdef.h"

#define MAX_METHOD_LEN 50
#define MAX_LANGUAGE_LEN 5
#define CERT_OBJ_MAX_SIZE 60


// Function to parse a canister call request
parser_error_t rs_parse_canister_call_request(const uint8_t *data,
                                           uint16_t data_len);

// Function to parse a cconsent request
parser_error_t rs_parse_consent_request(const uint8_t *data, uint16_t data_len);

// Function to parser certificate and verify
parser_error_t rs_verify_certificate(const uint8_t *certificate,
                                         uint16_t certificate_len,
                                         const uint8_t *root_key);

parser_error_t rs_getNumItems(uint8_t *num_items);

parser_error_t rs_getItem(int8_t displayIdx,
                          char *outKey, uint16_t outKeyLen, char *outValue,
                          uint16_t outValueLen, uint8_t pageIdx,
                          uint8_t *pageCount);

// use to clear resources after certificate verification and signing
void rs_clear_resources(void);
void rs_get_signing_hash(uint8_t *hash);
#endif
