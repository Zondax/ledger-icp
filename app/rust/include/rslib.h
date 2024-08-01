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

// Define the Canister call request structure
typedef struct {
    uint8_t arg_hash[32];
    uint8_t canister_id[29];
    uint16_t canister_id_len;
    uint64_t ingress_expiry;
    uint8_t method_name[50];
    uint16_t method_name_len;
    uint8_t request_type[50];
    uint16_t request_type_len;
    uint8_t sender[50];
    uint16_t sender_len;
} canister_call_t;

// Define the Consent request structure
typedef struct {
    uint8_t arg_hash[32];
    uint8_t canister_id[29];
    uint16_t canister_id_len;
    uint64_t ingress_expiry;
    uint8_t method_name[50];
    uint16_t method_name_len;
    uint8_t request_type[50];
    uint16_t request_type_len;
    uint8_t sender[50];
    uint16_t sender_len;
    uint8_t nonce[50];
    uint16_t nonce_len;
} consent_request_t;

// Function to parse a canister call request
uint8_t parse_canister_call_request(const uint8_t* data, uint16_t data_len, canister_call_t* out_request);

// Function to parse a cconsent request
uint8_t parse_consent_request(const uint8_t* data, uint16_t data_len, consent_request_t* out_request);
