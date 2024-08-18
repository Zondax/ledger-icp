#if defined(BLS_SIGNATURE)
#pragma once

#include <stdint.h>

#include "parser_common.h"
#include "parser_txdef.h"

#define MAX_METHOD_LEN 50
#define MAX_LANGUAGE_LEN 5
#define CERT_OBJ_MAX_SIZE 60


typedef struct {
   uint8_t *state;
   uint32_t len;
} parsed_obj_t;


parser_error_t rs_getNumItems(const parser_context_t *ctx, uint8_t *num_items);

parser_error_t rs_getItem(const parser_context_t *ctx, int8_t displayIdx,
                          char *outKey, uint16_t outKeyLen, char *outValue,
                          uint16_t outValueLen, uint8_t pageIdx,
                          uint8_t *pageCount);


// Define the Canister call request structure
typedef struct {
  uint8_t arg_hash[32];
  uint8_t canister_id[CANISTER_MAX_LEN + 1];
  uint16_t canister_id_len;
  uint64_t ingress_expiry;
  uint8_t method_name[METHOD_MAX_LEN + 1];
  uint16_t method_name_len;
  uint8_t request_type[REQUEST_MAX_LEN + 1];
  uint16_t request_type_len;
  uint8_t sender[SENDER_MAX_LEN + 1];
  uint16_t sender_len;
  uint8_t nonce[NONCE_MAX_LEN + 1];
  bool hash_nonce;

  // This holds the sha256 hash of this struct
  // and is used for signing
  uint8_t hash[32];
} canister_call_t;

// Define the Consent request structure
typedef struct {
  uint8_t arg_hash[32];
  uint8_t canister_id[CANISTER_MAX_LEN + 1];
  uint16_t canister_id_len;
  uint64_t ingress_expiry;
  uint8_t method_name[METHOD_MAX_LEN + 1];
  uint16_t method_name_len;
  uint8_t request_type[REQUEST_MAX_LEN + 1];
  uint16_t request_type_len;
  uint8_t sender[SENDER_MAX_LEN + 1];
  uint16_t sender_len;
  uint8_t nonce[NONCE_MAX_LEN + 1];
  bool hash_nonce;

  // Not part of the struct but
  // a place holder for the request_id
  // of this struct
  uint8_t request_id[32];
} consent_request_t;

// Function to parse a canister call request
parser_error_t parse_canister_call_request(const uint8_t *data,
                                           uint16_t data_len);

// Function to parse a cconsent request
// parser_error_t parse_consent_request(const uint8_t *data, uint16_t data_len,
//                                      consent_request_t *out_request);
parser_error_t parse_consent_request(const uint8_t *data, uint16_t data_len);

// Function to parser certificate and verify
parser_error_t parser_verify_certificate(const uint8_t *certificate,
                                         uint16_t certificate_len,
                                         const uint8_t *root_key);
void clear_resources(void);
#endif
