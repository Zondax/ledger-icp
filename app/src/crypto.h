/*******************************************************************************
*   (c) 2019 Zondax GmbH
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

#ifdef __cplusplus
extern "C" {
#endif

#include <zxmacros.h>
#include "coin.h"
#include <stdbool.h>
#include <sigutils.h>
#include <zxerror.h>

#include "parser_txdef.h"

extern uint32_t hdPath[HDPATH_LEN_DEFAULT];

typedef struct {
    uint8_t publicKey[SECP256K1_PK_LEN];
    uint8_t principalBytes[DFINITY_PRINCIPAL_LEN];
    uint8_t subAccountBytes[DFINITY_ADDR_LEN];
    char addrText[DFINITY_TEXTUAL_SIZE];

} __attribute__((packed)) answer_t;

zxerr_t crypto_extractPublicKey(uint8_t *pubKey, uint16_t pubKeyLen);

zxerr_t crypto_computePrincipal(const uint8_t *pubKey, uint8_t *principal);

zxerr_t crypto_principalToTextual(const uint8_t *address_in, uint16_t addressLen, char *textual, uint16_t *outLen);

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t bufferLen, uint16_t *addrLen);

zxerr_t addr_to_textual(char *s_out, uint16_t s_max, const char *text_in, uint16_t text_in_len);

void crc32_small(const void *data, uint16_t n_bytes, uint32_t *crc);

zxerr_t compressLEB128(uint64_t input, uint16_t maxSize,
                       uint8_t *output, uint16_t *outLen);

zxerr_t crypto_principalToSubaccount(const uint8_t *principal, uint16_t principalLen,
                                     const uint8_t *subAccount, uint16_t subaccountLen,
                                     uint8_t *address, uint16_t maxoutLen);

zxerr_t crypto_sign_bls(uint8_t *signatureBuffer,
                    uint16_t signatureMaxlen,
                    uint16_t *sigSize,
                    uint8_t *payload,
                    uint16_t payloadLen);

zxerr_t crypto_sign(uint8_t *signature,
                    uint16_t signatureMaxlen,
                    uint16_t *sigSize);

zxerr_t crypto_sign_combined(uint8_t *signatureBuffer,
                             uint16_t signatureMaxlen,
                             uint8_t *predigest_request,
                             uint8_t *predigest_stateread,
                             uint16_t *sigSize);

zxerr_t crypto_getDigest(uint8_t *digest, txtype_e txtype);

zxerr_t crypto_computeStakeSubaccount(const uint8_t *principal, uint16_t principalLen,
                                      const uint8_t *memo, uint16_t memoLen,
                                      uint8_t *subaccount, uint16_t subaccountLen);

zxerr_t crypto_principalToStakeAccount(const uint8_t *principal, uint16_t principalLen,
                                       const uint64_t neuron_creation_memo,
                                       uint8_t *address, uint16_t maxoutLen);

#ifdef __cplusplus
}
#endif
