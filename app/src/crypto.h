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

#define CHECKSUM_LENGTH             4

extern uint32_t hdPath[HDPATH_LEN_DEFAULT];

#define ADDRESS_PROTOCOL_LEN        1

#define BLAKE2B_256_SIZE            32

uint16_t formatProtocol(const uint8_t *addressBytes, uint16_t addressSize,
                        uint8_t *formattedAddress,
                        uint16_t formattedAddressSize);

bool isTestnet();

int prepareDigestToSign(const unsigned char *in, unsigned int inLen,
                        unsigned char *out, unsigned int outLen);

zxerr_t crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen);

zxerr_t crypto_computeAddress(uint8_t *pubKey, uint8_t *address);
zxerr_t crypto_addrToTextual(uint8_t *address, uint8_t addressLen, unsigned char *textual, uint16_t *outLen);
zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t bufferLen, uint16_t *addrLen);
void crc32_small(const void *data, uint8_t n_bytes, uint32_t* crc);

zxerr_t crypto_sign(uint8_t *signature,
                    uint16_t signatureMaxlen,
                    const uint8_t *message,
                    uint16_t messageLen,
                    uint16_t *sigSize);

#ifdef __cplusplus
}
#endif
