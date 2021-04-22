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

#include "crypto.h"
#include "coin.h"
#include "zxmacros.h"
#include "base32.h"
#include "parser_impl.h"

uint32_t hdPath[HDPATH_LEN_DEFAULT];

bool isTestnet() {
    return hdPath[0] == HDPATH_0_TESTNET &&
           hdPath[1] == HDPATH_1_TESTNET;
}

uint8_t const DER_PREFIX[] = {0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                              0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00};

#define DER_PREFIX_SIZE 23u
#define DER_INPUT_SIZE  DER_PREFIX_SIZE + SECP256K1_PK_LEN

#define SIGN_PREFIX_SIZE 11u
#define SIGN_PREHASH_SIZE SIGN_PREFIX_SIZE + CX_SHA256_SIZE

#if defined(TARGET_NANOS) || defined(TARGET_NANOX)
#include "cx.h"

zxerr_t crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];

    if (pubKeyLen < SECP256K1_PK_LEN) {
        return zxerr_invalid_crypto_settings;
    }

    BEGIN_TRY
    {
        TRY {
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       path,
                                       HDPATH_LEN_DEFAULT,
                                       privateKeyData, NULL);

            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey);
            cx_ecfp_init_public_key(CX_CURVE_256K1, NULL, 0, &cx_publicKey);
            cx_ecfp_generate_pair(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1);
        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    memcpy(pubKey, cx_publicKey.W, SECP256K1_PK_LEN);
    return zxerr_ok;
}

//DER encoding:
//3056 // SEQUENCE
//  3010 // SEQUENCE
//    06072a8648ce3d0201 // OID ECDSA
//    06052b8104000a // OID secp256k1
//  0342 // BIT STRING
//    00 // no padding
//    047060f720298ffa0f48d9606abdb0 ... // point on curve, uncompressed

zxerr_t crypto_computeAddress(uint8_t *pubKey, uint8_t *address) {
    uint8_t DER[DER_INPUT_SIZE];
    MEMZERO(DER, sizeof(DER));
    MEMCPY(DER, DER_PREFIX, DER_PREFIX_SIZE);

    MEMCPY(DER + DER_PREFIX_SIZE, pubKey, SECP256K1_PK_LEN);
    uint8_t buf[CX_SHA256_SIZE];
    cx_sha256_t ctx;
    cx_sha224_init(&ctx);
    cx_hash(&ctx.header, CX_LAST, DER, DER_INPUT_SIZE, buf, 224);

    buf[DFINITY_ADDR_LEN-1] = 0x02;
    MEMCPY(address, buf, DFINITY_ADDR_LEN);
    return zxerr_ok;
}

typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;

//    // DER signature max size should be 73
//    // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
    uint8_t der_signature[73];

} __attribute__((packed)) signature_t;

//Ordering by hashes of field names:
//sender
//0a367b92cf0b037dfd89960ee832d56f7fc151681bb41e53690e776f5786998a
//canister_id
//0a3eb2ba16702a387e6321066dd952db7a31f9b5cc92981e0a92dd56802d3df9
//ingress_expiry
//26cec6b6a9248a96ab24305b61b9d27e203af14a580a5b1ff2f67575cab4a868
//method_name
//293536232cf9231c86002f4ee293176a0179c002daa9fc24be9bb51acdd642b6
//request_type
//769e6f87bdda39c859642b74ce9763cdd37cb1cd672733e8c54efaa33ab78af9
//nonce
//78377b525757b494427f89014f97d79928f3938d14eb51e20fb5dec9834eb304
//arg
//b25f03dedd69be07f356a06fe35c1b0ddc0de77dcd9066c4be0c6bbde14b23ff
//paths
//504dbd7ea99e812ff1ef64c6a162e32890b928a3df1f9e3450aadb7037889be5

zxerr_t crypto_getDigestStateTransactionRead(uint8_t *digest){
    cx_sha256_t ctx;
    cx_sha256_init(&ctx);

    uint8_t tmpdigest[CX_SHA256_SIZE];
    MEMZERO(tmpdigest,sizeof(tmpdigest));

    cx_hash_sha256((uint8_t *)"sender", 6, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    cx_hash_sha256((uint8_t *)parser_tx_obj.sender.data, parser_tx_obj.sender.len, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    cx_hash_sha256((uint8_t *)"ingress_expiry", 14, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    uint8_t ingressbuf[10];
    uint16_t enc_size = 0;
    CHECK_ZXERR(compressLEB128(parser_tx_obj.ingress_expiry, sizeof(ingressbuf), ingressbuf, &enc_size));

    cx_hash_sha256((uint8_t *)ingressbuf, enc_size, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    cx_hash_sha256((uint8_t *)"paths", 5, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    uint8_t arrayBuffer[PATH_MAX_ARRAY * CX_SHA256_SIZE];
    for (uint8_t index = 0; index < parser_tx_obj.paths.arrayLen ; index++){
            cx_hash_sha256((uint8_t *)parser_tx_obj.paths.paths[index].data, parser_tx_obj.paths.paths[index].len, arrayBuffer + index * CX_SHA256_SIZE, CX_SHA256_SIZE);
    }
    cx_hash_sha256(arrayBuffer, parser_tx_obj.paths.arrayLen*CX_SHA256_SIZE, tmpdigest, CX_SHA256_SIZE);
    cx_hash_sha256(tmpdigest, CX_SHA256_SIZE, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    cx_hash_sha256((uint8_t *)"request_type", 12, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    cx_hash_sha256((uint8_t *)parser_tx_obj.request_type.data, parser_tx_obj.request_type.len, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, CX_LAST, tmpdigest, CX_SHA256_SIZE, digest, CX_SHA256_SIZE);
    CHECK_APP_CANARY()
    return zxerr_ok;
}

zxerr_t crypto_getDigestTokenTransfer(uint8_t *digest){
    cx_sha256_t ctx;
    cx_sha256_init(&ctx);

    uint8_t tmpdigest[CX_SHA256_SIZE];
    MEMZERO(tmpdigest,sizeof(tmpdigest));

    cx_hash_sha256((uint8_t *)"sender", 6, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    cx_hash_sha256((uint8_t *)parser_tx_obj.sender.data, parser_tx_obj.sender.len, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    cx_hash_sha256((uint8_t *)"canister_id", 11, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    cx_hash_sha256((uint8_t *)parser_tx_obj.canister_id.data, parser_tx_obj.canister_id.len, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    cx_hash_sha256((uint8_t *)"ingress_expiry", 14, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    uint8_t ingressbuf[10];
    uint16_t enc_size = 0;
    CHECK_ZXERR(compressLEB128(parser_tx_obj.ingress_expiry, sizeof(ingressbuf), ingressbuf, &enc_size));

    cx_hash_sha256((uint8_t *)ingressbuf, enc_size, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    cx_hash_sha256((uint8_t *)"method_name", 11, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    cx_hash_sha256((uint8_t *)parser_tx_obj.method_name.data, parser_tx_obj.method_name.len, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    cx_hash_sha256((uint8_t *)"request_type", 12, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    cx_hash_sha256((uint8_t *)parser_tx_obj.request_type.data, parser_tx_obj.request_type.len, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    cx_hash_sha256((uint8_t *)"nonce", 5, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    cx_hash_sha256((uint8_t *)parser_tx_obj.nonce.data, parser_tx_obj.nonce.len, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    cx_hash_sha256((uint8_t *)"arg", 3, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

    cx_hash_sha256((uint8_t *)parser_tx_obj.arg.data, parser_tx_obj.arg.len, tmpdigest, CX_SHA256_SIZE);
    cx_hash(&ctx.header, CX_LAST, tmpdigest, CX_SHA256_SIZE, digest, CX_SHA256_SIZE);

    return zxerr_ok;
}

zxerr_t crypto_sign(uint8_t *signatureBuffer,
                    uint16_t signatureMaxlen,
                    const uint8_t *message,
                    uint16_t messageLen,
                    uint16_t *sigSize) {

    if (signatureMaxlen < SIGN_PREHASH_SIZE + sizeof(signature_t)){
        return zxerr_buffer_too_small;
    }

    uint8_t message_digest[CX_SHA256_SIZE];
    MEMZERO(message_digest,sizeof(message_digest));

    signatureBuffer[0] = 0x0a;
    MEMCPY(&signatureBuffer[1], (uint8_t *)"ic-request",SIGN_PREFIX_SIZE - 1);

    switch(parser_tx_obj.txtype){
        case 0x00: {
            CHECK_ZXERR(crypto_getDigestTokenTransfer(signatureBuffer + SIGN_PREFIX_SIZE));
            break;
        }
        case 0x01 :{
            CHECK_ZXERR(crypto_getDigestStateTransactionRead(signatureBuffer + SIGN_PREFIX_SIZE));
            break;
        }
        default : {
            return zxerr_unknown;
        }
    }
    CHECK_APP_CANARY()
    cx_hash_sha256(signatureBuffer, SIGN_PREHASH_SIZE, message_digest, CX_SHA256_SIZE);

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];
    unsigned int info = 0;
    int signatureLength = 0;

    signature_t *const signature = (signature_t *) (signatureBuffer + SIGN_PREHASH_SIZE);

    BEGIN_TRY
    {
        TRY
        {
            // Generate keys
            os_perso_derive_node_bip32(CX_CURVE_SECP256K1,
                                                      hdPath,
                                                      HDPATH_LEN_DEFAULT,
                                                      privateKeyData, NULL);

            cx_ecfp_init_private_key(CX_CURVE_SECP256K1, privateKeyData, 32, &cx_privateKey);

            // Sign
            signatureLength = cx_ecdsa_sign(&cx_privateKey,
                                            CX_RND_RFC6979 | CX_LAST,
                                            CX_SHA256,
                                            message_digest,
                                            CX_SHA256_SIZE,
                                            signature->der_signature,
                                            sizeof_field(signature_t, der_signature),
                                            &info);
        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    err_convert_e err = convertDERtoRSV(signature->der_signature, info,  signature->r, signature->s, &signature->v);
    if (err != no_error) {
        // Error while converting so return length 0
        return zxerr_unknown;
    }
    *sigSize = SIGN_PREHASH_SIZE + sizeof_field(signature_t, r) + sizeof_field(signature_t, s) + sizeof_field(signature_t, v) + signatureLength;

    return zxerr_ok;
}

#else

#include <hexutils.h>
#include "picohash.h"

char *crypto_testPubKey;

zxerr_t crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    return zxerr_ok;
}

zxerr_t crypto_computeAddress(uint8_t *pubKey, uint8_t *address) {
    uint8_t DER[DER_INPUT_SIZE];
    MEMZERO(DER, sizeof(DER));
    MEMCPY(DER, DER_PREFIX, DER_PREFIX_SIZE);

    MEMCPY(DER + DER_PREFIX_SIZE, pubKey, SECP256K1_PK_LEN);
    uint8_t buf[32];

    picohash_ctx_t ctx;

    picohash_init_sha224(&ctx);
    picohash_update(&ctx, DER, DER_INPUT_SIZE);
    picohash_final(&ctx, buf);

    buf[DFINITY_ADDR_LEN - 1] = 0x02;
    MEMCPY(address, buf, DFINITY_ADDR_LEN);
    return zxerr_ok;
}

zxerr_t crypto_sign(uint8_t *signature,
                    uint16_t signatureMaxlen,
                    const uint8_t *message,
                    uint16_t messageLen,
                    uint16_t *sigSize) {
    return zxerr_ok;
}

#endif


uint32_t crc32_for_byte(uint8_t rbyte) {
    uint32_t r = (uint32_t) (rbyte) & (uint32_t) 0x000000FF;
    for (int j = 0; j < 8; ++j)
        r = (r & 1 ? 0 : (uint32_t) 0xEDB88320L) ^ r >> 1;
    return r ^ (uint32_t) 0xFF000000L;
}

void crc32_small(const void *data, uint8_t n_bytes, uint32_t *crc) {
    for (uint8_t i = 0; i < n_bytes; ++i) {
        uint8_t index = ((uint8_t) *crc ^ ((uint8_t *) data)[i]);
        uint32_t crcbyte = crc32_for_byte(index);
        *crc = crcbyte ^ *crc >> 8;
    }
}

zxerr_t crypto_addrToTextual(uint8_t *address, uint8_t addressLen, unsigned char *textual, uint16_t *outLen) {
    uint8_t input[33];
    uint32_t crc = 0;
    crc32_small(address, addressLen, &crc);
    input[0] = (uint8_t) ((crc & 0xFF000000) >> 24);
    input[1] = (uint8_t) ((crc & 0x00FF0000) >> 16);
    input[2] = (uint8_t) ((crc & 0x0000FF00) >> 8);
    input[3] = (uint8_t) ((crc & 0x000000FF) >> 0);
    MEMCPY(input + 4, address, addressLen);
    int enc_len = base32_encode(input, 4 + addressLen, textual, 100);
    if (enc_len == 0) {
        return zxerr_unknown;
    }
    *outLen = enc_len;
    return zxerr_ok;
}

zxerr_t addr_to_textual(char *s, uint16_t max, const char *text, uint16_t textLen) {
    MEMZERO(s, max);
    uint16_t offset = 0;
    for (uint16_t index = 0; index < textLen; index += 5) {
        if (offset + 6 > max) {
            return zxerr_unknown;
        }
        uint8_t maxLen = (textLen - index) < 5 ? (textLen - index) : 5;
        MEMCPY(s + offset, text + index, maxLen);
        offset += 5;
        if (index + 5 < textLen) {
            s[offset] = '-';
            offset += 1;
        }
    }
    return zxerr_ok;
}

zxerr_t compressLEB128(const uint64_t input, uint16_t maxSize, uint8_t *output, uint16_t *outLen) {
    uint64_t num = input;
    size_t bytes = 0;
    while (num) {
        if (bytes >= maxSize) {
            return zxerr_buffer_too_small;
        }
        output[bytes] = num & 0x7fU;
        if (num >>= 7) output[bytes] |= 0x80U;
        ++bytes;
    }
    *outLen = bytes;
    return zxerr_ok;
}

uint8_t decompressLEB128(const uint8_t *input, uint16_t inputSize, uint64_t *v) {
    unsigned int i = 0;

    *v = 0;
    uint16_t shift = 0;
    while (i < 10u && i < inputSize) {
        uint64_t b = input[i] & 0x7fu;

        if (shift >= 63 && b > 1) {
            // This will overflow uint64_t
            break;
        }

        *v |= b << shift;

        if (!(input[i] & 0x80u)) {
            return 1;
        }

        shift += 7;
        i++;
    }

    // exit because of overflowing outputSize
    *v = 0;
    return 0;
}

typedef struct {
    uint8_t publicKey[SECP256K1_PK_LEN];
    uint8_t addrBytes[DFINITY_ADDR_LEN];
    unsigned char addrText[100];

} __attribute__((packed)) answer_t;

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrLen) {
    MEMZERO(buffer, buffer_len);

    if (buffer_len < sizeof(answer_t)) {
        zemu_log_stack("crypto_fillAddress: zxerr_buffer_too_small");
        return zxerr_buffer_too_small;
    }

    answer_t *const answer = (answer_t *) buffer;

    CHECK_ZXERR(crypto_extractPublicKey(hdPath, answer->publicKey, sizeof_field(answer_t, publicKey)));

    CHECK_ZXERR(crypto_computeAddress(answer->publicKey, answer->addrBytes));

    uint16_t outLen = 0;

    CHECK_ZXERR(crypto_addrToTextual(answer->addrBytes, DFINITY_ADDR_LEN, answer->addrText, &outLen));

    *addrLen = SECP256K1_PK_LEN + DFINITY_ADDR_LEN + outLen;
    return zxerr_ok;
}
