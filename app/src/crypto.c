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

uint32_t hdPath[HDPATH_LEN_DEFAULT];

bool isTestnet() {
    return hdPath[0] == HDPATH_0_TESTNET &&
           hdPath[1] == HDPATH_1_TESTNET;
}

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

zxerr_t crypto_computeAddress(uint8_t *pubKey, uint8_t *address) {
    ///Fixme: add exact DER encoding
    uint8_t DER[76];
    MEMZERO(DER, sizeof(DER));

    MEMCPY(DER + 11, pubKey, SECP256K1_PK_LEN);

    cx_sha256_t ctx;
    cx_sha224_init(&ctx);
    cx_hash(&ctx.header, CX_LAST, DER, 76, address, CX_SHA224_SIZE);

    address[DFINITY_ADDR_LEN-1] = 0x02;
}


typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;

    // DER signature max size should be 73
    // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
    uint8_t der_signature[73];

} __attribute__((packed)) signature_t;


zxerr_t crypto_sign(uint8_t *signature,
                    uint16_t signatureMaxlen,
                    const uint8_t *message,
                    uint16_t messageLen,
                    uint16_t *sigSize) {

//    uint8_t tmp[BLAKE2B_256_SIZE];
//    uint8_t message_digest[BLAKE2B_256_SIZE];
//
//    blake_hash(message, messageLen, tmp, BLAKE2B_256_SIZE);
//    blake_hash_cid(tmp, BLAKE2B_256_SIZE, message_digest, BLAKE2B_256_SIZE);
//
//    cx_ecfp_private_key_t cx_privateKey;
//    uint8_t privateKeyData[32];
//    int signatureLength;
//    unsigned int info = 0;
//
//    signature_t *const signature = (signature_t *) buffer;
//
//    BEGIN_TRY
//    {
//        TRY
//        {
//            // Generate keys
//            os_perso_derive_node_bip32(CX_CURVE_256K1,
//                                                      hdPath,
//                                                      HDPATH_LEN_DEFAULT,
//                                                      privateKeyData, NULL);
//
//            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey);
//
//            // Sign
//            signatureLength = cx_ecdsa_sign(&cx_privateKey,
//                                            CX_RND_RFC6979 | CX_LAST,
//                                            CX_SHA256,
//                                            message_digest,
//                                            BLAKE2B_256_SIZE,
//                                            signature->der_signature,
//                                            sizeof_field(signature_t, der_signature),
//                                            &info);
//        }
//        FINALLY {
//            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
//            MEMZERO(privateKeyData, 32);
//        }
//    }
//    END_TRY;
//
//    err_convert_e err = convertDERtoRSV(signature->der_signature, info,  signature->r, signature->s, &signature->v);
//    if (err != no_error) {
//        // Error while converting so return length 0
//        return 0;
//    }
//
//    // return actual size using value from signatureLength
//    return sizeof_field(signature_t, r) + sizeof_field(signature_t, s) + sizeof_field(signature_t, v) + signatureLength;

    return zxerr_ok;
}

#else

#include <hexutils.h>
#include "blake2.h"

char *crypto_testPubKey;

zxerr_t crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    return zxerr_ok;
}

zxerr_t crypto_computeAddress(uint8_t *pubKey, uint8_t *address) {
    return zxerr_ok;
}

        __Z_INLINE int blake_hash(const unsigned char *in, unsigned int inLen,
                          unsigned char *out, unsigned int outLen) {
    blake2b_state s;
    blake2b_init(&s, outLen);
    blake2b_update(&s, in, inLen);
    blake2b_final(&s, out, outLen);
    return 0;
}

__Z_INLINE int blake_hash_cid(const unsigned char *in, unsigned int inLen,
                              unsigned char *out, unsigned int outLen) {

    uint8_t prefix[] = PREFIX;

    blake2b_state s;
    blake2b_init(&s, outLen);
    blake2b_update(&s, prefix, sizeof(prefix));
    blake2b_update(&s, in, inLen);
    blake2b_final(&s, out, outLen);

    return 0;
}

int prepareDigestToSign(const unsigned char *in, unsigned int inLen,
                        unsigned char *out, unsigned int outLen) {

    uint8_t tmp[BLAKE2B_256_SIZE];

    blake_hash(in, inLen, tmp, BLAKE2B_256_SIZE);
    blake_hash_cid(tmp, BLAKE2B_256_SIZE, out, outLen);

    return 0;
}

uint16_t crypto_sign(uint8_t *signature,
                     uint16_t signatureMaxlen,
                     const uint8_t *message,
                     uint16_t messageLen) {
    // Empty version for non-Ledger devices
    uint8_t tmp[BLAKE2B_256_SIZE];
    uint8_t message_digest[BLAKE2B_256_SIZE];

    blake_hash(message, messageLen, tmp, BLAKE2B_256_SIZE);
    blake_hash_cid(tmp, BLAKE2B_256_SIZE, message_digest, BLAKE2B_256_SIZE);

    return 0;
}

#endif

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

    // payload PK || 0x02    // 28 + 1
    uint8_t addrBytesLen;
    uint8_t addrBytes[DFINITY_ADDR_LEN];

    uint8_t addrStrLen;
    uint8_t addrStr[41];  // 41 = because (20+1+4)*8/5 (32 base encoded size)

    uint8_t padding[4];

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

    answer-> addrBytesLen = DFINITY_ADDR_LEN;

    *addrLen = SECP256K1_PK_LEN + DFINITY_ADDR_LEN;
    return zxerr_ok;
}
