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
#define DER_INPUT_SIZE  (DER_PREFIX_SIZE + SECP256K1_PK_LEN)

#define SIGN_PREFIX_SIZE 11u
#define SIGN_PREHASH_SIZE (SIGN_PREFIX_SIZE + CX_SHA256_SIZE)

#define SUBACCOUNT_PREFIX_SIZE 11u
#define STAKEACCOUNT_PREFIX_SIZE 12u
#define STAKEACCOUNT_PRINCIPAL_SIZE 10u

#define SIGNATURE_SIZE_R 32
#define SIGNATURE_SIZE_S 32
#define SIGNATURE_SIZE_RS 64

#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX)
#include "cx.h"

zxerr_t hash_sha224(uint8_t *input, uint16_t inputLen, uint8_t *output, uint16_t outputLen){
    if(outputLen < 28){
        return zxerr_invalid_crypto_settings;
    }
    cx_sha256_t ctx;
    cx_sha224_init(&ctx);
    cx_hash(&ctx.header, CX_LAST, input, inputLen, output, 224);
    return zxerr_ok;
}

zxerr_t crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];

    if (pubKeyLen < SECP256K1_PK_LEN) {
        return zxerr_invalid_crypto_settings;
    }

    zxerr_t err = zxerr_ok;
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
            memcpy(pubKey, cx_publicKey.W, SECP256K1_PK_LEN);
        }
        CATCH_ALL {
            err = zxerr_ledger_api_error;
        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    return err;
}

typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;

    // DER signature max size should be 73
    // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
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

#define HASH_U64(FIELDNAME, FIELDVALUE, TMPDIGEST) { \
    MEMZERO(TMPDIGEST,sizeof(TMPDIGEST));                      \
    cx_hash_sha256((uint8_t *)FIELDNAME, sizeof(FIELDNAME) - 1, TMPDIGEST, CX_SHA256_SIZE); \
    cx_hash(&ctx.header, 0, TMPDIGEST, CX_SHA256_SIZE, NULL, 0);         \
    uint8_t ingressbuf[10];                                             \
    uint16_t enc_size = 0;                                              \
    CHECK_ZXERR(compressLEB128(FIELDVALUE, sizeof(ingressbuf), ingressbuf, &enc_size)); \
    cx_hash_sha256((uint8_t *)ingressbuf, enc_size, tmpdigest, CX_SHA256_SIZE);         \
    cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);                        \
}

#define HASH_BYTES_INTERMEDIATE(FIELDNAME, FIELDVALUE, TMPDIGEST) { \
    MEMZERO(TMPDIGEST,sizeof(TMPDIGEST));                      \
    cx_hash_sha256((uint8_t *)FIELDNAME, sizeof(FIELDNAME) - 1, TMPDIGEST, CX_SHA256_SIZE); \
    cx_hash(&ctx.header, 0, TMPDIGEST, CX_SHA256_SIZE, NULL, 0);         \
    cx_hash_sha256((uint8_t *)(FIELDVALUE).data, (FIELDVALUE).len, TMPDIGEST, CX_SHA256_SIZE); \
    cx_hash(&ctx.header, 0, TMPDIGEST, CX_SHA256_SIZE, NULL, 0);                               \
}

#define HASH_BYTES_END(FIELDNAME, FIELDVALUE, TMPDIGEST, ENDDIGEST) { \
    MEMZERO(TMPDIGEST,sizeof(TMPDIGEST));                      \
    cx_hash_sha256((uint8_t *)FIELDNAME, sizeof(FIELDNAME) - 1, TMPDIGEST, CX_SHA256_SIZE); \
    cx_hash(&ctx.header, 0, TMPDIGEST, CX_SHA256_SIZE, NULL, 0);         \
    cx_hash_sha256((uint8_t *)(FIELDVALUE).data, (FIELDVALUE).len, TMPDIGEST, CX_SHA256_SIZE); \
    cx_hash(&ctx.header, CX_LAST, TMPDIGEST, CX_SHA256_SIZE, ENDDIGEST, CX_SHA256_SIZE);        \
}

#define HASH_BYTES_PTR_END(FIELDNAME, FIELDVALUE, TMPDIGEST, ENDDIGEST) { \
    MEMZERO(TMPDIGEST,sizeof(TMPDIGEST));                      \
    cx_hash_sha256((uint8_t *)FIELDNAME, sizeof(FIELDNAME) - 1, TMPDIGEST, CX_SHA256_SIZE); \
    cx_hash(&ctx.header, 0, TMPDIGEST, CX_SHA256_SIZE, NULL, 0);         \
    cx_hash_sha256((uint8_t *)(FIELDVALUE).dataPtr, (FIELDVALUE).len, TMPDIGEST, CX_SHA256_SIZE); \
    cx_hash(&ctx.header, CX_LAST, TMPDIGEST, CX_SHA256_SIZE, ENDDIGEST, CX_SHA256_SIZE);        \
}

zxerr_t crypto_getDigest(uint8_t *digest, txtype_e txtype){
    cx_sha256_t ctx;
    cx_sha256_init(&ctx);

    uint8_t tmpdigest[CX_SHA256_SIZE];
    MEMZERO(tmpdigest,sizeof(tmpdigest));

    switch(txtype){
        case call: {
            call_t *fields = &parser_tx_obj.tx_fields.call;
            HASH_BYTES_INTERMEDIATE("sender", fields->sender, tmpdigest);
            HASH_BYTES_INTERMEDIATE("canister_id", fields->canister_id, tmpdigest);
            HASH_U64("ingress_expiry",fields->ingress_expiry, tmpdigest);
            HASH_BYTES_INTERMEDIATE("method_name", fields->method_name, tmpdigest);
            HASH_BYTES_INTERMEDIATE("request_type", parser_tx_obj.request_type, tmpdigest);

            if(fields->has_nonce){
                HASH_BYTES_INTERMEDIATE("nonce", fields->nonce, tmpdigest);
            }
            HASH_BYTES_PTR_END("arg", fields->method_args, tmpdigest, digest);
            return zxerr_ok;
        }
        case state_transaction_read: {
            state_read_t *fields = &parser_tx_obj.tx_fields.stateRead;
            HASH_BYTES_INTERMEDIATE("sender", fields->sender, tmpdigest);
            HASH_U64("ingress_expiry",fields->ingress_expiry, tmpdigest);

            cx_hash_sha256((uint8_t *)"paths", 5, tmpdigest, CX_SHA256_SIZE);
            cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

            uint8_t arrayBuffer[PATH_MAX_ARRAY * CX_SHA256_SIZE];
            for (uint8_t index = 0; index < fields->paths.arrayLen ; index++){
                    cx_hash_sha256((uint8_t *)fields->paths.paths[index].data, fields->paths.paths[index].len, arrayBuffer + index * CX_SHA256_SIZE, CX_SHA256_SIZE);
            }
            cx_hash_sha256(arrayBuffer, fields->paths.arrayLen*CX_SHA256_SIZE, tmpdigest, CX_SHA256_SIZE);
            cx_hash_sha256(tmpdigest, CX_SHA256_SIZE, tmpdigest, CX_SHA256_SIZE);
            cx_hash(&ctx.header, 0, tmpdigest, CX_SHA256_SIZE, NULL, 0);

            HASH_BYTES_END("request_type", parser_tx_obj.request_type, tmpdigest, digest);
            return zxerr_ok;
        }

        default : {
            return zxerr_unknown;
        }
    }
}

zxerr_t crypto_sign(uint8_t *signatureBuffer,
                    uint16_t signatureMaxlen,
                    uint16_t *sigSize) {
    if (signatureMaxlen < SIGN_PREHASH_SIZE + sizeof(signature_t)){
        return zxerr_buffer_too_small;
    }

    uint8_t message_digest[CX_SHA256_SIZE];
    MEMZERO(message_digest,sizeof(message_digest));

    signatureBuffer[0] = 0x0a;
    MEMCPY(&signatureBuffer[1], (uint8_t *)"ic-request",SIGN_PREFIX_SIZE - 1);

    CHECK_ZXERR(crypto_getDigest(signatureBuffer + SIGN_PREFIX_SIZE, parser_tx_obj.txtype))
    CHECK_APP_CANARY()

    cx_hash_sha256(signatureBuffer, SIGN_PREHASH_SIZE, message_digest, CX_SHA256_SIZE);

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];
    unsigned int info = 0;
    int signatureLength = 0;

    signature_t *const signature = (signature_t *) (signatureBuffer + SIGN_PREHASH_SIZE);

    zxerr_t err = zxerr_ok;
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

            err_convert_e err_c = convertDERtoRSV(signature->der_signature, info,  signature->r, signature->s, &signature->v);
            if (err_c != no_error) {
                MEMZERO(signatureBuffer, signatureMaxlen);
                err = zxerr_unknown;
            }else{
                *sigSize = SIGN_PREHASH_SIZE + sizeof_field(signature_t, r) + sizeof_field(signature_t, s) + sizeof_field(signature_t, v) + signatureLength;
            }
        }
        CATCH_ALL {
            err = zxerr_ledger_api_error;
        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    return err;
}

//Start:
//PREDIGEST_REQUEST || PREDIGEST_STATEREAD
//END:
//DIGEST_REQUEST || SIGNATURE_REQUEST || DIGEST_STATEREAD || SIGNATURE_STATEREAD

zxerr_t crypto_sign_combined(uint8_t *signatureBuffer,
                    uint16_t signatureMaxlen,
                    uint8_t *predigest_request,
                    uint8_t *predigest_stateread,
                    uint16_t *sigSize) {
    if (signatureMaxlen < 2*(CX_SHA256_SIZE + SIGNATURE_SIZE_RS)){
        return zxerr_buffer_too_small;
    }

    uint8_t message_buffer[SIGN_PREFIX_SIZE + CX_SHA256_SIZE];
    MEMZERO(message_buffer, sizeof(message_buffer));

    uint8_t message_digest[CX_SHA256_SIZE];
    MEMZERO(message_digest,sizeof(message_digest));

    message_buffer[0] = 0x0a;
    MEMCPY(&message_buffer[1], (uint8_t *)"ic-request",SIGN_PREFIX_SIZE - 1);

    MEMCPY(message_buffer + SIGN_PREFIX_SIZE, predigest_stateread, CX_SHA256_SIZE);

    CHECK_APP_CANARY()

    cx_hash_sha256(message_buffer, SIGN_PREHASH_SIZE, message_digest, CX_SHA256_SIZE);
    MEMCPY(signatureBuffer + CX_SHA256_SIZE + SIGNATURE_SIZE_RS, message_digest, CX_SHA256_SIZE);


    MEMCPY(message_buffer + SIGN_PREFIX_SIZE, predigest_request, CX_SHA256_SIZE);
    cx_hash_sha256(message_buffer, SIGN_PREHASH_SIZE, message_digest, CX_SHA256_SIZE);
    MEMCPY(signatureBuffer, message_digest, CX_SHA256_SIZE);

    CHECK_APP_CANARY()

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];
    unsigned int info = 0;

    signature_t sigma;
    MEMZERO(&sigma, sizeof(signature_t));

    zxerr_t err = zxerr_ok;
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

            // Sign request
            cx_ecdsa_sign(&cx_privateKey,
                          CX_RND_RFC6979 | CX_LAST,
                          CX_SHA256,
                          signatureBuffer,
                          CX_SHA256_SIZE,
                          sigma.der_signature,
                          sizeof_field(signature_t, der_signature),
                          &info);

            err_convert_e err_c = convertDERtoRSV(sigma.der_signature, info,  sigma.r, sigma.s, &sigma.v);
            if (err_c != no_error) {
                MEMZERO(signatureBuffer, signatureMaxlen);
                err = zxerr_unknown;
            }else{
                MEMCPY(signatureBuffer + CX_SHA256_SIZE, sigma.r, SIGNATURE_SIZE_R);
                MEMCPY(signatureBuffer + CX_SHA256_SIZE + SIGNATURE_SIZE_R, sigma.s, SIGNATURE_SIZE_S);

                MEMZERO(&sigma, sizeof(signature_t));
                // Sign stateread
                cx_ecdsa_sign(&cx_privateKey,
                              CX_RND_RFC6979 | CX_LAST,
                              CX_SHA256,
                              signatureBuffer + CX_SHA256_SIZE + SIGNATURE_SIZE_RS,
                              CX_SHA256_SIZE,
                              sigma.der_signature,
                              sizeof_field(signature_t, der_signature),
                              &info);

                err_c = convertDERtoRSV(sigma.der_signature, info,  sigma.r, sigma.s, &sigma.v);
                if (err_c != no_error) {
                    MEMZERO(signatureBuffer, signatureMaxlen);
                    err = zxerr_unknown;
                }else{
                    MEMCPY(signatureBuffer + 2*CX_SHA256_SIZE + SIGNATURE_SIZE_RS, sigma.r, SIGNATURE_SIZE_R);
                    MEMCPY(signatureBuffer + 2*CX_SHA256_SIZE + SIGNATURE_SIZE_RS + SIGNATURE_SIZE_R, sigma.s, SIGNATURE_SIZE_S);
                    *sigSize = 2*(CX_SHA256_SIZE + SIGNATURE_SIZE_RS);
                }
            }
        }
        CATCH_ALL {
            err = zxerr_ledger_api_error;
        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    return err;
}


#else

#include <hexutils.h>
#include "picohash.h"

zxerr_t crypto_getDigest(uint8_t *digest, txtype_e txtype) {
    return zxerr_ok;
}

zxerr_t cx_hash_sha256(uint8_t *input, uint16_t inputLen, uint8_t *output, uint16_t outputLen) {
    if (outputLen < 32) {
        return zxerr_invalid_crypto_settings;
    }
    picohash_ctx_t ctx;

    picohash_init_sha256(&ctx);
    picohash_update(&ctx, input, inputLen);
    picohash_final(&ctx, output);
    return zxerr_ok;
}

zxerr_t hash_sha224(uint8_t *input, uint16_t inputLen, uint8_t *output, uint16_t outputLen) {
    if (outputLen < 28) {
        return zxerr_invalid_crypto_settings;
    }
    picohash_ctx_t ctx;

    picohash_init_sha224(&ctx);
    picohash_update(&ctx, input, inputLen);
    picohash_final(&ctx, output);
    return zxerr_ok;
}

zxerr_t
crypto_extractPublicKey(__Z_UNUSED const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    const uint8_t publicKey[SECP256K1_PK_LEN] = {
            0x04, 0x10, 0xD3, 0x49, 0x80, 0xA5, 0x1A, 0xF8, 0x9D, 0x33, 0x31, 0xAD,
            0x5F, 0xA8, 0x0F, 0xE3, 0x0D, 0x88, 0x68, 0xAD, 0x87, 0x52, 0x64, 0x60,
            0xB3, 0xB3, 0xE1, 0x55, 0x96, 0xEE, 0x58, 0xE8, 0x12, 0x42, 0x29, 0x87,
            0xD8, 0x58, 0x9B, 0xA6, 0x10, 0x98, 0x26, 0x4D, 0xF5, 0xBB, 0x9C, 0x2D,
            0x3F, 0xF6, 0xFE, 0x06, 0x17, 0x46, 0xB4, 0xB3, 0x1A, 0x44, 0xEC, 0x26,
            0x63, 0x66, 0x32, 0xB8, 0x35
    };
    if (pubKeyLen != SECP256K1_PK_LEN) {
        return zxerr_unknown;
    }
    memcpy(pubKey, publicKey, SECP256K1_PK_LEN);
    return zxerr_ok;
}

#endif

/*
 * neuron_sub_account =
     sha256(0x0c | “neuron-stake” | neuron_holder_principal | neuron_creation_memo)
to.hash = account_identifier(
             “rrkah-fqaaa-aaaaa-aaaaq-cai”,
             neuron_sub_account)

 */
typedef struct {
    uint8_t prefix_byte;
    uint8_t prefix_string[STAKEACCOUNT_PREFIX_SIZE];
    uint8_t principal[DFINITY_PRINCIPAL_LEN];
    uint64_t memo_be;
} __attribute__((packed)) stake_account_pre_hash;


typedef struct {
    uint8_t prefix_byte;
    uint8_t prefix_string[SUBACCOUNT_PREFIX_SIZE - 1];
    uint8_t principal[STAKEACCOUNT_PRINCIPAL_SIZE];
    uint8_t pre_hash[32];
} __attribute__((packed)) stake_account_hash;

typedef struct {
    union {
        stake_account_pre_hash pre_hash;
        stake_account_hash stake_hash;
    } hash_fields;
} stake_account;


uint64_t change_endianness(uint64_t value) {
    uint64_t result = 0;
    for (uint8_t i = 0; i < 7; i++) {
        result += ((value >> i * 8u) & 0xFFu);
        result <<= 8u;
    }
    result += ((value >> 56u) & 0xFFu);
    return result;
}

zxerr_t crypto_principalToStakeAccount(const uint8_t *principal, uint16_t principalLen,
                                       const uint64_t neuron_creation_memo,
                                       uint8_t *address, uint16_t maxoutLen) {
    if (principalLen != DFINITY_PRINCIPAL_LEN ||
        maxoutLen < DFINITY_ADDR_LEN) {
        return zxerr_invalid_crypto_settings;
    }
    stake_account account;
    MEMZERO(&account, sizeof(stake_account));

    stake_account_pre_hash *pre_hash = &account.hash_fields.pre_hash;
    pre_hash->prefix_byte = 0x0C;
    MEMCPY(pre_hash->prefix_string, (uint8_t *) "neuron-stake", STAKEACCOUNT_PREFIX_SIZE);
    MEMCPY(pre_hash->principal, principal, DFINITY_PRINCIPAL_LEN);
    pre_hash->memo_be = change_endianness(neuron_creation_memo);

    stake_account_hash *final_hash = &account.hash_fields.stake_hash;

    cx_hash_sha256((uint8_t *) pre_hash, sizeof(stake_account_pre_hash), final_hash->pre_hash, 32);

    final_hash->prefix_byte = 0x0A;
    MEMCPY(final_hash->prefix_string, (uint8_t *) "account-id", SUBACCOUNT_PREFIX_SIZE - 1);
    uint8_t stake_principal[STAKEACCOUNT_PRINCIPAL_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01};
    MEMCPY(final_hash->principal, stake_principal, STAKEACCOUNT_PRINCIPAL_SIZE);

    CHECK_ZXERR(
            hash_sha224((uint8_t *) final_hash, sizeof(stake_account_hash), address + 4,
                        (maxoutLen - 4)));

    uint32_t crc = 0;
    crc32_small(address + 4, DFINITY_ADDR_LEN - 4, &crc);
    address[0] = (uint8_t) ((crc & 0xFF000000) >> 24);
    address[1] = (uint8_t) ((crc & 0x00FF0000) >> 16);
    address[2] = (uint8_t) ((crc & 0x0000FF00) >> 8);
    address[3] = (uint8_t) ((crc & 0x000000FF) >> 0);
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

zxerr_t crypto_computePrincipal(const uint8_t *pubKey, uint8_t *principal) {
    uint8_t DER[DER_INPUT_SIZE];
    MEMZERO(DER, sizeof(DER));
    MEMCPY(DER, DER_PREFIX, DER_PREFIX_SIZE);

    MEMCPY(DER + DER_PREFIX_SIZE, pubKey, SECP256K1_PK_LEN);
    uint8_t buf[DFINITY_PRINCIPAL_LEN];

    CHECK_ZXERR(hash_sha224(DER, DER_INPUT_SIZE, buf, DFINITY_PRINCIPAL_LEN));

    buf[DFINITY_PRINCIPAL_LEN - 1] = 0x02;
    MEMCPY(principal, buf, DFINITY_PRINCIPAL_LEN);
    return zxerr_ok;
}

//CRC-32(b) || b with b = SHA-224(“\x0Aaccount-id“ || owner || sub-account), where owner is a (29-byte)
zxerr_t crypto_principalToSubaccount(const uint8_t *principal, uint16_t principalLen,
                                     const uint8_t *subAccount, uint16_t subaccountLen,
                                     uint8_t *address, uint16_t maxoutLen) {
    if (principalLen != DFINITY_PRINCIPAL_LEN || subaccountLen != DFINITY_SUBACCOUNT_LEN ||
        maxoutLen < DFINITY_ADDR_LEN) {
        return zxerr_invalid_crypto_settings;
    }
    uint8_t hashinput[SUBACCOUNT_PREFIX_SIZE + DFINITY_PRINCIPAL_LEN + DFINITY_SUBACCOUNT_LEN];
    MEMZERO(hashinput, sizeof(hashinput));
    hashinput[0] = 0x0a;
    MEMCPY(&hashinput[1], (uint8_t *) "account-id", SUBACCOUNT_PREFIX_SIZE - 1);
    MEMCPY(hashinput + SUBACCOUNT_PREFIX_SIZE, principal, DFINITY_PRINCIPAL_LEN);
    MEMCPY(hashinput + SUBACCOUNT_PREFIX_SIZE + DFINITY_PRINCIPAL_LEN, subAccount, DFINITY_SUBACCOUNT_LEN);

    CHECK_ZXERR(
            hash_sha224(hashinput, SUBACCOUNT_PREFIX_SIZE + DFINITY_PRINCIPAL_LEN + DFINITY_SUBACCOUNT_LEN, address + 4,
                        (maxoutLen - 4)));

    uint32_t crc = 0;
    crc32_small(address + 4, DFINITY_ADDR_LEN - 4, &crc);
    address[0] = (uint8_t) ((crc & 0xFF000000) >> 24);
    address[1] = (uint8_t) ((crc & 0x00FF0000) >> 16);
    address[2] = (uint8_t) ((crc & 0x0000FF00) >> 8);
    address[3] = (uint8_t) ((crc & 0x000000FF) >> 0);
    return zxerr_ok;
}

uint32_t crc32_for_byte(uint8_t rbyte) {
    uint32_t r = (uint32_t) (rbyte) & (uint32_t) 0x000000FF;
    for (int j = 0; j < 8; ++j)
        r = (r & 1 ? 0 : (uint32_t) 0xEDB88320L) ^ r >> 1;
    return r ^ (uint32_t) 0xFF000000L;
}

void crc32_small(const void *data, uint16_t n_bytes, uint32_t *crc) {
    for (uint16_t i = 0; i < n_bytes; ++i) {
        uint8_t index = ((uint8_t) *crc ^ ((uint8_t *) data)[i]);
        uint32_t crcbyte = crc32_for_byte(index);
        *crc = crcbyte ^ *crc >> 8;
    }
}

zxerr_t crypto_principalToTextual(const uint8_t *address_in, uint16_t addressLen, char *textual, uint16_t *outLen) {
    uint8_t input[33] = {0};
    if (addressLen >= sizeof (input) + 4) {
        return zxerr_buffer_too_small;
    }
    uint32_t crc = 0;
    crc32_small(address_in, addressLen, &crc);
    input[0] = (uint8_t) ((crc & 0xFF000000) >> 24);
    input[1] = (uint8_t) ((crc & 0x00FF0000) >> 16);
    input[2] = (uint8_t) ((crc & 0x0000FF00) >> 8);
    input[3] = (uint8_t) ((crc & 0x000000FF) >> 0);

    MEMCPY(input + 4, address_in, addressLen);
    uint32_t enc_len = base32_encode(input, 4 + addressLen, textual, *outLen);

    if (enc_len == 0) {
        return zxerr_unknown;
    }

    *outLen = enc_len;
    return zxerr_ok;
}

zxerr_t addr_to_textual(char *s_out, uint16_t s_max, const char *text_in, uint16_t text_in_len) {
    MEMZERO(s_out, s_max);
    uint16_t offset = 0;
    for (uint16_t index = 0; index < text_in_len; index += 5) {
        if (offset + 6 > s_max) {
            return zxerr_unknown;
        }
        uint8_t maxLen = (text_in_len - index) < 5 ? (text_in_len - index) : 5;
        MEMCPY(s_out + offset, text_in + index, maxLen);
        offset += 5;
        if (index + 5 < text_in_len) {
            s_out[offset] = '-';
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

typedef struct {
    uint8_t publicKey[SECP256K1_PK_LEN];
    uint8_t principalBytes[DFINITY_PRINCIPAL_LEN];
    uint8_t subAccountBytes[DFINITY_ADDR_LEN];
    char addrText[DFINITY_TEXTUAL_SIZE];

} __attribute__((packed)) answer_t;

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrLen) {
    MEMZERO(buffer, buffer_len);

    if (buffer_len < sizeof(answer_t)) {
        zemu_log_stack("crypto_fillAddress: zxerr_buffer_too_small");
        return zxerr_buffer_too_small;
    }

    answer_t *const answer = (answer_t *) buffer;

    CHECK_ZXERR(crypto_extractPublicKey(hdPath, answer->publicKey, sizeof_field(answer_t, publicKey)));

    CHECK_ZXERR(crypto_computePrincipal(answer->publicKey, answer->principalBytes));

    //For now only defeault subaccount, maybe later grab 32 bytes from the apdu buffer.
    uint8_t zero_subaccount[DFINITY_SUBACCOUNT_LEN];
    MEMZERO(zero_subaccount, DFINITY_SUBACCOUNT_LEN);

    CHECK_ZXERR(crypto_principalToSubaccount(answer->principalBytes, sizeof_field(answer_t, principalBytes),
                                             zero_subaccount, DFINITY_SUBACCOUNT_LEN, answer->subAccountBytes,
                                             sizeof_field(answer_t, subAccountBytes)));

    uint16_t outLen = DFINITY_TEXTUAL_SIZE;

    CHECK_ZXERR(crypto_principalToTextual(answer->principalBytes, DFINITY_PRINCIPAL_LEN, answer->addrText, &outLen));

    *addrLen = SECP256K1_PK_LEN + DFINITY_PRINCIPAL_LEN + DFINITY_SUBACCOUNT_LEN + outLen;
    return zxerr_ok;
}
