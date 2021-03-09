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

#include "gtest/gtest.h"
#include <string>
#include <cbor.h>
#include <hexutils.h>
#include <zxmacros.h>

// Basic CBOR test cases generated with http://cbor.me/

namespace {
    TEST(CBORParserTest, CBORDfinityTest){
        uint8_t inBuffer[1000];
        const char *tmp = "d9d9f7a76b6d6574686f645f6e616d656f6765745f6e6575726f6e5f696e666f6673656e6465724202036a63616e697365725f6964420001636172674f4449444c00017805000000000000006e696e67726573735f6578706972791b16648bd146f339d96c726571756573745f74797065657175657279656e6f6e636548cf8082785b0f987d";
        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        CborParser parser;
        CborValue it;
        CborError err;

        CborTag tag, tag2;

        err = cbor_parser_init(inBuffer, inBufferLen, 0, &parser, &it);
        EXPECT_EQ(err, CborNoError);

        CborType type = cbor_value_get_type(&it);
        EXPECT_EQ(type, CborTagType);
        EXPECT_TRUE(cbor_value_is_tag(&it));

        err = cbor_value_advance(&it);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        type = cbor_value_get_type(&it);
        EXPECT_EQ(type, CborMapType);

        EXPECT_TRUE(cbor_value_is_container(&it));
        size_t mapLen;
        err = cbor_value_get_map_length(&it, &mapLen);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(mapLen, 7);

        /// Enter container and iterate along items
        CborValue contents;
        err = cbor_value_enter_container(&it, &contents);
        EXPECT_EQ(err, CborNoError);

        size_t key_len;
        uint64_t val;
        char buffer[100];
        MEMZERO(buffer, 100);

        // "method_name"  key
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborTextStringType);
        key_len = sizeof(buffer);
        err = _cbor_value_copy_string(&contents, buffer, &key_len, nullptr);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(key_len, 11);
        EXPECT_EQ(strlen((const char *) buffer), 11);
        EXPECT_STREQ(buffer, "method_name");
        EXPECT_EQ(err, CborNoError);
        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        // get_neuron_info value
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborTextStringType);
        err =  cbor_value_get_string_length(&contents, &val);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(val, 15);
        err = _cbor_value_copy_string(&contents, buffer, &val, nullptr);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(strlen((const char *) buffer), 15);
        EXPECT_STREQ(buffer, "get_neuron_info");
        EXPECT_EQ(err, CborNoError);

        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);
        // get_neuron_info value
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborTextStringType);
        err =  cbor_value_get_string_length(&contents, &val);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(val, 6);
        err = _cbor_value_copy_string(&contents, buffer, &val, nullptr);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(strlen((const char *) buffer), 15);
        EXPECT_STREQ(buffer, "senderuron_info");
        EXPECT_EQ(err, CborNoError);

        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);
        // get_neuron_info value
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborByteStringType);
        EXPECT_EQ(err, CborNoError);

        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborTextStringType);
        err =  cbor_value_get_string_length(&contents, &val);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(val, 10);
        err = _cbor_value_copy_string(&contents, buffer, &val, nullptr);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(strlen((const char *) buffer), 15);
        EXPECT_STREQ(buffer, "caniser_id_info");
        EXPECT_EQ(err, CborNoError);

        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);
        // get_neuron_info value
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborByteStringType);
        EXPECT_EQ(err, CborNoError);

        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborTextStringType);
        err =  cbor_value_get_string_length(&contents, &val);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(val, 3);
        err = _cbor_value_copy_string(&contents, buffer, &val, nullptr);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(strlen((const char *) buffer), 15);
        EXPECT_STREQ(buffer, "argiser_id_info");
        EXPECT_EQ(err, CborNoError);

        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);
        // get_neuron_info value
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborByteStringType);
        EXPECT_EQ(err, CborNoError);

        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborTextStringType);
        err =  cbor_value_get_string_length(&contents, &val);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(val, 14);
        err = _cbor_value_copy_string(&contents, buffer, &val, nullptr);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(strlen((const char *) buffer), 15);
        EXPECT_STREQ(buffer, "ingress_expiryo");
        EXPECT_EQ(err, CborNoError);

        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);
        // get_neuron_info value
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborIntegerType);
        EXPECT_EQ(err, CborNoError);

        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborTextStringType);
        err =  cbor_value_get_string_length(&contents, &val);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(val, 12);
        err = _cbor_value_copy_string(&contents, buffer, &val, nullptr);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(strlen((const char *) buffer), 15);
        EXPECT_STREQ(buffer, "request_typeryo");
        EXPECT_EQ(err, CborNoError);

        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);
        // get_neuron_info value
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborTextStringType);
        EXPECT_EQ(err, CborNoError);

        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborTextStringType);
        err =  cbor_value_get_string_length(&contents, &val);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(val, 5);
        err = _cbor_value_copy_string(&contents, buffer, &val, nullptr);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(strlen((const char *) buffer), 15);
        EXPECT_STREQ(buffer, "noncest_typeryo");
        EXPECT_EQ(err, CborNoError);

        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborByteStringType);
        EXPECT_EQ(err, CborNoError);


        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborInvalidType);
    }

    TEST(CBORParserTest, MinimalListTest) {
        // [1,2,3]
        uint8_t inBuffer[100];
        const char *tmp = "83010203";
        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        CborParser parser;
        CborValue it;
        CborError err;

        err = cbor_parser_init(inBuffer, inBufferLen, 0, &parser, &it);
        EXPECT_EQ(err, CborNoError);
        size_t arrLen;
        err = cbor_value_get_array_length(&it, &arrLen);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(arrLen, 3);

        // Manually iterate
        EXPECT_FALSE(cbor_value_at_end(&it));

        CborType type = cbor_value_get_type(&it);
        EXPECT_EQ(type, CborArrayType);
        EXPECT_TRUE(cbor_value_is_container(&it));

        /// Enter container and iterate along items
        CborValue contents;
        err = cbor_value_enter_container(&it, &contents);
        EXPECT_EQ(err, CborNoError);

        int64_t val;
        // item = 1
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborIntegerType);
        err = cbor_value_get_int64(&contents, &val);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(val, 1);
        err = cbor_value_advance_fixed(&contents);
        EXPECT_EQ(err, CborNoError);

        // item = 2
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborIntegerType);
        err = cbor_value_get_int64(&contents, &val);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(val, 2);
        err = cbor_value_advance_fixed(&contents);
        EXPECT_EQ(err, CborNoError);

        // item = 3
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborIntegerType);
        err = cbor_value_get_int64(&contents, &val);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(val, 3);
        err = cbor_value_advance_fixed(&contents);
        EXPECT_EQ(err, CborNoError);

        // Close container
        err = cbor_value_leave_container(&it, &contents);
        EXPECT_EQ(err, CborNoError);
    }

    TEST(CBORParserTest, MinimalDictTest) {
        // { "x" : 1, "y" : 2, "z" : "test" }
        uint8_t inBuffer[100];
        const char *tmp = "A3617801617902617A6474657374";
        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        CborParser parser;
        CborValue it;
        CborError err = cbor_parser_init(inBuffer, inBufferLen, 0, &parser, &it);
        EXPECT_EQ(err, CborNoError);

        // Manually iterate
        EXPECT_FALSE(cbor_value_at_end(&it));

        CborType type = cbor_value_get_type(&it);
        EXPECT_EQ(type, CborMapType);
        EXPECT_TRUE(cbor_value_is_container(&it));
        size_t mapLen;
        err = cbor_value_get_map_length(&it, &mapLen);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(mapLen, 3);

        /// Enter container and iterate along items
        CborValue contents;
        err = cbor_value_enter_container(&it, &contents);
        EXPECT_EQ(err, CborNoError);

        size_t key_len;
        uint64_t val;
        char buffer[100];
        MEMZERO(buffer, 100);

        // "x":1  key
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborTextStringType);
        key_len = sizeof(buffer);
        err = _cbor_value_copy_string(&contents, buffer, &key_len, nullptr);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(key_len, 1);
        EXPECT_EQ(strlen((const char *) buffer), 1);
        EXPECT_STREQ(buffer, "x");
        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        // "x":1  value
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborIntegerType);
        err = cbor_value_get_uint64(&contents, &val);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(val, 1);
        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        // "y":2  key
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborTextStringType);
        EXPECT_EQ(err, CborNoError);
        key_len = sizeof(buffer);
        err = _cbor_value_copy_string(&contents, buffer, &key_len, nullptr);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(key_len, 1);
        EXPECT_EQ(strlen((const char *) buffer), 1);
        EXPECT_STREQ(buffer, "y");
        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        // "y":2  value
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborIntegerType);
        err = cbor_value_get_uint64(&contents, &val);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(val, 2);
        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        // "z":"test"  key
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborTextStringType);
        EXPECT_EQ(err, CborNoError);
        key_len = sizeof(buffer);
        err = _cbor_value_copy_string(&contents, buffer, &key_len, nullptr);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(key_len, 1);
        EXPECT_EQ(strlen((const char *) buffer), 1);
        EXPECT_STREQ(buffer, "z");
        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        // "z":"test"  value
        type = cbor_value_get_type(&contents);
        EXPECT_EQ(type, CborTextStringType);
        EXPECT_EQ(err, CborNoError);
        key_len = sizeof(buffer);
        err = _cbor_value_copy_string(&contents, buffer, &key_len, nullptr);
        EXPECT_EQ(err, CborNoError);
        EXPECT_EQ(key_len, 4);
        EXPECT_EQ(strlen((const char *) buffer), 4);
        EXPECT_STREQ(buffer, "test");
        err = cbor_value_advance(&contents);         // easier than advance_fixed, performance hit is small
        EXPECT_EQ(err, CborNoError);

        // Close container
        err = cbor_value_leave_container(&it, &contents);
        EXPECT_EQ(err, CborNoError);
    }
}
