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
#include <cbor.h>
#include <hexutils.h>
#include <zxmacros.h>
#include <algorithm>
#include <parser_common.h>
#include <parser_impl.h>
#include <parser.h>

#include "zxformat.h"

// Basic CBOR test cases generated with http://cbor.me/

namespace {
    // TODO: this test was removed because app no longer supports protobuf
    /* TEST(TxTest, one_byte_accountid) { */
    /*     parser_tx_obj.special_transfer_type = normal_transaction; */
    /*     uint8_t inBuffer[1000]; */
    /*     const char *tmp = "d9d9f7a167636f6e74656e74a6636172674c620210011a0612040a0211116b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b16a2cd02c5b2d1006b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d8a4aa4ffc7bc5ccdcd5a7a3d10c9bb06741063b02c7e908a624f721d02"; */
    /**/
    /*     auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp); */
    /**/
    /*     parser_context_t ctx; */
    /*     auto err = parser_parse(&ctx, inBuffer, inBufferLen); */
    /*     EXPECT_EQ(err, parser_ok); */
    /**/
    /*     //SHOULD FAIL */
    /*     err = parser_validate(&ctx); */
    /*     EXPECT_EQ(err, parser_context_unexpected_size); */
    /**/
    /* } */

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

    TEST(CBORParserTest, TransactionSimpleEnvelope) {
        uint8_t inBuffer[1000];

        const char *tmp = "d9d9f7a167636f6e74656e74a46e696e67726573735f6578706972791b167886d92efc388065706174687381824e726571756573745f7374617475735820564fd7aba0d5facd386adad8c095339be3ad9222389decf64e0bddee3cc11e466c726571756573745f747970656a726561645f73746174656673656e646572581dbd28a51aa219af2443896127d178f9b2de34215c948f3e265a0e083d02";
        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        parser_context_t ctx;
        auto err = parser_parse(&ctx, inBuffer, inBufferLen);
        EXPECT_EQ(err, parser_ok);

        err = parser_validate(&ctx);
        EXPECT_EQ(err, parser_ok);
    }

    TEST(CBORParserTest, TransactionStateRead) {
        uint8_t inBuffer[1000];
        const char *tmp = "d9d9f7a167636f6e74656e74a46e696e67726573735f6578706972791b167886d92efc388065706174687381824e726571756573745f7374617475735820564fd7aba0d5facd386adad8c095339be3ad9222389decf64e0bddee3cc11e466c726571756573745f747970656a726561645f73746174656673656e646572581dbd28a51aa219af2443896127d178f9b2de34215c948f3e265a0e083d02";
        auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp);

        parser_context_t ctx;
        auto err = parser_parse(&ctx, inBuffer, inBufferLen);
        EXPECT_EQ(err, parser_ok);

        err = parser_validate(&ctx);
        EXPECT_EQ(err, parser_ok);
    }

    // TODO: Test disabled as internally it uses protobuf data for which
    // the app is not longer compatible.
    /* TEST(CBORParserTest, TokenTransfer) { */
    /*     parser_tx_obj.special_transfer_type = normal_transaction; */
    /*     uint8_t inBuffer[1000]; */
    /*     const char *tmp = "d9d9f7a367636f6e74656e74a76c726571756573745f747970656463616c6c656e6f6e636550f5390d960c6e52f489155a4309da03da6e696e67726573735f6578706972791b1674c5e29ec9c2106673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e3026b63616e69737465725f69644a000000000000000201016b6d6574686f645f6e616d656773656e645f70626361726758560a0012050a0308e8071a0308890122220a2001010101010101010101010101010101010101010101010101010101010101012a220a2035548ec29e9d85305850e87a2d2642fe7214ff4bb36334070deafc3345c3b1276d73656e6465725f7075626b657958583056301006072a8648ce3d020106052b8104000a03420004e1142e1fbc940344d9161709196bb8bd151f94379c48dd507ab99a0776109128b94b5303cf2b2d28e25a779da175b62f8a975599b20c63d5193202640576ec5e6a73656e6465725f7369675840de5bccbb0a0173c432cd58ea4495d4d1e122d6ce04e31dcf63217f3d3a9b73130dc9bbf3b10e61c8db8bf8800bb4649e27786e5bc9418838c95864be28487a6a"; */
    /*     auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp); */
    /**/
    /*     parser_context_t ctx; */
    /*     auto err = parser_parse(&ctx, inBuffer, inBufferLen); */
    /*     EXPECT_EQ(err, parser_ok); */
    /**/
    /*     err = parser_validate(&ctx); */
    /*     EXPECT_EQ(err, parser_ok); */
    /**/
    /* } */
    /**/
    /* TEST(CBORParserTest, IncreaseNeuronTimer) { */
    /*     parser_tx_obj.special_transfer_type = normal_transaction; */
    /*     uint8_t inBuffer[1000]; */
    /**/
    /*     const char *tmp = "d9d9f7a167636f6e74656e74a6636172675839620a10a7d18aaad3a2a2c6131a2b0a0508959aef3a12220a2068d518e2fd2be6566e62c36611b9794dfcbc04eb4227eefb73ab3c7a2d0ae5776b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b169bc8985c330d006b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d8a4aa4ffc7bc5ccdcd5a7a3d10c9bb06741063b02c7e908a624f721d02"; */
    /*     auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp); */
    /**/
    /*     parser_context_t ctx; */
    /*     auto err = parser_parse(&ctx, inBuffer, inBufferLen); */
    /*     EXPECT_EQ(err, parser_ok); */
    /**/
    /*     err = parser_validate(&ctx); */
    /*     EXPECT_EQ(err, parser_ok); */
    /* } */

    /* TEST(CBORParserTest, StakeTx) { */
    /*     parser_tx_obj.special_transfer_type = neuron_stake_transaction; */
    /*     uint8_t inBuffer[1000]; */
    /**/
    /*     const char *tmp = "d9d9f7a167636f6e74656e74a663617267583e0a0a08f2d4a0eca697869f0812070a050880c2d72f1a0308904e2a220a20a8a1abecdb66f57eb6eba44c3b5f11a6c433fe932680a9519b064b80ca8794e16b63616e69737465725f69644a000000000000000201016e696e67726573735f6578706972791b16985a582755f1806b6d6574686f645f6e616d656773656e645f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302"; */
    /*     auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp); */
    /**/
    /*     parser_context_t ctx; */
    /*     auto err = parser_parse(&ctx, inBuffer, inBufferLen); */
    /*     EXPECT_EQ(err, parser_ok); */
    /**/
    /*     err = parser_validate(&ctx); */
    /*     EXPECT_EQ(err, parser_ok); */
    /*     parser_tx_obj.special_transfer_type = invalid; */
    /* } */

    /* TEST(CBORParserTest, ClaimNeuron) { */
    /*     parser_tx_obj.special_transfer_type = normal_transaction; */
    /*     uint8_t inBuffer[1000]; */
    /**/
    /*     const char *tmp = "d9d9f7a167636f6e74656e74a76c726571756573745f747970656463616c6c656e6f6e6365505833a6590c6d2b601e3a24557cfbb4336e696e67726573735f6578706972791b16bad506bb4ca0f06673656e646572581d2594dccb73ca0226c58299d4e21badbcee00d153deccb38fa20cd46e026b63616e69737465725f69644a000000000000000601016b6d6574686f645f6e616d656d636c61696d5f6e6575726f6e7363617267588b4449444c000171820130343139623066656363356639613164353162393033643262363234346430356531326134386661386233353731396538313262623635643966393035613365613965356137323362363537616665393136313236396431663134633164383034376530323230616461633434653731313630323531656364616662613064636535"; */
    /*     auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp); */
    /**/
    /*     parser_context_t ctx; */
    /*     auto err = parser_parse(&ctx, inBuffer, inBufferLen); */
    /*     EXPECT_EQ(err, parser_ok); */
    /**/
    /*     err = parser_validate(&ctx); */
    /*     EXPECT_EQ(err, parser_ok); */
    /* } */

    /* TEST(CBORParserTest, Configure_JoinCommunityFund) { */
    /*     parser_tx_obj.special_transfer_type = normal_transaction; */
    /*     uint8_t inBuffer[1000]; */
    /**/
    /*     const char *tmp = "d9d9f7a167636f6e74656e74a663617267486202107b12023a006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b16ba67d2b864bf406b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581dd899978f029508f4fa5fce3d2539de5aade6d229efcc458233deee7502"; */
    /*     auto inBufferLen = parseHexString(inBuffer, sizeof(inBuffer), tmp); */
    /**/
    /*     parser_context_t ctx; */
    /*     auto err = parser_parse(&ctx, inBuffer, inBufferLen); */
    /*     EXPECT_EQ(err, parser_ok); */
    /**/
    /*     err = parser_validate(&ctx); */
    /*     EXPECT_EQ(err, parser_ok); */
    /* } */

/*     TEST(CBORParserTest, CombinedTX) { */
/*         uint8_t inBuffer[1000]; */
/**/
/*         const char *tmp = "d9d9f7a167636f6e74656e74a46e696e67726573735f6578706972791b16bc685267142b8065706174687381824e726571756573745f737461747573582038b344ba26f15444b4f989078c952ce99b559d3eb59e829c5a463a33812e32546c726571756573745f747970656a726561645f73746174656673656e646572581dd899978f029508f4fa5fce3d2539de5aade6d229efcc458233deee7502"; */
/*         uint32_t inBufferLen = parseHexString(inBuffer + 4, sizeof(inBuffer) - 4, tmp); */
/*         EXPECT_EQ(inBufferLen, 156); */
/*         MEMCPY(&inBuffer[0], &inBufferLen, 4); */
/**/
/*         const char *tmp2 = "d9d9f7a167636f6e74656e74a66361726758320a0012050a0308904e1a0308904e2a220a20a2a794c66495083317e4be5197eb655b1e63015469d769e2338af3d3e3f3aa866b63616e69737465725f69644a000000000000000201016e696e67726573735f6578706972791b16bc685084d14ec06b6d6574686f645f6e616d656773656e645f70626c726571756573745f747970656463616c6c6673656e646572581dd899978f029508f4fa5fce3d2539de5aade6d229efcc458233deee7502"; */
/*         uint32_t inBufferLen2 = parseHexString(inBuffer + 8 + inBufferLen, sizeof(inBuffer) - 4 - inBufferLen, tmp2); */
/*         EXPECT_EQ(inBufferLen2, 192); */
/*         MEMCPY(&inBuffer[4 + inBufferLen], &inBufferLen2, 4); */
/* //        char array[2000]; */
/* //        MEMZERO(array,2000); */
/* //        uint16_t total_len = 156 + 192 + 8; */
/* //        uint32_t strLen = array_to_hexstr(array, sizeof(array), inBuffer, 160); */
/* //        strLen += array_to_hexstr(array + strLen, sizeof(array) - strLen, inBuffer + 160, 200); */
/* //        EXPECT_EQ(strLen, 2*(156+192 + 8)); */
/* //        std::cout << array << std::endl; */
/*         parser_context_t ctx; */
/*         parser_tx_obj.special_transfer_type = normal_transaction; */
/*         auto err = parser_parse_combined(&ctx, inBuffer, inBufferLen + inBufferLen2 + 8); */
/*         EXPECT_EQ(err, parser_ok); */
/*     } */

    TEST(CBORParserTest, CombinedTXFail) {
    uint8_t inBuffer[1000];

    const char *tmp = "d9d9f7a167636f6e74656e74a46e696e67726573735f6578706972791b16bc685267142b8065706174687381824e726571756573745f737461747573582038b344ba26f15444b4f989078c952ce99b559d3eb59e829c5a463a33812e32546c726571756573745f747970656a726561645f73746174656673656e646572581dd899978f029508f4fa5fce3d2539de5aade6d229efcc458233deee7502";
    uint32_t inBufferLen = parseHexString(inBuffer + 4, sizeof(inBuffer) - 4, tmp);
    EXPECT_EQ(inBufferLen, 156);
    uint32_t badLength = 1000;
    MEMCPY(&inBuffer[0], &badLength, 4);

    const char *tmp2 = "d9d9f7a167636f6e74656e74a66361726758320a0012050a0308904e1a0308904e2a220a20a2a794c66495083317e4be5197eb655b1e63015469d769e2338af3d3e3f3aa866b63616e69737465725f69644a000000000000000201016e696e67726573735f6578706972791b16bc685084d14ec06b6d6574686f645f6e616d656773656e645f70626c726571756573745f747970656463616c6c6673656e646572581dd899978f029508f4fa5fce3d2539de5aade6d229efcc458233deee7502";
    uint32_t inBufferLen2 = parseHexString(inBuffer + 8 + inBufferLen, sizeof(inBuffer) - 4 - inBufferLen, tmp2);
    EXPECT_EQ(inBufferLen2, 192);
    MEMCPY(&inBuffer[4 + inBufferLen], &inBufferLen2, 4);
//        char array[2000];
//        MEMZERO(array,2000);
//        uint16_t total_len = 156 + 192 + 8;
//        uint32_t strLen = array_to_hexstr(array, sizeof(array), inBuffer, 160);
//        strLen += array_to_hexstr(array + strLen, sizeof(array) - strLen, inBuffer + 160, 200);
//        EXPECT_EQ(strLen, 2*(156+192 + 8));
//        std::cout << array << std::endl;
    parser_context_t ctx;
    parser_tx_obj.special_transfer_type = normal_transaction;
    auto err = parser_parse_combined(&ctx, inBuffer, inBufferLen + inBufferLen2 + 8);
    EXPECT_EQ(err, parser_value_out_of_range);
    }

}
