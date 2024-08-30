/*******************************************************************************
*   (c) 2024 Zondax AG
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
mod c_api;
mod call_request;
mod consent_request;
mod resources;
mod ui;
mod verify_certificate;

#[cfg(test)]
mod ffi_verify_cert {
    use crate::{
        constants::CANISTER_ROOT_KEY,
        error::ParserError,
        ffi::{call_request::CanisterCallT, consent_request::ConsentRequestT},
    };

    use super::{
        call_request::rs_parse_canister_call_request, consent_request::rs_parse_consent_request,
        resources::rs_clear_resources, verify_certificate::rs_verify_certificate,
    };

    const CERT_DATA: &str = "d9d9f7a3647472656583018301820458200bbcc71092da3ce262b8154d398b9a6114bee87f1c0b72e16912757aa023626a8301820458200628a8e00432e8657ad99c4d1bf167dd54ace9199609bfc5d57d89f48d97565f83024e726571756573745f737461747573830258204ea057c46292fedb573d35319dd1ccab3fb5d6a2b106b785d1f7757cfa5a254283018302457265706c79820358b44449444c0b6b02bc8a0101c5fed201086c02efcee7800402e29fdcc806036c01d880c6d007716b02d9e5b0980404fcdfd79a0f716c01c4d6b4ea0b056d066c01ffbb87a807076d716b04d1c4987c09a3f2efe6020a9a8597e6030ae3c581900f0a6c02fc91f4f80571c498b1b50d7d6c01fc91f4f8057101000002656e0001021e50726f647563652074686520666f6c6c6f77696e67206772656574696e6714746578743a202248656c6c6f2c20746f626921228302467374617475738203477265706c696564830182045820891af3e8982f1ac3d295c29b9fdfedc52301c03fbd4979676c01059184060b0583024474696d65820349cbf7dd8ca1a2a7e217697369676e6174757265583088078c6fe75f32594bf4e322b14d47e5c849cf24a370e3bab0cab5daffb7ab6a2c49de18b7f2d631893217d0c716cd656a64656c65676174696f6ea2697375626e65745f6964581d2c55b347ecf2686c83781d6c59d1b43e7b4cba8deb6c1b376107f2cd026b6365727469666963617465590294d9d9f7a264747265658301820458200b0d62dc7b9d7de735bb9a6393b59c9f32ff7c4d2aacdfc9e6ffc70e341fb6f783018301820458204468514ca4af8224c055c386e3f7b0bfe018c2d9cfd5837e427b43e1ab0934f98302467375626e65748301830183018301820458208739fbbedd3dedaa8fef41870367c0905bde376b63dd37e2b176fb08b582052f830182045820f8c3eae0377ee00859223bf1c6202f5885c4dcdc8fd13b1d48c3c838688919bc83018302581d2c55b347ecf2686c83781d6c59d1b43e7b4cba8deb6c1b376107f2cd02830183024f63616e69737465725f72616e67657382035832d9d9f782824a000000000060000001014a00000000006000ae0101824a00000000006000b001014a00000000006fffff010183024a7075626c69635f6b657982035885308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c0503020103610090075120778eb21a530a02bcc763e7f4a192933506966af7b54c10a4d2b24de6a86b200e3440bae6267bf4c488d9a11d0472c38c1b6221198f98e4e6882ba38a5a4e3aa5afce899b7f825ed95adfa12629688073556f2747527213e8d73e40ce8204582036f3cd257d90fb38e42597f193a5e031dbd585b6292793bb04db4794803ce06e82045820028fc5e5f70868254e7215e7fc630dbd29eefc3619af17ce231909e1faf97e9582045820696179fceb777eaed283265dd690241999eb3ede594091748b24456160edc1278204582081398069f9684da260cfb002eac42211d0dbf22c62d49aee61617d62650e793183024474696d65820349a5948992aaa195e217697369676e6174757265583094e5f544a7681b0c2c3c5dbf97950c96fd837f2d19342f1050d94d3068371b0a95a5ee20c36c4395c2dbb4204f2b4742";
    const CALL_DATA: &str ="d9d9f7a167636f6e74656e74a6636172674c4449444c00017104746f62696b63616e69737465725f69644a00000000006000fd01016e696e67726573735f657870697279c24817c49db0b64dfb806b6d6574686f645f6e616d656567726565746c726571756573745f747970656571756572796673656e6465724104";
    const CONSENT_DATA: &str = "d9d9f7a167636f6e74656e74a763617267586b4449444c076d7b6c01d880c6d007716c02cbaeb581017ab183e7f1077a6b028beabfc2067f8ef1c1ee0d026e036c02efcee7800401c4fbf2db05046c03d6fca70200e1edeb4a7184f7fee80a0501060c4449444c00017104746f626905677265657402656e01011e0003006b63616e69737465725f69644a00000000006000fd01016e696e67726573735f657870697279c24817c49d49c5a920806b6d6574686f645f6e616d6578246963726332315f63616e69737465725f63616c6c5f636f6e73656e745f6d657373616765656e6f6e636550a3788c1805553fb69b20f08e87e23b136c726571756573745f747970656463616c6c6673656e6465724104";

    fn bls_flow() -> u32 {
        let cert_data = hex::decode(CERT_DATA).unwrap();
        let call_data = hex::decode(CALL_DATA).unwrap();
        let consent_data = hex::decode(CONSENT_DATA).unwrap();
        let root_key = hex::decode(CANISTER_ROOT_KEY).unwrap();

        unsafe {
            // 1. send consent_request
            if rs_parse_consent_request(consent_data.as_ptr(), consent_data.len() as u16)
                != ParserError::Ok as _
            {
                return ParserError::InvalidConsentMsg as u32;
            }

            // 2. send call request
            if rs_parse_canister_call_request(call_data.as_ptr(), call_data.len() as u16)
                != ParserError::Ok as _
            {
                return ParserError::InvalidCallRequest as u32;
            }
            // 3. send certificate, by default use root key
            if rs_verify_certificate(
                cert_data.as_ptr(),
                cert_data.len() as u16,
                root_key.as_ptr(),
            ) != ParserError::Ok as _
            {
                return ParserError::InvalidCertificate as u32;
            }

            ParserError::Ok as u32
        }
    }

    #[test]
    fn test_bls_flow() {
        assert_eq!(bls_flow(), ParserError::Ok as u32);
        unsafe {
            rs_clear_resources();
        }

        // now test again and ensure we error if resources are not empty
        assert_eq!(bls_flow(), ParserError::Ok as u32);
        // trying to verify without cleaning resources
        assert_ne!(bls_flow(), ParserError::Ok as u32);

        std::println!(
            "consent_request_t_size: {}",
            core::mem::size_of::<ConsentRequestT>()
        );
        std::println!(
            "call_request_t_size: {}",
            core::mem::size_of::<CanisterCallT>()
        )
    }
}
