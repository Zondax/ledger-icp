/*******************************************************************************
*   (c) 2018 - 2024 Zondax AG
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
use core::{mem::MaybeUninit, ptr::addr_of_mut};

use bls_signature::verify_bls_signature;
use minicbor::{Decode, Decoder};

use crate::{
    consent_message::msg_response::ConsentMessageResponse,
    constants::{
        CANISTER_RANGES_PATH, CBOR_CERTIFICATE_TAG, MAX_CERT_INGRESS_OFFSET, REPLY_PATH,
        SHA256_DIGEST_LENGTH,
    },
    error::ParserError,
    zlog, FromBytes, Signature,
};

use super::{
    canister_ranges::CanisterRanges, delegation::Delegation, hash_tree::HashTree,
    raw_value::RawValue,
};
// separator_len(1-bytes) + separator(13-bytes) + hash(32-bytes)
pub const SEPARATOR: &[u8] = b"ic-state-root";
pub const SEPARATOR_LEN: usize = SEPARATOR.len();
pub const BLS_MSG_SIZE: usize = 1 + SEPARATOR_LEN + SHA256_DIGEST_LENGTH;

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct Certificate<'a> {
    tree: RawValue<'a>,
    signature: Signature<'a>,
    delegation: Option<Delegation<'a>>,
}

impl<'a> FromBytes<'a> for Certificate<'a> {
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'a [u8], crate::error::ParserError> {
        zlog("Certificate::from_bytes_into\x00");

        let mut d = Decoder::new(input);

        if let Ok(tag) = d.tag() {
            if tag.as_u64() != CBOR_CERTIFICATE_TAG {
                return Err(ParserError::CborUnexpected);
            }
        }

        // Expect a map with 2/3 entries
        let len = d.map()?.ok_or(ParserError::UnexpectedValue)?;

        // Expect a map with 2/3 entries
        // A certificate could have either 2(delegation cert) or 3 entries(root cert)
        if len != 2 && len != 3 {
            return Err(ParserError::ValueOutOfRange);
        }

        let out = out.as_mut_ptr();
        let mut has_delegation = false;

        for _ in 0..len {
            let key = d.str()?;
            match key {
                "tree" => {
                    let raw_value: RawValue = RawValue::decode(&mut d, &mut ())?;
                    // Just to check that tree is fully parsed
                    let _tree = HashTree::try_from(&raw_value)?;

                    #[cfg(test)]
                    std::println!("Certificate tree:\n {}", _tree);
                    unsafe { addr_of_mut!((*out).tree).write(raw_value) };
                }
                "signature" => {
                    let signature: &mut MaybeUninit<Signature<'a>> =
                        unsafe { &mut *addr_of_mut!((*out).signature).cast() };
                    let data = &input[d.position()..];

                    let rem = Signature::from_bytes_into(data, signature)?;

                    d.set_position(d.position() + (data.len() - rem.len()));
                }
                "delegation" => {
                    // create a new delegation here because it is define as an option
                    let mut delegation = MaybeUninit::uninit();
                    let data = &input[d.position()..];
                    let rem = Delegation::from_bytes_into(data, &mut delegation)?;

                    unsafe {
                        addr_of_mut!((*out).delegation).write(Some(delegation.assume_init()))
                    };
                    has_delegation = true;

                    d.set_position(d.position() + (data.len() - rem.len()));
                }
                _ => return Err(ParserError::InvalidCertificate),
            }
        }

        if !has_delegation {
            unsafe { addr_of_mut!((*out).delegation).write(None) };
        }

        Ok(&input[d.position()..])
    }
}

impl<'a> Certificate<'a> {
    pub fn tree(&self) -> RawValue<'a> {
        self.tree
    }

    pub fn delegation(&self) -> Option<&Delegation<'a>> {
        self.delegation.as_ref()
    }

    pub fn signature(&self) -> &[u8] {
        self.signature.bls_signature()
    }

    #[inline(never)]
    pub fn hash(&self) -> Result<[u8; 32], ParserError> {
        let tree = HashTree::try_from(&self.tree)?;
        tree.reconstruct()
    }

    // The root_public_key is now a parameter to the verify method
    #[inline(never)]
    pub fn verify(&self, root_key: &[u8]) -> Result<bool, ParserError> {
        zlog("Certificate::verify\x00");

        // Step 2: Check delegation
        if !self.check_delegation(root_key)? {
            zlog("check_delegation_failed\x00");
            return Ok(false);
        }

        // Step 3: Compute BLS key
        let pubkey = self.delegation_key(root_key)?;

        self.verify_signature(pubkey)
    }

    #[inline(never)]
    pub fn bls_message(&self) -> Result<[u8; BLS_MSG_SIZE], ParserError> {
        // Step 1: Compute root hash, this is computed using certificate.tree
        // This hash is computed correctly as per testing data passed from icp team
        // we get to the same hash.
        let root_hash = self.hash()?;

        // Step 4: Verify signature
        // separator_len(1-bytes) + separator(13-bytes) + hash(32-bytes)
        let mut message = [0u8; BLS_MSG_SIZE];
        message[0] = SEPARATOR_LEN as u8;
        // message[1..14].copy_from_slice(b"ic-state-root");
        message[1..14].copy_from_slice(SEPARATOR);
        message[14..].copy_from_slice(&root_hash);

        Ok(message)
    }

    #[inline(never)]
    fn verify_signature(&self, pubkey: &[u8]) -> Result<bool, ParserError> {
        let signature = self.signature.bls_signature();
        let message = self.bls_message()?;

        // Call third-party library directly to verify this signature
        let verified = verify_bls_signature(signature, &message, pubkey);

        Ok(verified.is_ok())
    }

    // verify the inner certificate
    // the one that comes in the delegation
    // if delegation is not present, return true
    #[inline(never)]
    fn check_delegation(&self, root_key: &[u8]) -> Result<bool, ParserError> {
        zlog("Certificate::check_delegation\x00");
        match &self.delegation {
            None => Ok(true),
            Some(delegation) => {
                // Ensure the delegation's certificate contains the subnet's public key
                if delegation.public_key()?.is_none() {
                    return Ok(false);
                }

                // Ensure the delegation's certificate does not have another delegation
                if delegation.cert().delegation().is_some() {
                    return Ok(false);
                }

                // Verify the delegation's certificate
                // using the root key and not the delegation's key,
                // however the signature to use is the one contained in
                // the delegation certificate.
                // not the outer certificate one.
                if !delegation.verify(root_key)? {
                    return Ok(false);
                }

                Ok(true)
            }
        }
    }

    // The outer certificate uses the delegation key if present, otherwise the root key
    fn delegation_key(&self, root_key: &'a [u8]) -> Result<&'a [u8], ParserError> {
        match &self.delegation {
            None => Ok(root_key), // Use root_public_key if no delegation
            Some(d) => {
                let key = d.public_key()?.ok_or(ParserError::UnexpectedValue)?;
                Ok(key.as_bytes())
            }
        }
    }

    pub fn timestamp(&self) -> Result<Option<u64>, ParserError> {
        let tree = self.tree();
        let path = "time".into();

        // Perform the lookup
        let Some(time) = HashTree::lookup_path(&path, tree)?.value() else {
            return Ok(None);
        };

        // inner time value is candid encoded a nat
        // so we need to parse it as well
        let (_, timestamp) =
            crate::utils::decompress_leb128(time).map_err(|_| ParserError::UnexpectedError)?;

        Ok(Some(timestamp))
    }

    pub fn canister_ranges(&self) -> Option<CanisterRanges<'a>> {
        let tree = match self.delegation() {
            None => self.tree(),
            Some(delegation) => delegation.cert().tree(),
        };

        let path = CANISTER_RANGES_PATH.into();
        let found = HashTree::lookup_path(&path, tree).ok()?;
        let data = found.value()?;
        let mut ranges = MaybeUninit::uninit();
        CanisterRanges::from_bytes_into(data, &mut ranges).ok()?;
        let ranges = unsafe { ranges.assume_init() };
        Some(ranges)
    }

    // Safe to unwrap because this reply was parsed already
    pub fn msg_response(&self) -> Result<ConsentMessageResponse<'a>, ParserError> {
        let tree = self.tree();
        let found = HashTree::lookup_path(&REPLY_PATH.into(), tree)?;
        let bytes = found.value().ok_or(ParserError::InvalidConsentMsg)?;

        let mut msg = MaybeUninit::uninit();
        ConsentMessageResponse::from_bytes_into(bytes, &mut msg)?;
        Ok(unsafe { msg.assume_init() })
    }

    pub fn verify_time(&self, ingress_expiry: u64) -> bool {
        let Ok(Some(cert_time)) = self.timestamp() else {
            return false;
        };

        if cert_time > ingress_expiry {
            return false;
        }

        let time_difference = ingress_expiry.saturating_sub(cert_time);

        time_difference <= MAX_CERT_INGRESS_OFFSET
    }
}

impl<'a> TryFrom<RawValue<'a>> for Certificate<'a> {
    type Error = ParserError;

    fn try_from(value: RawValue<'a>) -> Result<Self, Self::Error> {
        let mut cert = MaybeUninit::uninit();

        Self::from_bytes_into(value.bytes(), &mut cert)?;
        Ok(unsafe { cert.assume_init() })
    }
}

#[cfg(test)]
mod test_certificate {
    use super::*;
    use crate::DisplayableItem;
    use ic_certification::Certificate as IcpCertificate;

    const REAL_CERT: &str = "d9d9f7a3647472656583018301820458209b2d6a38f0e5c7ac52a8f7bf6d7751b79b0100857c870eae71666c75d4a1f7f5830182045820380a9672b9af551df307e91c777b4fa8f37960e0a107cf489c759b1ef0dfe33383024e726571756573745f7374617475738301830183018301830183018204582010d2494eb22918a6c994dc6fefb58f7d7fb1b2d17a52ee9edf28e241a6d7a783830182045820f5d09b5a356a77d4820aeb17fcbcb93a0fd55ddee4ee3f8dde4bf7cbfd397b9d83018204582046a6c3582218264ea6d3c34dc225b09b642605b1753eca2961c06eabfa7cb309830258200db17a4999e6d1bb9dadb9042489dfe1eee589e3f036aa1c7bfe12964c1ec75a83018302457265706c7982035901234449444c0f6b02bc8a0101c5fed2010c6c02efcee7800402e29fdcc806046c02aeaeb1cc0503d880c6d007716e766b029ee0b53b05fcdfd79a0f716c02f99cba840806dcec99f409716d076c02007101086b04cdf1cbbe030991c38ee7040ae998e3c30a0bebd2e8d60f0b6c01b99adecb01716c03c295a993017bd8a38ca80d78d8def6f60e716c01d8a38ca80d786b04d1c4987c0da3f2efe6020e9a8597e6030ee3c581900f0e6c02fc91f4f80571c498b1b50d7d6c01fc91f4f805710100000002656e00040455736572000d48656c6c6f2c20776f726c64210a637265617465645f617402f0bc7068000000000a6163746976655f666f7203580200000000000006616d6f756e74010800c2eb0b00000000034943500a477265657420757365728302467374617475738203477265706c696564820458208264bfd38120767311a6858cd1ee4ce2a697f4e17026e824dd5e2f06a1e90181820458200a8c7afcbde567117cf1f3dae404fc6bd2d7d094774f740b5fb1abf522015d268204582029633b2785b61f32e8764ac65a977d7e609f1e05e9e5949a0b2d419a08b67e9882045820669b89933ea8636d1ba28e1ab072e2b980df498d0d0ea24c58c46848b48e9e38820458200423cae37e0670c3426f6f04b3a010c1f6010524d31486b769951324e800118283018204582079f11424b2c5e29ca256d504261cacdf7626a1a28f7863dd2b6bf93ffa3836e783024474696d65820349c699bbc6aefdb7aa18697369676e61747572655830b49a681d69c6e1f7089165cd0473f5e78fa09917e825c07041cdc0664f8977d9b1804e2c651ef7cf304bd99299997f4b6a64656c65676174696f6ea2697375626e65745f6964581d2c55b347ecf2686c83781d6c59d1b43e7b4cba8deb6c1b376107f2cd026b6365727469666963617465590294d9d9f7a264747265658301820458209b9acf5ebb96de4fd39f4928d5fe9ab3873620c4d5a71947c4580ac3a9c169ec8301830182045820d8470247bcd58a7a80aa89c80b203ca1b4b03de290996402f9df8f39f98043748302467375626e65748301830183018204582071387af6dac4d6350824bf1c24c8dd0af43a910b2dad8ce86390c816e63816158301830183018302581d2c55b347ecf2686c83781d6c59d1b43e7b4cba8deb6c1b376107f2cd02830183024f63616e69737465725f72616e67657382035832d9d9f782824a000000000060000001014a00000000006000ae0101824a00000000006000b001014a00000000006fffff010183024a7075626c69635f6b657982035885308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c0503020103610090075120778eb21a530a02bcc763e7f4a192933506966af7b54c10a4d2b24de6a86b200e3440bae6267bf4c488d9a11d0472c38c1b6221198f98e4e6882ba38a5a4e3aa5afce899b7f825ed95adfa12629688073556f2747527213e8d73e40ce8204582036f3cd257d90fb38e42597f193a5e031dbd585b6292793bb04db4794803ce06e820458205b9edd6408228a3956c4b4164ed3d9ec38afabe63310f84da7b97005e1fae375820458202729572815f63e48d2248738a83546bf521d479351ff52f172de77602ff682d382045820afaa8832101bcee23eb871f6a3b372b927eb3ad5bacbbbf67aa4df296bf8c49382045820962337bb2648bcf41e6d4f3cd80d6f6b3876dd18e62a8fb0cc5dc45f6e9d283e83024474696d65820349c8b9a8faedf8b7aa18697369676e617475726558308b0fc21a67a745f0716ba21ae4ec570cadbdb873c07b3584600d7815bae0e9c45c974ef4af028af5b165017b78ec9fc4";
    const CANISTER_ID: &str = "0000000000600B730101";
    const INGRESS_EXPIRY: u64 = 1753272540000000000;
    const CERT_GENERIC_DISPLAY: &str = "d9d9f7a2647472656583018301820458207970ca0b7b0c0e63228c4cf47ce6f4a94268cfc004a99ae8aba5e97f204126a183018204582080b175729756e05010ceab7db6bed386cc6db61d274fe7d38a5f0bcea7ef317783024e726571756573745f7374617475738301830258204b77e3e74aa91e7bf50f8cf1acc0cb1dbafa4ad45c050e2abcc5d910317862a383018302457265706c79820359032d4449444c0c6b02bc8a0101c5fed201096c02efcee7800402e29fdcc806046c02aeaeb1cc0503d880c6d007716e766b02d9e5b0980405fcdfd79a0f716c01c4d6b4ea0b066d076c01ffbb87a807086d716b04d1c4987c0aa3f2efe6020b9a8597e6030be3c581900f0b6c02fc91f4f80571c498b1b50d7d6c01fc91f4f805710100000002656e01a4052320417574686f72697a6520616e6f74686572206164647265737320746f2077697468647261772066726f6d20796f7572206163636f756e740a0a2a2a54686520666f6c6c6f77696e67206164647265737320697320616c6c6f77656420746f2077697468647261772066726f6d20796f7572206163636f756e743a2a2a0a72646d78362d6a616161612d61616161612d61616164712d6361690a0a2a2a596f7572207375626163636f756e743a2a2a0a303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030300a0a2a2a526571756573746564207769746864726177616c20616c6c6f77616e63653a2a2a0a3130204943500ae29aa02054686520616c6c6f77616e63652077696c6c2062652073657420746f2031302049435020696e646570656e64656e746c79206f6620616e792070726576696f757320616c6c6f77616e63652e20556e74696c2074686973207472616e73616374696f6e20686173206265656e20657865637574656420746865207370656e6465722063616e207374696c6c206578657263697365207468652070726576696f757320616c6c6f77616e63652028696620616e792920746f20697427732066756c6c20616d6f756e742e0a0a2a2a45787069726174696f6e20646174653a2a2a0a4e6f2065787069726174696f6e2e0a0a2a2a417070726f76616c206665653a2a2a0a302e30303031204943500a0a2a2a5472616e73616374696f6e206665657320746f206265207061696420627920796f7572207375626163636f756e743a2a2a0a303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030308302467374617475738203477265706c696564820458203c45af0e5805729f1d07fbce20047198017873e787c5a27744ca20c71ad357b8830182045820d4fdd3b69be601a88a9412234c7940446d55dbc09bd3f28eb96d8548a2fe885283024474696d65820349889893d986e3d58218697369676e61747572655830b60f55093dc0835939589c2a3dcb5313248b13b5d965f3019fb9f5f3d34503443100b5103386a9d2df229fa82fe0440c";
    const ROOT_KEY: &str =
        "814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae";
    const DER_ROOT_KEY: &str = "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae";

    use std::vec::Vec;

    fn extract_bls_from_der(der_bytes: &[u8]) -> Option<Vec<u8>> {
        // The BLS public key in this DER format comes after:
        // - SEQUENCE (0x30)
        // - Length of entire sequence (0x81 0x82)
        // - Inner SEQUENCE (0x30)
        // - Inner sequence length (0x1d)
        // - Two OID structures
        // - BIT STRING marker (0x03)
        // - BIT STRING length (0x61)
        // - Padding bit (0x00)

        // We can look for the bit string marker and length
        let mut i = 0;
        while i < der_bytes.len() {
            if der_bytes[i] == 0x03 && der_bytes[i + 1] == 0x61 && der_bytes[i + 2] == 0x00 {
                // Found the start of our key data
                // Skip the 0x03 0x61 0x00 markers and return the rest
                return Some(der_bytes[i + 3..].to_vec());
            }
            i += 1;
        }
        None
    }

    #[test]
    fn parse_cert() {
        let data = hex::decode(REAL_CERT).unwrap();
        let cert = Certificate::from_bytes(&data).unwrap();

        // Check we parse the message(reply field)
        assert!(cert.msg_response().is_ok());
    }

    #[test]
    fn verify_certificate() {
        let data = hex::decode(REAL_CERT).unwrap();
        let cert = Certificate::from_bytes(&data).unwrap();
        let cert_signature = hex::encode(cert.signature());
        let root_hash = hex::encode(cert.hash().unwrap());
        // Verify delegation.cert root_hash
        assert!(cert.delegation.is_some());

        // compare our root hash with the hash icp library computes
        let icp_cert: IcpCertificate = serde_cbor::from_slice(&data).unwrap();
        let icp_tree = icp_cert.tree;
        let icp_hash = icp_tree.digest();
        let icp_hash = hex::encode(icp_hash);
        let icp_signature = hex::encode(icp_cert.signature);

        assert_eq!(root_hash, icp_hash);
        assert_eq!(cert_signature, icp_signature);

        let root_key = hex::decode(ROOT_KEY).unwrap();
        assert!(cert.verify(&root_key).unwrap());

        // verify certificate expiry time
        assert!(cert.verify_time(INGRESS_EXPIRY));
    }

    #[test]
    fn check_canister_ranges() {
        let data = hex::decode(REAL_CERT).unwrap();
        let cert = Certificate::from_bytes(&data).unwrap();

        let Some(ranges) = cert.canister_ranges() else {
            // No ranges in this data
            return;
        };

        let mut num_ranges = 0;
        for (i, r) in ranges.iter().enumerate() {
            std::println!("Range{}: {:?}", i, r);
            num_ranges += 1;
        }

        assert_eq!(num_ranges, ranges.len());
        let canister_id = hex::decode(CANISTER_ID).unwrap();

        // the provided canister might be used in case of delegation
        assert!(ranges.is_canister_in_range(&canister_id));
    }

    #[test]
    fn error_generic_display() {
        let data = hex::decode(CERT_GENERIC_DISPLAY).unwrap();
        let cert = Certificate::from_bytes(&data).unwrap();

        // Check we parse the message(reply field)
        let msg = cert.msg_response();
        assert!(msg.is_err());
    }

    #[test]
    fn test_complete_canister_call() {
        let hex_input = "d9d9f7a3647472656583018301820458209b2d6a38f0e5c7ac52a8f7bf6d7751b79b0100857c870eae71666c75d4a1f7f5830182045820380a9672b9af551df307e91c777b4fa8f37960e0a107cf489c759b1ef0dfe33383024e726571756573745f7374617475738301830183018301830183018204582010d2494eb22918a6c994dc6fefb58f7d7fb1b2d17a52ee9edf28e241a6d7a783830182045820f5d09b5a356a77d4820aeb17fcbcb93a0fd55ddee4ee3f8dde4bf7cbfd397b9d83018204582046a6c3582218264ea6d3c34dc225b09b642605b1753eca2961c06eabfa7cb309830258200db17a4999e6d1bb9dadb9042489dfe1eee589e3f036aa1c7bfe12964c1ec75a83018302457265706c7982035901234449444c0f6b02bc8a0101c5fed2010c6c02efcee7800402e29fdcc806046c02aeaeb1cc0503d880c6d007716e766b029ee0b53b05fcdfd79a0f716c02f99cba840806dcec99f409716d076c02007101086b04cdf1cbbe030991c38ee7040ae998e3c30a0bebd2e8d60f0b6c01b99adecb01716c03c295a993017bd8a38ca80d78d8def6f60e716c01d8a38ca80d786b04d1c4987c0da3f2efe6020e9a8597e6030ee3c581900f0e6c02fc91f4f80571c498b1b50d7d6c01fc91f4f805710100000002656e00040455736572000d48656c6c6f2c20776f726c64210a637265617465645f617402f0bc7068000000000a6163746976655f666f7203580200000000000006616d6f756e74010800c2eb0b00000000034943500a477265657420757365728302467374617475738203477265706c696564820458208264bfd38120767311a6858cd1ee4ce2a697f4e17026e824dd5e2f06a1e90181820458200a8c7afcbde567117cf1f3dae404fc6bd2d7d094774f740b5fb1abf522015d268204582029633b2785b61f32e8764ac65a977d7e609f1e05e9e5949a0b2d419a08b67e9882045820669b89933ea8636d1ba28e1ab072e2b980df498d0d0ea24c58c46848b48e9e38820458200423cae37e0670c3426f6f04b3a010c1f6010524d31486b769951324e800118283018204582079f11424b2c5e29ca256d504261cacdf7626a1a28f7863dd2b6bf93ffa3836e783024474696d65820349c699bbc6aefdb7aa18697369676e61747572655830b49a681d69c6e1f7089165cd0473f5e78fa09917e825c07041cdc0664f8977d9b1804e2c651ef7cf304bd99299997f4b6a64656c65676174696f6ea2697375626e65745f6964581d2c55b347ecf2686c83781d6c59d1b43e7b4cba8deb6c1b376107f2cd026b6365727469666963617465590294d9d9f7a264747265658301820458209b9acf5ebb96de4fd39f4928d5fe9ab3873620c4d5a71947c4580ac3a9c169ec8301830182045820d8470247bcd58a7a80aa89c80b203ca1b4b03de290996402f9df8f39f98043748302467375626e65748301830183018204582071387af6dac4d6350824bf1c24c8dd0af43a910b2dad8ce86390c816e63816158301830183018302581d2c55b347ecf2686c83781d6c59d1b43e7b4cba8deb6c1b376107f2cd02830183024f63616e69737465725f72616e67657382035832d9d9f782824a000000000060000001014a00000000006000ae0101824a00000000006000b001014a00000000006fffff010183024a7075626c69635f6b657982035885308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c0503020103610090075120778eb21a530a02bcc763e7f4a192933506966af7b54c10a4d2b24de6a86b200e3440bae6267bf4c488d9a11d0472c38c1b6221198f98e4e6882ba38a5a4e3aa5afce899b7f825ed95adfa12629688073556f2747527213e8d73e40ce8204582036f3cd257d90fb38e42597f193a5e031dbd585b6292793bb04db4794803ce06e820458205b9edd6408228a3956c4b4164ed3d9ec38afabe63310f84da7b97005e1fae375820458202729572815f63e48d2248738a83546bf521d479351ff52f172de77602ff682d382045820afaa8832101bcee23eb871f6a3b372b927eb3ad5bacbbbf67aa4df296bf8c49382045820962337bb2648bcf41e6d4f3cd80d6f6b3876dd18e62a8fb0cc5dc45f6e9d283e83024474696d65820349c8b9a8faedf8b7aa18697369676e617475726558308b0fc21a67a745f0716ba21ae4ec570cadbdb873c07b3584600d7815bae0e9c45c974ef4af028af5b165017b78ec9fc4";

        let input = hex::decode(hex_input).unwrap();
        let mut cert = MaybeUninit::<Certificate>::uninit();

        let result = Certificate::from_bytes_into(&input, &mut cert);
        assert!(result.is_ok());

        let cert = unsafe { cert.assume_init() };
        let Ok(ConsentMessageResponse::Ok(ui)) = cert.msg_response() else {
            panic!("Invalid certificate");
        };

        // Get the underlying message that implements DisplayableItem
        let msg = &ui.message;

        // Test number of items (should be 4 fields)
        assert_eq!(msg.num_items().unwrap(), 4);

        // Expected field pairs from the encoded data
        let expected_fields = [
            ("User", "Hello, world!"),
            ("created_at", "1752218864 s"),
            ("active_for", "600 s"),
            ("amount", "2 ICP"),
        ];

        // Test each field rendering
        for (i, (expected_key, expected_value)) in expected_fields.iter().enumerate() {
            let mut title = [0u8; 64];
            let mut message = [0u8; 256];

            // Render the field
            let result = msg.render_item(i as u8, &mut title, &mut message, 0);
            assert!(result.is_ok(), "Failed to render field {}", i);

            // Extract title (key) - find null terminator
            let title_end = title.iter().position(|&x| x == 0).unwrap_or(title.len());
            let title_str = std::str::from_utf8(&title[..title_end]).unwrap();
            assert_eq!(title_str, *expected_key, "Key mismatch for field {}", i);

            // Extract message (value) - find null terminator
            let message_end = message
                .iter()
                .position(|&x| x == 0)
                .unwrap_or(message.len());
            let message_str = std::str::from_utf8(&message[..message_end]).unwrap();
            assert_eq!(
                message_str, *expected_value,
                "Value mismatch for field {}",
                i
            );
        }
    }
}
