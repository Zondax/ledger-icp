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
        BLS_MSG_SIZE, CANISTER_RANGES_PATH, CBOR_CERTIFICATE_TAG, MAX_CERT_INGRESS_OFFSET,
        REPLY_PATH,
    },
    error::{ParserError, ViewError},
    zlog, DisplayableItem, FromBytes, Signature,
};

use super::{
    canister_ranges::CanisterRanges, delegation::Delegation, hash_tree::HashTree,
    raw_value::RawValue,
};

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

        let cert = unsafe { &mut *out };
        // Verify that the tree raw value can be parsed sucessfully into a HashTree
        let _: HashTree = cert.tree.try_into().map_err(|_| ParserError::InvalidTree)?;

        #[cfg(test)]
        HashTree::parse_and_print_hash_tree(&cert.tree, 0);

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
        let tree: HashTree = self.tree.try_into()?;
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
    pub fn bls_message(&self) -> Result<[u8; 46], ParserError> {
        // Step 1: Compute root hash, this is computed using certificate.tree
        // This hash is computed correctly as per testing data passed from icp team
        // we get to the same hash.
        let root_hash = self.hash()?;

        // Step 4: Verify signature
        // separator_len(1-bytes) + separator(13-bytes) + hash(32-bytes)
        let mut message = [0u8; BLS_MSG_SIZE];
        message[0] = 13;
        message[1..14].copy_from_slice(b"ic-state-root");
        message[14..].copy_from_slice(&root_hash);

        Ok(message)
    }

    #[inline(never)]
    fn verify_signature(&self, pubkey: &[u8]) -> Result<bool, ParserError> {
        let signature = self.signature.bls_signature();
        let message = self.bls_message()?;

        // Call third-party library directly to verify this signature
        zlog("Certificate::verify_signature\x00");
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
                zlog("dele_pubkey\x00");
                if delegation.public_key()?.is_none() {
                    zlog("delegation_without_key\x00");
                    return Ok(false);
                }

                // Ensure the delegation's certificate does not have another delegation
                zlog("no_delegation\x00");
                if delegation.cert().delegation().is_some() {
                    return Ok(false);
                }

                // Verify the delegation's certificate
                // using the root key and not the delegation's key,
                // however the signature to use is the one contained in
                // the delegation certificate.
                // not the outer certificate one.
                zlog("delegation_verify\x00");
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
    fn msg(&self) -> Result<ConsentMessageResponse<'a>, ParserError> {
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

impl<'a> DisplayableItem for Certificate<'a> {
    #[inline(never)]
    fn num_items(&self) -> Result<u8, ViewError> {
        let msg = self.msg().map_err(|_| ViewError::Unknown)?;
        msg.num_items()
    }

    #[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        zlog("Certificate::render_item\x00");
        let msg = self.msg().map_err(|_| ViewError::Unknown)?;
        msg.render_item(item_n, title, message, page)
    }
}

#[cfg(test)]
mod test_certificate {

    use crate::constants::CANISTER_ROOT_KEY;

    use super::*;
    use ic_certification::Certificate as IcpCertificate;

    const REAL_CERT: &str = "d9d9f7a3647472656583018301820458200bbcc71092da3ce262b8154d398b9a6114bee87f1c0b72e16912757aa023626a8301820458200628a8e00432e8657ad99c4d1bf167dd54ace9199609bfc5d57d89f48d97565f83024e726571756573745f737461747573830258204ea057c46292fedb573d35319dd1ccab3fb5d6a2b106b785d1f7757cfa5a254283018302457265706c79820358b44449444c0b6b02bc8a0101c5fed201086c02efcee7800402e29fdcc806036c01d880c6d007716b02d9e5b0980404fcdfd79a0f716c01c4d6b4ea0b056d066c01ffbb87a807076d716b04d1c4987c09a3f2efe6020a9a8597e6030ae3c581900f0a6c02fc91f4f80571c498b1b50d7d6c01fc91f4f8057101000002656e0001021e50726f647563652074686520666f6c6c6f77696e67206772656574696e6714746578743a202248656c6c6f2c20746f626921228302467374617475738203477265706c696564830182045820891af3e8982f1ac3d295c29b9fdfedc52301c03fbd4979676c01059184060b0583024474696d65820349cbf7dd8ca1a2a7e217697369676e6174757265583088078c6fe75f32594bf4e322b14d47e5c849cf24a370e3bab0cab5daffb7ab6a2c49de18b7f2d631893217d0c716cd656a64656c65676174696f6ea2697375626e65745f6964581d2c55b347ecf2686c83781d6c59d1b43e7b4cba8deb6c1b376107f2cd026b6365727469666963617465590294d9d9f7a264747265658301820458200b0d62dc7b9d7de735bb9a6393b59c9f32ff7c4d2aacdfc9e6ffc70e341fb6f783018301820458204468514ca4af8224c055c386e3f7b0bfe018c2d9cfd5837e427b43e1ab0934f98302467375626e65748301830183018301820458208739fbbedd3dedaa8fef41870367c0905bde376b63dd37e2b176fb08b582052f830182045820f8c3eae0377ee00859223bf1c6202f5885c4dcdc8fd13b1d48c3c838688919bc83018302581d2c55b347ecf2686c83781d6c59d1b43e7b4cba8deb6c1b376107f2cd02830183024f63616e69737465725f72616e67657382035832d9d9f782824a000000000060000001014a00000000006000ae0101824a00000000006000b001014a00000000006fffff010183024a7075626c69635f6b657982035885308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c0503020103610090075120778eb21a530a02bcc763e7f4a192933506966af7b54c10a4d2b24de6a86b200e3440bae6267bf4c488d9a11d0472c38c1b6221198f98e4e6882ba38a5a4e3aa5afce899b7f825ed95adfa12629688073556f2747527213e8d73e40ce8204582036f3cd257d90fb38e42597f193a5e031dbd585b6292793bb04db4794803ce06e82045820028fc5e5f70868254e7215e7fc630dbd29eefc3619af17ce231909e1faf97e9582045820696179fceb777eaed283265dd690241999eb3ede594091748b24456160edc1278204582081398069f9684da260cfb002eac42211d0dbf22c62d49aee61617d62650e793183024474696d65820349a5948992aaa195e217697369676e6174757265583094e5f544a7681b0c2c3c5dbf97950c96fd837f2d19342f1050d94d3068371b0a95a5ee20c36c4395c2dbb4204f2b4742";
    const CERT_HASH: &str = "bcedf2eab3980aedd4d0d9f2159efebd5597cbad5f49217e0c9686b93d30d503";
    const DEL_CERT_HASH: &str = "04a94256c02e83aab4f203cb0784340279d7902f9b09305c978be1746e19b742";
    const CANISTER_ID: &str = "00000000006000FD0101";

    const REQUEST_ID: &str = "4ea057c46292fedb573d35319dd1ccab3fb5d6a2b106b785d1f7757cfa5a2542";

    const INGRESS_EXPIRY: u64 = 1712666798482000000;

    const CERT3: &str = "d9d9f7a2647472656583018301820458207970ca0b7b0c0e63228c4cf47ce6f4a94268cfc004a99ae8aba5e97f204126a183018204582080b175729756e05010ceab7db6bed386cc6db61d274fe7d38a5f0bcea7ef317783024e726571756573745f7374617475738301830258204b77e3e74aa91e7bf50f8cf1acc0cb1dbafa4ad45c050e2abcc5d910317862a383018302457265706c79820359032d4449444c0c6b02bc8a0101c5fed201096c02efcee7800402e29fdcc806046c02aeaeb1cc0503d880c6d007716e766b02d9e5b0980405fcdfd79a0f716c01c4d6b4ea0b066d076c01ffbb87a807086d716b04d1c4987c0aa3f2efe6020b9a8597e6030be3c581900f0b6c02fc91f4f80571c498b1b50d7d6c01fc91f4f805710100000002656e01a4052320417574686f72697a6520616e6f74686572206164647265737320746f2077697468647261772066726f6d20796f7572206163636f756e740a0a2a2a54686520666f6c6c6f77696e67206164647265737320697320616c6c6f77656420746f2077697468647261772066726f6d20796f7572206163636f756e743a2a2a0a72646d78362d6a616161612d61616161612d61616164712d6361690a0a2a2a596f7572207375626163636f756e743a2a2a0a303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030300a0a2a2a526571756573746564207769746864726177616c20616c6c6f77616e63653a2a2a0a3130204943500ae29aa02054686520616c6c6f77616e63652077696c6c2062652073657420746f2031302049435020696e646570656e64656e746c79206f6620616e792070726576696f757320616c6c6f77616e63652e20556e74696c2074686973207472616e73616374696f6e20686173206265656e20657865637574656420746865207370656e6465722063616e207374696c6c206578657263697365207468652070726576696f757320616c6c6f77616e63652028696620616e792920746f20697427732066756c6c20616d6f756e742e0a0a2a2a45787069726174696f6e20646174653a2a2a0a4e6f2065787069726174696f6e2e0a0a2a2a417070726f76616c206665653a2a2a0a302e30303031204943500a0a2a2a5472616e73616374696f6e206665657320746f206265207061696420627920796f7572207375626163636f756e743a2a2a0a303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030308302467374617475738203477265706c696564820458203c45af0e5805729f1d07fbce20047198017873e787c5a27744ca20c71ad357b8830182045820d4fdd3b69be601a88a9412234c7940446d55dbc09bd3f28eb96d8548a2fe885283024474696d65820349889893d986e3d58218697369676e61747572655830b60f55093dc0835939589c2a3dcb5313248b13b5d965f3019fb9f5f3d34503443100b5103386a9d2df229fa82fe0440c";
    const ROOT_KEY3: &str = "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100ac71eddf6821aee80802b879cf0d1f5e5cd3f29aca6239169b6c2a847fc5a633851782b775d11be832bee655826e234c0642be37b84a8d9527dab6321a595a8f78f39b725ddb20a471184644ab62de3aa7249825bad5a796aa29821ad69abf11";

    #[test]
    fn parse_cert() {
        let data = hex::decode(REAL_CERT).unwrap();
        let cert = Certificate::from_bytes(&data).unwrap();

        // Check we parse the message(reply field)
        assert!(cert.msg().is_ok());
    }

    #[test]
    fn verify_cert() {
        let data = hex::decode(REAL_CERT).unwrap();
        let cert = Certificate::from_bytes(&data).unwrap();
        let root_hash = hex::encode(cert.hash().unwrap());
        // Verify delegation.cert root_hash
        let del_cert = cert.delegation.unwrap().cert();
        let del_cert_hash = hex::encode(del_cert.hash().unwrap());

        // compare our root hash with the hash icp library computes
        let icp_cert: IcpCertificate = serde_cbor::from_slice(&data).unwrap();
        let icp_tree = icp_cert.tree;
        let icp_hash = icp_tree.digest();
        let icp_hash = hex::encode(icp_hash);

        assert_eq!(root_hash, icp_hash);
        assert_eq!(root_hash, CERT_HASH);

        // compare our root hash with the hash icp library computes
        let icp_cert: IcpCertificate = serde_cbor::from_slice(&data).unwrap();
        let delegation = icp_cert.delegation.unwrap();
        let del_cert: IcpCertificate = serde_cbor::from_slice(&delegation.certificate).unwrap();
        let icp_hash = hex::encode(del_cert.tree.digest());

        assert_eq!(del_cert_hash, icp_hash);
        assert_eq!(del_cert_hash, DEL_CERT_HASH);

        // verify certificate signatures
        let root_key = hex::decode(CANISTER_ROOT_KEY).unwrap();
        assert!(cert.verify(&root_key).unwrap());

        // verify certificate expiry time
        assert!(cert.verify_time(INGRESS_EXPIRY));
    }

    #[test]
    fn check_canister_ranges() {
        let data = hex::decode(REAL_CERT).unwrap();
        let cert = Certificate::from_bytes(&data).unwrap();
        let ranges = cert.canister_ranges().unwrap();
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
    fn cert_lookup_request_id() {
        let data = hex::decode(REAL_CERT).unwrap();
        let cert = Certificate::from_bytes(&data).unwrap();

        let request_id = hex::decode(REQUEST_ID).unwrap();

        let tree = cert.tree();

        let found = HashTree::lookup_path(&request_id[..].into(), tree).unwrap();
        assert!(found.raw_value().is_some());
    }

    #[test]
    fn parse_cert3() {
        let data = hex::decode(CERT3).unwrap();
        let cert = Certificate::from_bytes(&data).unwrap();

        // Check we parse the message(reply field)
        assert!(cert.msg().is_ok());
    }
}
