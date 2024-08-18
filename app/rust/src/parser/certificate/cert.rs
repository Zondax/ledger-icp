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
use minicbor::{data::Type, decode::Error, Decode, Decoder};

use crate::{
    consent_message::msg_response::ConsentMessageResponse,
    constants::{BLS_MSG_SIZE, CBOR_CERTIFICATE_TAG, REPLY_PATH},
    error::{ParserError, ViewError},
    DisplayableItem, FromBytes, Signature,
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
        crate::zlog("Certificate::from_bytes_into\x00");
        let mut d = Decoder::new(input);

        if let Ok(tag) = d.tag() {
            if tag.as_u64() != CBOR_CERTIFICATE_TAG {
                return Err(ParserError::CborUnexpected);
            }
        }

        // Expect a map with 2/3 entries
        let len = d.map()?.ok_or(ParserError::UnexpectedValue)?;
        crate::zlog("read_len\x00");

        // Expect a map with 2/3 entries
        // A certificate could have either 2(delegation cert) or 3 entries(root cert)
        if len != 2 && len != 3 {
            crate::zlog("wrong_len\x00");
            return Err(ParserError::ValueOutOfRange);
        }
        crate::zlog("good_len\x00");
        let out = out.as_mut_ptr();

        for _ in 0..len {
            crate::zlog("item_i\x00");
            let key = d.str()?;
            let mut rem = &input[d.position()..];
            match key {
                "tree" => {
                    let raw_value: RawValue = RawValue::decode(&mut d, &mut ())?;
                    unsafe { addr_of_mut!((*out).tree).write(raw_value) };
                } //tree = Some(RawValue::decode(d, ctx)?),
                "signature" => {
                    let signature = unsafe { &mut *addr_of_mut!((*out).signature).cast() };
                    let rem = Signature::from_bytes_into(rem, signature)?;
                    d = Decoder::new(rem);
                } //signature = Some(RawValue::decode(d, ctx)?.try_into()?),
                "delegation" => {
                    let delegation = unsafe { &mut *addr_of_mut!((*out).delegation).cast() };
                    rem = Delegation::from_bytes_into(rem, delegation)?;
                    d = Decoder::new(rem);
                } //delegation = Some(Delegation::decode(d, ctx)?),
                _ => return Err(ParserError::InvalidCertificate),
            }
        }

        let cert = unsafe { &mut *out };
        // Verify that the tree raw value can be parsed sucessfully into a HashTree
        let _: HashTree = cert.tree.try_into().map_err(|_| ParserError::InvalidTree)?;

        Ok(d.input())
    }
}

impl<'a> Certificate<'a> {
    pub fn parse(data: &[u8]) -> Result<Certificate, ParserError> {
        let mut decoder = Decoder::new(data);

        // Check for and skip the self-describing CBOR tag if present
        if let Ok(tag) = decoder.tag() {
            if tag.as_u64() != CBOR_CERTIFICATE_TAG {
                return Err(ParserError::CborUnexpected);
            }
        }

        let cert = Certificate::decode(&mut decoder, &mut ())?;

        // Integrity checks in certificates
        // check inner trees:
        let _: HashTree = cert.tree().try_into()?;

        // check delegation certificate if present
        if let Some(delegation) = cert.delegation {
            let _: Certificate = delegation.certificate.try_into()?;
        }

        Ok(cert)
    }

    pub fn tree(&self) -> RawValue<'a> {
        self.tree
    }

    pub fn delegation(&self) -> Option<&Delegation<'a>> {
        self.delegation.as_ref()
    }

    pub fn signature(&self) -> &[u8] {
        self.signature.bls_signature()
    }

    pub fn hash(&self) -> Result<[u8; 32], ParserError> {
        let tree: HashTree = self.tree.try_into()?;
        tree.reconstruct()
    }

    // The root_public_key is now a parameter to the verify method
    pub fn verify(&self, root_key: &[u8]) -> Result<bool, ParserError> {
        // Step 2: Check delegation
        if !self.check_delegation(root_key)? {
            crate::zlog("check_delegation: false\x00");
            return Ok(false);
        }

        // Step 3: Compute BLS key
        let pubkey = self.delegation_key(root_key)?;

        self.verify_signature(pubkey)
    }

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

    fn verify_signature(&self, pubkey: &[u8]) -> Result<bool, ParserError> {
        crate::zlog("verify_signature\x00");
        let signature = self.signature.bls_signature();
        let message = self.bls_message()?;

        // Call third-party library directly to verify this signature
        Ok(verify_bls_signature(signature, &message, pubkey).is_ok())
    }

    // verify the inner certificate
    // the one that comes in the delegation
    // if delegation is not present, return true
    fn check_delegation(&self, root_key: &[u8]) -> Result<bool, ParserError> {
        crate::zlog("Certificate::check_delegation\x00");
        match &self.delegation {
            None => Ok(true),
            Some(delegation) => {
                // Ensure the delegation's certificate contains the subnet's public key
                if delegation.public_key()?.is_none() {
                    crate::zlog("delegation_without_key\x00");
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
                    crate::zlog("delegation::verify: false\x00");
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

        let path = "canister_ranges".into();
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
}

impl<'a> TryFrom<RawValue<'a>> for Certificate<'a> {
    type Error = ParserError;

    fn try_from(value: RawValue<'a>) -> Result<Self, Self::Error> {
        Self::parse(value.bytes())
    }
}

impl<'b, C> Decode<'b, C> for Certificate<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        crate::zlog("Certificate::decode\x00");
        // Expect a map with 2/3 entries
        let len = d.map()?.ok_or(Error::type_mismatch(Type::Map))?;
        // Expect a map with 2/3 entries

        // A certificate could have either 2(delegation cert) or 3 entries(root cert)
        if len != 2 && len != 3 {
            return Err(Error::type_mismatch(Type::Map));
        }

        let mut tree = None;
        let mut signature = None;
        let mut delegation = None;

        for _ in 0..len {
            match d.str()? {
                "tree" => tree = Some(RawValue::decode(d, ctx)?),
                "signature" => signature = Some(RawValue::decode(d, ctx)?.try_into()?),
                "delegation" => delegation = Some(Delegation::decode(d, ctx)?),
                _ => return Err(Error::message("Unexpected key in certificate")),
            }
        }
        // Verify that the tree raw value can be parsed sucessfully into a HashTree
        let raw_tree = tree.ok_or(Error::message("Missing tree"))?;
        let _: HashTree = raw_tree
            .try_into()
            .map_err(|_| Error::message("Invalid tree"))?;

        Ok(Certificate {
            tree: raw_tree,
            signature: signature.ok_or(Error::message("Missing signature"))?,
            delegation,
        })
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
        crate::zlog("Certificate::render_item\x00");
        let msg = self.msg().map_err(|_| ViewError::Unknown)?;
        msg.render_item(item_n, title, message, page)
    }
}

#[cfg(test)]
mod test_certificate {

    use super::*;
    use ic_certification::Certificate as IcpCertificate;

    const REAL_CERT: &str = "d9d9f7a3647472656583018301820458200bbcc71092da3ce262b8154d398b9a6114bee87f1c0b72e16912757aa023626a8301820458200628a8e00432e8657ad99c4d1bf167dd54ace9199609bfc5d57d89f48d97565f83024e726571756573745f737461747573830258204ea057c46292fedb573d35319dd1ccab3fb5d6a2b106b785d1f7757cfa5a254283018302457265706c79820358b44449444c0b6b02bc8a0101c5fed201086c02efcee7800402e29fdcc806036c01d880c6d007716b02d9e5b0980404fcdfd79a0f716c01c4d6b4ea0b056d066c01ffbb87a807076d716b04d1c4987c09a3f2efe6020a9a8597e6030ae3c581900f0a6c02fc91f4f80571c498b1b50d7d6c01fc91f4f8057101000002656e0001021e50726f647563652074686520666f6c6c6f77696e67206772656574696e6714746578743a202248656c6c6f2c20746f626921228302467374617475738203477265706c696564830182045820891af3e8982f1ac3d295c29b9fdfedc52301c03fbd4979676c01059184060b0583024474696d65820349cbf7dd8ca1a2a7e217697369676e6174757265583088078c6fe75f32594bf4e322b14d47e5c849cf24a370e3bab0cab5daffb7ab6a2c49de18b7f2d631893217d0c716cd656a64656c65676174696f6ea2697375626e65745f6964581d2c55b347ecf2686c83781d6c59d1b43e7b4cba8deb6c1b376107f2cd026b6365727469666963617465590294d9d9f7a264747265658301820458200b0d62dc7b9d7de735bb9a6393b59c9f32ff7c4d2aacdfc9e6ffc70e341fb6f783018301820458204468514ca4af8224c055c386e3f7b0bfe018c2d9cfd5837e427b43e1ab0934f98302467375626e65748301830183018301820458208739fbbedd3dedaa8fef41870367c0905bde376b63dd37e2b176fb08b582052f830182045820f8c3eae0377ee00859223bf1c6202f5885c4dcdc8fd13b1d48c3c838688919bc83018302581d2c55b347ecf2686c83781d6c59d1b43e7b4cba8deb6c1b376107f2cd02830183024f63616e69737465725f72616e67657382035832d9d9f782824a000000000060000001014a00000000006000ae0101824a00000000006000b001014a00000000006fffff010183024a7075626c69635f6b657982035885308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c0503020103610090075120778eb21a530a02bcc763e7f4a192933506966af7b54c10a4d2b24de6a86b200e3440bae6267bf4c488d9a11d0472c38c1b6221198f98e4e6882ba38a5a4e3aa5afce899b7f825ed95adfa12629688073556f2747527213e8d73e40ce8204582036f3cd257d90fb38e42597f193a5e031dbd585b6292793bb04db4794803ce06e82045820028fc5e5f70868254e7215e7fc630dbd29eefc3619af17ce231909e1faf97e9582045820696179fceb777eaed283265dd690241999eb3ede594091748b24456160edc1278204582081398069f9684da260cfb002eac42211d0dbf22c62d49aee61617d62650e793183024474696d65820349a5948992aaa195e217697369676e6174757265583094e5f544a7681b0c2c3c5dbf97950c96fd837f2d19342f1050d94d3068371b0a95a5ee20c36c4395c2dbb4204f2b4742";
    const CERT_HASH: &str = "bcedf2eab3980aedd4d0d9f2159efebd5597cbad5f49217e0c9686b93d30d503";
    const DEL_CERT_HASH: &str = "04a94256c02e83aab4f203cb0784340279d7902f9b09305c978be1746e19b742";
    const CANISTER_ID: &str = "00000000006000FD0101";

    const REQUEST_ID: &str = "4ea057c46292fedb573d35319dd1ccab3fb5d6a2b106b785d1f7757cfa5a2542";

    #[test]
    fn parse_cert() {
        let data = hex::decode(REAL_CERT).unwrap();
        let cert = Certificate::parse(&data).unwrap();
        // let cert = Certificate::from_bytes(&data).unwrap();

        std::println!("Certificate: {:?}", cert);
        std::println!("=============================================");
        std::println!("Certificate Tree: ");
        HashTree::parse_and_print_hash_tree(&cert.tree(), 0).unwrap();
        std::println!("=============================================");
        std::println!("Delegation Certificate Tree: ");
        let delegation_certificate = cert.delegation().as_ref().unwrap().cert();
        HashTree::parse_and_print_hash_tree(&delegation_certificate.tree(), 0).unwrap();
        std::println!("=============================================");

        std::println!("timestamp: {:?}", cert.timestamp());
        let request_id = [
            78, 160, 87, 196, 98, 146, 254, 219, 87, 61, 53, 49, 157, 209, 204, 171, 63, 181, 214,
            162, 177, 6, 183, 133, 209, 247, 117, 124, 250, 90, 37, 66,
        ];

        std::println!("request_id: {}", hex::encode(request_id));
        std::println!("certificate_size: {}", core::mem::size_of::<Certificate>());

        // Check we parse the message(reply field)
        assert!(cert.msg().is_ok());
    }

    #[test]
    fn verify_cert() {
        let data = hex::decode(REAL_CERT).unwrap();
        let cert = Certificate::parse(&data).unwrap();
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
        std::println!("*root_hash: {}", root_hash);
        std::println!("*del_hash: {}", icp_hash);

        std::println!("icp_raw_signature {:?}", icp_cert.signature);
        std::println!("icp_signature: {:?}", hex::encode(icp_cert.signature));

        std::println!("=============================================");
        let signature = cert.signature();
        let cert_hash = cert.hash().unwrap();
        let message = cert.bls_message().unwrap();
        let pubkey = cert.delegation_key(&cert_hash).unwrap();
        assert!(pubkey != cert_hash);
        let signature = bls_signature::Signature::deserialize(signature).unwrap();
        std::println!("signature: {:?}", signature);
        let pubkey = bls_signature::PublicKey::deserialize(pubkey).unwrap();
        std::println!("pubkey: {:?}", pubkey);
        pubkey.verify(&message, &signature).unwrap();
        std::println!("=============================================");

        // verify certificate signatures
        let root_key = [0u8; 32];
        assert!(cert.verify(&root_key).unwrap());
    }

    #[test]
    fn check_canister_ranges() {
        let data = hex::decode(REAL_CERT).unwrap();
        let cert = Certificate::parse(&data).unwrap();
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
        let cert = Certificate::parse(&data).unwrap();

        let request_id = hex::decode(REQUEST_ID).unwrap();

        let tree = cert.tree();

        let found = HashTree::lookup_path(&request_id[..].into(), tree).unwrap();
        assert!(found.raw_value().is_some());
    }
}
