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
        HashTree::parse_and_print_hash_tree(&cert.tree, 0).unwrap();

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

    use crate::consent_message::msg_response::ResponseType;

    use super::*;
    use ic_certification::Certificate as IcpCertificate;

    const REAL_CERT: &str = "d9d9f7a264747265658301830182045820d4cff6a25570a56ac14e743e694daa2aa88b80a4bea761116471b56e4945ed6d830182045820f26d51d511039fcb5058441e6204fec42a0da824541f57d0c1c3468a13e16cbf83024e726571756573745f737461747573830182045820198df32f6757100316e899c7a3afec26f6933c06bf5d2f6233f6b0f14ac5b96f83025820ea37fdc5229d7273d500dc8ae3c009f0421049c1f02cc5ad85ea838ae7dfc04583018302457265706c7982035903304449444c0c6b02bc8a0101c5fed201096c02efcee7800402e29fdcc806046c02aeaeb1cc0503d880c6d007716e766b02d9e5b0980405fcdfd79a0f716c01c4d6b4ea0b066d076c01ffbb87a807086d716b04d1c4987c0aa3f2efe6020b9a8597e6030be3c581900f0b6c02fc91f4f80571c498b1b50d7d6c01fc91f4f805710100000002656e0007031e2320417574686f72697a6520616e6f74686572206164647265737320746f2077697468647261772066726f6d20796f7572206163636f756e74202a2a5468651f666f6c6c6f77696e67206164647265737320697320616c6c6f77656420746f031d77697468647261772066726f6d20796f7572206163636f756e743a2a2a2272646d78362d6a616161612d61616161612d61616164712d636169202a2a596f75720d7375626163636f756e743a2a2a032330303030303030303030303030303030303030303030303030303030303030303030301d3030303030303030303030303030303030303030303030303030303030232a2a526571756573746564207769746864726177616c20616c6c6f77616e63653a2a2a032031302049435020e29aa02054686520616c6c6f77616e63652077696c6c2062652273657420746f2031302049435020696e646570656e64656e746c79206f6620616e791e70726576696f757320616c6c6f77616e63652e20556e74696c207468697303217472616e73616374696f6e20686173206265656e206578656375746564207468651e7370656e6465722063616e207374696c6c206578657263697365207468652370726576696f757320616c6c6f77616e63652028696620616e792920746f2069742773032166756c6c20616d6f756e742e202a2a45787069726174696f6e20646174653a2a2a204e6f2065787069726174696f6e2e202a2a417070726f76616c206665653a2a2a23302e3030303120494350202a2a5472616e73616374696f6e206665657320746f206265031a7061696420627920796f7572207375626163636f756e743a2a2a2330303030303030303030303030303030303030303030303030303030303030303030301d30303030303030303030303030303030303030303030303030303030308302467374617475738203477265706c6965648301820458206d8327eb52806a887c0e4f444261e7bde20005e64d9b31479b9af72f8f89886083024474696d65820349c8ccbcfea4c8ca8318697369676e61747572655830b9eb03718c42aa1926bab9956dcef37432045ba1122baf120b8fc3e9fb56f75df8eee419e4e6488e60db79dcaba8c153";
    const REAL_CERT2: &str = "d9d9f7a264747265658301830182045820f7ce39e353276ef7eac40214d6294a53d45c840988b3ad8d0655230bac1893d483018204582045c8d9bed81048bbe60926bf8585350ba6bbe6523d6f5f994fff922edbdef96e83024e726571756573745f737461747573830183018301820458202d1afceef6681d8b8a48dbc7dcde236ad09ff53487b5f65c86f402c4019c81e08301830183018301830182045820bda400ec9debeeaf0e8e4dc6308cf1d0ccc2f6861984ffe8cb5c0f7ddd006bdd830183018301830182045820c3a04b54583072b58beab029efcbd9d9f2191c061fda4c79dfcd554f57534b598302582034a44c265c7ff6c8e4ed5c3d442f12b8b52580f800ffb892a89ad56b3167a62683018302457265706c7982035903304449444c0c6b02bc8a0101c5fed201096c02efcee7800402e29fdcc806046c02aeaeb1cc0503d880c6d007716e766b02d9e5b0980405fcdfd79a0f716c01c4d6b4ea0b066d076c01ffbb87a807086d716b04d1c4987c0aa3f2efe6020b9a8597e6030be3c581900f0b6c02fc91f4f80571c498b1b50d7d6c01fc91f4f805710100000002656e0007031e2320417574686f72697a6520616e6f74686572206164647265737320746f2077697468647261772066726f6d20796f7572206163636f756e74202a2a5468651f666f6c6c6f77696e67206164647265737320697320616c6c6f77656420746f031d77697468647261772066726f6d20796f7572206163636f756e743a2a2a2272646d78362d6a616161612d61616161612d61616164712d636169202a2a596f75720d7375626163636f756e743a2a2a032330303030303030303030303030303030303030303030303030303030303030303030301d3030303030303030303030303030303030303030303030303030303030232a2a526571756573746564207769746864726177616c20616c6c6f77616e63653a2a2a032031302049435020e29aa02054686520616c6c6f77616e63652077696c6c2062652273657420746f2031302049435020696e646570656e64656e746c79206f6620616e791e70726576696f757320616c6c6f77616e63652e20556e74696c207468697303217472616e73616374696f6e20686173206265656e206578656375746564207468651e7370656e6465722063616e207374696c6c206578657263697365207468652370726576696f757320616c6c6f77616e63652028696620616e792920746f2069742773032166756c6c20616d6f756e742e202a2a45787069726174696f6e20646174653a2a2a204e6f2065787069726174696f6e2e202a2a417070726f76616c206665653a2a2a23302e3030303120494350202a2a5472616e73616374696f6e206665657320746f206265031a7061696420627920796f7572207375626163636f756e743a2a2a2330303030303030303030303030303030303030303030303030303030303030303030301d30303030303030303030303030303030303030303030303030303030308302467374617475738203477265706c696564820458205c1a351ac2b7a24b96afcaf767521613b4fd3e577aee74769266cf9f36637d4e8204582068041707ea8d374da007bb1a7a0e0bed07ab24f04b026f7986fc2a85a8fe126282045820b1dcc25b9e681479a3a0c8e48f7ec659cba3a8d2432d9da3539993e3d07ca1be820458200a9b91be81767b301772430b1e4e3347c17b107de0fd585c88108d613550f1758204582035d8238a10e9bb5c4181e35da06ebebba1aea87bb3d144b2dda13c9fcba042f4820458205f41f1b3eda637ed957dbb173be06810a3518eeca57efee3538fbded7a146ef182045820642f92e0236f3dfa2becc643a3aa9703aa4c998360b67d57b03961fdf6c704fe82045820a2092115cfa051b579b9e20a04a9d711fe65e960e47a883a7971ae348af2100282045820175aaba4eea75ae431612394d2dc78fe5058c846466011f311b90b3b5df77000830182045820bc995b4159ff52ed2d587118a4260a039b6141b7af942d7f482c34b37d62e53c83024474696d65820349c18af7abc1d9fe8618697369676e61747572655830a272688e94dffcee62a658d41a6c19cf5f531bc5d1f238ffea80706fc8ffa878cb760a68bf32fa596c651652d2e00a2a";
    const CANISTER_ID: &str = "00000000000000020101";
    const REQUEST_ID: &str = "ea37fdc5229d7273d500dc8ae3c009f0421049c1f02cc5ad85ea838ae7dfc045";
    const INGRESS_EXPIRY: u64 = 1731399240000000000;
    const INGRESS_EXPIRY2: u64 = 1731399240000000000;
    const CERT_GENERIC_DISPLAY: &str = "d9d9f7a2647472656583018301820458207970ca0b7b0c0e63228c4cf47ce6f4a94268cfc004a99ae8aba5e97f204126a183018204582080b175729756e05010ceab7db6bed386cc6db61d274fe7d38a5f0bcea7ef317783024e726571756573745f7374617475738301830258204b77e3e74aa91e7bf50f8cf1acc0cb1dbafa4ad45c050e2abcc5d910317862a383018302457265706c79820359032d4449444c0c6b02bc8a0101c5fed201096c02efcee7800402e29fdcc806046c02aeaeb1cc0503d880c6d007716e766b02d9e5b0980405fcdfd79a0f716c01c4d6b4ea0b066d076c01ffbb87a807086d716b04d1c4987c0aa3f2efe6020b9a8597e6030be3c581900f0b6c02fc91f4f80571c498b1b50d7d6c01fc91f4f805710100000002656e01a4052320417574686f72697a6520616e6f74686572206164647265737320746f2077697468647261772066726f6d20796f7572206163636f756e740a0a2a2a54686520666f6c6c6f77696e67206164647265737320697320616c6c6f77656420746f2077697468647261772066726f6d20796f7572206163636f756e743a2a2a0a72646d78362d6a616161612d61616161612d61616164712d6361690a0a2a2a596f7572207375626163636f756e743a2a2a0a303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030300a0a2a2a526571756573746564207769746864726177616c20616c6c6f77616e63653a2a2a0a3130204943500ae29aa02054686520616c6c6f77616e63652077696c6c2062652073657420746f2031302049435020696e646570656e64656e746c79206f6620616e792070726576696f757320616c6c6f77616e63652e20556e74696c2074686973207472616e73616374696f6e20686173206265656e20657865637574656420746865207370656e6465722063616e207374696c6c206578657263697365207468652070726576696f757320616c6c6f77616e63652028696620616e792920746f20697427732066756c6c20616d6f756e742e0a0a2a2a45787069726174696f6e20646174653a2a2a0a4e6f2065787069726174696f6e2e0a0a2a2a417070726f76616c206665653a2a2a0a302e30303031204943500a0a2a2a5472616e73616374696f6e206665657320746f206265207061696420627920796f7572207375626163636f756e743a2a2a0a303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030308302467374617475738203477265706c696564820458203c45af0e5805729f1d07fbce20047198017873e787c5a27744ca20c71ad357b8830182045820d4fdd3b69be601a88a9412234c7940446d55dbc09bd3f28eb96d8548a2fe885283024474696d65820349889893d986e3d58218697369676e61747572655830b60f55093dc0835939589c2a3dcb5313248b13b5d965f3019fb9f5f3d34503443100b5103386a9d2df229fa82fe0440c";
    const ROOT_KEY: &str =
        "b354faa40626ebc91ed7e55b2307feff70d119ef37f89915bd4561a1ed8c5c26c8c2cb8c4711eec681bf213a75cb988008fb1f4d7aa278cd4fad6f295c83bab04b8cabcb32640cf926083daf865551f9f3b76fd800dac027a583858b9d1d3f64";
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
        assert!(cert.delegation.is_none());

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
    fn cert_lookup_request_id() {
        let data = hex::decode(REAL_CERT).unwrap();
        let cert = Certificate::from_bytes(&data).unwrap();

        let request_id = hex::decode(REQUEST_ID).unwrap();

        let tree = cert.tree();

        let found = HashTree::lookup_path(&request_id[..].into(), tree).unwrap();
        assert!(found.raw_value().is_some());
    }

    #[test]
    fn error_generic_display() {
        let data = hex::decode(CERT_GENERIC_DISPLAY).unwrap();
        let cert = Certificate::from_bytes(&data).unwrap();

        // Check we parse the message(reply field)
        let msg = cert.msg_response().unwrap();
        assert_eq!(msg.response_type(), ResponseType::Ok);
    }

    #[test]
    fn verify2() {
        let data = hex::decode(REAL_CERT2).unwrap();
        let cert = Certificate::from_bytes(&data).unwrap();
        let cert_signature = hex::encode(cert.signature());
        let root_hash = hex::encode(cert.hash().unwrap());
        // Verify delegation.cert root_hash
        assert!(cert.delegation.is_none());

        // compare our root hash with the hash icp library computes
        let icp_cert: IcpCertificate = serde_cbor::from_slice(&data).unwrap();
        let icp_tree = icp_cert.tree;
        let icp_hash = icp_tree.digest();
        let icp_hash = hex::encode(icp_hash);
        let icp_signature = hex::encode(icp_cert.signature);

        assert_eq!(root_hash, icp_hash);
        assert_eq!(cert_signature, icp_signature);

        let root_key = extract_bls_from_der(&hex::decode(DER_ROOT_KEY).unwrap()).unwrap();
        std::println!("rootykey: {}", hex::encode(&root_key));
        cert.msg_response().unwrap();
        assert!(cert.verify(&root_key).unwrap());
    }
}
