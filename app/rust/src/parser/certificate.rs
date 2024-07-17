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
use core::mem::MaybeUninit;

use bls_signature::verify_bls_signature;
use minicbor::{data::Type, decode::Error, Decode, Decoder};

use crate::{
    constants::CBOR_CERTIFICATE_TAG, error::ParserError, hash_tree::hash_with_domain_sep,
    signature::Signature, FromBytes,
};

use super::{delegation::Delegation, hash_tree::HashTree, raw_value::RawValue};

#[derive(Debug, Clone, Copy, PartialEq)]
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
        let cert = Certificate::parse(input)?;

        out.write(cert);

        // FIXME:assume we read all data
        Ok(&input[input.len()..])
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

    pub fn tree(&self) -> &RawValue<'a> {
        &self.tree
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
        // TODO: You can comment this if in order to check
        // the signature of the outer certificate, because
        // inner certificate(delegation.cert) is verified using
        // root key which we do not have at hand
        if !self.check_delegation(root_key)? {
            return Ok(false);
        }

        // Step 3: Compute BLS key
        let pubkey = self.delegation_key(root_key)?;

        self.verify_signature(pubkey)
    }

    fn verify_signature(&self, pubkey: &[u8]) -> Result<bool, ParserError> {
        // Step 1: Compute root hash, this is computed using certificate.tree
        // This hash is computed correctly as per testing data passed from icp team
        // we get to the same hash.
        let root_hash = self.hash()?;

        // Step 4: Verify signature
        let message = hash_with_domain_sep("ic-state-root", &root_hash);
        let signature = self.signature.bls_signature();

        // Call third-party library directly to verify this signature
        Ok(verify_bls_signature(signature, &message, pubkey).is_ok())
    }

    // verify the inner certificate
    // the one that comes in the delegation
    // if delegation is not present, return true
    fn check_delegation(&self, root_key: &[u8]) -> Result<bool, ParserError> {
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
}

impl<'a> TryFrom<RawValue<'a>> for Certificate<'a> {
    type Error = ParserError;

    fn try_from(value: RawValue<'a>) -> Result<Self, Self::Error> {
        Self::parse(value.bytes())
    }
}

impl<'b, C> Decode<'b, C> for Certificate<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        // Expect a map with 2/3 entries
        let len = d.map()?.ok_or(Error::type_mismatch(Type::Map))?;

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
        Ok(Certificate {
            tree: tree.ok_or(Error::message("Missing tree"))?,
            signature: signature.ok_or(Error::message("Missing signature"))?,
            delegation,
        })
    }
}

#[cfg(test)]
mod test_certificate {

    use super::*;
    use ic_certification::Certificate as IcpCertificate;

    const REAL_CERT: &str = "D9D9F7A3647472656583018301820458200BBCC71092DA3CE262B8154D398B9A6114BEE87F1C0B72E16912757AA023626A8301820458200628A8E00432E8657AD99C4D1BF167DD54ACE9199609BFC5D57D89F48D97565F83024E726571756573745F737461747573830258204EA057C46292FEDB573D35319DD1CCAB3FB5D6A2B106B785D1F7757CFA5A254283018302457265706C79820358B44449444C0B6B02BC8A0101C5FED201086C02EFCEE7800402E29FDCC806036C01D880C6D007716B02D9E5B0980404FCDFD79A0F716C01C4D6B4EA0B056D066C01FFBB87A807076D716B04D1C4987C09A3F2EFE6020A9A8597E6030AE3C581900F0A6C02FC91F4F80571C498B1B50D7D6C01FC91F4F8057101000002656E0001021E50726F647563652074686520666F6C6C6F77696E67206772656574696E6714746578743A202248656C6C6F2C20746F626921228302467374617475738203477265706C696564830182045820891AF3E8982F1AC3D295C29B9FDFEDC52301C03FBD4979676C01059184060B0583024474696D65820349CBF7DD8CA1A2A7E217697369676E6174757265583088078C6FE75F32594BF4E322B14D47E5C849CF24A370E3BAB0CAB5DAFFB7AB6A2C49DE18B7F2D631893217D0C716CD656A64656C65676174696F6EA2697375626E65745F6964581D2C55B347ECF2686C83781D6C59D1B43E7B4CBA8DEB6C1B376107F2CD026B6365727469666963617465590294D9D9F7A264747265658301820458200B0D62DC7B9D7DE735BB9A6393B59C9F32FF7C4D2AACDFC9E6FFC70E341FB6F783018301820458204468514CA4AF8224C055C386E3F7B0BFE018C2D9CFD5837E427B43E1AB0934F98302467375626E65748301830183018301820458208739FBBEDD3DEDAA8FEF41870367C0905BDE376B63DD37E2B176FB08B582052F830182045820F8C3EAE0377EE00859223BF1C6202F5885C4DCDC8FD13B1D48C3C838688919BC83018302581D2C55B347ECF2686C83781D6C59D1B43E7B4CBA8DEB6C1B376107F2CD02830183024F63616E69737465725F72616E67657382035832D9D9F782824A000000000060000001014A00000000006000AE0101824A00000000006000B001014A00000000006FFFFF010183024A7075626C69635F6B657982035885308182301D060D2B0601040182DC7C0503010201060C2B0601040182DC7C0503020103610090075120778EB21A530A02BCC763E7F4A192933506966AF7B54C10A4D2B24DE6A86B200E3440BAE6267BF4C488D9A11D0472C38C1B6221198F98E4E6882BA38A5A4E3AA5AFCE899B7F825ED95ADFA12629688073556F2747527213E8D73E40CE8204582036F3CD257D90FB38E42597F193A5E031DBD585B6292793BB04DB4794803CE06E82045820028FC5E5F70868254E7215E7FC630DBD29EEFC3619AF17CE231909E1FAF97E9582045820696179FCEB777EAED283265DD690241999EB3EDE594091748B24456160EDC1278204582081398069F9684DA260CFB002EAC42211D0DBF22C62D49AEE61617D62650E793183024474696D65820349A5948992AAA195E217697369676E6174757265583094E5F544A7681B0C2C3C5DBF97950C96FD837F2D19342F1050D94D3068371B0A95A5EE20C36C4395C2DBB4204F2B4742";
    const CERT_HASH: &str = "bcedf2eab3980aedd4d0d9f2159efebd5597cbad5f49217e0c9686b93d30d503";
    const DEL_CERT_HASH: &str = "04a94256c02e83aab4f203cb0784340279d7902f9b09305c978be1746e19b742";

    #[test]
    fn parse_cert() {
        let data = hex::decode(REAL_CERT).unwrap();
        let cert = Certificate::parse(&data).unwrap();

        std::println!("Certificate: {:?}", cert);
        std::println!("=============================================");
        std::println!("Certificate Tree: ");
        HashTree::parse_and_print_hash_tree(cert.tree(), 0).unwrap();
        std::println!("=============================================");
        std::println!("Delegation Certificate Tree: ");
        let delegation_certificate = cert.delegation().as_ref().unwrap().cert();
        HashTree::parse_and_print_hash_tree(delegation_certificate.tree(), 0).unwrap();
        std::println!("=============================================");
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
        let cert_hash = hash_with_domain_sep("ic-state-root", &cert_hash);
        let pubkey = cert.delegation_key(&cert_hash).unwrap();
        assert!(pubkey != cert_hash);
        let signature = bls_signature::Signature::deserialize(signature).unwrap();
        std::println!("signature: {:?}", signature);
        let pubkey = bls_signature::PublicKey::deserialize(pubkey).unwrap();
        std::println!("pubkey: {:?}", pubkey);
        pubkey.verify(&cert_hash, &signature).unwrap();
        std::println!("=============================================");

        // verify certificate signatures
        let root_key = [0u8; 32];
        assert!(cert.verify(&root_key).unwrap());
    }
}
