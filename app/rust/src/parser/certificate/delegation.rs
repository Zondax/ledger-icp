use core::{mem::MaybeUninit, ptr::addr_of_mut};

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
use minicbor::{decode::Error, Decoder};

use crate::{error::ParserError, zlog, FromBytes};

use super::{
    hash_tree::{HashTree, LookupResult},
    pubkey::PublicKey,
    Certificate, RawValue, SubnetId,
};

const DELEGATION_MAP_ENTRIES: u64 = 2;

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct Delegation<'a> {
    pub subnet_id: SubnetId<'a>,
    pub certificate: RawValue<'a>,
}

impl<'a> FromBytes<'a> for Delegation<'a> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'a [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'a [u8], crate::error::ParserError> {
        zlog("Delegation::from_bytes_into\x00");

        let out = out.as_mut_ptr();
        let mut d = Decoder::new(input);

        // Expect a map with 2 entries
        let len = d
            .map()?
            .ok_or(Error::type_mismatch(minicbor::data::Type::Map))?;

        if len != DELEGATION_MAP_ENTRIES {
            return Err(ParserError::InvalidDelegation);
        }

        for _ in 0..2 {
            let key = d.str()?;

            match key {
                "subnet_id" => {
                    let subnet_id: &mut MaybeUninit<SubnetId<'a>> =
                        unsafe { &mut *addr_of_mut!((*out).subnet_id).cast() };

                    let data = &input[d.position()..];

                    let rem = SubnetId::from_bytes_into(data, subnet_id)?;
                    d.set_position(d.position() + (data.len() - rem.len()));
                }
                "certificate" => {
                    let bytes = d.bytes()?;

                    let raw_value: &mut MaybeUninit<RawValue<'a>> =
                        unsafe { &mut *addr_of_mut!((*out).certificate).cast() };
                    _ = RawValue::from_bytes_into(bytes, raw_value)?;
                }
                _ => return Err(ParserError::UnexpectedField),
            }
        }

        Ok(&input[d.position()..])
    }
}

impl<'a> Delegation<'a> {
    #[inline(never)]
    pub fn cert(&self) -> Certificate<'a> {
        // Safe to unwrap as this was checked at parsing
        Certificate::try_from(self.certificate).unwrap()
    }

    pub fn tree(&self) -> HashTree<'a> {
        crate::zlog("Delegation::tree\x00");
        let cert = self.cert();
        // Safe to unwrap as this was checked
        // when Delegation was parsed
        let Ok(tree) = cert.tree().try_into() else {
            unreachable!();
        };

        tree
    }

    pub fn subnet(&self) -> &'a [u8] {
        self.subnet_id.id()
    }

    #[inline(never)]
    pub fn verify(&self, root_key: &[u8]) -> Result<bool, ParserError> {
        crate::zlog("Delegation::verify\x00");
        let cert = self.cert();

        cert.verify(root_key)
    }

    // Why an option?
    // It is not clear if delegation would always contain a key
    #[inline(never)]
    pub fn public_key(&self) -> Result<Option<PublicKey<'a>>, ParserError> {
        crate::zlog("Delegation::public_key\x00");
        let value = self.subnet_public_key()?;
        let Some(value) = value.value() else {
            return Ok(None);
        };
        Ok(Some(PublicKey::try_from(value)?))
    }

    // 1. subnet_id: This is available in the Delegation structure.
    // 2. public_key: We need to lookup ["subnet", subnet_id, "public_key"] in the inner certificate.
    #[inline(never)]
    fn subnet_public_key(&self) -> Result<LookupResult<'a>, ParserError> {
        crate::zlog("Delegation::subnet_public_key\x00");
        // Step 1: Look up "subnet" in the root of the tree
        let cert = self.cert();

        let subnet_result = HashTree::lookup_path(&"subnet".into(), cert.tree())?;

        match subnet_result {
            LookupResult::Found(subnet_value) => {
                // Step 2: Look up the specific subnet_id in the subnet subtree
                let subnet_id_result =
                    HashTree::lookup_path(&self.subnet_id.id().into(), subnet_value)?;

                match subnet_id_result {
                    LookupResult::Found(subnet_id_tree) => {
                        // Step 3: Look up "public_key" in the subnet_id subtree
                        HashTree::lookup_path(&"public_key".into(), subnet_id_tree)
                    }
                    _ => Ok(LookupResult::Absent),
                }
            }
            _ => Ok(LookupResult::Absent),
        }
    }
}

#[cfg(test)]
mod test_delegation {

    use crate::FromBytes;

    use super::*;

    const DATA: &str = "D9D9F7A3647472656583018301820458200BBCC71092DA3CE262B8154D398B9A6114BEE87F1C0B72E16912757AA023626A8301820458200628A8E00432E8657AD99C4D1BF167DD54ACE9199609BFC5D57D89F48D97565F83024E726571756573745F737461747573830258204EA057C46292FEDB573D35319DD1CCAB3FB5D6A2B106B785D1F7757CFA5A254283018302457265706C79820358B44449444C0B6B02BC8A0101C5FED201086C02EFCEE7800402E29FDCC806036C01D880C6D007716B02D9E5B0980404FCDFD79A0F716C01C4D6B4EA0B056D066C01FFBB87A807076D716B04D1C4987C09A3F2EFE6020A9A8597E6030AE3C581900F0A6C02FC91F4F80571C498B1B50D7D6C01FC91F4F8057101000002656E0001021E50726F647563652074686520666F6C6C6F77696E67206772656574696E6714746578743A202248656C6C6F2C20746F626921228302467374617475738203477265706C696564830182045820891AF3E8982F1AC3D295C29B9FDFEDC52301C03FBD4979676C01059184060B0583024474696D65820349CBF7DD8CA1A2A7E217697369676E6174757265583088078C6FE75F32594BF4E322B14D47E5C849CF24A370E3BAB0CAB5DAFFB7AB6A2C49DE18B7F2D631893217D0C716CD656A64656C65676174696F6EA2697375626E65745F6964581D2C55B347ECF2686C83781D6C59D1B43E7B4CBA8DEB6C1B376107F2CD026B6365727469666963617465590294D9D9F7A264747265658301820458200B0D62DC7B9D7DE735BB9A6393B59C9F32FF7C4D2AACDFC9E6FFC70E341FB6F783018301820458204468514CA4AF8224C055C386E3F7B0BFE018C2D9CFD5837E427B43E1AB0934F98302467375626E65748301830183018301820458208739FBBEDD3DEDAA8FEF41870367C0905BDE376B63DD37E2B176FB08B582052F830182045820F8C3EAE0377EE00859223BF1C6202F5885C4DCDC8FD13B1D48C3C838688919BC83018302581D2C55B347ECF2686C83781D6C59D1B43E7B4CBA8DEB6C1B376107F2CD02830183024F63616E69737465725F72616E67657382035832D9D9F782824A000000000060000001014A00000000006000AE0101824A00000000006000B001014A00000000006FFFFF010183024A7075626C69635F6B657982035885308182301D060D2B0601040182DC7C0503010201060C2B0601040182DC7C0503020103610090075120778EB21A530A02BCC763E7F4A192933506966AF7B54C10A4D2B24DE6A86B200E3440BAE6267BF4C488D9A11D0472C38C1B6221198F98E4E6882BA38A5A4E3AA5AFCE899B7F825ED95ADFA12629688073556F2747527213E8D73E40CE8204582036F3CD257D90FB38E42597F193A5E031DBD585B6292793BB04DB4794803CE06E82045820028FC5E5F70868254E7215E7FC630DBD29EEFC3619AF17CE231909E1FAF97E9582045820696179FCEB777EAED283265DD690241999EB3EDE594091748B24456160EDC1278204582081398069F9684DA260CFB002EAC42211D0DBF22C62D49AEE61617D62650E793183024474696D65820349A5948992AAA195E217697369676E6174757265583094E5F544A7681B0C2C3C5DBF97950C96FD837F2D19342F1050D94D3068371B0A95A5EE20C36C4395C2DBB4204F2B4742";
    const SUBNET_ID: &[u8] = &[
        44, 85, 179, 71, 236, 242, 104, 108, 131, 120, 29, 108, 89, 209, 180, 62, 123, 76, 186,
        141, 235, 108, 27, 55, 97, 7, 242, 205, 2,
    ];

    #[test]
    fn test_pubkey() {
        let data = hex::decode(DATA).unwrap();
        let cert = Certificate::from_bytes(&data).unwrap();
        let delegation = cert.delegation().expect("root cert must have a delegation");
        delegation.public_key().unwrap().unwrap();
    }

    #[test]
    fn test_subnet() {
        let data = hex::decode(DATA).unwrap();
        let cert = Certificate::from_bytes(&data).unwrap();
        let delegation = cert.delegation().expect("root cert must have a delegation");
        assert_eq!(delegation.subnet(), SUBNET_ID);
    }
}
