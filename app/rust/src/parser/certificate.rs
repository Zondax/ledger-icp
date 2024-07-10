use bls_signature::verify_bls_signature;
use minicbor::{decode::Error, Decode, Decoder};

use crate::{hash_tree::hash_with_domain_sep, signature::Signature};

use super::{delegation::Delegation, hash_tree::HashTree, raw_value::RawValue};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Certificate<'a> {
    tree: RawValue<'a>,
    signature: Signature<'a>,
    delegation: Option<Delegation<'a>>,
}

impl<'a> Certificate<'a> {
    pub fn parse(data: &[u8]) -> Result<Certificate, Error> {
        let mut decoder = Decoder::new(data);

        // Check for and skip the self-describing CBOR tag if present
        if let Ok(tag) = decoder.tag() {
            if tag.as_u64() != 55799 {
                return Err(Error::message("Unexpected tag"));
            }
        }

        let cert = Certificate::decode(&mut decoder, &mut ())?;

        // Integrity checks in certificates
        // check inner trees:
        let _: HashTree = cert.tree().try_into()?;

        // check delegation certificate if present
        if let Some(delegation) = cert.delegation {
            Self::parse(delegation.certificate.bytes())?;
        }

        Ok(cert)
    }

    pub fn tree(&self) -> &RawValue<'a> {
        &self.tree
    }

    pub fn delegation(&self) -> Option<&Delegation<'a>> {
        self.delegation.as_ref()
    }

    pub fn signature(&self) -> Signature<'a> {
        self.signature
    }

    pub fn hash(&self) -> Result<[u8; 32], Error> {
        let tree: HashTree = self.tree.try_into()?;
        tree.reconstruct()
    }

    // The root_public_key is now a parameter to the verify method
    pub fn verify(&self, root_public_key: &[u8]) -> Result<bool, Error> {
        // Step 1: Compute root hash of the outer certificate's tree
        let tree: HashTree = self.tree.try_into()?;
        let root_hash = tree.reconstruct()?;

        // Step 2: Check delegation
        // this ensure no delegation in delegation.cert
        // that delegation.cert.tree() contains a public key
        // verify the delegation.cert using root key
        if !self.check_delegation(root_public_key)? {
            return Ok(false);
        }

        // Step 3: Compute BLS key
        let pubkey = self.delegation_key(root_public_key)?;

        // Step 4: Verify signature
        let message = hash_with_domain_sep("ic-state-root", &root_hash);
        let signature = self.signature.bls_signature()?;
        Ok(verify_bls_signature(signature, &message, pubkey).is_ok())
    }

    // verify the inner certificate
    // the one that comes in the delegation
    fn check_delegation(&self, root_key: &[u8]) -> Result<bool, Error> {
        match &self.delegation {
            None => Ok(true),
            Some(delegation) => {
                // Verify the delegation's certificate
                if !delegation.verify(root_key)? {
                    return Ok(false);
                }

                // Ensure the delegation's certificate contains the subnet's public key
                if delegation.public_key()?.is_none() {
                    return Ok(false);
                }

                // Ensure the delegation's certificate does not have another delegation
                if delegation.cert().delegation().is_some() {
                    return Ok(false);
                }

                Ok(true)
            }
        }
    }

    fn delegation_key(&self, root_public_key: &'a [u8]) -> Result<&'a [u8], Error> {
        #[cfg(test)]
        std::println!("delegation: {:?}", self.delegation);

        match &self.delegation {
            None => Ok(root_public_key), // Use root_public_key if no delegation
            Some(d) => {
                #[cfg(test)]
                std::println!("delegation");
                let key = d
                    .public_key()?
                    .ok_or(Error::message("Missing public key"))?;
                Ok(key.as_bytes())
            }
        }
    }
}

impl<'b, C> Decode<'b, C> for Certificate<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        // Expect a map with 2/3 entries
        let len = d.map()?.ok_or(Error::message("Expected a map"))?;

        // A certificate could have either 2(delegation cert) or 3 entries(root cert)
        if len != 2 && len != 3 {
            return Err(Error::message("Expected a map with 3 entries"));
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
    // Same as above but we change the inner cbor typo to something invalid(different to a map)
    const INVALID_DATA: &str = "A9D9F7A3647472656583018301820458200BBCC71092DA3CE262B8154D398B9A6114BEE87F1C0B72E16912757AA023626A8301820458200628A8E00432E8657AD99C4D1BF167DD54ACE9199609BFC5D57D89F48D97565F83024E726571756573745F737461747573830258204EA057C46292FEDB573D35319DD1CCAB3FB5D6A2B106B785D1F7757CFA5A254283018302457265706C79820358B44449444C0B6B02BC8A0101C5FED201086C02EFCEE7800402E29FDCC806036C01D880C6D007716B02D9E5B0980404FCDFD79A0F716C01C4D6B4EA0B056D066C01FFBB87A807076D716B04D1C4987C09A3F2EFE6020A9A8597E6030AE3C581900F0A6C02FC91F4F80571C498B1B50D7D6C01FC91F4F8057101000002656E0001021E50726F647563652074686520666F6C6C6F77696E67206772656574696E6714746578743A202248656C6C6F2C20746F626921228302467374617475738203477265706C696564830182045820891AF3E8982F1AC3D295C29B9FDFEDC52301C03FBD4979676C01059184060B0583024474696D65820349CBF7DD8CA1A2A7E217697369676E6174757265583088078C6FE75F32594BF4E322B14D47E5C849CF24A370E3BAB0CAB5DAFFB7AB6A2C49DE18B7F2D631893217D0C716CD656A64656C65676174696F6EA2697375626E65745F6964581D2C55B347ECF2686C83781D6C59D1B43E7B4CBA8DEB6C1B376107F2CD026B6365727469666963617465590294D9D9F7A264747265658301820458200B0D62DC7B9D7DE735BB9A6393B59C9F32FF7C4D2AACDFC9E6FFC70E341FB6F783018301820458204468514CA4AF8224C055C386E3F7B0BFE018C2D9CFD5837E427B43E1AB0934F98302467375626E65748301830183018301820458208739FBBEDD3DEDAA8FEF41870367C0905BDE376B63DD37E2B176FB08B582052F830182045820F8C3EAE0377EE00859223BF1C6202F5885C4DCDC8FD13B1D48C3C838688919BC83018302581D2C55B347ECF2686C83781D6C59D1B43E7B4CBA8DEB6C1B376107F2CD02830183024F63616E69737465725F72616E67657382035832D9D9F782824A000000000060000001014A00000000006000AE0101824A00000000006000B001014A00000000006FFFFF010183024A7075626C69635F6B657982035885308182301D060D2B0601040182DC7C0503010201060C2B0601040182DC7C0503020103610090075120778EB21A530A02BCC763E7F4A192933506966AF7B54C10A4D2B24DE6A86B200E3440BAE6267BF4C488D9A11D0472C38C1B6221198F98E4E6882BA38A5A4E3AA5AFCE899B7F825ED95ADFA12629688073556F2747527213E8D73E40CE8204582036F3CD257D90FB38E42597F193A5E031DBD585B6292793BB04DB4794803CE06E82045820028FC5E5F70868254E7215E7FC630DBD29EEFC3619AF17CE231909E1FAF97E9582045820696179FCEB777EAED283265DD690241999EB3EDE594091748B24456160EDC1278204582081398069F9684DA260CFB002EAC42211D0DBF22C62D49AEE61617D62650E793183024474696D65820349A5948992AAA195E217697369676E6174757265583094E5F544A7681B0C2C3C5DBF97950C96FD837F2D19342F1050D94D3068371B0A95A5EE20C36C4395C2DBB4204F2B4742";

    #[test]
    fn parser_cert() {
        let data = hex::decode(REAL_CERT).unwrap();
        let cert = Certificate::parse(&data).unwrap();

        let sign = cert.signature();
        let sign = sign.bls_signature().unwrap();
        std::println!("sign: {:?} - len: {}", sign, sign.len());
    }

    #[test]
    fn error_invalid_certificate() {
        let data = hex::decode(INVALID_DATA).unwrap();
        assert!(Certificate::parse(&data).is_err());
    }

    #[test]
    fn verify_cert() {
        let data = hex::decode(REAL_CERT).unwrap();
        let cert = Certificate::parse(&data).unwrap();
        let root_hash = hex::encode(cert.hash().unwrap());
        // HashTree::parse_and_print_hash_tree(cert.tree(), 0);
        // let del = cert.delegation.unwrap();
        // HashTree::parse_and_print_hash_tree(del.cert().tree(), 0);

        // compare our root hash with the hash icp library computes
        let icp_cert: IcpCertificate = serde_cbor::from_slice(&data).unwrap();
        let icp_tree = icp_cert.tree;
        let icp_hash = icp_tree.digest();
        let icp_hash = hex::encode(icp_hash);

        assert_eq!(root_hash, icp_hash);
        // TODO: enable later
        let root_key = [0u8; 96];
        assert!(cert.verify(&root_key).unwrap());
    }
}
