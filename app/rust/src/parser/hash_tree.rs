use minicbor::{data::Type, decode::Error, Decode, Decoder};
use sha2::Digest;

// use core::cmp::Ordering;

use crate::error::ParserError;

use super::{label::Label, raw_value::RawValue};
const MAX_TREE_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashTree<'a> {
    Empty,
    Fork(RawValue<'a>, RawValue<'a>),
    Labeled(Label<'a>, RawValue<'a>),
    Leaf(RawValue<'a>),
    Pruned(RawValue<'a>),
}

impl<'a> HashTree<'a> {
    pub fn is_empty(&self) -> bool {
        matches!(self, HashTree::Empty)
    }

    pub fn is_fork(&self) -> bool {
        matches!(self, HashTree::Fork(_, _))
    }

    pub fn is_labeled(&self) -> bool {
        matches!(self, HashTree::Labeled(_, _))
    }

    pub fn is_leaf(&self) -> bool {
        matches!(self, HashTree::Leaf(_))
    }

    pub fn is_pruned(&self) -> bool {
        matches!(self, HashTree::Pruned(_))
    }

    pub fn label(&self) -> Option<&Label<'a>> {
        match self {
            HashTree::Labeled(label, _) => Some(label),
            _ => None,
        }
    }

    pub fn fork_left(&self) -> Option<&RawValue<'a>> {
        match self {
            HashTree::Fork(left, _) => Some(left),
            _ => None,
        }
    }

    pub fn fork_right(&self) -> Option<&RawValue<'a>> {
        match self {
            HashTree::Fork(_, right) => Some(right),
            _ => None,
        }
    }

    pub fn value(&self) -> Option<&'a [u8]> {
        let value = match self {
            HashTree::Leaf(value) => value,
            HashTree::Pruned(value) => value,
            _ => return None,
        };

        let mut d = Decoder::new(value.bytes());
        d.bytes().ok()
    }

    // Traverse all the tree ensuring
    // at parsing that we can handle its length
    // without reaching overflows, otherwise we error
    fn check_integrity(&self, depth: usize) -> Result<(), ParserError> {
        if depth >= MAX_TREE_DEPTH {
            return Err(ParserError::RecursionLimitReached);
        }

        match self {
            HashTree::Empty => Ok(()),
            HashTree::Fork(left, right) => {
                let tree: HashTree = left.try_into()?;
                tree.check_integrity(depth + 1)?;
                let tree: HashTree = right.try_into()?;
                tree.check_integrity(depth + 1)
            }
            HashTree::Labeled(_, subtree) => {
                let tree: HashTree = subtree.try_into()?;
                tree.check_integrity(depth + 1)
            }
            HashTree::Leaf(_) => Ok(()),
            HashTree::Pruned(_) => Ok(()),
        }
    }

    #[cfg(test)]
    pub fn parse_and_print_hash_tree(raw_tree: &RawValue, indent: usize) -> Result<(), Error> {
        use std::println;

        let mut decoder = Decoder::new(raw_tree.bytes());
        let tree = HashTree::decode(&mut decoder, &mut ())?;

        match tree {
            HashTree::Empty => println!("{}Empty", " ".repeat(indent)),
            HashTree::Fork(left, right) => {
                println!("{}Fork", " ".repeat(indent));
                println!("{}Left:", " ".repeat(indent + 2));
                Self::parse_and_print_hash_tree(&left, indent + 4)?;
                println!("{}Right:", " ".repeat(indent + 2));
                Self::parse_and_print_hash_tree(&right, indent + 4)?;
            }
            HashTree::Labeled(label, subtree) => {
                match label {
                    Label::Blob(b) => println!("{}Labeled (Blob): {:?}", " ".repeat(indent), b),
                    Label::String(s) => println!("{}Labeled (String): {}", " ".repeat(indent), s),
                }
                Self::parse_and_print_hash_tree(&subtree, indent + 2)?;
            }
            HashTree::Leaf(data) => {
                // here data is arraw containing twoo elements:
                // [hash_tree_variant_tag, CBOR_data]
                // we are interested in printing CBOR data
                // and it is just bytes(Blob) according to icp documentation
                // https://internetcomputer.org/docs/current/references/ic-interface-spec/#certification
                let mut d = Decoder::new(data.bytes());
                println!("{}Leaf: {:?}", " ".repeat(indent), d.bytes());
            }
            HashTree::Pruned(hash) => {
                let mut d = Decoder::new(hash.bytes());
                let h = d.bytes()?;
                println!("{}Pruned: {:?}", " ".repeat(indent), h)
            }
        }

        Ok(())
    }

    pub fn lookup_path(
        label: &Label<'a>,
        tree: RawValue<'a>,
    ) -> Result<LookupResult<'a>, ParserError> {
        fn inner_lookup<'a>(
            label: &Label<'a>,
            tree: RawValue<'a>,
            depth: usize,
        ) -> Result<LookupResult<'a>, ParserError> {
            if depth >= MAX_TREE_DEPTH {
                return Err(ParserError::RecursionLimitReached);
            }
            let current_tree = tree.try_into()?;

            match current_tree {
                HashTree::Fork(left, right) => match inner_lookup(label, left, depth + 1)? {
                    LookupResult::Found(value) => Ok(LookupResult::Found(value)),
                    LookupResult::Absent | LookupResult::Unknown => {
                        // check right leaft of this tree
                        inner_lookup(label, right, depth + 1)
                    }
                },
                HashTree::Labeled(node_label, subtree) => {
                    if &node_label == label {
                        Ok(LookupResult::Found(subtree))
                    } else {
                        // Continue searching in the subtree, maybe it contains another label
                        // node that could be the one we are looking for
                        inner_lookup(label, subtree, depth + 1)
                    }
                }
                // Below we should return Found just if Label is empty &[]
                // but currently we are taking a label not an slice of them
                // HashTree::Leaf(_) => Ok(LookupResult::Found(tree)),
                HashTree::Leaf(_) => Ok(LookupResult::Absent),
                HashTree::Pruned(_) => Ok(LookupResult::Unknown),
                HashTree::Empty => Ok(LookupResult::Absent),
            }
        }

        inner_lookup(label, tree, 1)
    }

    /// Reconstruct the root hash of this tree, following the rules in:
    /// https://internetcomputer.org/docs/current/references/ic-interface-spec/#certificate
    pub fn reconstruct(&self) -> Result<[u8; 32], ParserError> {
        let hash = match self {
            HashTree::Empty => hash_with_domain_sep("ic-hashtree-empty", &[]),
            HashTree::Fork(left, right) => {
                let left: HashTree = left.try_into()?;
                let right: HashTree = right.try_into()?;

                let left_hash = left.reconstruct()?;
                let right_hash = right.reconstruct()?;

                let mut concat = [0; 64];
                concat[..32].copy_from_slice(&left_hash);
                concat[32..].copy_from_slice(&right_hash);

                hash_with_domain_sep("ic-hashtree-fork", &concat)
            }
            HashTree::Labeled(label, subtree) => {
                let subtree: HashTree = subtree.try_into()?;
                let subtree_hash = subtree.reconstruct()?;

                // domain.len() + label_max_len + hash_len
                let mut concat = [0; Label::MAX_LEN + 32];
                let label_len = label.as_bytes().len();

                concat[..label_len].copy_from_slice(label.as_bytes());
                concat[label_len..label_len + 32].copy_from_slice(&subtree_hash);

                hash_with_domain_sep("ic-hashtree-labeled", &concat[..label_len + 32])
            }
            HashTree::Leaf(_) => {
                // Safe as this is a Leaf tree
                let value = self.value().unwrap();
                hash_with_domain_sep("ic-hashtree-leaf", value)
            }
            HashTree::Pruned(_) => {
                let hash = self.value().unwrap();
                if hash.len() != 32 {
                    return Err(ParserError::UnexpectedValue);
                }

                let mut result = [0; 32];
                result.copy_from_slice(hash);
                result
            }
        };
        Ok(hash)
    }
}

impl<'a> TryFrom<RawValue<'a>> for HashTree<'a> {
    type Error = ParserError;
    fn try_from(value: RawValue<'a>) -> Result<Self, Self::Error> {
        let mut d = Decoder::new(value.bytes());
        let tree = HashTree::decode(&mut d, &mut ()).map_err(|_| ParserError::InvalidTree)?;
        tree.check_integrity(0)?;
        Ok(tree)
    }
}

impl<'a> TryFrom<&RawValue<'a>> for HashTree<'a> {
    type Error = ParserError;
    fn try_from(value: &RawValue<'a>) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl<'b, C> Decode<'b, C> for HashTree<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        // Every tree is encoded as an array:
        // [tag(u8), data(CBOR blob)]
        // where tag tells the tree type
        let len = d.array()?.ok_or(Error::type_mismatch(Type::Array))?;
        if len == 0 {
            return Ok(HashTree::Empty);
        }
        let tag = u8::decode(d, ctx)?;
        match tag {
            0 => Ok(HashTree::Empty),
            1 => {
                let left = RawValue::decode(d, ctx)?;
                let right = RawValue::decode(d, ctx)?;
                Ok(HashTree::Fork(left, right))
            }
            2 => {
                let label = Label::decode(d, ctx)?;
                let subtree = RawValue::decode(d, ctx)?;
                Ok(HashTree::Labeled(label, subtree))
            }
            3 => Ok(HashTree::Leaf(RawValue::decode(d, ctx)?)),
            4 => Ok(HashTree::Pruned(RawValue::decode(d, ctx)?)),
            _ => Err(Error::message("Invalid HashTree tag")),
        }
    }
}

#[derive(Debug)]
pub enum LookupResult<'a> {
    Found(RawValue<'a>),
    Absent,
    Unknown,
}

impl<'a> LookupResult<'a> {
    pub fn value(&self) -> Option<&RawValue<'a>> {
        match self {
            LookupResult::Found(value) => Some(value),
            _ => None,
        }
    }
}

pub fn hash_with_domain_sep(domain: &str, data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update([domain.len() as u8]);
    hasher.update(domain.as_bytes());
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod hash_tree_tests {
    use crate::parser::certificate::Certificate;

    use super::*;

    const DATA: &str = "D9D9F7A3647472656583018301820458200BBCC71092DA3CE262B8154D398B9A6114BEE87F1C0B72E16912757AA023626A8301820458200628A8E00432E8657AD99C4D1BF167DD54ACE9199609BFC5D57D89F48D97565F83024E726571756573745F737461747573830258204EA057C46292FEDB573D35319DD1CCAB3FB5D6A2B106B785D1F7757CFA5A254283018302457265706C79820358B44449444C0B6B02BC8A0101C5FED201086C02EFCEE7800402E29FDCC806036C01D880C6D007716B02D9E5B0980404FCDFD79A0F716C01C4D6B4EA0B056D066C01FFBB87A807076D716B04D1C4987C09A3F2EFE6020A9A8597E6030AE3C581900F0A6C02FC91F4F80571C498B1B50D7D6C01FC91F4F8057101000002656E0001021E50726F647563652074686520666F6C6C6F77696E67206772656574696E6714746578743A202248656C6C6F2C20746F626921228302467374617475738203477265706C696564830182045820891AF3E8982F1AC3D295C29B9FDFEDC52301C03FBD4979676C01059184060B0583024474696D65820349CBF7DD8CA1A2A7E217697369676E6174757265583088078C6FE75F32594BF4E322B14D47E5C849CF24A370E3BAB0CAB5DAFFB7AB6A2C49DE18B7F2D631893217D0C716CD656A64656C65676174696F6EA2697375626E65745F6964581D2C55B347ECF2686C83781D6C59D1B43E7B4CBA8DEB6C1B376107F2CD026B6365727469666963617465590294D9D9F7A264747265658301820458200B0D62DC7B9D7DE735BB9A6393B59C9F32FF7C4D2AACDFC9E6FFC70E341FB6F783018301820458204468514CA4AF8224C055C386E3F7B0BFE018C2D9CFD5837E427B43E1AB0934F98302467375626E65748301830183018301820458208739FBBEDD3DEDAA8FEF41870367C0905BDE376B63DD37E2B176FB08B582052F830182045820F8C3EAE0377EE00859223BF1C6202F5885C4DCDC8FD13B1D48C3C838688919BC83018302581D2C55B347ECF2686C83781D6C59D1B43E7B4CBA8DEB6C1B376107F2CD02830183024F63616E69737465725F72616E67657382035832D9D9F782824A000000000060000001014A00000000006000AE0101824A00000000006000B001014A00000000006FFFFF010183024A7075626C69635F6B657982035885308182301D060D2B0601040182DC7C0503010201060C2B0601040182DC7C0503020103610090075120778EB21A530A02BCC763E7F4A192933506966AF7B54C10A4D2B24DE6A86B200E3440BAE6267BF4C488D9A11D0472C38C1B6221198F98E4E6882BA38A5A4E3AA5AFCE899B7F825ED95ADFA12629688073556F2747527213E8D73E40CE8204582036F3CD257D90FB38E42597F193A5E031DBD585B6292793BB04DB4794803CE06E82045820028FC5E5F70868254E7215E7FC630DBD29EEFC3619AF17CE231909E1FAF97E9582045820696179FCEB777EAED283265DD690241999EB3EDE594091748B24456160EDC1278204582081398069F9684DA260CFB002EAC42211D0DBF22C62D49AEE61617D62650E793183024474696D65820349A5948992AAA195E217697369676E6174757265583094E5F544A7681B0C2C3C5DBF97950C96FD837F2D19342F1050D94D3068371B0A95A5EE20C36C4395C2DBB4204F2B4742";
    const REPLY: &[u8] = &[
        88, 180, 68, 73, 68, 76, 11, 107, 2, 188, 138, 1, 1, 197, 254, 210, 1, 8, 108, 2, 239, 206,
        231, 128, 4, 2, 226, 159, 220, 200, 6, 3, 108, 1, 216, 128, 198, 208, 7, 113, 107, 2, 217,
        229, 176, 152, 4, 4, 252, 223, 215, 154, 15, 113, 108, 1, 196, 214, 180, 234, 11, 5, 109,
        6, 108, 1, 255, 187, 135, 168, 7, 7, 109, 113, 107, 4, 209, 196, 152, 124, 9, 163, 242,
        239, 230, 2, 10, 154, 133, 151, 230, 3, 10, 227, 197, 129, 144, 15, 10, 108, 2, 252, 145,
        244, 248, 5, 113, 196, 152, 177, 181, 13, 125, 108, 1, 252, 145, 244, 248, 5, 113, 1, 0, 0,
        2, 101, 110, 0, 1, 2, 30, 80, 114, 111, 100, 117, 99, 101, 32, 116, 104, 101, 32, 102, 111,
        108, 108, 111, 119, 105, 110, 103, 32, 103, 114, 101, 101, 116, 105, 110, 103, 20, 116,
        101, 120, 116, 58, 32, 34, 72, 101, 108, 108, 111, 44, 32, 116, 111, 98, 105, 33, 34,
    ];

    // example tree:
    //─┬─┬╴"a" ─┬─┬╴"x" ─╴"hello"
    // │ │      │ └╴Empty
    // │ │      └╴  "y" ─╴"world"
    // │ └╴"b" ──╴"good"
    // └─┬╴"c" ──╴Empty
    //   └╴"d" ──╴"morning"
    const TREE: &str =  "8301830183024161830183018302417882034568656c6c6f810083024179820345776f726c6483024162820344676f6f648301830241638100830241648203476d6f726e696e67";
    const TREE_ROOT_HASH: &str = "eb5c5b2195e62d996b84c9bcc8259d19a83786a2f59e0878cec84c811f669aa0";

    #[test]
    fn test_lookup_time() {
        // Parse the certificate
        let data = hex::decode(DATA).unwrap();
        let cert = Certificate::parse(&data).unwrap();

        // Create the path for "time"
        let path = "time".into();

        // Perform the lookup
        let found = HashTree::lookup_path(&path, *cert.tree()).unwrap();
        let time: HashTree = found.value().unwrap().try_into().unwrap();
        let time = time.value().unwrap();
        let expected = [203, 247, 221, 140, 161, 162, 167, 226, 23];
        assert_eq!(time, expected, "Leaf data does not match expected value");
    }

    #[test]
    fn test_lookup_reply() {
        // Parse the certificate
        let data = hex::decode(DATA).unwrap();
        let cert = Certificate::parse(&data).unwrap();

        let path = "reply".into();

        let found = HashTree::lookup_path(&path, *cert.tree()).unwrap();
        assert!(found.value().is_some());
    }

    #[test]
    fn test_example_tree() {
        // example tree:
        //─┬─┬╴"a" ─┬─┬╴"x" ─╴"hello"
        // │ │      │ └╴Empty
        // │ │      └╴  "y" ─╴"world"
        // │ └╴"b" ──╴"good"
        // └─┬╴"c" ──╴Empty
        //   └╴"d" ──╴"morning"
        let tree = hex::decode(TREE).unwrap();
        let tree = RawValue::from_bytes(&tree).unwrap();

        // Checking "a" branch
        let label_a = "a".into();
        let a_value = HashTree::lookup_path(&label_a, tree).unwrap();
        let LookupResult::Found(value) = a_value else {
            panic!("Node not found");
        };
        let a_tree: HashTree = value.try_into().unwrap();
        assert!(a_tree.is_fork());

        let a_empty = a_tree.fork_left().unwrap();
        let a_empty: HashTree = a_empty.try_into().unwrap();
        let a_empty: HashTree = (a_empty.fork_right().unwrap()).try_into().unwrap();
        assert!(a_empty.is_empty());

        //   lookup x
        let x_value = HashTree::lookup_path(&"x".into(), tree).unwrap();
        let value = x_value.value().unwrap();
        let x_value: HashTree = value.try_into().unwrap();
        assert_eq!(&b"hello", &x_value.value().unwrap());

        //   lookup y
        let y_value = HashTree::lookup_path(&"y".into(), tree).unwrap();
        let value = y_value.value().unwrap();
        let y_value: HashTree = value.try_into().unwrap();
        assert_eq!(&b"world", &y_value.value().unwrap());

        //   lookup b
        let b_value = HashTree::lookup_path(&"b".into(), tree).unwrap();
        let value = b_value.value().unwrap();
        let b_value: HashTree = value.try_into().unwrap();
        assert_eq!(&b"good", &b_value.value().unwrap());

        //   lookup c
        let c_value = HashTree::lookup_path(&"c".into(), tree).unwrap();
        let value = c_value.value().unwrap();
        let c_value: HashTree = value.try_into().unwrap();
        assert!(matches!(c_value, HashTree::Empty));

        //   lookup d
        let d_value = HashTree::lookup_path(&"d".into(), tree).unwrap();
        let value = d_value.value().unwrap();
        let d_value: HashTree = value.try_into().unwrap();
        assert_eq!(&b"morning", &d_value.value().unwrap());
    }

    #[test]
    fn test_reconstruct() {
        let tree = hex::decode(TREE).unwrap();
        let tree = RawValue::from_bytes(&tree).unwrap();
        let tree: HashTree = tree.try_into().unwrap();
        let hash = tree.reconstruct().unwrap();
        let hash_str = hex::encode(hash);
        assert_eq!(hash_str, TREE_ROOT_HASH);
    }
}
