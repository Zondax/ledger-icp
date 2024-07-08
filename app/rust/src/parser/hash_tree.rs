use minicbor::{decode::Error, Decode, Decoder};
use sha2::Digest;

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
    pub fn parse(raw_tree: RawValue<'a>) -> Result<Self, Error> {
        let mut d = Decoder::new(raw_tree.bytes());
        HashTree::decode(&mut d, &mut ())
    }

    pub fn reconstruct(&self) -> Result<[u8; 32], Error> {
        reconstruct(self)
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
            HashTree::Leaf(data) => println!(
                "{}Leaf: {:?}",
                " ".repeat(indent),
                &data.bytes()[..std::cmp::min(data.len(), 32)]
            ),
            HashTree::Pruned(hash) => println!(
                "{}Pruned: {:?}",
                " ".repeat(indent),
                &hash.bytes()[..std::cmp::min(hash.len(), 32)]
            ),
        }

        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for HashTree<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        match d.datatype()? {
            minicbor::data::Type::Array => {
                let len = d.array()?.ok_or(Error::message("Expected array"))?;
                match len {
                    0 => Ok(HashTree::Empty),
                    _ => {
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
            }
            _ => Err(Error::message("Expected array for HashTree")),
        }
    }
}

#[derive(Debug)]
pub enum LookupResult<'a> {
    Found(RawValue<'a>),
    Absent,
    Unknown,
}

pub fn lookup_path<'a>(label: &Label<'a>, tree: RawValue<'a>) -> Result<LookupResult<'a>, Error> {
    fn inner_lookup<'a>(
        label: &Label<'a>,
        tree: RawValue<'a>,
        depth: usize,
    ) -> Result<LookupResult<'a>, Error> {
        if depth >= MAX_TREE_DEPTH {
            return Err(Error::message("Maximum tree depth exceeded"));
        }
        let current_tree = HashTree::parse(tree)?;

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
                    // Continue searching in the subtree
                    inner_lookup(label, subtree, depth + 1)
                }
            }
            HashTree::Leaf(_) => Ok(LookupResult::Found(tree)),
            HashTree::Pruned(_) => Ok(LookupResult::Unknown),
            HashTree::Empty => Ok(LookupResult::Absent),
        }
    }

    inner_lookup(label, tree, 1)
}

use core::cmp::Ordering;

pub fn lookup_path_list<'a>(
    path: &[Label<'a>],
    tree: RawValue<'a>,
) -> Result<LookupResult<'a>, Error> {
    fn inner_lookup<'a>(
        path: &[Label<'a>],
        tree: RawValue<'a>,
        depth: usize,
    ) -> Result<LookupResult<'a>, Error> {
        if depth >= MAX_TREE_DEPTH {
            return Err(Error::message("Maximum tree depth exceeded"));
        }

        let current_tree = HashTree::parse(tree)?;

        if path.is_empty() {
            return match current_tree {
                HashTree::Empty => Ok(LookupResult::Absent),
                HashTree::Leaf(_) => Ok(LookupResult::Found(tree)),
                HashTree::Pruned(_) => Ok(LookupResult::Unknown),
                HashTree::Labeled(_, _) | HashTree::Fork(_, _) => Err(Error::message(
                    "Path is empty, but tree is not a leaf or empty",
                )),
            };
        }

        match current_tree {
            HashTree::Fork(left, right) => match find_label(&path[0], left, right)? {
                LookupResult::Found(subtree) => inner_lookup(&path[1..], subtree, depth + 1),
                other => Ok(other),
            },
            HashTree::Labeled(node_label, subtree) => match compare_labels(&path[0], &node_label) {
                Ordering::Equal => inner_lookup(&path[1..], subtree, depth + 1),
                _ => Ok(LookupResult::Absent),
            },
            HashTree::Empty | HashTree::Leaf(_) | HashTree::Pruned(_) => Ok(LookupResult::Absent),
        }
    }

    inner_lookup(path, tree, 0)
}

fn find_label<'a>(
    label: &Label,
    left: RawValue<'a>,
    right: RawValue<'a>,
) -> Result<LookupResult<'a>, Error> {
    let left_tree = HashTree::parse(left)?;
    let right_tree = HashTree::parse(right)?;

    match (&left_tree, &right_tree) {
        (HashTree::Labeled(l1, t1), HashTree::Labeled(l2, _)) => match compare_labels(label, l1) {
            Ordering::Equal => Ok(LookupResult::Found(*t1)),
            Ordering::Less => Ok(LookupResult::Absent),
            Ordering::Greater => match compare_labels(label, l2) {
                Ordering::Less => Ok(LookupResult::Absent),
                Ordering::Equal => Ok(LookupResult::Found(right)),
                Ordering::Greater => find_label(label, *t1, right),
            },
        },
        (HashTree::Labeled(l, t), _) => match compare_labels(label, l) {
            Ordering::Equal => Ok(LookupResult::Found(*t)),
            Ordering::Less => Ok(LookupResult::Absent),
            Ordering::Greater => find_label(label, *t, right),
        },
        (_, HashTree::Labeled(l, t)) => match compare_labels(label, l) {
            Ordering::Equal => Ok(LookupResult::Found(*t)),
            Ordering::Less => Ok(LookupResult::Absent),
            Ordering::Greater => Ok(LookupResult::Absent),
        },
        (HashTree::Leaf(_), _) | (_, HashTree::Leaf(_)) => Ok(LookupResult::Absent),
        (HashTree::Empty, _) | (_, HashTree::Empty) => Ok(LookupResult::Absent),
        (HashTree::Pruned(_), _) | (_, HashTree::Pruned(_)) => Ok(LookupResult::Unknown),
        (HashTree::Fork(l1, r1), HashTree::Fork(l2, r2)) => match find_label(label, *l1, *r1)? {
            LookupResult::Absent => find_label(label, *l2, *r2),
            result => Ok(result),
        },
    }
}

fn compare_labels(a: &Label, b: &Label) -> Ordering {
    match (a, b) {
        (Label::Blob(a), Label::Blob(b)) => a.cmp(b),
        (Label::String(a), Label::String(b)) => a.cmp(b),
        (Label::Blob(a), Label::String(b)) => a.cmp(&b.as_bytes()),
        (Label::String(a), Label::Blob(b)) => a.as_bytes().cmp(b),
    }
}

fn reconstruct(tree: &HashTree) -> Result<[u8; 32], Error> {
    let hash = match tree {
        HashTree::Empty => hash_with_domain_sep("ic-hashtree-empty", &[]),
        HashTree::Fork(left, right) => {
            let left = HashTree::parse(*left)?;
            let right = HashTree::parse(*right)?;

            let left_hash = reconstruct(&left)?;
            let right_hash = reconstruct(&right)?;
            let mut concat = [0; 64];
            concat[..32].copy_from_slice(&left_hash);
            concat[32..].copy_from_slice(&right_hash);
            hash_with_domain_sep("ic-hashtree-fork", &concat)
        }
        HashTree::Labeled(label, subtree) => {
            let subtree = HashTree::parse(*subtree)?;
            let subtree_hash = reconstruct(&subtree)?;
            // domain.len() + label_max_len + hash_len
            let mut concat = [0; Label::MAX_LEN + 32];
            let label_len = label.as_bytes().len();
            concat[..label_len].copy_from_slice(label.as_bytes());
            concat[label_len..label_len + 32].copy_from_slice(&subtree_hash);
            hash_with_domain_sep("ic-hashtree-labeled", &concat[..label_len + 32])
        }
        HashTree::Leaf(v) => hash_with_domain_sep("ic-hashtree-leaf", v.bytes()),
        HashTree::Pruned(h) => {
            // Skip the CBOR type identifier and length information
            let hash_start = if h.len() == 34 && h.bytes()[0] == 0x58 && h.bytes()[1] == 0x20 {
                2
            } else {
                0
            };

            if h.len() - hash_start != 32 {
                // FIXME: Do not panic
                panic!("Pruned node hash must be 32 bytes");
            }

            let mut result = [0; 32];
            result.copy_from_slice(&h.bytes()[hash_start..]);
            result
        }
    };
    Ok(hash)
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

    #[test]
    fn test_lookup_time() {
        // Parse the certificate
        let data = hex::decode(DATA).unwrap();
        let cert = Certificate::parse(&data).unwrap();

        // Create the path for "time"
        let path = Label::String("time");

        // Perform the lookup
        match lookup_path(&path, *cert.tree()).unwrap() {
            LookupResult::Found(value) => {
                match HashTree::parse(value) {
                    Ok(HashTree::Leaf(leaf_data)) => {
                        // The expected leaf data
                        let expected = [73, 203, 247, 221, 140, 161, 162, 167, 226, 23];
                        assert_eq!(
                            leaf_data.bytes(),
                            expected,
                            "Leaf data does not match expected value"
                        );
                        std::println!("Successfully found and matched 'time' leaf data");
                    }
                    _ => panic!("Expected Leaf, found {:?}", value),
                }
            }
            _ => panic!("'{:?}' path not found in the tree", path),
        }
    }

    #[test]
    fn test_lookup_reply() {
        // Parse the certificate
        let data = hex::decode(DATA).unwrap();
        let cert = Certificate::parse(&data).unwrap();

        // Create the path for "time"
        // let path = Label::String("reply");
        // let path = [Label::String("request_status"), Label::String("reply")];
        let path = Label::String("reply");

        HashTree::parse_and_print_hash_tree(cert.tree(), 0).unwrap();

        // Perform the lookup
        match lookup_path(&path, *cert.tree()).unwrap() {
            LookupResult::Found(value) => {
                let tree = HashTree::parse(value).unwrap();
                match tree {
                    HashTree::Leaf(leaf_data) => {
                        // The expected leaf data
                        assert_eq!(
                            leaf_data.bytes(),
                            REPLY,
                            "Leaf data does not match expected value"
                        );
                    }
                    _ => panic!("Expected Leaf, found {:?}", value),
                }
            }
            _ => panic!("'{:?}' path not found in the tree", path),
        }
    }

    #[test]
    fn test_reconstruct() {
        let data = hex::decode(DATA).unwrap();
        let cert = Certificate::parse(&data).unwrap();

        let tree = HashTree::parse(*cert.tree()).unwrap();
        let hash = tree.reconstruct().unwrap();
        let hash_str = hex::encode(hash);
        std::println!("Reconstructed hash: {}", hash_str);
    }

    // Fork
    //   Left:
    //     Fork
    //       Left:
    //         Pruned: [88, 32, 11, 188, 199, 16, 146, 218, 60, 226, 98, 184, 21, 77, 57, 139, 154, 97, 20, 190, 232, 127, 28, 11, 114,
    // 225, 105, 18, 117, 122, 160, 35]
    //       Right:
    //         Fork
    //           Left:
    //             Pruned: [88, 32, 6, 40, 168, 224, 4, 50, 232, 101, 122, 217, 156, 77, 27, 241, 103, 221, 84, 172, 233, 25, 150, 9, 19
    // 1, 197, 213, 125, 137, 244, 141, 151]
    //           Right:
    //             Labeled (String): request_status
    //               Labeled (Blob): [78, 160, 87, 196, 98, 146, 254, 219, 87, 61, 53, 49, 157, 209, 204, 171, 63, 181, 214, 162, 177, 6
    // , 183, 133, 209, 247, 117, 124, 250, 90, 37, 66]
    //                 Fork
    //                   Left:
    //                     Labeled (String): reply
    //                       Leaf: [88, 180, 68, 73, 68, 76, 11, 107, 2, 188, 138, 1, 1, 197, 254, 210, 1, 8, 108, 2, 239, 206, 231, 128
    // , 4, 2, 226, 159, 220, 200, 6, 3]
    //                   Right:
    //                     Labeled (String): status
    //                       Leaf: [71, 114, 101, 112, 108, 105, 101, 100]
    //   Right:
    //     Fork
    //       Left:
    //         Pruned: [88, 32, 137, 26, 243, 232, 152, 47, 26, 195, 210, 149, 194, 155, 159, 223, 237, 197, 35, 1, 192, 63, 189, 73, 12
    // 1, 103, 108, 1, 5, 145, 132, 6]
    //       Right:
    //         Labeled (String): time
    //           Leaf: [73, 203, 247, 221, 140, 161, 162, 167, 226, 23]
    //
}
